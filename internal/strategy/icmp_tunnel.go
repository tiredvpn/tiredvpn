package strategy

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMPTunnelStrategy implements ICMP-based backup tunnel
// Priority: 70 (low priority, used as fallback only)
// Mode: Stealth ONLY (Fast and Burst are DISABLED for safety)
// Rate limit: 10 packets/sec maximum
type ICMPTunnelStrategy struct {
	serverAddr string
	secret     []byte
	mode       string // only "stealth" is allowed
	rateLimit  int    // 10 pps max

	mu sync.RWMutex
}

// ICMP Tunnel constants
const (
	// ICMPTunnelMagic is the magic bytes to identify tunnel packets
	ICMPTunnelMagic uint16 = 0x4943 // "IC"

	// ICMPTunnelVersion is the protocol version
	ICMPTunnelVersion uint8 = 2

	// Header sizes
	ICMPHeaderSize   = 8
	TunnelHeaderSize = 16
	AuthTagSize      = 16 // Poly1305

	// MaxPayloadSize = MTU - IP header - ICMP header - Tunnel header - Auth tag
	MaxPayloadSize = 1400 - ICMPHeaderSize - TunnelHeaderSize - AuthTagSize

	// Stealth mode parameters (ONLY allowed mode)
	StealthPacketRate  = 10  // packets per second
	StealthPayloadSize = 56  // bytes, matches standard ping
	StealthJitterMin   = 10  // milliseconds
	StealthJitterMax   = 50  // milliseconds

	// Timeouts
	ICMPConnectTimeout = 10 * time.Second
	ICMPReadTimeout    = 30 * time.Second
	ICMPWriteTimeout   = 10 * time.Second
	ICMPProbeTimeout   = 5 * time.Second
)

// TunnelHeader is the header for tunnel packets
type TunnelHeader struct {
	Magic      uint16 // 0x4943 ("IC")
	Version    uint8  // 2
	Flags      uint8  // [mode:2][compress:1][fragment:1][last:1][reserved:3]
	SessionID  uint32
	PacketSeq  uint32 // Sequence for crypto nonce
	PayloadLen uint16
	Reserved   uint16
}

// Tunnel flags
const (
	FlagControl  uint8 = 0x80 // Control message
	FlagCompress uint8 = 0x40 // Compressed
	FlagFragment uint8 = 0x20 // Fragment follows
	FlagLast     uint8 = 0x10 // Last fragment
)

// NewICMPTunnelStrategy creates a new ICMP tunnel strategy (backup only)
func NewICMPTunnelStrategy(serverAddr string, secret []byte) *ICMPTunnelStrategy {
	return &ICMPTunnelStrategy{
		serverAddr: serverAddr,
		secret:     secret,
		mode:       "stealth", // ONLY stealth mode is allowed
		rateLimit:  StealthPacketRate,
	}
}

// Name returns human-readable strategy name
func (s *ICMPTunnelStrategy) Name() string {
	return "ICMP Tunnel (Backup)"
}

// ID returns unique strategy identifier
func (s *ICMPTunnelStrategy) ID() string {
	return "icmp_tunnel"
}

// Priority returns execution priority (70 = backup, low priority)
// Lower numbers = higher priority, so 70 is very low
func (s *ICMPTunnelStrategy) Priority() int {
	return 70 // Backup strategy - only used when primary strategies fail
}

// RequiresServer returns true if strategy needs special server support
func (s *ICMPTunnelStrategy) RequiresServer() bool {
	return true
}

// Description returns detailed description
func (s *ICMPTunnelStrategy) Description() string {
	return "ICMP Echo tunnel for backup connectivity (stealth mode only, 10 pps, requires root/CAP_NET_RAW)"
}

// Probe tests if ICMP connectivity works to the server
func (s *ICMPTunnelStrategy) Probe(ctx context.Context, target string) error {
	// Extract host from server address
	host, _, err := net.SplitHostPort(s.serverAddr)
	if err != nil {
		host = s.serverAddr
	}

	// Resolve IP
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return fmt.Errorf("icmp probe: resolve failed: %w", err)
	}

	// Create ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// Likely missing CAP_NET_RAW
		return fmt.Errorf("icmp probe: listen failed (need root/CAP_NET_RAW): %w", err)
	}
	defer conn.Close()

	// Build ping packet
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: make([]byte, 56), // Standard ping size
		},
	}

	// Fill with random data
	rand.Read(msg.Body.(*icmp.Echo).Data)

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("icmp probe: marshal failed: %w", err)
	}

	// Set timeout
	probeCtx, cancel := context.WithTimeout(ctx, ICMPProbeTimeout)
	defer cancel()

	deadline, _ := probeCtx.Deadline()
	conn.SetDeadline(deadline)

	// Send ping
	if _, err := conn.WriteTo(msgBytes, ip); err != nil {
		return fmt.Errorf("icmp probe: send failed: %w", err)
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return fmt.Errorf("icmp probe: receive failed: %w", err)
	}

	// Parse reply
	rm, err := icmp.ParseMessage(1, reply[:n]) // 1 = ICMP for IPv4
	if err != nil {
		return fmt.Errorf("icmp probe: parse failed: %w", err)
	}

	// Check if it's Echo Reply
	if rm.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("icmp probe: unexpected type %v", rm.Type)
	}

	log.Debug("ICMP probe successful to %s (replied from %s)", host, peer)
	return nil
}

// Connect establishes ICMP tunnel connection
func (s *ICMPTunnelStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	log.Debug("ICMP Tunnel: Connecting to %s via %s (mode=%s)", target, s.serverAddr, s.mode)

	// Extract host from server address
	host, _, err := net.SplitHostPort(s.serverAddr)
	if err != nil {
		host = s.serverAddr
	}

	// Resolve server IP
	serverIP, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel: resolve failed: %w", err)
	}

	// Create ICMP connection (requires root/CAP_NET_RAW)
	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel: listen failed (need root/CAP_NET_RAW): %w", err)
	}

	// Derive session key from secret
	cipher, err := chacha20poly1305.New(deriveICMPKey(s.secret))
	if err != nil {
		icmpConn.Close()
		return nil, fmt.Errorf("icmp tunnel: cipher init failed: %w", err)
	}

	// Generate session ID
	var sessionID uint32
	binary.Read(rand.Reader, binary.BigEndian, &sessionID)

	// Create tunnel connection wrapper
	tunnel := &icmpTunnelConn{
		icmpConn:   icmpConn,
		serverIP:   serverIP,
		serverAddr: s.serverAddr,
		cipher:     cipher,
		sessionID:  sessionID,
		tunnelID:   uint16(os.Getpid() & 0xffff),
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		done:       make(chan struct{}),
		rateLimit:  s.rateLimit,
	}

	// Perform handshake
	connectCtx, cancel := context.WithTimeout(ctx, ICMPConnectTimeout)
	defer cancel()

	if err := tunnel.handshake(connectCtx); err != nil {
		tunnel.Close()
		return nil, fmt.Errorf("icmp tunnel: handshake failed: %w", err)
	}

	// Start send/receive loops
	go tunnel.sendLoop()
	go tunnel.recvLoop()

	log.Info("ICMP Tunnel: Established to %s (session=%08x, mode=%s)", s.serverAddr, sessionID, s.mode)

	return tunnel, nil
}

// icmpTunnelConn implements net.Conn over ICMP
type icmpTunnelConn struct {
	icmpConn   *icmp.PacketConn
	serverIP   *net.IPAddr
	serverAddr string
	cipher     cipher.AEAD
	sessionID  uint32
	tunnelID   uint16

	// Packet sequencing
	sendSeq atomic.Uint64
	recvSeq atomic.Uint64

	// Queues
	sendQueue chan []byte
	recvQueue chan []byte

	// State
	done   chan struct{}
	closed atomic.Bool

	// Rate limiting (stealth mode)
	rateLimit    int
	lastSendTime time.Time
	rateMu       sync.Mutex

	// Read buffer for partial reads
	readBuf   []byte
	readBufMu sync.Mutex
}

// handshake performs ICMP tunnel handshake
func (c *icmpTunnelConn) handshake(ctx context.Context) error {
	// Generate client random
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)

	// Build handshake init packet
	initPacket, err := c.buildPacket(clientRandom, FlagControl)
	if err != nil {
		return fmt.Errorf("build init packet: %w", err)
	}

	// Set deadline
	deadline, _ := ctx.Deadline()
	c.icmpConn.SetDeadline(deadline)

	// Send handshake init
	if _, err := c.icmpConn.WriteTo(initPacket, c.serverIP); err != nil {
		return fmt.Errorf("send init: %w", err)
	}

	log.Debug("ICMP Tunnel: Handshake init sent")

	// Wait for reply
	reply := make([]byte, 1500)
	n, peer, err := c.icmpConn.ReadFrom(reply)
	if err != nil {
		return fmt.Errorf("receive ack: %w", err)
	}

	// Verify sender
	if peer.String() != c.serverIP.String() {
		return fmt.Errorf("unexpected sender: %s", peer)
	}

	// Parse and validate reply
	if err := c.parseHandshakeReply(reply[:n]); err != nil {
		return fmt.Errorf("parse reply: %w", err)
	}

	log.Debug("ICMP Tunnel: Handshake complete")
	return nil
}

// parseHandshakeReply validates handshake response
func (c *icmpTunnelConn) parseHandshakeReply(data []byte) error {
	// Parse ICMP message
	msg, err := icmp.ParseMessage(1, data)
	if err != nil {
		return err
	}

	// Must be Echo Reply
	if msg.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("not echo reply: %v", msg.Type)
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return errors.New("not echo body")
	}

	// Verify tunnel header magic
	if len(echo.Data) < TunnelHeaderSize {
		return errors.New("payload too short")
	}

	magic := binary.BigEndian.Uint16(echo.Data[0:2])
	if magic != ICMPTunnelMagic {
		return errors.New("invalid magic")
	}

	version := echo.Data[2]
	if version != ICMPTunnelVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}

	return nil
}

// buildPacket creates an ICMP Echo Request with encrypted tunnel data
func (c *icmpTunnelConn) buildPacket(data []byte, flags uint8) ([]byte, error) {
	seq := c.sendSeq.Add(1)

	// Create tunnel header
	header := TunnelHeader{
		Magic:      ICMPTunnelMagic,
		Version:    ICMPTunnelVersion,
		Flags:      flags,
		SessionID:  c.sessionID,
		PacketSeq:  uint32(seq),
		PayloadLen: uint16(len(data)),
	}

	// Serialize header
	headerBytes := serializeTunnelHeader(header)

	// Create nonce from sequence
	nonce := make([]byte, 24) // XChaCha20 uses 24-byte nonce
	binary.BigEndian.PutUint64(nonce[16:], seq)

	// Encrypt payload with header as additional data
	encrypted := c.cipher.Seal(nil, nonce, data, headerBytes)

	// Build ICMP payload: tunnel header + encrypted data
	payload := make([]byte, TunnelHeaderSize+len(encrypted))
	copy(payload[0:TunnelHeaderSize], headerBytes)
	copy(payload[TunnelHeaderSize:], encrypted)

	// Create ICMP Echo Request
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(c.tunnelID),
			Seq:  int(seq & 0xffff),
			Data: payload,
		},
	}

	return msg.Marshal(nil)
}

// serializeTunnelHeader converts header to bytes
func serializeTunnelHeader(h TunnelHeader) []byte {
	buf := make([]byte, TunnelHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], h.Magic)
	buf[2] = h.Version
	buf[3] = h.Flags
	binary.BigEndian.PutUint32(buf[4:8], h.SessionID)
	binary.BigEndian.PutUint32(buf[8:12], h.PacketSeq)
	binary.BigEndian.PutUint16(buf[12:14], h.PayloadLen)
	binary.BigEndian.PutUint16(buf[14:16], h.Reserved)
	return buf
}

// parseTunnelHeader extracts header from bytes
func parseTunnelHeader(data []byte) TunnelHeader {
	return TunnelHeader{
		Magic:      binary.BigEndian.Uint16(data[0:2]),
		Version:    data[2],
		Flags:      data[3],
		SessionID:  binary.BigEndian.Uint32(data[4:8]),
		PacketSeq:  binary.BigEndian.Uint32(data[8:12]),
		PayloadLen: binary.BigEndian.Uint16(data[12:14]),
		Reserved:   binary.BigEndian.Uint16(data[14:16]),
	}
}

// sendLoop handles outgoing packets with rate limiting
func (c *icmpTunnelConn) sendLoop() {
	// Calculate minimum interval for rate limit
	interval := time.Second / time.Duration(c.rateLimit)

	for {
		select {
		case <-c.done:
			return
		case data := <-c.sendQueue:
			// Rate limiting
			c.rateMu.Lock()
			elapsed := time.Since(c.lastSendTime)
			if elapsed < interval {
				// Add jitter (10-50ms for stealth)
				jitter := time.Duration(StealthJitterMin+int(time.Now().UnixNano()%int64(StealthJitterMax-StealthJitterMin))) * time.Millisecond
				time.Sleep(interval - elapsed + jitter)
			}
			c.lastSendTime = time.Now()
			c.rateMu.Unlock()

			// Build and send packet
			packet, err := c.buildPacket(data, 0)
			if err != nil {
				log.Debug("ICMP Tunnel: build packet error: %v", err)
				continue
			}

			c.icmpConn.SetWriteDeadline(time.Now().Add(ICMPWriteTimeout))
			if _, err := c.icmpConn.WriteTo(packet, c.serverIP); err != nil {
				log.Debug("ICMP Tunnel: send error: %v", err)
			}
		}
	}
}

// recvLoop handles incoming packets
func (c *icmpTunnelConn) recvLoop() {
	buf := make([]byte, 1500)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.icmpConn.SetReadDeadline(time.Now().Add(ICMPReadTimeout))
		n, peer, err := c.icmpConn.ReadFrom(buf)
		if err != nil {
			if c.closed.Load() {
				return
			}
			// Timeout is OK, continue
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Debug("ICMP Tunnel: recv error: %v", err)
			continue
		}

		// Verify sender
		if peer.String() != c.serverIP.String() {
			continue // Ignore packets from other sources
		}

		// Parse ICMP
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		// Must be Echo Reply
		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || len(echo.Data) < TunnelHeaderSize {
			continue
		}

		// Verify magic
		if binary.BigEndian.Uint16(echo.Data[0:2]) != ICMPTunnelMagic {
			continue
		}

		// Parse header
		header := parseTunnelHeader(echo.Data[:TunnelHeaderSize])

		// Verify session
		if header.SessionID != c.sessionID {
			continue
		}

		// Decrypt payload
		encrypted := echo.Data[TunnelHeaderSize:]
		headerBytes := echo.Data[:TunnelHeaderSize]

		nonce := make([]byte, 24)
		binary.BigEndian.PutUint64(nonce[16:], uint64(header.PacketSeq))

		plaintext, err := c.cipher.Open(nil, nonce, encrypted, headerBytes)
		if err != nil {
			log.Debug("ICMP Tunnel: decrypt error: %v", err)
			continue
		}

		// Queue for reading
		select {
		case c.recvQueue <- plaintext:
		default:
			log.Debug("ICMP Tunnel: recv queue full, dropping packet")
		}
	}
}

// Read implements io.Reader
func (c *icmpTunnelConn) Read(b []byte) (int, error) {
	c.readBufMu.Lock()
	defer c.readBufMu.Unlock()

	// First, drain any buffered data
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Wait for new data
	select {
	case <-c.done:
		return 0, io.EOF
	case data := <-c.recvQueue:
		n := copy(b, data)
		if n < len(data) {
			// Buffer remaining data
			c.readBuf = append(c.readBuf, data[n:]...)
		}
		return n, nil
	}
}

// Write implements io.Writer
func (c *icmpTunnelConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	// Fragment if needed (stealth mode uses small payloads)
	maxPayload := StealthPayloadSize - AuthTagSize
	total := 0

	for i := 0; i < len(b); i += maxPayload {
		end := i + maxPayload
		if end > len(b) {
			end = len(b)
		}

		chunk := make([]byte, end-i)
		copy(chunk, b[i:end])

		select {
		case <-c.done:
			return total, io.ErrClosedPipe
		case c.sendQueue <- chunk:
			total += len(chunk)
		case <-time.After(ICMPWriteTimeout):
			return total, os.ErrDeadlineExceeded
		}
	}

	return total, nil
}

// Close closes the tunnel
func (c *icmpTunnelConn) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}

	close(c.done)
	return c.icmpConn.Close()
}

// LocalAddr returns the local network address
func (c *icmpTunnelConn) LocalAddr() net.Addr {
	return c.icmpConn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (c *icmpTunnelConn) RemoteAddr() net.Addr {
	return c.serverIP
}

// SetDeadline sets read and write deadlines
func (c *icmpTunnelConn) SetDeadline(t time.Time) error {
	return c.icmpConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *icmpTunnelConn) SetReadDeadline(t time.Time) error {
	return c.icmpConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *icmpTunnelConn) SetWriteDeadline(t time.Time) error {
	return c.icmpConn.SetWriteDeadline(t)
}

// deriveICMPKey derives a 32-byte key for ChaCha20-Poly1305 from secret
func deriveICMPKey(secret []byte) []byte {
	// Simple key derivation
	// In production, use HKDF or similar
	h := make([]byte, 32)
	if len(secret) >= 32 {
		copy(h, secret[:32])
	} else if len(secret) > 0 {
		// Pad with deterministic expansion
		copy(h, secret)
		for i := len(secret); i < 32; i++ {
			h[i] = byte(i ^ int(secret[i%len(secret)]))
		}
	} else {
		// Empty secret: use deterministic fill (not secure, but valid for testing)
		for i := 0; i < 32; i++ {
			h[i] = byte(i * 7) // Deterministic but distinct bytes
		}
	}
	return h
}

// Ensure interface compliance
var _ Strategy = (*ICMPTunnelStrategy)(nil)
var _ net.Conn = (*icmpTunnelConn)(nil)
