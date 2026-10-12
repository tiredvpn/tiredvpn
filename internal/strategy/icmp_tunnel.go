package strategy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"golang.org/x/crypto/hkdf"
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

	// MaxPayloadSize is the most tunnel data one packet carries: a 1400-byte
	// ICMP message minus the ICMP header, tunnel header and auth tag. On the
	// wire that is a 1420-byte IPv4 packet; on a path with a smaller MTU the
	// send loop lowers the limit further (packetPayloadLimit).
	MaxPayloadSize = 1400 - ICMPHeaderSize - TunnelHeaderSize - AuthTagSize

	// icmpPacketOverhead is what an IPv4 packet adds around tunnel data.
	icmpPacketOverhead = 20 + ICMPHeaderSize + TunnelHeaderSize + AuthTagSize
	// icmpMinPathMTU is the smallest MTU we size packets for (RFC 791).
	icmpMinPathMTU = 576

	// Stealth mode parameters (ONLY allowed mode)
	StealthPacketRate  = 10 // packets per second
	StealthPayloadSize = 56 // bytes, standard ping payload; data packets are not cut to it, see Write
	StealthJitterMin   = 10 // milliseconds
	StealthJitterMax   = 50 // milliseconds

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
	// The address to tunnel to is whatever the caller passed - i.e. the endpoint
	// the selector pinned for this cycle. s.serverAddr, baked in at
	// construction, is only the fallback for callers that pass nothing: with a
	// server list it names the first endpoint forever, so honouring it over
	// target would keep pinging a server the client has already given up on.
	dest := target
	if dest == "" {
		dest = s.serverAddr
	}
	log.Debug("ICMP Tunnel: Connecting to %s (mode=%s)", dest, s.mode)

	// Extract host from server address
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}

	// Resolve server IP
	serverIP, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel: resolve failed: %w", err)
	}

	// Create ICMP connection (requires root/CAP_NET_RAW)
	icmpConn, err := icmpListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel: listen failed (need root/CAP_NET_RAW): %w", err)
	}

	// Generate session ID
	var sessionID uint32
	binary.Read(rand.Reader, binary.BigEndian, &sessionID)

	// Derive per-direction keys so client-to-server and server-to-client packets
	// use independent keystreams, preventing bidirectional nonce reuse.
	masterKey := DeriveICMPKey(dialSecret(ctx, s.secret))
	sendCipher, err := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "c2s"))
	if err != nil {
		icmpConn.Close()
		return nil, fmt.Errorf("icmp tunnel: send cipher: %w", err)
	}
	recvCipher, err := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "s2c"))
	if err != nil {
		icmpConn.Close()
		return nil, fmt.Errorf("icmp tunnel: recv cipher: %w", err)
	}

	// Create tunnel connection wrapper
	tunnel := &icmpTunnelConn{
		icmpConn:   icmpConn,
		serverIP:   serverIP,
		serverAddr: s.serverAddr,
		sendCipher: sendCipher,
		recvCipher: recvCipher,
		sessionID:  sessionID,
		tunnelID:   uint16(os.Getpid() & 0xffff),
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		done:       make(chan struct{}),
		rateLimit:  s.rateLimit,
		pathMTU:    icmpCachedRouteMTU(serverIP.IP),
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

// icmpListenPacket opens the raw ICMP socket the tunnel runs over. It is a
// variable so tests can put a scripted network in place of the raw socket,
// which needs CAP_NET_RAW and a real peer.
var icmpListenPacket = func(network, address string) (net.PacketConn, error) {
	conn, err := icmp.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// icmpTunnelConn implements net.Conn over ICMP
type icmpTunnelConn struct {
	icmpConn   net.PacketConn
	serverIP   *net.IPAddr
	serverAddr string
	// sendCipher encrypts client-to-server packets (c2s direction).
	// recvCipher decrypts server-to-client packets (s2c direction).
	sendCipher cipher.AEAD
	recvCipher cipher.AEAD
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

	// pathMTU reports the MTU towards the server, 0 if unknown. Packets are
	// sized to it so the kernel never has to fragment them.
	pathMTU func() int

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
	stop := context.AfterFunc(ctx, func() { c.icmpConn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()

	// Send handshake init. It counts against the packet rate like any other
	// packet, so the first data packet does not follow it within a millisecond.
	c.rateMu.Lock()
	_, err = c.icmpConn.WriteTo(initPacket, c.serverIP)
	c.lastSendTime = time.Now()
	c.rateMu.Unlock()
	if err != nil {
		return fmt.Errorf("send init: %w", err)
	}

	log.Debug("ICMP Tunnel: Handshake init sent")

	initMsg, err := icmp.ParseMessage(1, initPacket)
	if err != nil {
		return fmt.Errorf("parse init packet: %w", err)
	}
	initData := initMsg.Body.(*icmp.Echo).Data

	// Wait for the server's reply. A raw socket sees every ICMP packet the host
	// receives, and with the default net.ipv4.icmp_echo_ignore_all=0 the
	// server's kernel answers our Echo Request itself, reflecting its payload,
	// before the tunnel server's reply arrives. Skip whatever does not
	// authenticate as s2c from the server. Once the reflection has shown that
	// the host answers ping, wait only icmpTunnelReplyGrace for the tunnel
	// server: a host without one would otherwise cost the whole deadline and
	// be counted as silent.
	reply := make([]byte, 1500)
	var rejected error
	var reflectedAt time.Time
	for {
		n, peer, err := c.icmpConn.ReadFrom(reply)
		if err != nil {
			if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.DeadlineExceeded) {
				return fmt.Errorf("handshake aborted: %w", cause)
			}
			if !reflectedAt.IsZero() {
				return fmt.Errorf("%w: kernel answered the init, no tunnel server reply in %v (server without -enable-icmp, or a different secret)",
					errICMPNoTunnelServer, time.Since(reflectedAt).Round(time.Millisecond))
			}
			if rejected != nil {
				return fmt.Errorf("receive ack: no valid reply from the tunnel server: %w (last rejected packet: %v)", err, rejected)
			}
			return fmt.Errorf("receive ack: no reply from the server: %w", err)
		}
		if peer.String() != c.serverIP.String() {
			continue
		}
		if icmpIsReflectionOf(reply[:n], initData) {
			if reflectedAt.IsZero() {
				reflectedAt = time.Now()
				graceEnd := reflectedAt.Add(icmpTunnelReplyGrace)
				if deadline.IsZero() || graceEnd.Before(deadline) {
					c.icmpConn.SetReadDeadline(graceEnd)
				}
				log.Debug("ICMP Tunnel: Handshake: server kernel reflected the init, waiting %v for the tunnel server", icmpTunnelReplyGrace)
			}
			continue
		}
		if err := c.parseHandshakeReply(reply[:n]); err != nil {
			rejected = err
			log.Debug("ICMP Tunnel: Handshake: skipping reply from %s: %v", peer, err)
			continue
		}
		break
	}

	log.Debug("ICMP Tunnel: Handshake complete")
	return nil
}

// errICMPNoTunnelServer reports a server host that answers ping but runs no
// ICMP tunnel server for us. Its text avoids "timeout" on purpose: the scan
// counts timeouts as silence, and this host is talking.
var errICMPNoTunnelServer = errors.New("host answers ping but no ICMP tunnel server replied")

// icmpTunnelReplyGrace is how long the handshake waits for the tunnel server
// after the server kernel's reflection of the init arrived. The tunnel reply
// trails the kernel's by well under a millisecond on the bench.
var icmpTunnelReplyGrace = 2 * time.Second

// icmpIsReflectionOf reports whether packet is an Echo Reply carrying exactly
// the payload we sent: the server kernel answering our request itself. The
// ICMP ID and sequence are not compared, a NAT on the way may rewrite the ID.
func icmpIsReflectionOf(packet, sentData []byte) bool {
	msg, err := icmp.ParseMessage(1, packet)
	if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
		return false
	}
	echo, ok := msg.Body.(*icmp.Echo)
	return ok && bytes.Equal(echo.Data, sentData)
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

	// Parse header to extract sessionID and replySeq for nonce construction.
	header := ParseTunnelHeader(echo.Data[:TunnelHeaderSize])

	// Verify this reply belongs to our session.
	if header.SessionID != c.sessionID {
		return fmt.Errorf("handshake: session ID mismatch")
	}

	// Decrypt the reply payload using recvCipher to prove server knows the shared secret.
	// Any host's kernel can echo ICMP with the same plaintext payload, but only a server
	// with the correct key can produce a valid ciphertext that passes AEAD authentication.
	// Nonce: [sessionID:4][zeros:12][replySeq:8]
	nonce := make([]byte, 24)
	binary.BigEndian.PutUint32(nonce[0:], header.SessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(header.PacketSeq))

	encrypted := echo.Data[TunnelHeaderSize:]
	headerBytes := echo.Data[:TunnelHeaderSize]
	if _, err := c.recvCipher.Open(nil, nonce, encrypted, headerBytes); err != nil {
		return errors.New("handshake: server auth failed")
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
	headerBytes := SerializeTunnelHeader(header)

	// Nonce: [sessionID:4][zeros:12][seq:8] - sessionID prevents nonce reuse across sessions
	// Use uint64(uint32(seq)) to keep sender and receiver nonces in sync: PacketSeq in the
	// header is uint32, so recvLoop reconstructs nonce[16:] from uint64(header.PacketSeq).
	// Without the cast, sender and receiver would diverge after 2^32 packets.
	nonce := make([]byte, 24) // XChaCha20 uses 24-byte nonce
	binary.BigEndian.PutUint32(nonce[0:], c.sessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(uint32(seq)))

	// Encrypt with c2s direction key.
	encrypted := c.sendCipher.Seal(nil, nonce, data, headerBytes)

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

// SerializeTunnelHeader converts header to bytes
func SerializeTunnelHeader(h TunnelHeader) []byte {
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

// ParseTunnelHeader extracts header from bytes
func ParseTunnelHeader(data []byte) TunnelHeader {
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
	// carry holds a queued write that did not fit into the previous packet.
	var carry []byte
	// cut marks carry as the tail of a write already split across packets.
	cut := false

	for {
		var data []byte
		if carry != nil {
			data, carry = carry, nil
		} else {
			cut = false
			select {
			case <-c.done:
				return
			case data = <-c.sendQueue:
			}
		}

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

		// The conn may have closed while we slept; a write held as carry
		// would otherwise go into the closed socket.
		select {
		case <-c.done:
			return
		default:
		}

		// A write larger than the path allows is cut here rather than left to
		// IP fragmentation, which a fragmented echo request would show on the
		// wire. A packet that starts with the tail of a cut write is filled up
		// with the bytes that follow: that write is split already, and leaving
		// its tail alone in a packet would spend a rate-limited slot on a few
		// bytes. Otherwise writes queued while we waited for the slot ride in
		// this packet whole.
		limit := c.packetPayloadLimit()
		switch {
		case len(data) > limit:
			data, carry, cut = data[:limit], data[limit:], true
		case cut:
			data, carry, cut = c.fillQueued(data, limit)
		default:
			data, carry = c.coalesceQueued(data, limit)
		}

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

// packetPayloadLimit is how much tunnel data fits into one packet without IP
// fragmentation on the way to the server.
func (c *icmpTunnelConn) packetPayloadLimit() int {
	limit := MaxPayloadSize
	if c.pathMTU != nil {
		if mtu := c.pathMTU(); mtu > 0 {
			limit = min(limit, max(mtu, icmpMinPathMTU)-icmpPacketOverhead)
		}
	}
	return limit
}

// icmpCachedRouteMTU returns a pathMTU func that asks the kernel at most once
// a second: the path MTU it learns from Fragmentation Needed can change
// during a session, but not per packet.
func icmpCachedRouteMTU(ip net.IP) func() int {
	var (
		mu      sync.Mutex
		checked time.Time
		mtu     int
	)
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(checked) >= time.Second {
			mtu = icmpRouteMTU(ip)
			checked = time.Now()
		}
		return mtu
	}
}

// coalesceQueued appends writes already waiting in sendQueue to data, as many
// as fit into limit. Writes are never split: the TUN layer writes one
// length-prefixed frame per Write, and a packet that carries only whole frames
// can be lost without misaligning the stream for the frames after it. The
// first write that does not fit is returned as carry for the next packet.
func (c *icmpTunnelConn) coalesceQueued(data []byte, limit int) (packet, carry []byte) {
	for len(data) < limit {
		select {
		case next := <-c.sendQueue:
			if len(data)+len(next) > limit {
				return data, next
			}
			data = append(data, next...)
		default:
			return data, nil
		}
	}
	return data, nil
}

// fillQueued appends queued writes to data up to exactly limit bytes, cutting
// the write that does not fit. It returns that write's remainder as carry and
// whether carry is such a cut tail.
func (c *icmpTunnelConn) fillQueued(data []byte, limit int) (packet, carry []byte, cut bool) {
	for len(data) < limit {
		select {
		case next := <-c.sendQueue:
			if room := limit - len(data); len(next) > room {
				return append(data, next[:room]...), next[room:], true
			}
			data = append(data, next...)
		default:
			return data, nil, false
		}
	}
	return data, nil, false
}

// recvLoop handles incoming packets
func (c *icmpTunnelConn) recvLoop() {
	buf := make([]byte, 1500)
	consecutiveErrors := 0

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
			// Timeout is OK, continue without counting against error budget
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			consecutiveErrors++
			log.Debug("ICMP Tunnel: recv error: %v", err)
			if consecutiveErrors >= 5 {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		consecutiveErrors = 0

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
		header := ParseTunnelHeader(echo.Data[:TunnelHeaderSize])

		// Verify session
		if header.SessionID != c.sessionID {
			continue
		}

		// Decrypt payload
		encrypted := echo.Data[TunnelHeaderSize:]
		headerBytes := echo.Data[:TunnelHeaderSize]

		nonce := make([]byte, 24)
		binary.BigEndian.PutUint32(nonce[0:], header.SessionID)
		binary.BigEndian.PutUint64(nonce[16:], uint64(header.PacketSeq))

		plaintext, err := c.recvCipher.Open(nil, nonce, encrypted, headerBytes)
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

	// Cut only what cannot fit into one packet; sendLoop cuts further if the
	// path MTU is smaller. The packet rate is what stealth mode limits;
	// cutting a frame into StealthPayloadSize pieces on top of that left about
	// 2 kbit/s of uplink (measured), less than Auto-MTU probes alone consume,
	// so everything queued behind them for tens of seconds.
	total := 0

	for i := 0; i < len(b); i += MaxPayloadSize {
		end := min(i+MaxPayloadSize, len(b))

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

// DeriveICMPKey derives a 32-byte master key for the ICMP tunnel from the shared
// secret using HKDF-SHA256, matching the KDF used elsewhere (reality_conn.go).
//
// WIRE-COMPATIBILITY: both client (icmp_tunnel.go Connect) and server
// (server/icmp_server.go) call this same function with the same shared secret,
// so both derive an identical master key and the directional keys stay in sync.
// Changing this derivation is wire-incompatible across versions, but client and
// server ship together so the new HKDF applies to both at once.
func DeriveICMPKey(secret []byte) []byte {
	r := hkdf.New(sha256.New, secret, nil, []byte("tiredvpn-icmp-master-v1"))
	out := make([]byte, 32)
	// HKDF-SHA256 never fails for a 32-byte output (well under the 255*HashLen
	// limit), so io.ReadFull cannot error here; the check is defensive.
	if _, err := io.ReadFull(r, out); err != nil {
		// Should be unreachable; fall back to a deterministic SHA-256 of the
		// secret so callers still receive a valid 32-byte key.
		sum := sha256.Sum256(secret)
		copy(out, sum[:])
	}
	return out
}

// DeriveICMPDirectionalKey derives a 32-byte key for a specific traffic direction.
// direction is "c2s" (client-to-server) or "s2c" (server-to-client).
// Both sides derive the same key pair from the shared masterKey + sessionID,
// ensuring client.sendCipher == server.c2sCipher and client.recvCipher == server.s2cCipher.
func DeriveICMPDirectionalKey(masterKey []byte, sessionID uint32, direction string) []byte {
	h := hmac.New(sha256.New, masterKey)
	var sidBuf [4]byte
	binary.BigEndian.PutUint32(sidBuf[:], sessionID)
	h.Write(sidBuf[:])
	h.Write([]byte("icmp-" + direction))
	return h.Sum(nil) // sha256 → 32 bytes, exactly what NewX needs
}

// Ensure interface compliance
var _ Strategy = (*ICMPTunnelStrategy)(nil)
var _ net.Conn = (*icmpTunnelConn)(nil)
