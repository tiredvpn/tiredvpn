package strategy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ProtocolConfusionStrategy crafts packets that look like different protocols
// to different parsers (DPI vs real server)
type ProtocolConfusionStrategy struct {
	manager       *Manager // Reference to Manager for IPv6/IPv4 support
	confusionType ConfusionType
	baseStrat     Strategy
}

// ConfusionType defines which protocol confusion to use
type ConfusionType int

const (
	// ConfusionDNSoverTLS - Packet looks like DNS to DPI, TLS to server
	ConfusionDNSoverTLS ConfusionType = iota

	// ConfusionHTTPoverTLS - HTTP request prefix, but actually TLS
	ConfusionHTTPoverTLS

	// ConfusionSSHoverTLS - SSH banner prefix, then TLS
	ConfusionSSHoverTLS

	// ConfusionSMTPoverTLS - SMTP EHLO prefix, then TLS
	ConfusionSMTPoverTLS

	// ConfusionMultiLayer - Multiple protocol headers stacked
	ConfusionMultiLayer
)

// NewProtocolConfusionStrategy creates a new confusion strategy
// manager is required for IPv6/IPv4 transport layer support
func NewProtocolConfusionStrategy(manager *Manager, confType ConfusionType, base Strategy) *ProtocolConfusionStrategy {
	return &ProtocolConfusionStrategy{
		manager:       manager,
		confusionType: confType,
		baseStrat:     base,
	}
}

func (s *ProtocolConfusionStrategy) Name() string {
	names := map[ConfusionType]string{
		ConfusionDNSoverTLS:  "Protocol Confusion (DNS)",
		ConfusionHTTPoverTLS: "Protocol Confusion (HTTP)",
		ConfusionSSHoverTLS:  "Protocol Confusion (SSH)",
		ConfusionSMTPoverTLS: "Protocol Confusion (SMTP)",
		ConfusionMultiLayer:  "Protocol Confusion (Multi-Layer)",
	}
	return names[s.confusionType]
}

func (s *ProtocolConfusionStrategy) ID() string {
	return "confusion_" + string(rune('0'+s.confusionType))
}

func (s *ProtocolConfusionStrategy) Priority() int {
	return 25
}

func (s *ProtocolConfusionStrategy) Description() string {
	return "Crafts packets that appear as safe protocols to DPI but are parsed differently by server"
}

func (s *ProtocolConfusionStrategy) RequiresServer() bool {
	return true // Server must understand the confusion format
}

func (s *ProtocolConfusionStrategy) Probe(ctx context.Context, target string) error {
	// Basic connectivity check
	conn, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *ProtocolConfusionStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("Protocol Confusion: Connecting to %s (raw TCP, no TLS)", serverAddr)

	// Confusion operates on raw TCP — the confused preamble IS the transport layer.
	// No TLS wrapper; DPI sees DNS/HTTP/SSH/SMTP, server detects TIRED marker.
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	return NewConfusedConn(conn, s.confusionType), nil
}

// ConfusedConn wraps connection with protocol confusion
var confusionDomains = []string{
	"yandex.ru",
	"baidu.com",
	"aparat.com",
	"qq.com",
	"mail.ru",
	"digikala.com",
}

func getRandomConfusionDomain() string {
	return confusionDomains[mathrand.Intn(len(confusionDomains))]
}

type ConfusedConn struct {
	net.Conn
	confType    ConfusionType
	headerSent  bool
	headerRead  bool
	serverMagic []byte
	rawMode     bool // When true, Read() passes data through without deframing (for VPN mode)
}

// NewConfusedConn creates a confused connection
func NewConfusedConn(conn net.Conn, confType ConfusionType) *ConfusedConn {
	return &ConfusedConn{
		Conn:        conn,
		confType:    confType,
		serverMagic: []byte("TIRED"), // Server responds with this to confirm
	}
}

// SetRawMode enables raw mode where Read() passes data through without deframing.
// This is required for VPN mode where the caller (vpn.go) handles framing itself.
func (c *ConfusedConn) SetRawMode(raw bool) {
	c.rawMode = raw
}

// Write prepends confusion header to first write, adds length-prefix to subsequent writes
func (c *ConfusedConn) Write(p []byte) (int, error) {
	if !c.headerSent {
		c.headerSent = true

		// Build confused packet
		confusedData := c.buildConfusedPacket(p)
		_, err := c.Conn.Write(confusedData)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}

	// Subsequent writes: add length prefix (server expects length-prefixed data)
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(p)))
	copy(frame[4:], p)
	_, err := c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// buildConfusedPacket creates a packet that confuses DPI
func (c *ConfusedConn) buildConfusedPacket(realData []byte) []byte {
	switch c.confType {
	case ConfusionDNSoverTLS:
		return c.buildDNSConfusion(realData)
	case ConfusionHTTPoverTLS:
		return c.buildHTTPConfusion(realData)
	case ConfusionSSHoverTLS:
		return c.buildSSHConfusion(realData)
	case ConfusionSMTPoverTLS:
		return c.buildSMTPConfusion(realData)
	case ConfusionMultiLayer:
		return c.buildMultiLayerConfusion(realData)
	default:
		return realData
	}
}

// buildDNSConfusion makes packet look like a DNS-over-TCP query.
// DNS-over-TCP format: [length:2][dns-message], flags=0x0100 (standard query, RD set).
func (c *ConfusedConn) buildDNSConfusion(realData []byte) []byte {
	var dns bytes.Buffer

	// Random transaction ID
	txid := make([]byte, 2)
	rand.Read(txid)
	dns.Write(txid)
	// Flags: standard query (0x0100) - not a response
	dns.Write([]byte{0x01, 0x00})
	// Questions: 1, Answers: 0, Authority: 0, Additional: 0
	dns.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Question: encode getRandomConfusionDomain() as DNS labels
	domain := getRandomConfusionDomain()
	labels := encodeDNSName(domain)
	dns.Write(labels)
	// Type: A (0x0001), Class: IN (0x0001)
	dns.Write([]byte{0x00, 0x01, 0x00, 0x01})

	// Magic marker + length + real data embedded after question
	dns.Write([]byte{0x00, 0x00, 0x54, 0x49, 0x52, 0x45, 0x44}) // \0\0TIRED
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(realData)))
	dns.Write(lenBytes)
	dns.Write(realData)

	// DNS-over-TCP 2-byte length prefix
	msg := dns.Bytes()
	var buf bytes.Buffer
	buf.Write([]byte{byte(len(msg) >> 8), byte(len(msg))})
	buf.Write(msg)
	return buf.Bytes()
}

// encodeDNSName encodes a dotted domain into DNS label format.
func encodeDNSName(domain string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			label := domain[start:i]
			if len(label) > 0 {
				out = append(out, byte(len(label)))
				out = append(out, []byte(label)...)
			}
			start = i + 1
		}
	}
	out = append(out, 0x00) // root label
	return out
}

// buildHTTPConfusion makes packet look like HTTP request
func (c *ConfusedConn) buildHTTPConfusion(realData []byte) []byte {
	var buf bytes.Buffer

	// Fake HTTP request header
	buf.WriteString("GET / HTTP/1.1\r\n")
	fmt.Fprintf(&buf, "Host: %s\r\n", getRandomConfusionDomain())
	buf.WriteString("User-Agent: Mozilla/5.0\r\n")
	buf.WriteString("Accept: */*\r\n")
	buf.WriteString("\r\n") // End of headers

	// Magic marker in body
	buf.Write([]byte{0x54, 0x49, 0x52, 0x45, 0x44}) // TIRED

	// Length
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(realData)))
	buf.Write(lenBytes)

	// Real data
	buf.Write(realData)

	return buf.Bytes()
}

// buildSSHConfusion starts with SSH banner
func (c *ConfusedConn) buildSSHConfusion(realData []byte) []byte {
	var buf bytes.Buffer

	// SSH banner
	buf.WriteString("SSH-2.0-OpenSSH_8.9\r\n")

	// Key exchange init (fake, truncated)
	buf.Write([]byte{
		0x00, 0x00, 0x00, 0x00, // Packet length (placeholder)
		0x14, // SSH_MSG_KEXINIT
	})

	// Cookie (random)
	cookie := make([]byte, 16)
	rand.Read(cookie)
	buf.Write(cookie)

	// Magic marker
	buf.Write([]byte{0x54, 0x49, 0x52, 0x45, 0x44}) // TIRED

	// Length
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(realData)))
	buf.Write(lenBytes)

	// Real data
	buf.Write(realData)

	return buf.Bytes()
}

// buildSMTPConfusion opens with SMTP client role (EHLO only, no server 220 greeting).
func (c *ConfusedConn) buildSMTPConfusion(realData []byte) []byte {
	var buf bytes.Buffer

	// Client starts the conversation: EHLO followed by the magic marker
	fmt.Fprintf(&buf, "EHLO %s\r\n", getRandomConfusionDomain())

	// Magic marker + length + real data
	buf.Write([]byte{0x00, 0x00})
	buf.Write([]byte("TIRED"))

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(realData)))
	buf.Write(lenBytes)
	buf.Write(realData)

	return buf.Bytes()
}

// buildMultiLayerConfusion stacks multiple protocol headers
func (c *ConfusedConn) buildMultiLayerConfusion(realData []byte) []byte {
	var buf bytes.Buffer

	// Layer 1: HTTP
	buf.WriteString("POST /api HTTP/1.1\r\n")
	buf.WriteString("Host: googleapis.com\r\n")
	buf.WriteString("Content-Type: application/grpc\r\n")
	buf.WriteString("\r\n")

	// Layer 2: gRPC frame header
	buf.Write([]byte{0x00})                   // No compression
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Placeholder length

	// Layer 3: Protocol buffers-like structure
	buf.Write([]byte{0x0a}) // Field 1, wire type 2 (length-delimited)

	// Magic in "field value"
	buf.Write([]byte{0x05})                         // Length 5
	buf.Write([]byte{0x54, 0x49, 0x52, 0x45, 0x44}) // TIRED

	// Real data length
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(realData)))
	buf.Write(lenBytes)

	// Real data
	buf.Write(realData)

	return buf.Bytes()
}

// frameData adds length framing for subsequent data
func (c *ConfusedConn) frameData(data []byte) []byte {
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	return frame
}

// Read handles server response, stripping confusion headers
// After initial handshake (server magic), reads length-prefixed frames from server
// In rawMode, passes data through without deframing (for VPN mode where caller handles framing)
func (c *ConfusedConn) Read(p []byte) (int, error) {
	if !c.headerRead {
		// First read - expect server magic
		magic := make([]byte, len(c.serverMagic))
		_, err := io.ReadFull(c.Conn, magic)
		if err != nil {
			return 0, err
		}

		if !bytes.Equal(magic, c.serverMagic) {
			// Server doesn't understand protocol, fall back
			// Return magic as data
			copy(p, magic)
			c.headerRead = true
			return len(magic), nil
		}

		c.headerRead = true
	}

	// In raw mode, pass data through without deframing
	// This is for VPN mode where vpn.go handles [len:4][data] framing itself
	if c.rawMode {
		return c.Conn.Read(p)
	}

	// Read length-prefixed frame from server
	// Format: [4 bytes length (big-endian)][data]
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}

	pktLen := binary.BigEndian.Uint32(lenBuf)
	if pktLen == 0 {
		// Zero-length packet, return empty read
		return 0, nil
	}
	if pktLen > 64*1024 {
		// Sanity check - max 64KB per frame
		return 0, io.ErrUnexpectedEOF
	}

	// Read exactly pktLen bytes
	if int(pktLen) > len(p) {
		// Buffer too small - read what we can, discard rest
		// This shouldn't happen with normal usage
		n, err := io.ReadFull(c.Conn, p)
		if err != nil {
			return n, err
		}
		// Discard remaining bytes
		remaining := int(pktLen) - len(p)
		discard := make([]byte, remaining)
		io.ReadFull(c.Conn, discard)
		return n, nil
	}

	return io.ReadFull(c.Conn, p[:pktLen])
}

// AllConfusionTypes returns all available confusion strategies
// manager is required for IPv6/IPv4 transport layer support
func AllConfusionTypes(manager *Manager) []*ProtocolConfusionStrategy {
	types := []ConfusionType{
		ConfusionDNSoverTLS,
		ConfusionHTTPoverTLS,
		ConfusionSSHoverTLS,
		ConfusionSMTPoverTLS,
		ConfusionMultiLayer,
	}

	strategies := make([]*ProtocolConfusionStrategy, len(types))
	for i, t := range types {
		strategies[i] = NewProtocolConfusionStrategy(manager, t, nil)
	}
	return strategies
}
