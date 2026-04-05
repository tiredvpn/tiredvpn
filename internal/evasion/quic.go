package evasion

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

// QUICEvasion implements QUIC-specific DPI evasion techniques
// Based on research.md: TSPU blocks QUIC v1 (0x00000001) but not draft-29
type QUICEvasion struct {
	config *QUICEvasionConfig
}

// QUICEvasionConfig configures QUIC evasion
type QUICEvasionConfig struct {
	// UseAlternativeVersion uses draft-29 or other non-v1 versions
	UseAlternativeVersion bool

	// AlternativeVersion is the version to use (default: draft-29)
	// 0xff00001d = draft-29 (sometimes works)
	// 0xbabababa = quicping (sometimes works)
	AlternativeVersion uint32

	// PadInitialPacket pads Initial packet to different size
	// TSPU triggers on payload >= 1001 bytes
	PadInitialPacket bool

	// InitialPadSize is target size for Initial packet
	InitialPadSize int

	// SpoofConnectionID randomizes Connection ID
	SpoofConnectionID bool

	// FakeInitial sends fake Initial packets first
	FakeInitial bool

	// FakeInitialCount is number of fake Initial packets
	FakeInitialCount int
}

// DefaultQUICEvasionConfig returns default config
func DefaultQUICEvasionConfig() *QUICEvasionConfig {
	return &QUICEvasionConfig{
		UseAlternativeVersion: true,
		AlternativeVersion:    0xff00001d, // draft-29
		PadInitialPacket:      false,
		InitialPadSize:        1000, // Just under 1001 threshold
		SpoofConnectionID:     true,
		FakeInitial:           false,
		FakeInitialCount:      3,
	}
}

// NewQUICEvasion creates a new QUIC evasion handler
func NewQUICEvasion(config *QUICEvasionConfig) *QUICEvasion {
	if config == nil {
		config = DefaultQUICEvasionConfig()
	}
	return &QUICEvasion{config: config}
}

// QUICVersion constants
const (
	QUICVersion1        uint32 = 0x00000001 // BLOCKED by TSPU
	QUICVersionDraft29  uint32 = 0xff00001d // Sometimes works
	QUICVersionDraft32  uint32 = 0xff000020 // Sometimes works
	QUICVersionQuicPing uint32 = 0xbabababa // quicping - usually allowed
	QUICVersionReserved uint32 = 0x00000000 // Version negotiation
)

// AlternativeVersions are versions that might bypass DPI
var AlternativeVersions = []uint32{
	QUICVersionDraft29,
	QUICVersionDraft32,
	0xff000017, // draft-23
	0xff000019, // draft-25
	0xff00001b, // draft-27
}

// ModifyQUICVersion modifies QUIC version in Initial packet
func (q *QUICEvasion) ModifyQUICVersion(packet []byte) ([]byte, error) {
	if len(packet) < 5 {
		return packet, nil
	}

	// QUIC Long Header format:
	// [0]: Header Form (1) + Fixed Bit (1) + Long Packet Type (2) + Type-Specific (4)
	// [1-4]: Version (4 bytes)
	// [5]: DCID Length
	// [6...]: DCID
	// [...]: SCID Length + SCID
	// [...]: Rest of packet

	// Check if this is a Long Header packet (first bit = 1)
	if packet[0]&0x80 == 0 {
		// Short header - no version field
		return packet, nil
	}

	// Modify version field (bytes 1-4)
	if q.config.UseAlternativeVersion {
		binary.BigEndian.PutUint32(packet[1:5], q.config.AlternativeVersion)
	}

	return packet, nil
}

// BuildFakeInitialPacket creates a fake QUIC Initial packet
func (q *QUICEvasion) BuildFakeInitialPacket(dstConnID []byte, fakeSNI string) ([]byte, error) {
	// Build a minimal QUIC Initial packet with allowed version
	packet := make([]byte, 0, 1200)

	// Header byte: Long Header (1) + Fixed (1) + Initial (00) + Reserved (0000)
	packet = append(packet, 0xc0)

	// Version: use allowed version
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, q.config.AlternativeVersion)
	packet = append(packet, versionBytes...)

	// DCID Length + DCID
	if len(dstConnID) == 0 {
		dstConnID = make([]byte, 8)
		_, _ = rand.Read(dstConnID)
	}
	packet = append(packet, byte(len(dstConnID)))
	packet = append(packet, dstConnID...)

	// SCID Length + SCID
	scid := make([]byte, 8)
	_, _ = rand.Read(scid)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)

	// Token Length (0 for Initial from client)
	packet = append(packet, 0x00)

	// Length field (variable length integer) - we'll add placeholder
	// Payload will be minimal
	payloadSize := 100
	packet = append(packet, 0x40, byte(payloadSize)) // 2-byte var int

	// Packet Number (1 byte for simplicity)
	packet = append(packet, 0x00)

	// Payload: fake CRYPTO frame with fake ClientHello
	// Frame type: CRYPTO (0x06)
	packet = append(packet, 0x06)
	// Offset: 0
	packet = append(packet, 0x00)
	// Length: remaining
	fakeClientHello := buildMinimalClientHello(fakeSNI)
	packet = append(packet, byte(len(fakeClientHello)))
	packet = append(packet, fakeClientHello...)

	// Pad to specified size if needed
	if q.config.PadInitialPacket {
		for len(packet) < q.config.InitialPadSize {
			packet = append(packet, 0x00) // PADDING frame
		}
	}

	return packet, nil
}

// buildMinimalClientHello builds minimal TLS ClientHello for QUIC
func buildMinimalClientHello(sni string) []byte {
	// Minimal ClientHello with SNI
	hello := []byte{
		0x01,             // HandshakeType: ClientHello
		0x00, 0x00, 0x00, // Length placeholder
		0x03, 0x03, // Version: TLS 1.2
	}

	// Random (32 bytes)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	hello = append(hello, random...)

	// Session ID (empty)
	hello = append(hello, 0x00)

	// Cipher Suites
	hello = append(hello, 0x00, 0x02, 0x13, 0x01) // TLS_AES_128_GCM_SHA256

	// Compression
	hello = append(hello, 0x01, 0x00)

	// Extensions
	sniExt := buildSNIExtension(sni)
	extLen := len(sniExt)
	hello = append(hello, byte(extLen>>8), byte(extLen))
	hello = append(hello, sniExt...)

	// Update length
	helloLen := len(hello) - 4
	hello[1] = byte(helloLen >> 16)
	hello[2] = byte(helloLen >> 8)
	hello[3] = byte(helloLen)

	return hello
}

// QUICConnection wraps UDP connection with QUIC evasion
type QUICConnection struct {
	conn    *net.UDPConn
	evasion *QUICEvasion
	remote  *net.UDPAddr
}

// NewQUICConnection creates a QUIC connection with evasion
func NewQUICConnection(address string, config *QUICEvasionConfig) (*QUICConnection, error) {
	raddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, err
	}

	return &QUICConnection{
		conn:    conn,
		evasion: NewQUICEvasion(config),
		remote:  raddr,
	}, nil
}

// Write sends data with QUIC evasion applied
func (c *QUICConnection) Write(p []byte) (int, error) {
	// Check if this is a QUIC Initial packet
	if len(p) > 5 && p[0]&0x80 != 0 {
		// Long header - check if Initial (type bits 00)
		if p[0]&0x30 == 0x00 {
			// This is an Initial packet
			if c.evasion.config.FakeInitial {
				// Send fake Initial packets first
				for i := 0; i < c.evasion.config.FakeInitialCount; i++ {
					fakePacket, _ := c.evasion.BuildFakeInitialPacket(nil, "yandex.ru")
					_, _ = c.conn.Write(fakePacket)
					time.Sleep(time.Millisecond)
				}
			}

			// Modify version in real packet
			modified, _ := c.evasion.ModifyQUICVersion(p)
			return c.conn.Write(modified)
		}
	}

	return c.conn.Write(p)
}

// Read receives data
func (c *QUICConnection) Read(p []byte) (int, error) {
	return c.conn.Read(p)
}

// Close closes the connection
func (c *QUICConnection) Close() error {
	return c.conn.Close()
}

// LocalAddr returns local address
func (c *QUICConnection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *QUICConnection) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline sets deadline
func (c *QUICConnection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *QUICConnection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *QUICConnection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// DetectQUICBlocking tests if QUIC is being blocked
func DetectQUICBlocking(testAddr string) (bool, string) {
	// Test QUIC v1
	v1Blocked := testQUICVersion(testAddr, QUICVersion1)

	// Test draft-29
	draft29Blocked := testQUICVersion(testAddr, QUICVersionDraft29)

	if v1Blocked && !draft29Blocked {
		return true, "QUIC v1 blocked, draft-29 works"
	} else if v1Blocked && draft29Blocked {
		return true, "All QUIC versions blocked"
	}

	return false, "QUIC not blocked"
}

func testQUICVersion(addr string, version uint32) bool {
	conn, err := net.DialTimeout("udp4", addr, 3*time.Second)
	if err != nil {
		return true
	}
	defer conn.Close()

	// Build test Initial packet
	packet := make([]byte, 1200)
	packet[0] = 0xc0 // Long header, Initial
	binary.BigEndian.PutUint32(packet[1:5], version)
	// Rest is filled with zeros

	// Send and wait for response
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write(packet)

	response := make([]byte, 1500)
	n, err := conn.Read(response)

	if err != nil || n == 0 {
		return true // No response = blocked
	}

	return false
}

// Ensure QUICConnection implements net.Conn
var _ net.Conn = (*QUICConnection)(nil)
