package strategy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// AntiProbeStrategy implements resistance to active probing
// Server appears as a normal website to unknown clients
type AntiProbeStrategy struct {
	manager      *Manager // Reference to Manager for IPv6/IPv4 support
	serverAddr   string   // Deprecated: use manager.GetServerAddr() instead
	knockSecret  []byte
	timingWindow time.Duration
	baseStrat    Strategy

	// ECH configuration (optional)
	echEnabled    bool
	echConfigList []byte
	echPublicName string
}

// KnockSequence defines the port knocking / timing sequence
type KnockSequence struct {
	Delays []time.Duration // Delays between packets
	Sizes  []int           // Packet sizes to send
}

// NewAntiProbeStrategy creates a new anti-probe strategy
// manager is required for IPv6/IPv4 transport layer support
func NewAntiProbeStrategy(manager *Manager, secret []byte) *AntiProbeStrategy {
	return &AntiProbeStrategy{
		manager:      manager,
		serverAddr:   "", // Deprecated: use manager.GetServerAddr() instead
		knockSecret:  secret,
		timingWindow: 100 * time.Millisecond,
	}
}

// SetECH enables ECH for this strategy
func (s *AntiProbeStrategy) SetECH(configList []byte, publicName string) {
	s.echEnabled = len(configList) > 0
	s.echConfigList = configList
	s.echPublicName = publicName
}

func (s *AntiProbeStrategy) Name() string {
	return "Anti-Probe Resistance"
}

func (s *AntiProbeStrategy) ID() string {
	return "antiprobe"
}

func (s *AntiProbeStrategy) Priority() int {
	return 20
}

func (s *AntiProbeStrategy) Description() string {
	return "Server masquerades as normal website; reveals tunnel only to authenticated clients"
}

func (s *AntiProbeStrategy) RequiresServer() bool {
	return true
}

func (s *AntiProbeStrategy) Probe(ctx context.Context, target string) error {
	// Check basic connectivity
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *AntiProbeStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("AntiProbe: Using server address: %s", serverAddr)

	// Phase 1: Connect with TLS first (server requires TLS)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "www.google.com", // Mimic Google
		NextProtos:         []string{"http/1.1"},
	}

	var tlsConn *tls.Conn
	var err error

	// Use context-aware dialing (respects Android optimized timeouts)
	dialer := &net.Dialer{}

	// Use ECH if enabled
	if s.echEnabled && len(s.echConfigList) > 0 {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.EncryptedClientHelloConfigList = s.echConfigList

		tcpConn, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}

		tlsConn = tls.Client(tcpConn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			// Fallback to non-ECH
			tlsConfig.EncryptedClientHelloConfigList = nil
			tcpConn2, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			tlsConn = tls.Client(tcpConn2, tlsConfig)
			if err = tlsConn.HandshakeContext(ctx); err != nil {
				tcpConn2.Close()
				return nil, err
			}
		}
	} else {
		tcpConn, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}
		tlsConn = tls.Client(tcpConn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, err
		}
	}

	// Phase 2: Perform timing-based authentication over TLS
	if err := s.timingKnock(tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Phase 3: Verify server response
	if err := s.verifyServerAuth(tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// timingKnock performs timing-based knock sequence
func (s *AntiProbeStrategy) timingKnock(conn net.Conn) error {
	// Generate timing sequence from secret
	sequence := s.generateKnockSequence()

	// Send packets with specific timing
	for i, delay := range sequence.Delays {
		time.Sleep(delay)

		// Send packet of specific size
		packet := make([]byte, sequence.Sizes[i])
		packet[0] = byte(i) // Sequence number

		// Fill with deterministic data based on secret
		s.fillPacketData(packet, i)

		if _, err := conn.Write(packet); err != nil {
			return err
		}
	}

	// Wait for ACK
	ack := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, ack); err != nil {
		return errors.New("timing knock not acknowledged")
	}

	if ack[0] != 0x01 {
		return errors.New("invalid knock response")
	}

	conn.SetReadDeadline(time.Time{})
	return nil
}

// generateKnockSequence creates timing sequence from secret
func (s *AntiProbeStrategy) generateKnockSequence() *KnockSequence {
	h := hmac.New(sha256.New, s.knockSecret)
	h.Write([]byte("knock-sequence"))
	hash := h.Sum(nil)

	// Generate 5 delays (50-200ms each) and 5 sizes (10-100 bytes)
	delays := make([]time.Duration, 5)
	sizes := make([]int, 5)

	for i := 0; i < 5; i++ {
		// Delay: 50ms + (hash[i] % 150)ms
		delays[i] = time.Duration(50+int(hash[i])%150) * time.Millisecond

		// Size: 10 + (hash[i+5] % 90)
		sizes[i] = 10 + int(hash[i+5])%90
	}

	return &KnockSequence{Delays: delays, Sizes: sizes}
}

// fillPacketData fills packet with deterministic data
func (s *AntiProbeStrategy) fillPacketData(packet []byte, seqNum int) {
	h := hmac.New(sha256.New, s.knockSecret)
	h.Write([]byte{byte(seqNum)})
	hash := h.Sum(nil)

	// Use (i-1) to match server's verification: expected[(i-1)%len(expected)]
	for i := 1; i < len(packet); i++ {
		packet[i] = hash[(i-1)%len(hash)]
	}
}

// verifyServerAuth verifies server recognized us
// After timing knock ACK, server is ready for tunnel - just return success
func (s *AntiProbeStrategy) verifyServerAuth(conn *tls.Conn) error {
	// Server already sent 0x01 ACK in timingKnock, now ready for tunnel
	return nil
}

