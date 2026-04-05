package strategy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// androidModeEnabled disables strategies that require root (raw sockets, ICMP, etc.)
var androidModeEnabled bool

// SetAndroidMode enables or disables Android mode
// When enabled, strategies requiring root privileges are disabled
func SetAndroidMode(enabled bool) {
	androidModeEnabled = enabled
}

// StateExhaustionStrategy attempts to overflow DPI state tables
// ТСПУ has finite state table capacity - filling it causes fail-open
type StateExhaustionStrategy struct {
	manager   *Manager // Reference to Manager for IPv6/IPv4 support
	baseStrat Strategy

	// Attack parameters
	decoyCount    int           // Number of decoy connections
	decoyInterval time.Duration // Interval between decoy batches
	decoyTimeout  time.Duration // How long to keep decoys alive

	// State
	activedecoys int64
	mu           sync.Mutex
}

// NewStateExhaustionStrategy creates a new state exhaustion strategy
// manager is required for IPv6/IPv4 transport layer support
func NewStateExhaustionStrategy(manager *Manager) *StateExhaustionStrategy {
	return &StateExhaustionStrategy{
		manager:       manager,
		baseStrat:     nil, // No base strategy - works independently
		decoyCount:    1000, // Number of decoy SYNs per batch
		decoyInterval: 5 * time.Second,
		decoyTimeout:  60 * time.Second, // TSPU SYN_SENT timeout is 60s
	}
}

func (s *StateExhaustionStrategy) Name() string {
	return "State Table Exhaustion"
}

func (s *StateExhaustionStrategy) ID() string {
	return "state_exhaustion"
}

func (s *StateExhaustionStrategy) Priority() int {
	return 50 // Lower priority - more aggressive
}

func (s *StateExhaustionStrategy) Description() string {
	return "Floods DPI state table with decoy connections to trigger fail-open mode"
}

func (s *StateExhaustionStrategy) RequiresServer() bool {
	return false // Works without special server
}

func (s *StateExhaustionStrategy) Probe(ctx context.Context, target string) error {
	// Note: This strategy PREFERS raw sockets but can work without them
	// We'll fallback to normal TCP if raw sockets unavailable

	// Android mode: warn but don't fail (will use fallback)
	if androidModeEnabled {
		log.Debug("State Exhaustion on Android: will use fallback mode (no raw sockets)")
		return nil
	}

	// Quick check - can we create raw sockets?
	// If not, we'll fallback to normal TCP in Connect()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Debug("State Exhaustion: raw sockets unavailable, will use fallback mode")
		return nil // Don't fail - fallback available
	}
	syscall.Close(fd)

	return nil
}

func (s *StateExhaustionStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Check if we can use raw sockets
	canUseRaw := !androidModeEnabled
	if canUseRaw {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		if err != nil {
			canUseRaw = false
			log.Debug("State Exhaustion: raw sockets unavailable, using fallback")
		} else {
			syscall.Close(fd)
		}
	}

	// Phase 1: Launch decoy flood (only if we have raw sockets)
	if canUseRaw {
		log.Debug("State Exhaustion: launching decoy flood")
		go s.launchDecoyFlood(ctx, target)

		// Phase 2: Wait for state table to fill
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	} else {
		log.Debug("State Exhaustion: fallback mode (no decoy flood)")
	}

	// Phase 3: Attempt real connection through base strategy
	if s.baseStrat != nil {
		return s.baseStrat.Connect(ctx, target)
	}

	// Use TLS connection with Confusion wrapper (server requires protocol magic)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err != nil {
		return nil, err
	}

	// Wrap with Confusion protocol so server recognizes us
	return NewConfusedConn(conn, ConfusionHTTPoverTLS), nil
}

// launchDecoyFlood sends decoy SYN packets to fill DPI state table
func (s *StateExhaustionStrategy) launchDecoyFlood(ctx context.Context, realTarget string) {
	// Parse target to get destination network
	host, _, err := net.SplitHostPort(realTarget)
	if err != nil {
		return
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		// Try to resolve
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return
		}
		targetIP = ips[0]
	}

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)

	// Enable IP_HDRINCL
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	// Generate decoy targets in same /24 subnet as real target
	// This spreads state table entries
	baseIP := targetIP.To4()
	if baseIP == nil {
		return
	}

	// Launch decoy flood
	for batch := 0; batch < 10; batch++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for i := 0; i < s.decoyCount/10; i++ {
			// Generate random destination in nearby range
			decoyIP := make(net.IP, 4)
			copy(decoyIP, baseIP)

			// Randomize last two octets
			randBytes := make([]byte, 2)
			rand.Read(randBytes)
			decoyIP[2] = (baseIP[2] &^ 0x0F) | (randBytes[0] & 0x0F) // Keep /20
			decoyIP[3] = randBytes[1]

			// Random source port
			srcPort := 10000 + (i % 50000)

			// Random destination port (common ports to look legitimate)
			ports := []int{80, 443, 8080, 8443, 22, 21}
			dstPort := ports[i%len(ports)]

			// Build SYN packet
			packet := s.buildSYNPacket(getLocalIP(), decoyIP, uint16(srcPort), uint16(dstPort))

			// Send
			addr := &syscall.SockaddrInet4{Port: dstPort}
			copy(addr.Addr[:], decoyIP.To4())

			syscall.Sendto(fd, packet, 0, addr)
			atomic.AddInt64(&s.activedecoys, 1)
		}

		// Brief pause between batches
		time.Sleep(100 * time.Millisecond)
	}
}

// buildSYNPacket creates a TCP SYN packet
func (s *StateExhaustionStrategy) buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	// IP Header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0x00 // DSCP/ECN
	totalLen := uint16(40) // IP(20) + TCP(20)
	binary.BigEndian.PutUint16(ipHeader[2:4], totalLen)

	// Random ID
	randID := make([]byte, 2)
	rand.Read(randID)
	copy(ipHeader[4:6], randID)

	ipHeader[6] = 0x40 // Don't fragment
	ipHeader[7] = 0x00
	ipHeader[8] = 64   // TTL
	ipHeader[9] = 6    // TCP

	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	// IP Checksum
	ipChecksum := tcpChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

	// TCP Header (20 bytes)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)

	// Random sequence number
	randSeq := make([]byte, 4)
	rand.Read(randSeq)
	copy(tcpHeader[4:8], randSeq)

	// ACK number = 0
	tcpHeader[12] = 0x50 // Data offset = 5 (20 bytes)
	tcpHeader[13] = 0x02 // SYN flag

	// Window size
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	// TCP Checksum (with pseudo-header)
	tcpChecksum := s.calculateTCPChecksum(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum)

	// Combine
	packet := append(ipHeader, tcpHeader...)
	return packet
}

func (s *StateExhaustionStrategy) calculateTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	// Pseudo-header
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHeader)))

	// Combine for checksum
	data := append(pseudo, tcpHeader...)

	// Zero out checksum field
	data[12+16] = 0
	data[12+17] = 0

	return tcpChecksum(data)
}

func tcpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func getLocalIP() net.IP {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

// DecoyStats returns current decoy statistics
func (s *StateExhaustionStrategy) DecoyStats() int64 {
	return atomic.LoadInt64(&s.activedecoys)
}
