package evasion

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

// FragmentationConfig configures TCP fragmentation attack
type FragmentationConfig struct {
	// FragmentSize is the size of each TCP segment
	// Smaller = more fragments = harder for DPI to reassemble
	FragmentSize int

	// SplitPosition is where to split the SNI within ClientHello
	// 0 = split at first byte, 1 = after first byte, etc.
	// Splitting SNI across fragments defeats signature matching
	SplitPosition int

	// Delay between fragments (optional)
	// Some DPIs have short reassembly timeouts (TSPU: 5 seconds)
	FragmentDelay time.Duration

	// BufferFlood sends fake fragments to overflow DPI buffer
	// TSPU has 45 fragment limit - we send 40 fakes with low TTL
	BufferFlood bool

	// BufferFloodCount is number of fake fragments (max 44)
	BufferFloodCount int

	// BufferFloodTTL is TTL for fake fragments
	BufferFloodTTL int

	// BufferFloodTimeout is time to wait after flooding (for DPI timeout)
	// TSPU fragment timeout is 5 seconds
	BufferFloodTimeout time.Duration
}

// DefaultFragmentationConfig returns default config
func DefaultFragmentationConfig() *FragmentationConfig {
	return &FragmentationConfig{
		FragmentSize:       2,
		SplitPosition:      1,
		FragmentDelay:      0,
		BufferFlood:        false,
		BufferFloodCount:   40,
		BufferFloodTTL:     2,
		BufferFloodTimeout: 6 * time.Second, // Just over TSPU's 5s timeout
	}
}

// FragmentedWriter wraps a connection and fragments writes
type FragmentedWriter struct {
	conn           net.Conn
	config         *FragmentationConfig
	mu             sync.Mutex
	firstWriteDone bool
}

// NewFragmentedWriter creates a fragmented writer
func NewFragmentedWriter(conn net.Conn, config *FragmentationConfig) *FragmentedWriter {
	if config == nil {
		config = DefaultFragmentationConfig()
	}
	return &FragmentedWriter{
		conn:   conn,
		config: config,
	}
}

// Write implements io.Writer with TCP fragmentation
func (f *FragmentedWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Only fragment first write (ClientHello)
	// Subsequent writes are passed through normally
	if f.firstWriteDone {
		return f.conn.Write(p)
	}
	f.firstWriteDone = true

	// Check if this looks like TLS ClientHello
	if !isTLSClientHello(p) {
		return f.conn.Write(p)
	}

	// Perform buffer flood attack if enabled
	if f.config.BufferFlood {
		if err := f.bufferFloodAttack(); err != nil {
			// Log but continue - flood is best-effort
			fmt.Printf("Buffer flood warning: %v\n", err)
		}
	}

	// Fragment the ClientHello
	return f.writeFragmented(p)
}

// writeFragmented sends data in small TCP segments
func (f *FragmentedWriter) writeFragmented(data []byte) (int, error) {
	totalWritten := 0
	fragSize := f.config.FragmentSize

	for offset := 0; offset < len(data); {
		end := offset + fragSize
		if end > len(data) {
			end = len(data)
		}

		fragment := data[offset:end]

		// Write fragment
		n, err := f.conn.Write(fragment)
		totalWritten += n

		if err != nil {
			return totalWritten, err
		}

		// Apply delay between fragments if configured
		if f.config.FragmentDelay > 0 && end < len(data) {
			time.Sleep(f.config.FragmentDelay)
		}

		offset = end
	}

	return totalWritten, nil
}

// bufferFloodAttack floods DPI fragment buffer with fake fragments
// This exploits TSPU's 45 fragment limit
func (f *FragmentedWriter) bufferFloodAttack() error {
	// Create raw socket for sending fake fragments
	rawSocket, err := NewRawSocket()
	if err != nil {
		return fmt.Errorf("cannot create raw socket: %w", err)
	}
	defer rawSocket.Close()

	// Get connection details
	localAddr := f.conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := f.conn.RemoteAddr().(*net.TCPAddr)

	// Create fake fragment payload
	fakePayload := make([]byte, 100)
	for i := range fakePayload {
		fakePayload[i] = byte(i)
	}

	injector := &FakePacketInjector{
		ttl:         f.config.BufferFloodTTL,
		badChecksum: false, // We want DPI to process these
		badSeq:      false,
		fakeSNI:     "",
		count:       1,
	}

	// Send fake fragments
	for i := 0; i < f.config.BufferFloodCount; i++ {
		// Build IP fragment (not TCP segment - IP level fragmentation)
		packet, err := buildIPFragment(
			localAddr.IP, remoteAddr.IP,
			uint16(localAddr.Port), uint16(remoteAddr.Port),
			uint16(i), // Fragment offset
			fakePayload,
			f.config.BufferFloodTTL,
			i < f.config.BufferFloodCount-1, // More fragments flag
		)

		if err != nil {
			continue // Best effort
		}

		_ = injector.sendRawPacket(rawSocket, remoteAddr.IP, packet)
	}

	// Wait for DPI fragment timeout
	time.Sleep(f.config.BufferFloodTimeout)

	return nil
}

// sendRawPacket sends a raw packet
func (f *FakePacketInjector) sendRawPacket(rawSocket *RawSocket, dstIP net.IP, packet []byte) error {
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP.To4())

	return syscall.Sendto(rawSocket.fd, packet, 0, addr)
}

// buildIPFragment builds an IP fragment
func buildIPFragment(srcIP, dstIP net.IP, srcPort, dstPort, fragOffset uint16, payload []byte, ttl int, moreFragments bool) ([]byte, error) {
	// IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version + IHL

	totalLen := uint16(20 + len(payload))
	binary.BigEndian.PutUint16(ipHeader[2:4], totalLen)

	// Identification - should be same for all fragments of one packet
	binary.BigEndian.PutUint16(ipHeader[4:6], 0x1234)

	// Flags + Fragment Offset
	flagsAndOffset := fragOffset >> 3 // Offset is in 8-byte units
	if moreFragments {
		flagsAndOffset |= 0x2000 // MF flag
	}
	binary.BigEndian.PutUint16(ipHeader[6:8], flagsAndOffset)

	ipHeader[8] = byte(ttl)
	ipHeader[9] = 6 // TCP

	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	// Calculate checksum
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	// For first fragment, include TCP header
	var data []byte
	if fragOffset == 0 {
		tcpHeader := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
		binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
		// Rest is zeros/minimal
		tcpHeader[12] = 0x50 // Data offset
		tcpHeader[13] = 0x02 // SYN flag

		data = append(ipHeader, tcpHeader...)
		data = append(data, payload...)
	} else {
		data = append(ipHeader, payload...)
	}

	return data, nil
}

// isTLSClientHello checks if data looks like TLS ClientHello
func isTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// TLS Record: ContentType(1) + Version(2) + Length(2) + Handshake
	// ContentType 0x16 = Handshake
	// Handshake type 0x01 = ClientHello
	return data[0] == 0x16 && // Handshake
		data[1] == 0x03 && // TLS major version
		data[5] == 0x01 // ClientHello handshake type
}

// Read passes through to underlying connection
func (f *FragmentedWriter) Read(p []byte) (int, error) {
	return f.conn.Read(p)
}

// Close closes the underlying connection
func (f *FragmentedWriter) Close() error {
	return f.conn.Close()
}

// LocalAddr returns local address
func (f *FragmentedWriter) LocalAddr() net.Addr {
	return f.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (f *FragmentedWriter) RemoteAddr() net.Addr {
	return f.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (f *FragmentedWriter) SetDeadline(t time.Time) error {
	return f.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (f *FragmentedWriter) SetReadDeadline(t time.Time) error {
	return f.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (f *FragmentedWriter) SetWriteDeadline(t time.Time) error {
	return f.conn.SetWriteDeadline(t)
}

// SNISplitter splits ClientHello to place SNI across fragment boundary
type SNISplitter struct {
	splitPosition int
}

// NewSNISplitter creates a new SNI splitter
func NewSNISplitter(position int) *SNISplitter {
	return &SNISplitter{splitPosition: position}
}

// FindSNIOffset finds the byte offset of SNI in ClientHello
func (s *SNISplitter) FindSNIOffset(clientHello []byte) (int, int, error) {
	// Search for SNI extension (type 0x0000)
	// Extension format: type(2) + length(2) + data
	// SNI data: list_len(2) + type(1) + name_len(2) + name

	if len(clientHello) < 50 {
		return 0, 0, fmt.Errorf("clientHello too short")
	}

	// Skip TLS record header (5 bytes) + Handshake header (4 bytes) +
	// Version (2) + Random (32) + SessionID length
	offset := 5 + 4 + 2 + 32
	if offset >= len(clientHello) {
		return 0, 0, fmt.Errorf("malformed clientHello")
	}

	// Skip session ID
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites
	if offset+2 > len(clientHello) {
		return 0, 0, fmt.Errorf("malformed clientHello")
	}
	cipherSuitesLen := int(clientHello[offset])<<8 | int(clientHello[offset+1])
	offset += 2 + cipherSuitesLen

	// Skip compression methods
	if offset+1 > len(clientHello) {
		return 0, 0, fmt.Errorf("malformed clientHello")
	}
	compMethodsLen := int(clientHello[offset])
	offset += 1 + compMethodsLen

	// Extensions length
	if offset+2 > len(clientHello) {
		return 0, 0, fmt.Errorf("no extensions")
	}
	extensionsLen := int(clientHello[offset])<<8 | int(clientHello[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen

	// Search extensions for SNI (type 0x0000)
	for offset < extensionsEnd-4 {
		extType := int(clientHello[offset])<<8 | int(clientHello[offset+1])
		extLen := int(clientHello[offset+2])<<8 | int(clientHello[offset+3])

		if extType == 0 { // SNI extension
			// SNI structure: list_len(2) + type(1) + name_len(2) + name
			sniOffset := offset + 4 + 2 + 1 + 2 // Skip to actual name
			nameLen := int(clientHello[offset+4+2+1])<<8 | int(clientHello[offset+4+2+1+1])
			return sniOffset, nameLen, nil
		}

		offset += 4 + extLen
	}

	return 0, 0, fmt.Errorf("SNI extension not found")
}

// SplitAtSNI returns fragments that split at SNI boundary
func (s *SNISplitter) SplitAtSNI(clientHello []byte) ([][]byte, error) {
	sniOffset, sniLen, err := s.FindSNIOffset(clientHello)
	if err != nil {
		// Fallback to simple split
		return [][]byte{clientHello}, nil
	}

	// Split position within SNI
	splitAt := sniOffset + s.splitPosition
	if splitAt >= sniOffset+sniLen {
		splitAt = sniOffset + 1 // At least split after first byte
	}

	if splitAt >= len(clientHello) {
		return [][]byte{clientHello}, nil
	}

	return [][]byte{
		clientHello[:splitAt],
		clientHello[splitAt:],
	}, nil
}

// Ensure FragmentedWriter implements necessary interfaces
var _ io.ReadWriter = (*FragmentedWriter)(nil)
var _ net.Conn = (*FragmentedWriter)(nil)
