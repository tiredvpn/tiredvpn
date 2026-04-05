package evasion

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// FakePacketInjector injects fake packets to confuse DPI
// Based on research.md: DPI doesn't verify checksums and ignores low TTL packets
type FakePacketInjector struct {
	ttl         int
	badChecksum bool
	badSeq      bool
	fakeSNI     string
	count       int
}

// FakePacketConfig configures the injector
type FakePacketConfig struct {
	// TTL for fake packets (1-3 recommended)
	// Low TTL ensures packets don't reach destination
	// but DPI still processes them
	TTL int

	// BadChecksum sends packets with invalid TCP checksum
	// DPI doesn't verify, but destination drops them
	BadChecksum bool

	// BadSeq sends packets with wrong sequence numbers
	// DPI processes, but destination ignores
	BadSeq bool

	// FakeSNI is the SNI to put in fake ClientHello
	// Should be a whitelisted domain
	FakeSNI string

	// Count is number of fake packets to send
	Count int
}

// NewFakePacketInjector creates a new injector
func NewFakePacketInjector(cfg FakePacketConfig) *FakePacketInjector {
	if cfg.TTL == 0 {
		cfg.TTL = 2
	}
	if cfg.Count == 0 {
		cfg.Count = 3
	}
	if cfg.FakeSNI == "" {
		cfg.FakeSNI = "yandex.ru"
	}

	return &FakePacketInjector{
		ttl:         cfg.TTL,
		badChecksum: cfg.BadChecksum,
		badSeq:      cfg.BadSeq,
		fakeSNI:     cfg.FakeSNI,
		count:       cfg.Count,
	}
}

// RawSocket represents a raw socket for packet injection
type RawSocket struct {
	fd int
}

// NewRawSocket creates a raw socket (requires root/CAP_NET_RAW)
func NewRawSocket() (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w (need root?)", err)
	}

	// Enable IP_HDRINCL to build our own IP headers
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	return &RawSocket{fd: fd}, nil
}

// Close closes the raw socket
func (r *RawSocket) Close() error {
	return syscall.Close(r.fd)
}

// InjectFakeClientHello injects fake TLS ClientHello packets
func (f *FakePacketInjector) InjectFakeClientHello(
	rawSocket *RawSocket,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seqNum, ackNum uint32,
) error {
	// Build fake ClientHello with whitelisted SNI
	clientHello := buildFakeClientHello(f.fakeSNI)

	for i := 0; i < f.count; i++ {
		packet, err := f.buildPacket(srcIP, dstIP, srcPort, dstPort, seqNum, ackNum, clientHello)
		if err != nil {
			return err
		}

		// Send packet
		addr := &syscall.SockaddrInet4{
			Port: int(dstPort),
		}
		copy(addr.Addr[:], dstIP.To4())

		if err := syscall.Sendto(rawSocket.fd, packet, 0, addr); err != nil {
			return fmt.Errorf("failed to send fake packet: %w", err)
		}
	}

	return nil
}

// buildPacket constructs the raw IP+TCP+Payload packet
func (f *FakePacketInjector) buildPacket(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seqNum, ackNum uint32,
	payload []byte,
) ([]byte, error) {
	// IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                                  // Version (4) + IHL (5)
	ipHeader[1] = 0x00                                  // DSCP/ECN
	totalLen := uint16(20 + 20 + len(payload))          // IP + TCP + Payload
	binary.BigEndian.PutUint16(ipHeader[2:4], totalLen) // Total length
	binary.BigEndian.PutUint16(ipHeader[4:6], 0x0000)   // ID (set to 0 - detectable but ok)
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)   // Flags (Don't Fragment)
	ipHeader[8] = byte(f.ttl)                           // TTL - KEY: low TTL
	ipHeader[9] = 0x06                                  // Protocol: TCP
	// Checksum at [10:12] - calculated later
	copy(ipHeader[12:16], srcIP.To4()) // Source IP
	copy(ipHeader[16:20], dstIP.To4()) // Destination IP

	// Calculate IP checksum
	ipChecksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

	// TCP header (20 bytes minimum)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort) // Source port
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // Destination port

	// Sequence number
	if f.badSeq {
		seqNum = seqNum - 10000 // Wrong sequence - server will ignore
	}
	binary.BigEndian.PutUint32(tcpHeader[4:8], seqNum)  // Sequence number
	binary.BigEndian.PutUint32(tcpHeader[8:12], ackNum) // ACK number

	tcpHeader[12] = 0x50                                // Data offset (5 words = 20 bytes)
	tcpHeader[13] = 0x18                                // Flags: PSH + ACK
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Window size
	// Checksum at [16:18] - calculated later
	// Urgent pointer at [18:20] - zero

	// Calculate TCP checksum (includes pseudo-header)
	tcpChecksum := f.calculateTCPChecksum(srcIP, dstIP, tcpHeader, payload)

	if f.badChecksum {
		// Corrupt the checksum - server drops, DPI doesn't check
		tcpChecksum = tcpChecksum ^ 0xFFFF
	}
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum)

	// Combine all parts
	packet := make([]byte, 0, len(ipHeader)+len(tcpHeader)+len(payload))
	packet = append(packet, ipHeader...)
	packet = append(packet, tcpHeader...)
	packet = append(packet, payload...)

	return packet, nil
}

// calculateChecksum calculates IP/TCP checksum
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// Handle odd byte
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateTCPChecksum calculates TCP checksum with pseudo-header
func (f *FakePacketInjector) calculateTCPChecksum(srcIP, dstIP net.IP, tcpHeader, payload []byte) uint16 {
	// Build pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP protocol
	tcpLen := uint16(len(tcpHeader) + len(payload))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)

	// Combine for checksum calculation
	checksumData := make([]byte, 0, len(pseudoHeader)+len(tcpHeader)+len(payload))
	checksumData = append(checksumData, pseudoHeader...)

	// Zero out checksum field in TCP header for calculation
	tcpCopy := make([]byte, len(tcpHeader))
	copy(tcpCopy, tcpHeader)
	tcpCopy[16] = 0
	tcpCopy[17] = 0

	checksumData = append(checksumData, tcpCopy...)
	checksumData = append(checksumData, payload...)

	return calculateChecksum(checksumData)
}

// buildFakeClientHello builds a minimal TLS ClientHello with given SNI
func buildFakeClientHello(sni string) []byte {
	// TLS Record Layer
	record := []byte{
		0x16,       // Content Type: Handshake
		0x03, 0x01, // Version: TLS 1.0
		// Length: to be filled
		0x00, 0x00,
	}

	// Handshake: ClientHello
	hello := []byte{
		0x01,             // Handshake Type: ClientHello
		0x00, 0x00, 0x00, // Length: to be filled
		0x03, 0x03, // Version: TLS 1.2
	}

	// Random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i) // Predictable for fake
	}
	hello = append(hello, random...)

	// Session ID (empty)
	hello = append(hello, 0x00)

	// Cipher Suites (minimal)
	cipherSuites := []byte{
		0x00, 0x02, // Length: 2 bytes
		0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	}
	hello = append(hello, cipherSuites...)

	// Compression Methods
	hello = append(hello, 0x01, 0x00) // Length: 1, null compression

	// Extensions
	extensions := buildSNIExtension(sni)
	extLen := uint16(len(extensions))
	hello = append(hello, byte(extLen>>8), byte(extLen))
	hello = append(hello, extensions...)

	// Update lengths
	helloLen := len(hello) - 4 // Exclude handshake header
	hello[1] = byte(helloLen >> 16)
	hello[2] = byte(helloLen >> 8)
	hello[3] = byte(helloLen)

	recordLen := len(hello)
	record[3] = byte(recordLen >> 8)
	record[4] = byte(recordLen)

	return append(record, hello...)
}

// buildSNIExtension builds Server Name Indication extension
func buildSNIExtension(sni string) []byte {
	sniBytes := []byte(sni)
	nameLen := len(sniBytes)

	ext := []byte{
		0x00, 0x00, // Extension Type: SNI
	}

	// Extension data length
	extDataLen := 2 + 1 + 2 + nameLen // list_len + type + name_len + name
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))

	// Server Name List Length
	listLen := 1 + 2 + nameLen // type + name_len + name
	ext = append(ext, byte(listLen>>8), byte(listLen))

	// Server Name Type: hostname (0)
	ext = append(ext, 0x00)

	// Server Name Length
	ext = append(ext, byte(nameLen>>8), byte(nameLen))

	// Server Name
	ext = append(ext, sniBytes...)

	return ext
}

// SetSocketTTL sets TTL on an existing socket using setsockopt
func SetSocketTTL(conn net.Conn, ttl int) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	})

	if err != nil {
		return err
	}
	return setErr
}
