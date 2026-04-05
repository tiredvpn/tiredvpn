package tun

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestIPPacketParsing tests IPv4 packet parsing
func TestIPPacketParsing(t *testing.T) {
	// Create a minimal IPv4 packet
	packet := make([]byte, 20) // Minimum IPv4 header

	// Version (4) and IHL (5) - 20 bytes header
	packet[0] = 0x45

	// Total length (20 bytes)
	binary.BigEndian.PutUint16(packet[2:4], 20)

	// Protocol (TCP = 6)
	packet[9] = 6

	// Source IP: 10.8.0.2
	packet[12] = 10
	packet[13] = 8
	packet[14] = 0
	packet[15] = 2

	// Dest IP: 8.8.8.8
	packet[16] = 8
	packet[17] = 8
	packet[18] = 8
	packet[19] = 8

	// Parse packet
	version := packet[0] >> 4
	if version != 4 {
		t.Errorf("Expected IPv4 (version 4), got %d", version)
	}

	ihl := packet[0] & 0x0F
	if ihl != 5 {
		t.Errorf("Expected IHL 5, got %d", ihl)
	}

	totalLen := binary.BigEndian.Uint16(packet[2:4])
	if totalLen != 20 {
		t.Errorf("Expected length 20, got %d", totalLen)
	}

	protocol := packet[9]
	if protocol != 6 {
		t.Errorf("Expected TCP (6), got %d", protocol)
	}

	srcIP := net.IP(packet[12:16])
	if !srcIP.Equal(net.ParseIP("10.8.0.2")) {
		t.Errorf("Expected source IP 10.8.0.2, got %s", srcIP)
	}

	dstIP := net.IP(packet[16:20])
	if !dstIP.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("Expected dest IP 8.8.8.8, got %s", dstIP)
	}
}

// TestIPv6PacketParsing tests IPv6 packet parsing
func TestIPv6PacketParsing(t *testing.T) {
	// Create minimal IPv6 packet (40 bytes header)
	packet := make([]byte, 40)

	// Version (6) and traffic class
	packet[0] = 0x60

	// Payload length (0 for this test)
	binary.BigEndian.PutUint16(packet[4:6], 0)

	// Next header (TCP = 6)
	packet[6] = 6

	// Hop limit
	packet[7] = 64

	// Source address: 2001:db8::1
	packet[8] = 0x20
	packet[9] = 0x01
	packet[10] = 0x0d
	packet[11] = 0xb8
	packet[23] = 0x01

	// Dest address: 2001:db8::2
	packet[24] = 0x20
	packet[25] = 0x01
	packet[26] = 0x0d
	packet[27] = 0xb8
	packet[39] = 0x02

	// Parse packet
	version := packet[0] >> 4
	if version != 6 {
		t.Errorf("Expected IPv6 (version 6), got %d", version)
	}

	payloadLen := binary.BigEndian.Uint16(packet[4:6])
	if payloadLen != 0 {
		t.Errorf("Expected payload length 0, got %d", payloadLen)
	}

	nextHeader := packet[6]
	if nextHeader != 6 {
		t.Errorf("Expected TCP (6), got %d", nextHeader)
	}

	hopLimit := packet[7]
	if hopLimit != 64 {
		t.Errorf("Expected hop limit 64, got %d", hopLimit)
	}
}

// TestTCPPacketParsing tests TCP header parsing
func TestTCPPacketParsing(t *testing.T) {
	// Create minimal TCP header (20 bytes)
	tcpHeader := make([]byte, 20)

	// Source port: 443
	binary.BigEndian.PutUint16(tcpHeader[0:2], 443)

	// Dest port: 12345
	binary.BigEndian.PutUint16(tcpHeader[2:4], 12345)

	// Sequence number
	binary.BigEndian.PutUint32(tcpHeader[4:8], 1000)

	// Ack number
	binary.BigEndian.PutUint32(tcpHeader[8:12], 2000)

	// Data offset (5 = 20 bytes) and flags
	tcpHeader[12] = 0x50 // Data offset = 5
	tcpHeader[13] = 0x02 // SYN flag

	// Window size
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	// Parse
	srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
	if srcPort != 443 {
		t.Errorf("Expected source port 443, got %d", srcPort)
	}

	dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])
	if dstPort != 12345 {
		t.Errorf("Expected dest port 12345, got %d", dstPort)
	}

	seqNum := binary.BigEndian.Uint32(tcpHeader[4:8])
	if seqNum != 1000 {
		t.Errorf("Expected seq 1000, got %d", seqNum)
	}

	ackNum := binary.BigEndian.Uint32(tcpHeader[8:12])
	if ackNum != 2000 {
		t.Errorf("Expected ack 2000, got %d", ackNum)
	}

	dataOffset := (tcpHeader[12] >> 4) * 4
	if dataOffset != 20 {
		t.Errorf("Expected data offset 20, got %d", dataOffset)
	}

	flags := tcpHeader[13]
	synFlag := flags & 0x02
	if synFlag == 0 {
		t.Error("Expected SYN flag to be set")
	}

	windowSize := binary.BigEndian.Uint16(tcpHeader[14:16])
	if windowSize != 65535 {
		t.Errorf("Expected window 65535, got %d", windowSize)
	}
}

// TestUDPPacketParsing tests UDP header parsing
func TestUDPPacketParsing(t *testing.T) {
	// Create minimal UDP header (8 bytes)
	udpHeader := make([]byte, 8)

	// Source port: 53 (DNS)
	binary.BigEndian.PutUint16(udpHeader[0:2], 53)

	// Dest port: 12345
	binary.BigEndian.PutUint16(udpHeader[2:4], 12345)

	// Length: 8 (header only)
	binary.BigEndian.PutUint16(udpHeader[4:6], 8)

	// Checksum
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	// Parse
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	if srcPort != 53 {
		t.Errorf("Expected source port 53, got %d", srcPort)
	}

	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	if dstPort != 12345 {
		t.Errorf("Expected dest port 12345, got %d", dstPort)
	}

	length := binary.BigEndian.Uint16(udpHeader[4:6])
	if length != 8 {
		t.Errorf("Expected length 8, got %d", length)
	}
}

// TestICMPPacketParsing tests ICMP packet parsing
func TestICMPPacketParsing(t *testing.T) {
	// Create ICMP Echo Request
	icmpPacket := make([]byte, 8)

	// Type: 8 (Echo Request)
	icmpPacket[0] = 8

	// Code: 0
	icmpPacket[1] = 0

	// Checksum
	binary.BigEndian.PutUint16(icmpPacket[2:4], 0)

	// Identifier
	binary.BigEndian.PutUint16(icmpPacket[4:6], 1234)

	// Sequence number
	binary.BigEndian.PutUint16(icmpPacket[6:8], 1)

	// Parse
	icmpType := icmpPacket[0]
	if icmpType != 8 {
		t.Errorf("Expected ICMP type 8 (Echo Request), got %d", icmpType)
	}

	icmpCode := icmpPacket[1]
	if icmpCode != 0 {
		t.Errorf("Expected ICMP code 0, got %d", icmpCode)
	}

	identifier := binary.BigEndian.Uint16(icmpPacket[4:6])
	if identifier != 1234 {
		t.Errorf("Expected identifier 1234, got %d", identifier)
	}

	seqNum := binary.BigEndian.Uint16(icmpPacket[6:8])
	if seqNum != 1 {
		t.Errorf("Expected sequence 1, got %d", seqNum)
	}
}

// TestMTUValidation tests MTU size validation
func TestMTUValidation(t *testing.T) {
	tests := []struct {
		name  string
		mtu   int
		valid bool
	}{
		{"Standard 1500", 1500, true},
		{"VPN typical 1400", 1400, true},
		{"Minimum 68", 68, true},
		{"Too small", 67, false},
		{"Jumbo 9000", 9000, true},
		{"Too large", 65536, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.mtu >= 68 && tt.mtu <= 65535
			if valid != tt.valid {
				t.Errorf("MTU %d validity: got %v, want %v", tt.mtu, valid, tt.valid)
			}
		})
	}
}

// TestIPChecksumCalculation tests IPv4 checksum calculation
func TestIPChecksumCalculation(t *testing.T) {
	// Create IPv4 header without checksum
	header := []byte{
		0x45, 0x00, // Version, IHL, DSCP, ECN
		0x00, 0x3c, // Total length
		0x1c, 0x46, // Identification
		0x40, 0x00, // Flags, Fragment offset
		0x40, 0x06, // TTL, Protocol
		0x00, 0x00, // Checksum (will calculate)
		0xac, 0x10, 0x0a, 0x63, // Source IP
		0xac, 0x10, 0x0a, 0x0c, // Dest IP
	}

	// Calculate checksum
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		if i == 10 { // Skip checksum field
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	checksum := uint16(^sum)

	// Verify checksum is non-zero
	if checksum == 0 {
		t.Error("Checksum should not be zero for this header")
	}

	// Put checksum in header
	binary.BigEndian.PutUint16(header[10:12], checksum)

	// Verify checksum
	sum = 0
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	if sum != 0xffff {
		t.Errorf("Checksum verification failed: got 0x%04x, want 0xffff", sum)
	}
}

// TestIPFragmentation tests IP fragmentation fields
func TestIPFragmentation(t *testing.T) {
	tests := []struct {
		name           string
		flags          byte
		fragmentOffset uint16
		isFragment     bool
		moreFragments  bool
	}{
		{
			name:           "No fragmentation",
			flags:          0x40, // Don't Fragment
			fragmentOffset: 0,
			isFragment:     false,
			moreFragments:  false,
		},
		{
			name:           "First fragment",
			flags:          0x20, // More Fragments
			fragmentOffset: 0,
			isFragment:     true,
			moreFragments:  true,
		},
		{
			name:           "Middle fragment",
			flags:          0x20, // More Fragments
			fragmentOffset: 185, // 1480 bytes offset (185 * 8)
			isFragment:     true,
			moreFragments:  true,
		},
		{
			name:           "Last fragment",
			flags:          0x00,
			fragmentOffset: 370, // 2960 bytes offset
			isFragment:     true,
			moreFragments:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build flags and offset field (2 bytes)
			flagsOffset := uint16(tt.flags)<<8 | (tt.fragmentOffset & 0x1FFF)

			isFragment := (tt.fragmentOffset != 0) || ((tt.flags & 0x20) != 0)
			if isFragment != tt.isFragment {
				t.Errorf("isFragment: got %v, want %v", isFragment, tt.isFragment)
			}

			moreFragments := (tt.flags & 0x20) != 0
			if moreFragments != tt.moreFragments {
				t.Errorf("moreFragments: got %v, want %v", moreFragments, tt.moreFragments)
			}

			// Verify offset extraction
			extractedOffset := flagsOffset & 0x1FFF
			if extractedOffset != tt.fragmentOffset {
				t.Errorf("Offset: got %d, want %d", extractedOffset, tt.fragmentOffset)
			}
		})
	}
}

// TestTCPFlags tests TCP control flags
func TestTCPFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags byte
		fin   bool
		syn   bool
		rst   bool
		psh   bool
		ack   bool
		urg   bool
	}{
		{"SYN", 0x02, false, true, false, false, false, false},
		{"SYN+ACK", 0x12, false, true, false, false, true, false},
		{"ACK", 0x10, false, false, false, false, true, false},
		{"PSH+ACK", 0x18, false, false, false, true, true, false},
		{"FIN+ACK", 0x11, true, false, false, false, true, false},
		{"RST", 0x04, false, false, true, false, false, false},
		{"URG+ACK", 0x30, false, false, false, false, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fin := (tt.flags & 0x01) != 0
			syn := (tt.flags & 0x02) != 0
			rst := (tt.flags & 0x04) != 0
			psh := (tt.flags & 0x08) != 0
			ack := (tt.flags & 0x10) != 0
			urg := (tt.flags & 0x20) != 0

			if fin != tt.fin {
				t.Errorf("FIN: got %v, want %v", fin, tt.fin)
			}
			if syn != tt.syn {
				t.Errorf("SYN: got %v, want %v", syn, tt.syn)
			}
			if rst != tt.rst {
				t.Errorf("RST: got %v, want %v", rst, tt.rst)
			}
			if psh != tt.psh {
				t.Errorf("PSH: got %v, want %v", psh, tt.psh)
			}
			if ack != tt.ack {
				t.Errorf("ACK: got %v, want %v", ack, tt.ack)
			}
			if urg != tt.urg {
				t.Errorf("URG: got %v, want %v", urg, tt.urg)
			}
		})
	}
}
