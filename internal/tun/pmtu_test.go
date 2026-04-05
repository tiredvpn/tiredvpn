package tun

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestClampTCPMSS_SYNPacket(t *testing.T) {
	// Build a minimal IPv4+TCP SYN packet with MSS=1460
	pkt := buildTCPSYNWithMSS(1460)

	clamped := ClampTCPMSS(pkt, 1280)
	if !clamped {
		t.Fatal("Expected MSS to be clamped")
	}

	// Extract MSS from the TCP options
	ihl := int(pkt[0]&0x0F) * 4
	mss := binary.BigEndian.Uint16(pkt[ihl+22 : ihl+24]) // option at offset +20 (kind=2,len=4,mss=2)
	expectedMSS := uint16(1280 - 40)
	if mss != expectedMSS {
		t.Errorf("Expected MSS %d, got %d", expectedMSS, mss)
	}
}

func TestClampTCPMSS_AlreadySmall(t *testing.T) {
	// MSS=500 is already smaller than 1280-40=1240
	pkt := buildTCPSYNWithMSS(500)

	clamped := ClampTCPMSS(pkt, 1280)
	if clamped {
		t.Fatal("Should not clamp MSS that already fits")
	}

	ihl := int(pkt[0]&0x0F) * 4
	mss := binary.BigEndian.Uint16(pkt[ihl+22 : ihl+24])
	if mss != 500 {
		t.Errorf("MSS should remain 500, got %d", mss)
	}
}

func TestClampTCPMSS_NonSYN(t *testing.T) {
	// Build ACK packet (not SYN) - should not be clamped
	pkt := buildTCPSYNWithMSS(1460)
	ihl := int(pkt[0]&0x0F) * 4
	pkt[ihl+13] = 0x10 // ACK only, clear SYN

	clamped := ClampTCPMSS(pkt, 1280)
	if clamped {
		t.Fatal("Should not clamp non-SYN packet")
	}
}

func TestClampTCPMSS_NonTCP(t *testing.T) {
	pkt := buildTCPSYNWithMSS(1460)
	pkt[9] = 17 // UDP

	clamped := ClampTCPMSS(pkt, 1280)
	if clamped {
		t.Fatal("Should not clamp non-TCP packet")
	}
}

func TestClampTCPMSS_SYNACKPacket(t *testing.T) {
	pkt := buildTCPSYNWithMSS(1460)
	ihl := int(pkt[0]&0x0F) * 4
	pkt[ihl+13] = 0x12 // SYN+ACK

	clamped := ClampTCPMSS(pkt, 1280)
	if !clamped {
		t.Fatal("Expected MSS to be clamped on SYN+ACK")
	}
}

func TestClampTCPMSS_ChecksumValid(t *testing.T) {
	pkt := buildTCPSYNWithMSS(1460)

	ClampTCPMSS(pkt, 1280)

	// Verify TCP checksum
	ihl := int(pkt[0]&0x0F) * 4
	tcpLen := len(pkt) - ihl

	var sum uint32
	// Pseudo header
	sum += uint32(pkt[12])<<8 | uint32(pkt[13])
	sum += uint32(pkt[14])<<8 | uint32(pkt[15])
	sum += uint32(pkt[16])<<8 | uint32(pkt[17])
	sum += uint32(pkt[18])<<8 | uint32(pkt[19])
	sum += 6 // TCP
	sum += uint32(tcpLen)

	// TCP data
	for i := ihl; i < len(pkt)-1; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if (len(pkt)-ihl)%2 != 0 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Errorf("TCP checksum invalid after clamping: 0x%04x (expected 0xffff)", sum)
	}
}

func TestBuildICMPFragNeeded(t *testing.T) {
	// Build a sample IPv4 packet (40 bytes: IP header + 20 bytes payload)
	origPkt := make([]byte, 40)
	origPkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(origPkt[2:4], 40)
	origPkt[9] = 6 // TCP
	copy(origPkt[12:16], net.IPv4(10, 9, 0, 2).To4()) // src
	copy(origPkt[16:20], net.IPv4(8, 8, 8, 8).To4())  // dst

	srcIP := net.IPv4(10, 9, 0, 1)
	icmpPkt := BuildICMPFragNeeded(srcIP, origPkt, 1280)

	if icmpPkt == nil {
		t.Fatal("Expected non-nil ICMP packet")
	}

	// Check IP header
	if icmpPkt[0] != 0x45 {
		t.Errorf("Expected IPv4 version+ihl 0x45, got 0x%02x", icmpPkt[0])
	}
	if icmpPkt[9] != 1 { // ICMP
		t.Errorf("Expected protocol 1 (ICMP), got %d", icmpPkt[9])
	}

	// Source should be our TUN IP
	if !net.IP(icmpPkt[12:16]).Equal(srcIP) {
		t.Errorf("Expected src %s, got %s", srcIP, net.IP(icmpPkt[12:16]))
	}
	// Dest should be original packet's source
	if !net.IP(icmpPkt[16:20]).Equal(net.IPv4(10, 9, 0, 2)) {
		t.Errorf("Expected dst 10.9.0.2, got %s", net.IP(icmpPkt[16:20]))
	}

	// Check ICMP header
	if icmpPkt[20] != 3 { // Type: Destination Unreachable
		t.Errorf("Expected ICMP type 3, got %d", icmpPkt[20])
	}
	if icmpPkt[21] != 4 { // Code: Fragmentation Needed
		t.Errorf("Expected ICMP code 4, got %d", icmpPkt[21])
	}

	// Check Next-Hop MTU
	nextHopMTU := binary.BigEndian.Uint16(icmpPkt[26:28])
	if nextHopMTU != 1280 {
		t.Errorf("Expected next-hop MTU 1280, got %d", nextHopMTU)
	}

	// Verify ICMP checksum
	icmpLen := len(icmpPkt) - 20
	var sum uint32
	for i := 20; i < 20+icmpLen-1; i += 2 {
		sum += uint32(icmpPkt[i])<<8 | uint32(icmpPkt[i+1])
	}
	if icmpLen%2 != 0 {
		sum += uint32(icmpPkt[20+icmpLen-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Errorf("ICMP checksum invalid: 0x%04x (expected 0xffff)", sum)
	}

	// Verify IP checksum
	var ipSum uint32
	for i := 0; i < 20; i += 2 {
		ipSum += uint32(binary.BigEndian.Uint16(icmpPkt[i : i+2]))
	}
	for ipSum > 0xffff {
		ipSum = (ipSum & 0xffff) + (ipSum >> 16)
	}
	if uint16(ipSum) != 0xffff {
		t.Errorf("IP checksum invalid: 0x%04x (expected 0xffff)", ipSum)
	}
}

func TestBuildICMPFragNeeded_ShortPacket(t *testing.T) {
	result := BuildICMPFragNeeded(net.IPv4(10, 9, 0, 1), []byte{0x45}, 1280)
	if result != nil {
		t.Error("Expected nil for too-short packet")
	}
}

func TestDefaultMTU(t *testing.T) {
	if DefaultMTU != 1280 {
		t.Errorf("Expected DefaultMTU=1280, got %d", DefaultMTU)
	}
}

// buildTCPSYNWithMSS creates a minimal IPv4+TCP SYN packet with the given MSS option.
func buildTCPSYNWithMSS(mss uint16) []byte {
	// IP header (20) + TCP header with MSS option (24) = 44 bytes
	pkt := make([]byte, 44)

	// IPv4 header
	pkt[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], 44) // Total length
	pkt[8] = 64                               // TTL
	pkt[9] = 6                                // TCP
	copy(pkt[12:16], net.IPv4(10, 9, 0, 2).To4())
	copy(pkt[16:20], net.IPv4(8, 8, 8, 8).To4())

	// IP checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	// TCP header (at offset 20)
	tcp := 20
	binary.BigEndian.PutUint16(pkt[tcp:tcp+2], 12345) // src port
	binary.BigEndian.PutUint16(pkt[tcp+2:tcp+4], 443) // dst port
	pkt[tcp+12] = 0x60                                 // Data offset = 6 (24 bytes)
	pkt[tcp+13] = 0x02                                 // SYN flag

	// MSS option: kind=2, len=4, mss
	pkt[tcp+20] = 2 // kind = MSS
	pkt[tcp+21] = 4 // len = 4
	binary.BigEndian.PutUint16(pkt[tcp+22:tcp+24], mss)

	// Compute TCP checksum
	recomputeTCPChecksum(pkt, tcp)

	return pkt
}
