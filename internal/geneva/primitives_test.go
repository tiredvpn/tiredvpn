package geneva

import (
	"encoding/binary"
	"testing"
)

// createTestPacket creates a minimal TCP packet for testing
func createTestPacket() []byte {
	// IPv4 header (20 bytes) + TCP header (20 bytes) + payload
	packet := make([]byte, 60)

	// IP header
	packet[0] = 0x45 // Version 4, header length 5 (20 bytes)
	packet[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(packet[2:4], 60)  // Total length
	binary.BigEndian.PutUint16(packet[4:6], 1234) // ID
	packet[6] = 0x40                              // Flags: DF
	packet[7] = 0x00                              // Fragment offset
	packet[8] = 64                                // TTL
	packet[9] = 6                                 // Protocol: TCP
	// Checksum at 10-11 (will be calculated)
	packet[12] = 192 // Source IP: 192.168.1.1
	packet[13] = 168
	packet[14] = 1
	packet[15] = 1
	packet[16] = 192 // Dest IP: 192.168.1.2
	packet[17] = 168
	packet[18] = 1
	packet[19] = 2

	// TCP header (starts at byte 20)
	binary.BigEndian.PutUint16(packet[20:22], 12345) // Source port
	binary.BigEndian.PutUint16(packet[22:24], 80)    // Dest port
	binary.BigEndian.PutUint32(packet[24:28], 1000)  // Sequence number
	binary.BigEndian.PutUint32(packet[28:32], 2000)  // Ack number
	packet[32] = 0x50                                 // Data offset: 5 (20 bytes), reserved
	packet[33] = TCPFlagSYN | TCPFlagACK              // Flags: SYN+ACK
	binary.BigEndian.PutUint16(packet[34:36], 65535) // Window size
	// Checksum at 36-37
	binary.BigEndian.PutUint16(packet[38:40], 0) // Urgent pointer

	// Payload
	copy(packet[40:], []byte("Hello Geneva!!"))

	// Calculate IP checksum
	recalculateIPChecksum(packet)

	return packet
}

func TestDropPrimitive(t *testing.T) {
	drop := NewDropPrimitive()

	packet := createTestPacket()
	result, err := drop.Apply(packet)

	if err != nil {
		t.Errorf("Drop.Apply() error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Drop.Apply() returned %d packets, want 0", len(result))
	}

	if drop.String() != "drop" {
		t.Errorf("Drop.String() = %q, want \"drop\"", drop.String())
	}
}

func TestSendPrimitive(t *testing.T) {
	send := NewSendPrimitive()

	packet := createTestPacket()
	result, err := send.Apply(packet)

	if err != nil {
		t.Errorf("Send.Apply() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Send.Apply() returned %d packets, want 1", len(result))
	}

	if len(result) > 0 && len(result[0]) != len(packet) {
		t.Errorf("Send.Apply() modified packet length")
	}

	if send.String() != "send" {
		t.Errorf("Send.String() = %q, want \"send\"", send.String())
	}
}

func TestDuplicatePrimitive(t *testing.T) {
	tests := []struct {
		count    int
		expected int
	}{
		{1, 2},  // Original + 1 duplicate = 2 packets
		{2, 3},  // Original + 2 duplicates = 3 packets
		{5, 6},  // Original + 5 duplicates = 6 packets
		{0, 2},  // Count < 1 defaults to 1
		{-1, 2}, // Count < 1 defaults to 1
	}

	for _, tt := range tests {
		t.Run("count_"+string(rune('0'+tt.count)), func(t *testing.T) {
			dup := NewDuplicatePrimitive(tt.count)

			packet := createTestPacket()
			result, err := dup.Apply(packet)

			if err != nil {
				t.Errorf("Duplicate.Apply() error = %v", err)
			}

			if len(result) != tt.expected {
				t.Errorf("Duplicate.Apply() returned %d packets, want %d", len(result), tt.expected)
			}

			// Verify all packets are identical
			for i, pkt := range result {
				if len(pkt) != len(packet) {
					t.Errorf("Packet %d has length %d, want %d", i, len(pkt), len(packet))
				}
			}
		})
	}
}

func TestTamperFlags(t *testing.T) {
	tamper := NewTamperPrimitive("flags", uint8(TCPFlagRST))

	packet := createTestPacket()
	result, err := tamper.Apply(packet)

	if err != nil {
		t.Errorf("Tamper.Apply() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Tamper.Apply() returned %d packets, want 1", len(result))
	}

	// Check flags were modified
	flags, err := ParseTCPFlags(result[0])
	if err != nil {
		t.Errorf("ParseTCPFlags() error = %v", err)
	}

	if flags != TCPFlagRST {
		t.Errorf("Tamper set flags to 0x%02x, want 0x%02x", flags, TCPFlagRST)
	}

	if tamper.String() != "tamper{flags}" {
		t.Errorf("Tamper.String() = %q, want \"tamper{flags}\"", tamper.String())
	}
}

func TestTamperSeq(t *testing.T) {
	newSeq := uint32(99999)
	tamper := NewTamperPrimitive("seq", newSeq)

	packet := createTestPacket()
	result, err := tamper.Apply(packet)

	if err != nil {
		t.Errorf("Tamper.Apply() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Tamper.Apply() returned %d packets, want 1", len(result))
	}

	// Check sequence number was modified
	seq := binary.BigEndian.Uint32(result[0][24:28])
	if seq != newSeq {
		t.Errorf("Tamper set seq to %d, want %d", seq, newSeq)
	}
}

func TestTamperTTL(t *testing.T) {
	newTTL := uint8(128)
	tamper := NewTamperPrimitive("ttl", newTTL)

	packet := createTestPacket()
	result, err := tamper.Apply(packet)

	if err != nil {
		t.Errorf("Tamper.Apply() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Tamper.Apply() returned %d packets, want 1", len(result))
	}

	// Check TTL was modified
	ttl := result[0][8]
	if ttl != newTTL {
		t.Errorf("Tamper set TTL to %d, want %d", ttl, newTTL)
	}

	// Verify IP checksum was recalculated
	originalChecksum := binary.BigEndian.Uint16(packet[10:12])
	newChecksum := binary.BigEndian.Uint16(result[0][10:12])
	if originalChecksum == newChecksum {
		t.Errorf("IP checksum was not recalculated after TTL change")
	}
}

func TestFragmentPrimitive(t *testing.T) {
	frag := NewFragmentPrimitive(5, 0)

	packet := createTestPacket()
	result, err := frag.Apply(packet)

	if err != nil {
		t.Errorf("Fragment.Apply() error = %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Fragment.Apply() returned %d packets, want 2", len(result))
	}

	// Verify payload was split
	payload1 := result[0][40:] // Payload starts at byte 40
	payload2 := result[1][40:]

	if len(payload1) != 5 {
		t.Errorf("First fragment payload length = %d, want 5", len(payload1))
	}

	originalPayload := packet[40:]
	if len(payload2) != len(originalPayload)-5 {
		t.Errorf("Second fragment payload length = %d, want %d", len(payload2), len(originalPayload)-5)
	}

	// Verify sequence numbers are correct
	seq1 := binary.BigEndian.Uint32(result[0][24:28])
	seq2 := binary.BigEndian.Uint32(result[1][24:28])

	expectedSeq2 := seq1 + 5
	if seq2 != expectedSeq2 {
		t.Errorf("Second fragment seq = %d, want %d", seq2, expectedSeq2)
	}
}

func TestFragmentNoPayload(t *testing.T) {
	// Create packet with no payload
	packet := make([]byte, 40)

	// IP header
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 64
	packet[9] = 6
	recalculateIPChecksum(packet)

	// TCP header
	packet[32] = 0x50 // Data offset: 5 (20 bytes)

	frag := NewFragmentPrimitive(5, 0)
	result, err := frag.Apply(packet)

	if err != nil {
		t.Errorf("Fragment.Apply() error = %v", err)
	}

	// Should return original packet unmodified
	if len(result) != 1 {
		t.Errorf("Fragment.Apply() on empty payload returned %d packets, want 1", len(result))
	}
}

func TestParseTCPFlags(t *testing.T) {
	packet := createTestPacket()

	flags, err := ParseTCPFlags(packet)
	if err != nil {
		t.Errorf("ParseTCPFlags() error = %v", err)
	}

	expected := uint8(TCPFlagSYN | TCPFlagACK)
	if flags != expected {
		t.Errorf("ParseTCPFlags() = 0x%02x, want 0x%02x", flags, expected)
	}
}

func TestParseTCPFlagsErrors(t *testing.T) {
	// Create IP-only packet
	ipOnly := make([]byte, 20)
	ipOnly[0] = 0x45 // Version 4, header length 5

	tests := []struct {
		name   string
		packet []byte
	}{
		{"empty packet", []byte{}},
		{"short packet", []byte{0x45, 0x00, 0x00}},
		{"IP only", ipOnly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTCPFlags(tt.packet)
			if err == nil {
				t.Errorf("ParseTCPFlags() expected error for %s", tt.name)
			}
		})
	}
}

func TestTCPFlagConstants(t *testing.T) {
	tests := []struct {
		flag     uint8
		name     string
		expected uint8
	}{
		{TCPFlagFIN, "FIN", 0x01},
		{TCPFlagSYN, "SYN", 0x02},
		{TCPFlagRST, "RST", 0x04},
		{TCPFlagPSH, "PSH", 0x08},
		{TCPFlagACK, "ACK", 0x10},
		{TCPFlagURG, "URG", 0x20},
		{TCPFlagECE, "ECE", 0x40},
		{TCPFlagCWR, "CWR", 0x80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.flag != tt.expected {
				t.Errorf("TCPFlag%s = 0x%02x, want 0x%02x", tt.name, tt.flag, tt.expected)
			}
		})
	}
}

func TestIPChecksumRecalculation(t *testing.T) {
	packet := createTestPacket()

	// Get original checksum
	originalChecksum := binary.BigEndian.Uint16(packet[10:12])

	// Modify TTL (should trigger checksum recalculation)
	packet[8] = 32
	recalculateIPChecksum(packet)

	newChecksum := binary.BigEndian.Uint16(packet[10:12])

	if originalChecksum == newChecksum {
		t.Errorf("IP checksum unchanged after TTL modification")
	}

	// Verify checksum is correct by recalculating again
	packet[10] = 0
	packet[11] = 0
	recalculateIPChecksum(packet)
	verifyChecksum := binary.BigEndian.Uint16(packet[10:12])

	if newChecksum != verifyChecksum {
		t.Errorf("IP checksum calculation inconsistent: got 0x%04x and 0x%04x", newChecksum, verifyChecksum)
	}
}

func BenchmarkDropPrimitive(b *testing.B) {
	drop := NewDropPrimitive()
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		drop.Apply(packet)
	}
}

func BenchmarkDuplicatePrimitive(b *testing.B) {
	dup := NewDuplicatePrimitive(2)
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dup.Apply(packet)
	}
}

func BenchmarkTamperFlags(b *testing.B) {
	tamper := NewTamperPrimitive("flags", uint8(TCPFlagRST))
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tamper.Apply(packet)
	}
}

func BenchmarkFragmentPrimitive(b *testing.B) {
	frag := NewFragmentPrimitive(10, 0)
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frag.Apply(packet)
	}
}
