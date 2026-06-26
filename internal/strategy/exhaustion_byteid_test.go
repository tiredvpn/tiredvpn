package strategy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// oldBuildSYNPacket is a verbatim copy of the pre-refactor implementation,
// parameterized on the random ID and sequence so we can compare byte-for-byte
// against the new buffer-reusing implementation on identical random input.
func oldBuildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, randID, randSeq []byte) []byte {
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:4], 40)
	copy(ipHeader[4:6], randID)
	ipHeader[6] = 0x40
	ipHeader[7] = 0x00
	ipHeader[8] = 64
	ipHeader[9] = 6
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ipHeader[10:12], tcpChecksum(ipHeader))

	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	copy(tcpHeader[4:8], randSeq)
	tcpHeader[12] = 0x50
	tcpHeader[13] = 0x02
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHeader)))
	data := append(pseudo, tcpHeader...)
	data[12+16] = 0
	data[12+17] = 0
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum(data))

	return append(ipHeader, tcpHeader...)
}

func TestBuildSYNPacketByteIdentical(t *testing.T) {
	s := &StateExhaustionStrategy{}
	src := net.ParseIP("192.168.1.50")
	dst := net.ParseIP("203.0.113.77")
	var srcPort uint16 = 12345
	var dstPort uint16 = 443

	var buf [40]byte
	for iter := 0; iter < 1000; iter++ {
		got := s.buildSYNPacket(buf[:], src, dst, srcPort, dstPort)
		// Extract the random bytes the new impl placed, feed them to the old impl.
		randID := append([]byte(nil), got[4:6]...)
		randSeq := append([]byte(nil), got[24:28]...)
		want := oldBuildSYNPacket(src, dst, srcPort, dstPort, randID, randSeq)
		if !bytes.Equal(got, want) {
			t.Fatalf("iter %d: packet bytes differ\n got=%x\nwant=%x", iter, got, want)
		}
	}
}
