package server

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// frame builds a [len:4][pkt:N] TUN frame.
func frame(pkt []byte) []byte {
	b := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(b[0:4], uint32(len(pkt)))
	copy(b[4:], pkt)
	return b
}

// ipPacket returns a dummy IP-sized payload of n bytes (n must be >= 20).
func ipPacket(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

// feed drives reassembleH2TUNFrames payload-by-payload (simulating stego DATA
// frames), accumulating the carry-over buffer exactly like forwardH2TUNPacket.
func feed(payloads [][]byte) (delivered [][]byte, keepalives int, finalBuf []byte) {
	var buf []byte
	for _, p := range payloads {
		buf = append(buf, p...)
		buf = reassembleH2TUNFrames(buf,
			func(ipPkt []byte) {
				delivered = append(delivered, bytes.Clone(ipPkt))
			},
			func() { keepalives++ },
		)
	}
	return delivered, keepalives, buf
}

func TestReassembleSinglePayload(t *testing.T) {
	pkt := ipPacket(1400)
	delivered, ka, rest := feed([][]byte{frame(pkt)})
	if ka != 0 {
		t.Fatalf("unexpected keepalives: %d", ka)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected remainder: %d bytes", len(rest))
	}
	if len(delivered) != 1 || !bytes.Equal(delivered[0], pkt) {
		t.Fatalf("packet not delivered intact: got %d packets", len(delivered))
	}
}

// The core regression: a 1400-byte inner packet (1404-byte frame) arrives split
// across stego payloads (relay leg chunks at 1000/1400). It must reassemble, not drop.
func TestReassembleSplitAcrossTwoPayloads(t *testing.T) {
	pkt := ipPacket(1400)
	f := frame(pkt) // 1404 bytes
	delivered, _, rest := feed([][]byte{f[:1000], f[1000:]})
	if len(rest) != 0 {
		t.Fatalf("unexpected remainder: %d bytes", len(rest))
	}
	if len(delivered) != 1 || !bytes.Equal(delivered[0], pkt) {
		t.Fatalf("split frame not reassembled: got %d packets", len(delivered))
	}
}

func TestReassembleSplitAcrossThreePayloads(t *testing.T) {
	pkt := ipPacket(1400)
	f := frame(pkt)
	// Split mid-header too: first payload carries only 2 of the 4 length bytes.
	delivered, _, rest := feed([][]byte{f[:2], f[2:700], f[700:]})
	if len(rest) != 0 {
		t.Fatalf("unexpected remainder: %d bytes", len(rest))
	}
	if len(delivered) != 1 || !bytes.Equal(delivered[0], pkt) {
		t.Fatalf("3-way split frame not reassembled: got %d packets", len(delivered))
	}
}

// Multiple complete frames batched into one payload (io.Copy can coalesce) must
// all be delivered, not just the first.
func TestReassembleMultipleFramesInOnePayload(t *testing.T) {
	a, b, c := ipPacket(60), ipPacket(1400), ipPacket(300)
	var batch []byte
	batch = append(batch, frame(a)...)
	batch = append(batch, frame(b)...)
	batch = append(batch, frame(c)...)

	delivered, _, rest := feed([][]byte{batch})
	if len(rest) != 0 {
		t.Fatalf("unexpected remainder: %d bytes", len(rest))
	}
	if len(delivered) != 3 {
		t.Fatalf("want 3 packets, got %d", len(delivered))
	}
	if !bytes.Equal(delivered[0], a) || !bytes.Equal(delivered[1], b) || !bytes.Equal(delivered[2], c) {
		t.Fatalf("batched packets corrupted")
	}
}

func TestReassembleKeepalive(t *testing.T) {
	pkt := ipPacket(64)
	ka := frame(nil) // [0,0,0,0]
	// keepalive between two data frames
	var stream []byte
	stream = append(stream, ka...)
	stream = append(stream, frame(pkt)...)
	stream = append(stream, ka...)

	delivered, keepalives, rest := feed([][]byte{stream})
	if len(rest) != 0 {
		t.Fatalf("unexpected remainder: %d bytes", len(rest))
	}
	if keepalives != 2 {
		t.Fatalf("want 2 keepalives, got %d", keepalives)
	}
	if len(delivered) != 1 || !bytes.Equal(delivered[0], pkt) {
		t.Fatalf("data packet around keepalives lost")
	}
}

func TestReassemblePartialFrameHeldAsRemainder(t *testing.T) {
	pkt := ipPacket(500)
	f := frame(pkt)
	// Only deliver the first half; the rest must be retained for the next call.
	delivered, _, rest := feed([][]byte{f[:200]})
	if len(delivered) != 0 {
		t.Fatalf("should not deliver incomplete frame, got %d", len(delivered))
	}
	if !bytes.Equal(rest, f[:200]) {
		t.Fatalf("remainder not preserved: %d bytes", len(rest))
	}
}

// A bogus leading byte desyncs the stream; the reassembler must slide forward and
// recover the next valid frame rather than dropping everything. A single non-zero
// leading byte makes window[0:4] = [G,0,0,0] (huge -> oversized -> slide by 1),
// after which the buffer is aligned on the real length header.
func TestReassembleResyncAfterGarbage(t *testing.T) {
	pkt := ipPacket(80)
	good := frame(pkt)
	stream := append([]byte{0xab}, good...)

	delivered, _, _ := feed([][]byte{stream})
	found := false
	for _, d := range delivered {
		if bytes.Equal(d, pkt) {
			found = true
		}
	}
	if !found {
		t.Fatalf("reassembler did not recover valid frame after garbage")
	}
}

// An oversized length field (> 65535) is rejected and resynced past.
func TestReassembleRejectsOversizedLength(t *testing.T) {
	bad := make([]byte, 4)
	binary.BigEndian.PutUint32(bad, 70000)
	pkt := ipPacket(64)
	stream := append(bad, frame(pkt)...)

	delivered, _, _ := feed([][]byte{stream})
	if len(delivered) == 0 {
		t.Fatalf("expected recovery to a valid frame after oversized length")
	}
}

// A persistently desynced stream must stay bounded - it must not accumulate into
// an unbounded buffer (AMS prod runs with swap 0). All-0xFF bytes form an oversized
// length at every window, so the reassembler slides through without ever delivering
// or holding a large remainder.
func TestReassembleJunkStaysBounded(t *testing.T) {
	junk := bytes.Repeat([]byte{0xFF}, 2*h2ReasmBufLimit)
	delivered, _, rest := feed([][]byte{junk})
	if len(delivered) != 0 {
		t.Fatalf("junk should deliver nothing, got %d", len(delivered))
	}
	if len(rest) > h2ReasmBufLimit {
		t.Fatalf("buffer exceeded cap: %d > %d", len(rest), h2ReasmBufLimit)
	}
}
