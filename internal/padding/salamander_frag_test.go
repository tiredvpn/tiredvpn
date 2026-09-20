package padding

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// --- C1.3: a bad datagram must not kill the listener ---------------------

// TestSalamanderReadFromSurvivesGarbage is the regression guard for the defect
// that made one stray packet fatal to every live QUIC connection on the port.
//
// ReadFrom used to answer a failed tag check with fmt.Errorf, which is not a
// net.Error and therefore not temporary. quic-go's transport read loop treats
// such an error as terminal and tears the whole transport down, so a scan, a
// late datagram from a closed session or any unrelated traffic aimed at the UDP
// port took every session with it.
//
// The shape of the check matters: a test that only asserted "ReadFrom returns
// no error for garbage" would pass on an implementation that returned the
// garbage itself. This one requires the *next* datagram to arrive intact, which
// is the property that was actually lost.
func TestSalamanderReadFromSurvivesGarbage(t *testing.T) {
	mc := newChanPacketConn()
	defer mc.Close()

	padder := NewSalamanderPadder([]byte("listener-survives-secret"), Balanced)
	conn := NewSalamanderPacketConn(mc, padder)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	want := []byte("the datagram that must still arrive")
	good, err := padder.EncryptUDP(want)
	if err != nil {
		t.Fatal(err)
	}

	// Garbage first: random bytes, a runt, and a datagram from a foreign secret.
	junk := make([]byte, 600)
	rand.Read(junk)
	foreign := NewSalamanderPadder([]byte("a-secret-this-listener-never-saw"), Balanced)
	alien, err := foreign.EncryptUDP(make([]byte, 400))
	if err != nil {
		t.Fatal(err)
	}

	mc.inject(junk)
	mc.inject([]byte{0x01, 0x02, 0x03})
	mc.inject(alien)
	mc.inject(good)

	buf := make([]byte, 65536)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("three unreadable datagrams killed the listener: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("ReadFrom delivered %d bytes of something else, want the good datagram", n)
	}

	// And the conn is still usable afterwards, not merely alive for one read.
	again, err := padder.EncryptUDP(want)
	if err != nil {
		t.Fatal(err)
	}
	mc.inject(again)
	n, _, err = conn.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("second read after the garbage failed: n=%d err=%v", n, err)
	}
}

// TestMultiSecretReadFromSurvivesGarbage is the same guard for the multi-secret
// listener, which is the one that actually faces the public port.
func TestMultiSecretReadFromSurvivesGarbage(t *testing.T) {
	mc := newChanPacketConn()
	defer mc.Close()

	globalSecret := []byte("multi-listener-survives-secret")
	conn := NewMultiSecretSalamanderPacketConn(mc, globalSecret, Balanced, nil)
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	padder := NewSalamanderPadder(globalSecret, Balanced)
	want := []byte("the datagram that must still arrive")
	good, err := padder.EncryptUDP(want)
	if err != nil {
		t.Fatal(err)
	}

	junk := make([]byte, 900)
	rand.Read(junk)
	mc.inject(junk)
	mc.inject(good)

	buf := make([]byte, 65536)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("an unreadable datagram killed the multi-secret listener: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("ReadFrom delivered %d bytes of something else, want the good datagram", n)
	}
}

// TestReadFromPropagatesSocketErrors is the positive control for the two tests
// above: they would both pass on a ReadFrom that swallowed every error forever,
// including a closed socket, and that would hang the caller instead of
// returning. Errors from the underlying conn must still come out.
func TestReadFromPropagatesSocketErrors(t *testing.T) {
	mc := newChanPacketConn()
	padder := NewSalamanderPadder([]byte("socket-error-secret"), Balanced)
	conn := NewSalamanderPacketConn(mc, padder)

	mc.Close()
	if _, _, err := conn.ReadFrom(make([]byte, 2048)); err == nil {
		t.Fatal("ReadFrom on a closed underlying conn returned no error")
	}

	mc2 := newChanPacketConn()
	defer mc2.Close()
	conn2 := NewMultiSecretSalamanderPacketConn(mc2, []byte("g"), Balanced, nil)
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err := conn2.ReadFrom(make([]byte, 2048))
	var netErr net.Error
	if err == nil || !asNetError(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read deadline did not surface through the drop loop: %v", err)
	}
}

func asNetError(err error, target *net.Error) bool {
	if ne, ok := err.(net.Error); ok {
		*target = ne
		return true
	}
	return false
}

// --- C1.2: nothing goes out unpadded at its exact length -----------------

// TestNoDatagramExceedsCeilingOrLeaksLength sweeps the payload sizes that used
// to fall off the end of the bucket ladder. Every one of them travelled bare:
// paddingLen was clamped to 0 and the datagram went out at exactly
// len(payload)+8+udpHeaderLen, which is the payload length in plain sight.
//
// Both halves are asserted, because they fail independently: a fix that padded
// to some huge size would kill the first, and a fix that only clamped the size
// would kill the second.
func TestNoDatagramExceedsCeilingOrLeaksLength(t *testing.T) {
	padder := NewSalamanderPadder([]byte("no-bare-datagrams-secret"), Balanced)
	ceiling := padder.MaxDatagram()

	// A datagram is well-formed when it sits in the jitter band of some rung of
	// the ladder and under the ceiling. "Not exactly payload+18" is the wrong
	// test: at the top rung a full payload legitimately fills the ceiling and
	// lands on payload+18 with zero padding.
	inBand := func(size int) bool {
		if size > ceiling {
			return false
		}
		for _, rung := range padder.dgramBuckets {
			if size >= rung && size <= rung+paddingJitterWidth {
				return true
			}
		}
		return false
	}

	for _, payloadLen := range []int{1400, 1430, 1434, 1435, 1500, 2000, 4096, 9000, 20000, 65535} {
		payload := make([]byte, payloadLen)
		rand.Read(payload)

		datagrams, err := padder.EncryptUDPDatagrams(payload)
		if err != nil {
			t.Fatalf("payload %d: %v", payloadLen, err)
		}

		for i, d := range datagrams {
			if len(d) > ceiling {
				t.Errorf("payload %d: datagram %d is %d bytes, above the %d-byte ceiling - it will be IP-fragmented",
					payloadLen, i, len(d), ceiling)
				continue
			}
			if !inBand(len(d)) {
				t.Errorf("payload %d: datagram %d is %d bytes, in no rung's band of %v - it went out unpadded and its length is on the wire",
					payloadLen, i, len(d), padder.dgramBuckets)
			}
		}

		if payloadLen+udpHeaderLen+8 > ceiling && len(datagrams) < 2 {
			t.Errorf("payload %d does not fit one datagram but was emitted as %d datagram(s)",
				payloadLen, len(datagrams))
		}
	}
}

// TestOversizedPayloadRoundtripsThroughConn checks the split end to end: what
// WriteTo splits, ReadFrom must put back together byte for byte.
func TestOversizedPayloadRoundtripsThroughConn(t *testing.T) {
	for _, payloadLen := range []int{1435, 2000, 5000, 20000, 65535} {
		mc := newChanPacketConn()
		padder := NewSalamanderPadder([]byte("split-roundtrip-secret"), Balanced)
		conn := NewSalamanderPacketConn(mc, padder)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		payload := make([]byte, payloadLen)
		rand.Read(payload)

		if _, err := conn.WriteTo(payload, mc.LocalAddr()); err != nil {
			mc.Close()
			t.Fatalf("payload %d: WriteTo: %v", payloadLen, err)
		}

		buf := make([]byte, 65536)
		n, _, err := conn.ReadFrom(buf)
		mc.Close()
		if err != nil {
			t.Fatalf("payload %d: ReadFrom: %v", payloadLen, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Errorf("payload %d: came back as %d bytes and did not match", payloadLen, n)
		}
	}
}

// TestDecryptUDPRejectsFragmentAsWholePayload keeps the plain accessor honest:
// a chunk is not a payload, and handing one back would splice a fraction of the
// data into the caller as if it were complete.
func TestDecryptUDPRejectsFragmentAsWholePayload(t *testing.T) {
	padder := NewSalamanderPadder([]byte("fragment-not-payload-secret"), Balanced)

	datagrams, err := padder.EncryptUDPDatagrams(make([]byte, 4000))
	if err != nil {
		t.Fatal(err)
	}
	if len(datagrams) < 2 {
		t.Fatalf("4000 bytes produced %d datagram(s), expected a split", len(datagrams))
	}
	for i, d := range datagrams {
		if _, ok := padder.DecryptUDP(d); ok {
			t.Errorf("DecryptUDP accepted fragment %d as a whole payload", i)
		}
		frame, ok := padder.decryptUDPFrame(d)
		if !ok || !frame.frag {
			t.Errorf("fragment %d did not decode as a fragment (ok=%v frag=%v)", i, ok, frame.frag)
		}
	}
}

// --- C1.1: the size histogram is no longer a comb ------------------------

// TestDatagramSizesAreNotAComb is the distribution check. Quantising onto the
// bucket exactly made one payload length produce exactly one datagram length,
// so a flow's size histogram was four spikes - see paddingJitterWidth for what
// this does and does not claim to fix.
//
// Note what is NOT asserted here: the shape of the distribution. There is no
// measured donor distribution in this repository to compare against, so the
// test can only state that the alphabet stopped being a short list.
func TestDatagramSizesAreNotAComb(t *testing.T) {
	padder := NewSalamanderPadder([]byte("distribution-secret"), Balanced)

	// One payload length, many draws: under exact quantisation this set has
	// exactly one member.
	const draws = 500
	sizes := make(map[int]int, draws)
	for i := 0; i < draws; i++ {
		enc, err := padder.EncryptUDP(make([]byte, 100))
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(enc)]++
	}
	if len(sizes) < 40 {
		t.Errorf("payload 100 produced only %d distinct datagram sizes over %d draws; "+
			"the size is still effectively quantised", len(sizes), draws)
	}
	lo, hi := dgramBand(padder, 100)
	for size := range sizes {
		if size < lo || size > hi {
			t.Errorf("datagram of %d bytes outside the band [%d, %d]", size, lo, hi)
		}
	}

	// And across the whole range of payloads that fit one datagram, the
	// alphabet must be far wider than the ladder. Under exact quantisation this
	// was len(dgramBuckets).
	alphabet := make(map[int]struct{})
	for n := 1; n <= padder.MaxDatagram()-8-udpHeaderLen; n++ {
		enc, err := padder.EncryptUDP(make([]byte, n))
		if err != nil {
			t.Fatal(err)
		}
		alphabet[len(enc)] = struct{}{}
	}
	if len(alphabet) <= 4*len(padder.dgramBuckets) {
		t.Errorf("the whole payload range produced %d distinct datagram sizes over a %d-rung ladder; "+
			"that is still a comb", len(alphabet), len(padder.dgramBuckets))
	}
}

// TestStreamRecordsAboveTopBucketAreStillPadded covers the byte-stream path,
// where oversized records used to be emitted at exactly plaintext+8. There is
// no MTU on that path - the record travels inside a WebSocket frame over TCP -
// so the ladder repeats its top rung rather than giving up.
func TestStreamRecordsAboveTopBucketAreStillPadded(t *testing.T) {
	padder := NewSalamanderPadder([]byte("stream-padding-secret"), Balanced)

	for _, n := range []int{1400, 1500, 3000, 10240, 65535} {
		enc, err := padder.Encrypt(make([]byte, n))
		if err != nil {
			t.Fatalf("plaintext %d: %v", n, err)
		}
		if len(enc) == n+8 {
			t.Errorf("plaintext %d came out at exactly %d bytes - unpadded, the length is on the wire", n, len(enc))
		}
		if len(enc) < n+8 {
			t.Errorf("plaintext %d came out at %d bytes, shorter than the data it carries", n, len(enc))
		}
		// Still recoverable.
		got, err := padder.DecryptWithLength(enc, n)
		if err != nil || len(got) != n {
			t.Errorf("plaintext %d did not survive the round trip: %v", n, err)
		}
	}
}

// --- reassembler ---------------------------------------------------------

// TestFragReassemblerOutOfOrderAndDuplicate feeds the reassembler the two
// things UDP guarantees it will see: reordering and retransmission. A
// duplicate that were counted as progress would complete a group while a
// different chunk is still missing, and the payload would be assembled with a
// hole in it.
func TestFragReassemblerOutOfOrderAndDuplicate(t *testing.T) {
	r := newFragReassembler()
	const addr = "203.0.113.7:4433"

	chunks := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")}
	frame := func(i int) udpFrame {
		return udpFrame{data: chunks[i], frag: true, id: 42, index: i, count: len(chunks)}
	}

	if _, ok := r.add(addr, frame(2)); ok {
		t.Fatal("group completed on its last chunk arriving first")
	}
	if _, ok := r.add(addr, frame(2)); ok {
		t.Fatal("a duplicate chunk completed the group")
	}
	if _, ok := r.add(addr, frame(0)); ok {
		t.Fatal("group completed with chunk 1 still missing")
	}
	payload, ok := r.add(addr, frame(1))
	if !ok {
		t.Fatal("group never completed after every chunk arrived")
	}
	if want := "alphabravocharlie"; string(payload) != want {
		t.Fatalf("assembled %q, want %q", payload, want)
	}
	if len(r.pending) != 0 {
		t.Errorf("completed group left %d entries behind", len(r.pending))
	}
}

// TestFragReassemblerSeparatesAddresses checks that two peers using the same
// group id do not bleed into each other. The id is 32 random bits, so a
// collision across peers is rare but not impossible, and the consequence would
// be a silently corrupted payload.
func TestFragReassemblerSeparatesAddresses(t *testing.T) {
	r := newFragReassembler()
	a, b := "198.51.100.1:1000", "198.51.100.2:1000"

	mk := func(data string, i int) udpFrame {
		return udpFrame{data: []byte(data), frag: true, id: 7, index: i, count: 2}
	}

	if _, ok := r.add(a, mk("AA", 0)); ok {
		t.Fatal("peer A completed on one chunk")
	}
	if _, ok := r.add(b, mk("BB", 0)); ok {
		t.Fatal("peer B completed on one chunk")
	}
	pa, ok := r.add(a, mk("aa", 1))
	if !ok || string(pa) != "AAaa" {
		t.Fatalf("peer A assembled %q (ok=%v), want %q", pa, ok, "AAaa")
	}
	pb, ok := r.add(b, mk("bb", 1))
	if !ok || string(pb) != "BBbb" {
		t.Fatalf("peer B assembled %q (ok=%v), want %q", pb, ok, "BBbb")
	}
}

// TestFragReassemblerEvictsUnderPressure checks the memory bound. Incomplete
// groups are only created by datagrams that already passed the keyed tag, so
// this is about a peer behaving badly rather than an arbitrary sender, but an
// unbounded map is still an unbounded map.
func TestFragReassemblerEvictsUnderPressure(t *testing.T) {
	r := newFragReassembler()

	for i := 0; i < maxFragGroups*2; i++ {
		r.add("192.0.2.9:1234", udpFrame{
			data: []byte{byte(i)}, frag: true, id: uint32(i), index: 0, count: 4,
		})
	}
	if len(r.pending) > maxFragGroups {
		t.Fatalf("%d incomplete groups held, cap is %d", len(r.pending), maxFragGroups)
	}

	// drop() must clear a peer outright.
	r.drop("192.0.2.9:1234")
	if len(r.pending) != 0 {
		t.Fatalf("drop left %d groups for the address", len(r.pending))
	}
}
