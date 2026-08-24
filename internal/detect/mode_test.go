package detect

import "testing"

// prodHead is the head of a caught production flow, read off
// test-logs/detect-baseline/ours-reality-dubai.pcap (client port 52944) with
// tshark. Direction, TCP payload length and the first payload byte:
//
//	c2s 1752 0x16   outer ClientHello
//	c2s  323 0x65   continuation of the same record
//	s2c  387 0x16   outer ServerHello
//	c2s    1 0x08   our dispatch byte
//	c2s   13 0x17   data
//	c2s   33 0x17   data
//	s2c   14 0x17   data
//	c2s  530 0x17   the tunnelled ClientHello
//
// There is no 0x14 anywhere in this flow, in either direction - checked across
// all twelve caught flows, ten of which have none at all.
var prodHead = []WirePacket{
	{ToServer: true, PayloadLen: 1752, FirstByte: 0x16},
	{ToServer: true, PayloadLen: 323, FirstByte: 0x65},
	{ToServer: false, PayloadLen: 387, FirstByte: 0x16},
	{ToServer: true, PayloadLen: 1, FirstByte: 0x08},
	{ToServer: true, PayloadLen: 13, FirstByte: 0x17},
	{ToServer: true, PayloadLen: 33, FirstByte: 0x17},
	{ToServer: false, PayloadLen: 14, FirstByte: 0x17},
	{ToServer: true, PayloadLen: 530, FirstByte: 0x17},
	{ToServer: false, PayloadLen: 1400, FirstByte: 0x17},
	{ToServer: false, PayloadLen: 1433, FirstByte: 0x17},
	{ToServer: true, PayloadLen: 281, FirstByte: 0x17},
	{ToServer: false, PayloadLen: 588, FirstByte: 0x17},
}

// TestPlainModeCountsFromTheFirstPacket pins the finding that resolved the
// bytes[0]=530 question: on the plain path counting starts immediately, so the
// tunnelled ClientHello lands in a window and nothing is subtracted.
func TestPlainModeCountsFromTheFirstPacket(t *testing.T) {
	windows, started := Analyze(prodHead, ModePlain)
	if !started {
		t.Fatal("plain mode must always start counting")
	}
	if len(windows) == 0 {
		t.Fatal("no windows produced")
	}
	first := windows[0].Bytes()
	// 1752+323 outer hello, then the dispatch byte and data merge into the
	// same client burst, so the first burst is not 530 on its own. What matters
	// is that 530 appears as a counted client burst, unmodified.
	found := false
	for _, w := range windows {
		for _, b := range w.Bytes() {
			if b == 530 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("530 should survive into a window untouched; first window %v", first)
	}
}

// TestPlainModeDoesNotSubtractOverhead is the concrete trap: subtracting 24 per
// packet on this path changes every number the baseline reported.
func TestPlainModeDoesNotSubtractOverhead(t *testing.T) {
	plain, _ := Analyze(prodHead, ModePlain)
	viaHelper := Windows(Merge(BurstsFromPackets(toPackets(prodHead), true)))
	if len(plain) == 0 || len(viaHelper) == 0 {
		t.Fatal("expected windows from both")
	}
	if plain[0].Bytes() == viaHelper[0].Bytes() {
		t.Fatal("subtraction made no difference; the test is not testing anything")
	}
	t.Logf("plain %v vs wrongly-subtracted %v", plain[0].Bytes(), viaHelper[0].Bytes())
}

// TestTLSInTLSNeverStartsWithoutChangeCipherSpec reproduces the local stand:
// nDPI saw thirty flows, entered the heuristic on all thirty, and scored none,
// because our framing only ever writes 0x17.
func TestTLSInTLSNeverStartsWithoutChangeCipherSpec(t *testing.T) {
	windows, started := Analyze(prodHead, ModeTLSInTLS)
	if started {
		t.Errorf("counting must not start without a 0x14 in each direction, got %d windows", len(windows))
	}
	if len(windows) != 0 {
		t.Errorf("no windows expected, got %v", windows)
	}
}

// TestTLSInTLSExcludesOnTheDispatchByte records a second reason this path never
// scores our traffic, independent of the missing ChangeCipherSpec: nDPI drops
// the flow outright when a packet is shorter than the overhead it wants to
// subtract, and our one-byte dispatch is exactly that packet.
func TestTLSInTLSExcludesOnTheDispatchByte(t *testing.T) {
	withCCS := append([]WirePacket{
		{ToServer: true, PayloadLen: 6, FirstByte: 0x14},
		{ToServer: false, PayloadLen: 6, FirstByte: 0x14},
	}, prodHead...)

	windows, scored := Analyze(withCCS, ModeTLSInTLS)
	if scored || len(windows) != 0 {
		t.Errorf("the one-byte dispatch must exclude the flow, got %d windows", len(windows))
	}
}

// TestTLSInTLSScoresACleanFlow shows the path does work when nothing trips it:
// both directions send a ChangeCipherSpec and no packet is shorter than the
// overhead. This is the shape B1 will produce, which is why B1 is expected to
// switch this detector on rather than off.
func TestTLSInTLSScoresACleanFlow(t *testing.T) {
	flow := []WirePacket{
		{ToServer: true, PayloadLen: 6, FirstByte: 0x14},
		{ToServer: false, PayloadLen: 6, FirstByte: 0x14},
		{ToServer: true, PayloadLen: 554, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 1400, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 1481, FirstByte: 0x17},
		{ToServer: true, PayloadLen: 305, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 612, FirstByte: 0x17},
	}
	windows, scored := Analyze(flow, ModeTLSInTLS)
	if !scored || len(windows) == 0 {
		t.Fatal("a clean flow must be scored on this path")
	}
	// 554-24 = 530: the same tunnelled ClientHello the baseline saw, this time
	// net of the overhead, which is what makes the two paths comparable only
	// after the subtraction is accounted for.
	if got := windows[0].Bytes()[0]; got != 530 {
		t.Errorf("first burst %d, want 530 after subtracting the overhead", got)
	}
	t.Logf("scored window: %v", windows[0].Bytes())
}

// TestModeChangesTheVerdict is the reason this file exists: the same packets
// give different answers on the two paths, so a model that ignores the mode is
// guessing.
func TestModeChangesTheVerdict(t *testing.T) {
	_, plainStarted := Analyze(prodHead, ModePlain)
	_, tunnelStarted := Analyze(prodHead, ModeTLSInTLS)
	if plainStarted == tunnelStarted {
		t.Fatal("the two modes must not agree on this input")
	}
	t.Logf("plain started=%v, tls-in-tls started=%v", plainStarted, tunnelStarted)
}

func toPackets(w []WirePacket) []Packet {
	out := make([]Packet, 0, len(w))
	for _, p := range w {
		out = append(out, Packet{ToServer: p.ToServer, PayloadLen: p.PayloadLen})
	}
	return out
}
