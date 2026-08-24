package detect

import (
	"math"
	"testing"
)

// window builds a Window from byte counts, one packet per burst, starting
// client-to-server. Packet counts only matter for the MaxFirstBurstPackets
// guard, which has its own test.
func window(b0, b1, b2, b3 uint32) Window {
	return Window{
		{ToServer: true, Bytes: b0, Pkts: 1},
		{ToServer: false, Bytes: b1, Pkts: 1},
		{ToServer: true, Bytes: b2, Pkts: 1},
		{ToServer: false, Bytes: b3, Pkts: 1},
	}
}

// TestBaselineDistances is the anchor of this package.
//
// These twelve flows and their distances were measured on 2026-08-24 with a
// patched nDPI 5.1.0 against a live capture of our own client; the numbers are
// in test-logs/detectability-baseline-2026-08-24.md, section 2.2. If this test
// fails, the model here no longer matches the detector it claims to reproduce,
// and every conclusion drawn from it is void.
func TestBaselineDistances(t *testing.T) {
	cases := []struct {
		port                    int
		bytes                   [4]uint32
		tls12, tls13, chromeDis float64
	}{
		{52944, [4]uint32{530, 4096, 267, 661}, 7.224, 0.815, 3.516},
		{35900, [4]uint32{530, 3767, 251, 78}, 6.502, 1.040, 3.584},
		{51984, [4]uint32{530, 3348, 200, 1242}, 9.191, 1.294, 3.658},
		{38964, [4]uint32{530, 3110, 247, 235}, 6.346, 1.477, 3.728},
		{47100, [4]uint32{530, 2833, 281, 588}, 7.307, 1.667, 3.795},
		{47106, [4]uint32{530, 2833, 281, 588}, 7.307, 1.667, 3.795},
		{47128, [4]uint32{530, 2834, 281, 557}, 7.232, 1.667, 3.795},
		{47914, [4]uint32{530, 2834, 281, 557}, 7.232, 1.667, 3.795},
		{47894, [4]uint32{530, 2833, 281, 601}, 7.340, 1.666, 3.795},
		{52974, [4]uint32{530, 2835, 270, 566}, 7.073, 1.667, 3.796},
		{47118, [4]uint32{530, 2835, 268, 566}, 7.041, 1.668, 3.797},
		{57372, [4]uint32{530, 2833, 281, 557}, 7.232, 1.668, 3.796},
	}

	const tolerance = 0.001

	for _, tc := range cases {
		w := window(tc.bytes[0], tc.bytes[1], tc.bytes[2], tc.bytes[3])
		got := Distances(w)

		for name, want := range map[string]float64{
			"tls12":  tc.tls12,
			"tls13":  tc.tls13,
			"chrome": tc.chromeDis,
		} {
			if diff := math.Abs(got[name] - want); diff > tolerance {
				t.Errorf("flow %d, model %s: distance %.4f, baseline %.3f (off by %.4f)",
					tc.port, name, got[name], want, diff)
			}
		}

		// Every one of the twelve was flagged, by the TLS 1.3 model.
		caught, by := Caught(w)
		if !caught {
			t.Errorf("flow %d: not caught, baseline says it was", tc.port)
		}
		if by != "tls13" {
			t.Errorf("flow %d: caught by %q, baseline says tls13", tc.port, by)
		}
	}
}

// TestThresholdsClearTheControlCapture guards the other half of the baseline.
//
// Live Chrome 150 produced no hits over 1057 flows; the closest any of them
// came was 3.038 to the TLS 1.3 centroid and 3.861 to the Chrome one. Those
// minima are the reason the thresholds can stay where they are, and the reason
// RequiredMargin is 0.9 rather than something just above zero: real browser
// traffic is already sitting 0.038 from the TLS 1.3 cutoff, so a censor can
// raise it substantially before paying in false positives.
//
// If someone edits a threshold upward, this test fails and says why.
func TestThresholdsClearTheControlCapture(t *testing.T) {
	const (
		controlMinTLS13  = 3.038
		controlMinChrome = 3.861
	)
	if modelTLS13.Threshold >= controlMinTLS13 {
		t.Errorf("tls13 threshold %.3f would have flagged the control capture (closest real flow %.3f)",
			modelTLS13.Threshold, controlMinTLS13)
	}
	if modelChrome.Threshold >= controlMinChrome {
		t.Errorf("chrome threshold %.3f would have flagged the control capture (closest real flow %.3f)",
			modelChrome.Threshold, controlMinChrome)
	}
	if RequiredMargin <= controlMinTLS13-modelTLS13.Threshold {
		t.Errorf("RequiredMargin %.2f is no better than where real browsers already sit (%.3f)",
			RequiredMargin, controlMinTLS13-modelTLS13.Threshold)
	}
}

// TestOutsideEveryClusterIsClear checks the negative path with a synthetic
// vector. It is not a captured flow and is not claimed to be one - it just
// sits far from all three centroids, which is where a countermeasure is
// supposed to put us.
func TestOutsideEveryClusterIsClear(t *testing.T) {
	w := window(900, 12000, 700, 1400)

	if caught, by := Caught(w); caught {
		t.Errorf("caught by %s, want clear: %v", by, Distances(w))
	}
	if m := Margin(w); m < RequiredMargin {
		t.Errorf("margin %.3f below RequiredMargin %.2f", m, RequiredMargin)
	}
}

func TestPacketCountGuard(t *testing.T) {
	// A vector the models would otherwise flag.
	w := window(530, 2833, 281, 588)
	if caught, _ := Caught(w); !caught {
		t.Fatal("fixture is not caught with one packet, test is meaningless")
	}

	w[0].Pkts = MaxFirstBurstPackets
	if caught, _ := Caught(w); !caught {
		t.Errorf("still within the packet guard at %d packets, want caught", MaxFirstBurstPackets)
	}

	w[0].Pkts = MaxFirstBurstPackets + 1
	if caught, by := Caught(w); caught {
		t.Errorf("caught by %s at %d packets, guard should have rejected it", by, w[0].Pkts)
	}
	if m := Margin(w); m != MarginClear {
		t.Errorf("margin %v past the packet guard, want MarginClear", m)
	}
}

func TestTLS13FirstBurstGuard(t *testing.T) {
	// Sits close to the TLS 1.3 centroid on the last three axes but has a
	// first burst below the guard, so that model must not fire.
	small := window(400, 4649, 448, 1094)
	if d := modelTLS13.Mahalanobis(small.Bytes()); d >= modelTLS13.Threshold {
		t.Fatalf("fixture is not inside the TLS 1.3 model (%.3f), test is meaningless", d)
	}
	if caught, by := Caught(small); caught && by == "tls13" {
		t.Error("TLS 1.3 model fired below MinFirstBurstBytesTLS13")
	}

	// The same shape at the guard boundary is fair game again.
	big := window(MinFirstBurstBytesTLS13, 4649, 448, 1094)
	if caught, by := Caught(big); !caught || by != "tls13" {
		t.Errorf("at the guard boundary: caught=%v by=%q, want tls13", caught, by)
	}
}

// TestVisionPaddingStillCaught is the result that decided the design of the
// countermeasure, kept here so it cannot quietly stop being true.
//
// XTLS Vision pads every record shorter than 900 bytes up to 900-1400
// (testseed {900, 500, 900, 256}, .ref/Xray-core/proxy/proxy.go:496-532).
// Applied to our measured flows it does not clear the detector: it walks the
// vector out of the Firefox cluster and into the Chrome one, which is why we
// do not copy it.
func TestVisionPaddingStillCaught(t *testing.T) {
	// [530, 4096, 267, 661] with short bursts pulled to ~968 and ~1030.
	padded := window(968, 4128, 1030, 960)

	caught, by := Caught(padded)
	if !caught {
		t.Fatal("Vision-style padding now clears the detector; " +
			"the countermeasure design in .claude/epics/reality-phase3 rests on it not doing so")
	}
	if by != "chrome" {
		t.Errorf("caught by %q, expected the chrome model - that migration is the whole point", by)
	}

	// And the direction of travel: further from TLS 1.3, closer to Chrome.
	before := Distances(window(530, 4096, 267, 661))
	after := Distances(padded)
	if after["tls13"] <= before["tls13"] {
		t.Errorf("tls13 distance %.3f -> %.3f, expected it to grow", before["tls13"], after["tls13"])
	}
	if after["chrome"] >= before["chrome"] {
		t.Errorf("chrome distance %.3f -> %.3f, expected it to shrink", before["chrome"], after["chrome"])
	}
}

// TestRoundTripSplitClears is the countermeasure: breaking the inner server
// flight with a short client-bound record and a client reply turns
// [530, 2833, 281, 588] into [530, ~80, ~50, 2833]. Every window must clear
// RequiredMargin, not just the first.
func TestRoundTripSplitClears(t *testing.T) {
	flights := [][3]uint32{
		{4096, 267, 661}, {3767, 251, 78}, {3348, 200, 1242},
		{3110, 247, 235}, {2833, 281, 588}, {2833, 281, 557},
	}

	for _, f := range flights {
		bursts := []Burst{
			{ToServer: true, Bytes: 530, Pkts: 1},
			{ToServer: false, Bytes: 80, Pkts: 1},  // nudge
			{ToServer: true, Bytes: 50, Pkts: 1},   // ack
			{ToServer: false, Bytes: f[0], Pkts: 3},
			{ToServer: true, Bytes: f[1], Pkts: 1},
			{ToServer: false, Bytes: f[2], Pkts: 1},
			{ToServer: true, Bytes: 300, Pkts: 1},
			{ToServer: false, Bytes: 1500, Pkts: 2},
		}

		w, margin, ok := Worst(bursts)
		if !ok {
			t.Fatalf("flight %v: no scoreable window", f)
		}
		if margin < RequiredMargin {
			t.Errorf("flight %v: worst margin %.3f below RequiredMargin %.2f, worst window %v",
				f, margin, RequiredMargin, w.Bytes())
		}
	}
}

func TestMergeCollapsesSameDirection(t *testing.T) {
	got := Merge([]Burst{
		{ToServer: true, Bytes: 100, Pkts: 1},
		{ToServer: true, Bytes: 200, Pkts: 2},
		{ToServer: false, Bytes: 300, Pkts: 1},
	})
	if len(got) != 2 {
		t.Fatalf("got %d bursts, want 2: %+v", len(got), got)
	}
	if got[0].Bytes != 300 || got[0].Pkts != 3 {
		t.Errorf("merged burst = %d bytes / %d pkts, want 300/3", got[0].Bytes, got[0].Pkts)
	}
}

func TestWindowsStartClientToServerOnly(t *testing.T) {
	bursts := []Burst{
		{ToServer: true, Bytes: 1}, {ToServer: false, Bytes: 2},
		{ToServer: true, Bytes: 3}, {ToServer: false, Bytes: 4},
		{ToServer: true, Bytes: 5}, {ToServer: false, Bytes: 6},
	}
	got := Windows(bursts)
	if len(got) != 2 {
		t.Fatalf("got %d windows, want 2", len(got))
	}
	for i, w := range got {
		if !w[0].ToServer {
			t.Errorf("window %d starts server-to-client", i)
		}
	}
	if b := got[0].Bytes(); b != [4]uint32{1, 2, 3, 4} {
		t.Errorf("first window %v, want [1 2 3 4]", b)
	}
	if b := got[1].Bytes(); b != [4]uint32{3, 4, 5, 6} {
		t.Errorf("second window %v, want [3 4 5 6]", b)
	}
}






func BenchmarkMahalanobis(b *testing.B) {
	w := window(530, 2833, 281, 588)
	bytes := w.Bytes()
	for b.Loop() {
		modelTLS13.Mahalanobis(bytes)
	}
}

func BenchmarkWorst(b *testing.B) {
	bursts := make([]Burst, 0, 64)
	for i := range 64 {
		bursts = append(bursts, Burst{ToServer: i%2 == 0, Bytes: uint32(500 + i*13), Pkts: 1})
	}
	b.ResetTimer()
	for b.Loop() {
		Worst(bursts)
	}
}
