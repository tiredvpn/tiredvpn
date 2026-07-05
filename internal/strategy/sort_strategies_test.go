package strategy

import "testing"

// orderedIDs returns the current strategy order as a slice of IDs.
func orderedIDs(m *Manager) []string {
	ids := make([]string, len(m.strategies))
	for i, s := range m.strategies {
		ids[i] = s.ID()
	}
	return ids
}

// setConfidence overrides the neutral confidence assigned at Register time so a
// test can pin an exact score = Priority() - Confidence*10.
func setConfidence(m *Manager, id string, conf float64) {
	m.results[id].Confidence = conf
}

func assertOrder(t *testing.T, m *Manager, want []string) {
	t.Helper()
	got := orderedIDs(m)
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order mismatch: got %v, want %v", got, want)
		}
	}
}

// TestSortStrategiesByPriority: with confidence pinned to 0, score == priority,
// so strategies sort ascending by priority (lower tried first) regardless of the
// order they were registered in.
func TestSortStrategiesByPriority(t *testing.T) {
	m := NewManager()
	m.Register(&mockStrategy{id: "high", priority: 20})
	m.Register(&mockStrategy{id: "low", priority: 5})
	m.Register(&mockStrategy{id: "mid", priority: 12})
	for _, id := range []string{"high", "low", "mid"} {
		setConfidence(m, id, 0)
	}

	m.sortStrategies()

	assertOrder(t, m, []string{"low", "mid", "high"})
}

// TestSortStrategiesConfidenceBonus: equal priority, but higher confidence lowers
// the score (Confidence*10 bonus subtracted), so the more-confident strategy wins
// the tie and sorts first.
func TestSortStrategiesConfidenceBonus(t *testing.T) {
	m := NewManager()
	m.Register(&mockStrategy{id: "cold", priority: 10}) // score 10 - 0*10 = 10
	m.Register(&mockStrategy{id: "warm", priority: 10}) // score 10 - 1*10 = 0
	setConfidence(m, "cold", 0.0)
	setConfidence(m, "warm", 1.0)

	m.sortStrategies()

	assertOrder(t, m, []string{"warm", "cold"})
}

// TestSortStrategiesStableOnEqualScore: the bubble sort swaps only on strict
// score1 > score2, so entries with identical scores keep their registration
// order (stable). Guards against a strict->non-strict comparison regression that
// would reorder equal-score strategies nondeterministically.
func TestSortStrategiesStableOnEqualScore(t *testing.T) {
	m := NewManager()
	ids := []string{"a", "b", "c", "d"}
	for _, id := range ids {
		m.Register(&mockStrategy{id: id, priority: 10})
		setConfidence(m, id, 0.5)
	}

	m.sortStrategies()

	assertOrder(t, m, ids)
}

// androidPenaltyCase brackets the QUIC strategy's effective score between two TCP
// anchors to pin the exact adaptive penalty applied at a given TCP-timeout count.
// QUIC base score is 4.9 (priority 5, confidence 0.01); the penalty shifts it to
// 4.9+penalty, which must land strictly between anchorLow and anchorHigh.
type androidPenaltyCase struct {
	name       string
	timeouts   int
	anchorLow  int // TCP priority just below quic effective score
	anchorHigh int // TCP priority just above quic effective score
}

// TestSortStrategiesAndroidPenalty verifies the adaptive UDP penalty at all three
// thresholds: 0 timeouts -> +10, 1 -> +5, 2+ -> 0. This is the branch behind the
// prod bug where QUIC sorted first on a -no-quic server because AndroidMode was
// not propagated. TCP anchors are never penalized (penalty applies to UDP only),
// so their scores stay at their priority and bracket the QUIC score.
func TestSortStrategiesAndroidPenalty(t *testing.T) {
	cases := []androidPenaltyCase{
		{name: "0 timeouts penalty 10", timeouts: 0, anchorLow: 14, anchorHigh: 15}, // 4.9+10 = 14.9
		{name: "1 timeout penalty 5", timeouts: 1, anchorLow: 9, anchorHigh: 10},    // 4.9+5  = 9.9
		{name: "2 timeouts penalty 0", timeouts: 2, anchorLow: 4, anchorHigh: 5},    // 4.9+0  = 4.9
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager()
			m.androidMode = true
			m.consecutiveTCPTimeouts = tc.timeouts

			m.Register(&mockStrategy{id: "quic_test", priority: 5})
			m.Register(&mockStrategy{id: "tcp_low", priority: tc.anchorLow})
			m.Register(&mockStrategy{id: "tcp_high", priority: tc.anchorHigh})
			setConfidence(m, "quic_test", 0.01) // score 5 - 0.1 = 4.9
			setConfidence(m, "tcp_low", 0)
			setConfidence(m, "tcp_high", 0)

			m.sortStrategies()

			assertOrder(t, m, []string{"tcp_low", "quic_test", "tcp_high"})
		})
	}
}

// TestSortStrategiesAndroidPenaltyClampsAtZero: with timeouts far past the
// threshold the reduction exceeds basePenalty, but the penalty is clamped to 0
// (never negative), so QUIC gets no bonus and simply sorts by its raw score.
func TestSortStrategiesAndroidPenaltyClampsAtZero(t *testing.T) {
	m := NewManager()
	m.androidMode = true
	m.consecutiveTCPTimeouts = 100 // reduction 500 >> basePenalty 10

	m.Register(&mockStrategy{id: "quic_test", priority: 5})
	m.Register(&mockStrategy{id: "tcp_low", priority: 4})
	m.Register(&mockStrategy{id: "tcp_high", priority: 6})
	setConfidence(m, "quic_test", 0.01) // score 4.9, penalty clamped to 0
	setConfidence(m, "tcp_low", 0)
	setConfidence(m, "tcp_high", 0)

	m.sortStrategies()

	assertOrder(t, m, []string{"tcp_low", "quic_test", "tcp_high"})
}

// TestSortStrategiesAndroidModeOffNoPenalty: the same QUIC strategy that gets
// pushed below both TCP anchors under androidMode+0 timeouts sorts strictly
// first when androidMode is off, confirming the penalty is gated on the flag.
func TestSortStrategiesAndroidModeOffNoPenalty(t *testing.T) {
	m := NewManager()
	m.androidMode = false
	m.consecutiveTCPTimeouts = 0

	m.Register(&mockStrategy{id: "quic_test", priority: 5})
	m.Register(&mockStrategy{id: "tcp_a", priority: 8})
	m.Register(&mockStrategy{id: "tcp_b", priority: 12})
	for _, id := range []string{"quic_test", "tcp_a", "tcp_b"} {
		setConfidence(m, id, 0)
	}

	m.sortStrategies()

	assertOrder(t, m, []string{"quic_test", "tcp_a", "tcp_b"})
}

// TestSortStrategiesSingleAndEmpty: bubble sort bounds must not panic or corrupt
// the slice for lists of length 1 or 0.
func TestSortStrategiesSingleAndEmpty(t *testing.T) {
	single := NewManager()
	single.Register(&mockStrategy{id: "only", priority: 7})
	single.sortStrategies()
	assertOrder(t, single, []string{"only"})

	empty := NewManager()
	empty.sortStrategies()
	if len(empty.strategies) != 0 {
		t.Fatalf("expected empty strategy list, got %v", orderedIDs(empty))
	}
}
