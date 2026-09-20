package strategy

import (
	"context"
	"testing"
	"time"
)

// gateFixture wires a manager whose full scan has one always-succeeding strategy
// ("scanok"), and a separate fast-reconnect candidate that is NOT registered, so
// any Connect on it can only have come from the fast path.
func gateFixture(t *testing.T) (*Manager, *countingStrategy, *countingStrategy) {
	t.Helper()
	m := NewManager()
	t.Cleanup(m.Close)

	scanok := &countingStrategy{id: "scanok", prio: 1}
	m.Register(scanok)

	fast := &countingStrategy{id: "fast", prio: 1}
	m.mu.Lock()
	m.lastSuccessfulStrategy = fast
	m.lastSuccessfulTime = time.Now()
	m.mu.Unlock()

	return m, fast, scanok
}

func TestFastReconnectSkipsExcluded(t *testing.T) {
	m, fast, scanok := gateFixture(t)

	conn, s, err := m.connectWithRTTScan(context.Background(), "srv:443", []string{"fast"}, false, &scanState{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if fast.count() != 0 {
		t.Errorf("fast path dialled an EXCLUDED strategy %d time(s)", fast.count())
	}
	if s.ID() != "scanok" || scanok.count() == 0 {
		t.Errorf("scan did not fall through to scanok (got %s)", s.ID())
	}
}

func TestFastReconnectSkipsUDPWhenBlocked(t *testing.T) {
	m, _, scanok := gateFixture(t)
	// Make the fast candidate UDP and block UDP.
	udpFast := &countingStrategy{id: "quic-fast", prio: 1}
	m.mu.Lock()
	m.lastSuccessfulStrategy = udpFast
	m.lastSuccessfulTime = time.Now()
	m.excludeUDPStrategies = true
	m.mu.Unlock()

	conn, s, err := m.connectWithRTTScan(context.Background(), "srv:443", nil, false, &scanState{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if udpFast.count() != 0 {
		t.Errorf("fast path dialled a UDP strategy while UDP was blocked (%d calls)", udpFast.count())
	}
	if s.ID() != "scanok" || scanok.count() == 0 {
		t.Errorf("scan did not fall through to scanok (got %s)", s.ID())
	}
}

func TestFastReconnectSkipsOpenBreaker(t *testing.T) {
	m, fast, scanok := gateFixture(t)

	// Drive the fast candidate's breaker open.
	for i := 0; i < 50 && m.circuitBreakers.CanTry("fast"); i++ {
		m.circuitBreakers.RecordFailure("fast")
	}
	if m.circuitBreakers.CanTry("fast") {
		t.Fatal("could not open the breaker for the fast candidate")
	}

	conn, s, err := m.connectWithRTTScan(context.Background(), "srv:443", nil, false, &scanState{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if fast.count() != 0 {
		t.Errorf("fast path dialled through an OPEN breaker (%d calls)", fast.count())
	}
	if s.ID() != "scanok" || scanok.count() == 0 {
		t.Errorf("scan did not fall through to scanok (got %s)", s.ID())
	}
}

// TestFastReconnectSucceedsWhenEligible is the positive control: with no gate
// tripped, the fast path IS taken and the scan strategy is never reached.
func TestFastReconnectSucceedsWhenEligible(t *testing.T) {
	m, fast, scanok := gateFixture(t)

	conn, s, err := m.connectWithRTTScan(context.Background(), "srv:443", nil, false, &scanState{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if s != Strategy(fast) {
		t.Errorf("expected fast path to win, got %s", s.ID())
	}
	if fast.count() != 1 {
		t.Errorf("fast candidate dialled %d times, want 1", fast.count())
	}
	if scanok.count() != 0 {
		t.Errorf("scan ran despite a good fast reconnect (%d calls)", scanok.count())
	}
}

// TestFastReconnectFailureFeedsBreaker guards "отказы писать корректно": a fast
// reconnect that fails must record a breaker failure, not loop invisibly. The
// fast candidate is unregistered, so a recorded failure can only come from the
// fast path (the scan never sees it).
//
// Predicated against the broken code: drop the RecordFailure/RecordTimeout block
// on the fast path and ConsecutiveFail stays 0.
func TestFastReconnectFailureFeedsBreaker(t *testing.T) {
	m, _, scanok := gateFixture(t)
	failFast := &countingStrategy{id: "failfast", prio: 1, fail: true}
	m.mu.Lock()
	m.lastSuccessfulStrategy = failFast
	m.lastSuccessfulTime = time.Now()
	m.mu.Unlock()

	conn, s, err := m.connectWithRTTScan(context.Background(), "srv:443", nil, false, &scanState{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()

	if failFast.count() != 1 {
		t.Fatalf("fast candidate dialled %d times, want 1", failFast.count())
	}
	if s.ID() != "scanok" {
		t.Fatalf("scan did not fall through to scanok (got %s)", s.ID())
	}
	if got := m.circuitBreakers.Get("failfast").Stats().ConsecutiveFail; got == 0 {
		t.Error("fast reconnect failure was not recorded in the breaker")
	}
	_ = scanok
}

// TestRTTMaskingSinglePass guards the removal of the second full scan. RTT
// masking only wraps an already-successful conn, so with masking on and every
// strategy failing, each strategy must be dialled exactly maxRetries times (one
// pass), not twice.
//
// Predicated against the broken code: restore the two-pass ConnectExcluding and
// each strategy is dialled 2*maxRetries times.
func TestRTTMaskingSinglePass(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Close)
	m.maxRetries = 1
	m.mu.Lock()
	m.rttMaskingEnabled = true
	m.rttProfile = MoscowToYandexProfile
	m.mu.Unlock()

	a := &countingStrategy{id: "a", prio: 1, fail: true}
	b := &countingStrategy{id: "b", prio: 2, fail: true}
	m.Register(a)
	m.Register(b)

	conn, _, err := m.ConnectExcluding(context.Background(), "srv:443", nil)
	if err == nil {
		conn.Close()
		t.Fatal("expected all strategies to fail")
	}
	if a.count() != 1 || b.count() != 1 {
		t.Errorf("strategies dialled a=%d b=%d, want 1 each (single pass)", a.count(), b.count())
	}
}
