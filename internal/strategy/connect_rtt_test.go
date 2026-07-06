package strategy

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// echoMockServer starts a TCP echo server the mock strategies can dial so that
// connectWithRTT sees a real, usable net.Conn on the success paths.
func echoMockServer(t *testing.T) *mockServer {
	t.Helper()
	return newMockServer(t, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	})
}

// newTestManager builds a Manager tuned for fast, deterministic connect tests:
// no real network delays, storm grace disabled so parking can be driven
// directly, and a single retry unless the test overrides it.
func newTestManager() *Manager {
	m := NewManager()
	m.connectTimeout = 500 * time.Millisecond
	m.maxRetries = 2
	// Grace disabled: tests park strategies by feeding short sessions directly.
	m.stormDetector = NewStormDetector(StormConfig{Grace: -1})
	return m
}

// TestConnectWithRTT_FastReconnectSuccess covers the fast-reconnect happy path:
// a recent lastSuccessfulStrategy that still connects is reused without touching
// the full strategy list.
func TestConnectWithRTT_FastReconnectSuccess(t *testing.T) {
	srv := echoMockServer(t)
	defer srv.Close()

	m := newTestManager()
	s := &mockStrategy{id: "fast1", priority: 1, serverAddr: srv.Addr()}
	m.Register(s)

	m.mu.Lock()
	m.lastSuccessfulStrategy = s
	m.lastSuccessfulTime = time.Now()
	m.consecutiveTCPTimeouts = 7 // must be reset to 0 on fast-reconnect success
	m.mu.Unlock()

	conn, used, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err != nil {
		t.Fatalf("fast reconnect should succeed, got %v", err)
	}
	defer conn.Close()

	if used.ID() != "fast1" {
		t.Errorf("expected strategy fast1, got %s", used.ID())
	}
	m.mu.RLock()
	tcpTO := m.consecutiveTCPTimeouts
	m.mu.RUnlock()
	if tcpTO != 0 {
		t.Errorf("consecutiveTCPTimeouts should reset on success, got %d", tcpTO)
	}
}

// TestConnectWithRTT_FastReconnectFailFallthrough covers the case where the
// recent lastSuccessfulStrategy no longer connects: the code must fall through
// to the full strategy list and pick a working one.
func TestConnectWithRTT_FastReconnectFailFallthrough(t *testing.T) {
	srv := echoMockServer(t)
	defer srv.Close()

	m := newTestManager()
	dead := &mockStrategy{id: "dead", priority: 1, connectErr: errors.New("connection refused")}
	good := &mockStrategy{id: "good", priority: 2, serverAddr: srv.Addr()}
	m.Register(dead)
	m.Register(good)

	m.mu.Lock()
	m.lastSuccessfulStrategy = dead // fast path will fail on this
	m.lastSuccessfulTime = time.Now()
	m.mu.Unlock()

	conn, used, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err != nil {
		t.Fatalf("expected fallthrough to succeed, got %v", err)
	}
	defer conn.Close()

	if used.ID() != "good" {
		t.Errorf("expected fallthrough to strategy good, got %s", used.ID())
	}
}

// TestConnectWithRTT_StormParkedUnparkOnEmptyList covers the failover-convergence
// guarantee: when storm parking empties the candidate list, the detector is
// reset and the connect is retried with the full set rather than dead-ending.
func TestConnectWithRTT_StormParkedUnparkOnEmptyList(t *testing.T) {
	srv := echoMockServer(t)
	defer srv.Close()

	m := newTestManager()
	s := &mockStrategy{id: "parked", priority: 1, serverAddr: srv.Addr()}
	m.Register(s)

	// Park the only strategy: three short sessions with grace disabled.
	for i := 0; i < 3; i++ {
		m.stormDetector.RecordSession("parked", time.Second)
	}
	if !m.stormDetector.IsParked("parked") {
		t.Fatal("precondition: strategy should be parked")
	}

	conn, used, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err != nil {
		t.Fatalf("empty-list unpark should recover, got %v", err)
	}
	defer conn.Close()

	if used.ID() != "parked" {
		t.Errorf("expected recovery via strategy parked, got %s", used.ID())
	}
	if m.stormDetector.AnyParked() {
		t.Error("storm detector should have been reset (nothing parked)")
	}
}

// TestConnectWithRTT_AndroidQUICFastFallback covers the androidMode fast QUIC
// fallback: after the TCP-timeout threshold is crossed, the loop skips remaining
// TCP strategies and jumps straight to a QUIC strategy.
func TestConnectWithRTT_AndroidQUICFastFallback(t *testing.T) {
	srv := echoMockServer(t)
	defer srv.Close()

	m := newTestManager()
	m.maxRetries = 1 // one timeout per TCP strategy is enough to cross threshold
	m.androidMode = true
	m.tcpFailuresBeforeQUIC = 1

	tcp1 := &mockStrategy{id: "tcp1", priority: 1, connectErr: errors.New("i/o timeout")}
	tcp2 := &mockStrategy{id: "tcp2", priority: 2, connectErr: errors.New("i/o timeout")}
	quic1 := &mockStrategy{id: "quic_test", priority: 3, serverAddr: srv.Addr()}
	m.Register(tcp1)
	m.Register(tcp2)
	m.Register(quic1)

	conn, used, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err != nil {
		t.Fatalf("QUIC fast fallback should succeed, got %v", err)
	}
	defer conn.Close()

	if used.ID() != "quic_test" {
		t.Errorf("expected fallback to quic_test, got %s", used.ID())
	}
}

// TestConnectWithRTT_RetryExhaustionMovesToNext covers the retry-cycle: a failing
// strategy exhausts maxRetries, updates confidence downward, and the loop moves
// on to the next strategy that works.
func TestConnectWithRTT_RetryExhaustionMovesToNext(t *testing.T) {
	srv := echoMockServer(t)
	defer srv.Close()

	m := newTestManager() // maxRetries = 2
	bad := &mockStrategy{id: "bad", priority: 1, connectErr: errors.New("connection refused")}
	good := &mockStrategy{id: "good", priority: 2, serverAddr: srv.Addr()}
	m.Register(bad)
	m.Register(good)

	conn, used, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err != nil {
		t.Fatalf("expected next-strategy success, got %v", err)
	}
	defer conn.Close()

	if used.ID() != "good" {
		t.Errorf("expected strategy good, got %s", used.ID())
	}

	// attemptCount = maxRetries failed attempts on bad + 1 success on good.
	m.mu.RLock()
	attempts := m.lastConnectionAttempts
	m.mu.RUnlock()
	if attempts != m.maxRetries+1 {
		t.Errorf("expected %d attempts, got %d", m.maxRetries+1, attempts)
	}
}

// TestConnectWithRTT_AllFailTriggersEmergencyReprobe covers the total-outage
// path: every strategy fails, an error is returned, and an emergency reprobe is
// kicked off in the background.
func TestConnectWithRTT_AllFailTriggersEmergencyReprobe(t *testing.T) {
	m := newTestManager()
	bad := &mockStrategy{id: "bad", priority: 1, connectErr: errors.New("connection refused")}
	m.Register(bad)

	// Ensure the throttle window does not suppress the emergency reprobe.
	m.mu.Lock()
	m.lastEmergencyReprobe = time.Now().Add(-2 * time.Minute)
	m.mu.Unlock()

	conn, used, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err == nil {
		conn.Close()
		t.Fatal("expected error when all strategies fail")
	}
	if used != nil {
		t.Errorf("expected nil strategy on total failure, got %s", used.ID())
	}

	// TriggerEmergencyReprobe is launched via `go`, so poll for it to engage.
	running := false
	for i := 0; i < 100; i++ {
		m.mu.RLock()
		running = m.emergencyReprobeRunning
		m.mu.RUnlock()
		if running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !running {
		t.Error("expected emergency reprobe to be triggered on total failure")
	}
	m.StopEmergencyReprobe() // stop the background goroutine
}

// TestConnectWithRTT_ExhaustedStrategyCircuitBreakerBaseline verifies that the
// double/triple-counting bug (task zze) is fixed: one exhausted strategy is
// recorded in the circuit breaker exactly ONCE, regardless of maxRetries.
//
// Before the fix the breaker was recorded maxRetries+1 times (one RecordFailure
// per retry inside the retry loop, plus one more via updateConfidence(false) on
// exhaustion) - 3 records for a single logical failure with the default
// maxRetries=2. Now the retry loop no longer writes to the breaker and
// exhaustion records a single failure, while the confidence EMA is still updated
// on every attempt.
func TestConnectWithRTT_ExhaustedStrategyCircuitBreakerBaseline(t *testing.T) {
	m := newTestManager() // maxRetries = 2
	bad := &mockStrategy{id: "bad", priority: 1, connectErr: errors.New("connection refused")}
	m.Register(bad)

	m.mu.Lock()
	m.lastEmergencyReprobe = time.Now() // suppress the background reprobe goroutine
	m.mu.Unlock()

	_, _, err := m.connectWithRTT(context.Background(), "target:443", nil, false)
	if err == nil {
		t.Fatal("expected failure for the single failing strategy")
	}

	stats := m.circuitBreakers.Get("bad").Stats()

	// One logical strategy failure = one circuit-breaker record, independent of
	// the internal retry count (maxRetries=2 here).
	const baselineRecords = 1
	if stats.WindowSamples != baselineRecords {
		t.Errorf("circuit-breaker records per exhausted strategy = %d, expected %d "+
			"(retry count is %d; a single logical failure must count once)",
			stats.WindowSamples, baselineRecords, m.maxRetries)
	}
	if stats.ConsecutiveFail != baselineRecords {
		t.Errorf("consecutive failures = %d, expected %d",
			stats.ConsecutiveFail, baselineRecords)
	}

	// Confidence EMA must still reflect every failed attempt honestly: the
	// per-strategy result records one failure per exhausted strategy.
	m.mu.RLock()
	failureCount := m.results["bad"].FailureCount
	m.mu.RUnlock()
	if failureCount != 1 {
		t.Errorf("confidence stats FailureCount = %d, expected 1", failureCount)
	}

	t.Logf("one exhausted strategy => %d circuit-breaker record (maxRetries=%d): double-counting fixed",
		stats.WindowSamples, m.maxRetries)
}
