package strategy

import (
	"net"
	"testing"
	"time"
)

// startEchoListener spins up a throwaway TCP listener so mockStrategy.Connect
// succeeds (the storm scenario is "connect always works, session dies fast").
func startEchoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// newStormTestManager builds a manager with two always-connecting strategies
// and a fast-clock storm detector.
func newStormTestManager(t *testing.T, clk *fakeClock) (*Manager, string) {
	t.Helper()
	addr := startEchoListener(t)

	m := NewManager()
	m.serverAddrV4 = addr
	m.stormDetector = newTestDetector(clk)
	m.Register(&mockStrategy{id: "reality", name: "REALITY", priority: 5, serverAddr: addr})
	m.Register(&mockStrategy{id: "http2_stego", name: "HTTP2 Stego", priority: 10, serverAddr: addr})
	return m, addr
}

// storm drives RecordSessionEnd enough times to park a strategy.
func storm(m *Manager, clk *fakeClock, id string) {
	for range 3 {
		m.RecordSessionStart(id)
		clk.Advance(6 * time.Second) // short-lived session
		m.RecordSessionEnd(id)
		clk.Advance(1 * time.Second)
	}
}

func TestManager_StormFailsOverToNextStrategy(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	// First connection picks the highest-priority strategy: reality.
	conn, strat, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("initial connect: %v", err)
	}
	conn.Close()
	if strat.ID() != "reality" {
		t.Fatalf("expected reality first, got %s", strat.ID())
	}

	// Simulate a storm on reality.
	storm(m, clk, "reality")
	if !m.stormDetector.IsParked("reality") {
		t.Fatal("reality should be parked after storm")
	}

	// Next connect must avoid reality and pick http2_stego.
	conn2, strat2, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("failover connect: %v", err)
	}
	conn2.Close()
	if strat2.ID() != "http2_stego" {
		t.Fatalf("expected failover to http2_stego, got %s", strat2.ID())
	}
}

func TestManager_StableSessionNoFailover(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	// A healthy long session must not park anything.
	m.RecordSessionStart("reality")
	clk.Advance(10 * time.Minute)
	if m.RecordSessionEnd("reality") {
		t.Fatal("healthy session declared a storm")
	}
	if m.stormDetector.IsParked("reality") {
		t.Fatal("reality parked after a healthy session")
	}

	conn, strat, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if strat.ID() != "reality" {
		t.Fatalf("expected reality to stay selected, got %s", strat.ID())
	}
}

func TestManager_CooldownRestoresStrategy(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	storm(m, clk, "reality")
	if !m.stormDetector.IsParked("reality") {
		t.Fatal("reality should be parked")
	}

	// Advance past the cooldown.
	clk.Advance(6 * time.Minute)
	if m.stormDetector.IsParked("reality") {
		t.Fatal("reality should be available after cooldown")
	}

	// reality is highest priority and should be picked again.
	conn, strat, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("post-cooldown connect: %v", err)
	}
	conn.Close()
	if strat.ID() != "reality" {
		t.Fatalf("expected reality after cooldown, got %s", strat.ID())
	}
}

func TestManager_AllParkedUnparksToAvoidOutage(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	storm(m, clk, "reality")
	storm(m, clk, "http2_stego")
	if !m.stormDetector.AnyParked() {
		t.Fatal("expected strategies parked")
	}

	// Both parked: the fallback must unpark and still return a connection.
	conn, _, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("expected connection via unpark fallback, got error: %v", err)
	}
	conn.Close()
	if m.stormDetector.AnyParked() {
		t.Fatal("fallback should have unparked all strategies")
	}
}

func TestManager_ForcedModeDoesNotPark(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	if err := m.ForceStrategy("reality"); err != nil {
		t.Fatalf("force: %v", err)
	}
	if !m.IsForced() {
		t.Fatal("manager should report forced")
	}

	// Storm reported, but RecordSessionEnd must still surface it (for logging)
	// while NOT removing reality from selection.
	m.RecordSessionStart("reality")
	clk.Advance(6 * time.Second)
	m.RecordSessionEnd("reality")
	m.RecordSessionStart("reality")
	clk.Advance(6 * time.Second)
	m.RecordSessionEnd("reality")
	m.RecordSessionStart("reality")
	clk.Advance(6 * time.Second)
	storming := m.RecordSessionEnd("reality")
	if !storming {
		t.Fatal("forced mode should still detect/report the storm")
	}

	// Even though parked in the detector, forced mode keeps using reality.
	conn, strat, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("forced connect: %v", err)
	}
	conn.Close()
	if strat.ID() != "reality" {
		t.Fatalf("forced mode must keep reality, got %s", strat.ID())
	}
}

func TestManager_StormClearsLastSuccessful(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	conn, _, err := m.Connect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()

	m.mu.RLock()
	last := m.lastSuccessfulStrategy
	m.mu.RUnlock()
	if last == nil || last.ID() != "reality" {
		t.Fatalf("expected lastSuccessful=reality, got %v", last)
	}

	storm(m, clk, "reality")

	m.mu.RLock()
	last = m.lastSuccessfulStrategy
	m.mu.RUnlock()
	if last != nil {
		t.Fatalf("storm should clear lastSuccessful when it is the storming strategy, got %v", last.ID())
	}
}

// TestManager_FastReconnectLoopGuard verifies that a strategy which keeps
// fast-reconnecting (connects fine, tunnel dies before the storm detector parks
// it) is eventually pushed off the fast path into a full scan.
func TestManager_FastReconnectLoopGuard(t *testing.T) {
	m := NewManager()
	const id = "http_polling"

	now := time.Unix(1_700_000_000, 0)
	// First fastReconnectLimit calls stay on the fast path.
	for i := range fastReconnectLimit {
		if m.shouldSkipFastReconnect(id, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("fast reconnect %d/%d should NOT be skipped yet", i+1, fastReconnectLimit)
		}
	}
	// The next one exceeds the limit and must force a full scan.
	if !m.shouldSkipFastReconnect(id, now.Add(time.Duration(fastReconnectLimit)*time.Second)) {
		t.Fatal("fast reconnect past the limit should be skipped")
	}

	// A different strategy restarts the count.
	if m.shouldSkipFastReconnect("reality", now.Add(time.Minute)) {
		t.Fatal("switching strategy must restart the fast-reconnect count")
	}

	// An expired window also restarts the count for the same strategy.
	for range fastReconnectLimit {
		m.shouldSkipFastReconnect(id, now.Add(2*time.Minute))
	}
	if m.shouldSkipFastReconnect(id, now.Add(2*time.Minute+fastReconnectWindow+time.Second)) {
		t.Fatal("a fast reconnect after the window expired must not be skipped")
	}
}

// TestManager_ReconnectSkipsParkedStrategy verifies ConnectForReconnect does NOT
// retry a parked lastSuccessful strategy (Phase 1) and instead reconnects via
// another strategy. This is the relay-mode source of the reconnect storm.
func TestManager_ReconnectSkipsParkedStrategy(t *testing.T) {
	clk := newFakeClock()
	m, _ := newStormTestManager(t, clk)
	ctx := t.Context()

	// Storm parks reality (and clears it as lastSuccessful). Re-pin reality as the
	// last successful strategy so Phase 1 of ConnectForReconnect would target it.
	storm(m, clk, "reality")
	if !m.stormDetector.IsParked("reality") {
		t.Fatal("reality should be parked after storm")
	}
	var reality Strategy
	for _, s := range m.strategies {
		if s.ID() == "reality" {
			reality = s
		}
	}
	m.mu.Lock()
	m.lastSuccessfulStrategy = reality
	m.mu.Unlock()

	conn, strat, err := m.ConnectForReconnect(ctx, m.serverAddrV4)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	conn.Close()
	if strat.ID() != "http2_stego" {
		t.Fatalf("reconnect must skip parked reality and pick http2_stego, got %s", strat.ID())
	}
}

// ensure the helper compiles against the real signature
var _ = func() time.Duration { return stormCooldown }
