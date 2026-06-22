package strategy

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a controllable clock for deterministic storm tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestDetector(clk *fakeClock) *StormDetector {
	d := NewStormDetector(StormConfig{
		ShortSession: 20 * time.Second,
		MinSessions:  3,
		Window:       3 * time.Minute,
		Cooldown:     5 * time.Minute,
		Grace:        -1, // disable grace window: these tests exercise parking directly
	})
	d.now = clk.Now
	d.startedAt = clk.Now()
	return d
}

func TestStorm_ShortSessionStreakParks(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)

	const id = "reality"

	// Two short sessions: not yet a storm.
	if d.RecordSession(id, 6*time.Second) {
		t.Fatal("storm declared after 1 short session")
	}
	clk.Advance(7 * time.Second)
	if d.RecordSession(id, 6*time.Second) {
		t.Fatal("storm declared after 2 short sessions")
	}
	if d.IsParked(id) {
		t.Fatal("strategy parked before reaching MinSessions")
	}

	// Third short session crosses the threshold.
	clk.Advance(7 * time.Second)
	if !d.RecordSession(id, 6*time.Second) {
		t.Fatal("storm NOT declared after 3 consecutive short sessions")
	}
	if !d.IsParked(id) {
		t.Fatal("strategy not parked after storm declared")
	}
}

func TestStorm_StableSessionResetsStreak(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)
	const id = "reality"

	d.RecordSession(id, 5*time.Second)
	clk.Advance(6 * time.Second)
	d.RecordSession(id, 5*time.Second)

	// A long, healthy session clears the streak.
	clk.Advance(2 * time.Minute)
	if d.RecordSession(id, 10*time.Minute) {
		t.Fatal("healthy session should not declare storm")
	}

	// Now two more shorts should NOT park (streak was reset to 0).
	clk.Advance(6 * time.Second)
	d.RecordSession(id, 5*time.Second)
	clk.Advance(6 * time.Second)
	if d.RecordSession(id, 5*time.Second) {
		t.Fatal("storm declared with only 2 short sessions after reset")
	}
	if d.IsParked(id) {
		t.Fatal("parked despite stable session resetting the streak")
	}
}

func TestStorm_WindowExpiryResetsStreak(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)
	const id = "reality"

	d.RecordSession(id, 5*time.Second)
	clk.Advance(6 * time.Second)
	d.RecordSession(id, 5*time.Second)

	// Gap larger than the window: streak restarts at 1.
	clk.Advance(4 * time.Minute)
	if d.RecordSession(id, 5*time.Second) {
		t.Fatal("storm declared though window expired between shorts")
	}
	// One more short -> only 2 in the current streak, no park.
	clk.Advance(6 * time.Second)
	if d.RecordSession(id, 5*time.Second) {
		t.Fatal("storm declared with 2 shorts after window reset")
	}
}

func TestStorm_CooldownExpires(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)
	const id = "reality"

	for range 3 {
		d.RecordSession(id, 5*time.Second)
		clk.Advance(6 * time.Second)
	}
	if !d.IsParked(id) {
		t.Fatal("expected parked after storm")
	}

	// Within cooldown: still parked.
	clk.Advance(4 * time.Minute)
	if !d.IsParked(id) {
		t.Fatal("should still be parked within cooldown")
	}

	// After cooldown: available again.
	clk.Advance(2 * time.Minute)
	if d.IsParked(id) {
		t.Fatal("should be unparked after cooldown")
	}
}

func TestStorm_SessionOpenedClosed(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)
	const id = "reality"

	for i := range 3 {
		d.SessionOpened(id)
		clk.Advance(6 * time.Second) // session lives 6s -> short
		storming := d.SessionClosed(id)
		if i < 2 && storming {
			t.Fatalf("storm declared too early at session %d", i)
		}
		if i == 2 && !storming {
			t.Fatal("storm not declared on 3rd short session via Opened/Closed")
		}
		clk.Advance(1 * time.Second)
	}
}

func TestStorm_SessionClosedWithoutOpenIsNoop(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)
	if d.SessionClosed("ghost") {
		t.Fatal("SessionClosed without a matching open should be a no-op")
	}
	if d.IsParked("ghost") {
		t.Fatal("ghost strategy should not be parked")
	}
}

func TestStorm_PerStrategyIsolation(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)

	// reality storms, http2_stego stays healthy.
	for range 3 {
		d.RecordSession("reality", 5*time.Second)
		clk.Advance(6 * time.Second)
	}
	d.RecordSession("http2_stego", 10*time.Minute)

	if !d.IsParked("reality") {
		t.Fatal("reality should be parked")
	}
	if d.IsParked("http2_stego") {
		t.Fatal("http2_stego must not be parked by reality's storm")
	}
	if !d.AnyParked() {
		t.Fatal("AnyParked should be true")
	}
}

func TestStorm_ResetAndUnpark(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)
	const id = "reality"

	for range 3 {
		d.RecordSession(id, 5*time.Second)
		clk.Advance(6 * time.Second)
	}
	if !d.IsParked(id) {
		t.Fatal("expected parked")
	}

	d.Unpark(id)
	if d.IsParked(id) {
		t.Fatal("Unpark should clear parking")
	}

	// Park again, then Reset.
	for range 3 {
		d.RecordSession(id, 5*time.Second)
		clk.Advance(6 * time.Second)
	}
	d.Reset()
	if d.IsParked(id) {
		t.Fatal("Reset should clear parking")
	}
	if d.AnyParked() {
		t.Fatal("Reset should clear all parking")
	}
}

func TestStorm_ConcurrentAccess(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetector(clk)

	var wg sync.WaitGroup
	for i := range 8 {
		id := "s" + string(rune('0'+i))
		wg.Go(func() {
			for range 100 {
				d.SessionOpened(id)
				d.SessionClosed(id)
				d.IsParked(id)
				d.AnyParked()
				d.RecordSession(id, 5*time.Second)
			}
		})
	}
	wg.Wait()
}

// newTestDetectorWithGrace builds a detector with the grace window enabled and
// the fake clock wired through both `now` and the grace start time.
func newTestDetectorWithGrace(clk *fakeClock, grace time.Duration) *StormDetector {
	d := NewStormDetector(StormConfig{
		ShortSession: 20 * time.Second,
		MinSessions:  3,
		Window:       3 * time.Minute,
		Cooldown:     5 * time.Minute,
		Grace:        grace,
	})
	d.now = clk.Now
	d.startedAt = clk.Now()
	return d
}

// TestStorm_GraceWindowSuppressesStartupChurn verifies that short sessions
// inside the grace window never park a strategy, while the same pattern after
// the window does. This is the guard against startup turbulence (and post
// network-change churn) falsely parking the best strategy.
func TestStorm_GraceWindowSuppressesStartupChurn(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetectorWithGrace(clk, 30*time.Second)

	// Three short sessions inside the 30s grace window: must NOT park.
	for range 5 {
		if d.RecordSession("reality", 2*time.Second) {
			t.Fatal("parked during grace window — startup churn should be ignored")
		}
		clk.Advance(3 * time.Second) // stays within 30s for the first few
	}
	if d.IsParked("reality") {
		t.Fatal("reality parked during grace window")
	}

	// Move well past the grace window.
	clk.Advance(60 * time.Second)

	// Now the same short-session pattern must park after MinSessions.
	parked := false
	for range 3 {
		if d.RecordSession("reality", 2*time.Second) {
			parked = true
		}
		clk.Advance(1 * time.Second)
	}
	if !parked || !d.IsParked("reality") {
		t.Fatal("reality should park on sustained short sessions after grace window")
	}
}

// TestStorm_ResetRestartsGraceWindow verifies a network change (Reset) reopens
// the grace window so post-change churn is tolerated again.
func TestStorm_ResetRestartsGraceWindow(t *testing.T) {
	clk := newFakeClock()
	d := newTestDetectorWithGrace(clk, 30*time.Second)

	// Burn past the initial grace window with a healthy session.
	clk.Advance(60 * time.Second)
	d.RecordSession("reality", time.Minute) // healthy, resets streak

	// Network change.
	d.Reset()

	// Short sessions right after Reset are within the new grace window.
	for range 4 {
		if d.RecordSession("reality", 2*time.Second) {
			t.Fatal("parked during post-Reset grace window")
		}
		clk.Advance(2 * time.Second)
	}
	if d.IsParked("reality") {
		t.Fatal("reality parked during post-Reset grace window")
	}
}
