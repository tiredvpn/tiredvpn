package strategy

import (
	"testing"
	"time"
)

// TestCircuitBreaker_HalfOpen_TimeBasedExit proves the time-based exit from
// half-open (S15): a probe window whose slots were spent but which never
// resolved must unblock once its timer elapses, instead of excluding the
// strategy until process restart or a network change.
//
// The clock is injected so the window boundary is exact, not slept for.
func TestCircuitBreaker_HalfOpen_TimeBasedExit(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	cfg.ResetTimeout = 10 * time.Second
	cfg.MaxResetTimeout = 10 * time.Second
	cfg.HalfOpenMax = 2
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	now := time.Unix(0, 0)
	cb.now = func() time.Time { return now }
	cb.lastStateChange = now

	// Open the circuit.
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatalf("expected Open, got %s", cb.State())
	}

	// Backoff window elapses: Open -> half-open by time.
	now = now.Add(cfg.ResetTimeout)
	if !cb.CanTry() {
		t.Fatal("CanTry should allow after the Open backoff window elapses")
	}

	// Spend both half-open slots WITHOUT recording an outcome - a stalled probe:
	// the slot is taken but the dial never completes or reports back. This is the
	// state that used to strand the strategy forever.
	if !cb.BeginHalfOpenAttempt() {
		t.Fatal("1st half-open attempt should be granted")
	}
	if !cb.BeginHalfOpenAttempt() {
		t.Fatal("2nd half-open attempt should be granted")
	}
	if cb.BeginHalfOpenAttempt() {
		t.Fatal("3rd attempt must be blocked: slots exhausted, window still fresh")
	}
	if cb.CanTry() {
		t.Fatal("CanTry must report blocked while slots are exhausted and the window is fresh")
	}

	// The half-open window elapses. The stalled half-open must unblock by time.
	now = now.Add(cfg.ResetTimeout)
	if !cb.CanTry() {
		t.Fatal("CanTry must allow again after the half-open window elapses (time-based exit)")
	}
	if !cb.BeginHalfOpenAttempt() {
		t.Fatal("BeginHalfOpenAttempt must renew the window and grant a slot after timeout")
	}
}

// TestCircuitBreaker_CanTry_DoesNotMutate proves CanTry is a pure check (S15):
// however many times it is called, it consumes no half-open slots. Only
// BeginHalfOpenAttempt occupies them.
func TestCircuitBreaker_CanTry_DoesNotMutate(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	cfg.ResetTimeout = 10 * time.Second
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	now := time.Unix(0, 0)
	cb.now = func() time.Time { return now }
	cb.lastStateChange = now

	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	now = now.Add(cfg.ResetTimeout) // Open -> half-open by time

	// Hammering CanTry must not burn a single recovery slot.
	for i := 0; i < 100; i++ {
		if !cb.CanTry() {
			t.Fatalf("CanTry should stay true at call %d - it must not consume slots", i)
		}
	}

	// The real attempts: exactly HalfOpenMax are granted, proving the 100 CanTry
	// calls consumed nothing.
	granted := 0
	for i := 0; i < cfg.HalfOpenMax+2; i++ {
		if cb.BeginHalfOpenAttempt() {
			granted++
		}
	}
	if granted != cfg.HalfOpenMax {
		t.Fatalf("expected exactly %d half-open slots granted after CanTry hammering, got %d", cfg.HalfOpenMax, granted)
	}
}

// TestManager_NonDialingChecksDoNotBurnHalfOpenSlots proves the S15 caller fix:
// candidate assembly and HasAvailableStrategies (both non-dialing) must use the
// pure CanTry, so repeatedly asking "what is available" never spends a
// strategy's half-open recovery attempts.
func TestManager_NonDialingChecksDoNotBurnHalfOpenSlots(t *testing.T) {
	m := NewManager()
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	cfg.ResetTimeout = 10 * time.Second
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	m.circuitBreakers = NewCircuitBreakerManager(cfg)

	s := &mockStrategy{id: "s1", priority: 1}
	m.Register(s)

	cb := m.circuitBreakers.Get(s.ID())
	now := time.Unix(0, 0)
	cb.now = func() time.Time { return now }
	cb.lastStateChange = now

	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	now = now.Add(cfg.ResetTimeout) // eligible for half-open by time

	// Five rounds of non-dialing availability checks (each calls CanTry through
	// HasAvailableStrategies and directly). None may spend a recovery slot.
	for i := 0; i < 5; i++ {
		if !m.HasAvailableStrategies() {
			t.Fatalf("HasAvailableStrategies should be true at round %d", i)
		}
		if !m.circuitBreakers.CanTry(s.ID()) {
			t.Fatalf("CanTry should be true at round %d", i)
		}
	}

	// The real dials: all HalfOpenMax recovery attempts must still be available.
	granted := 0
	for i := 0; i < cfg.HalfOpenMax+2; i++ {
		if m.circuitBreakers.BeginHalfOpenAttempt(s.ID()) {
			granted++
		}
	}
	if granted != cfg.HalfOpenMax {
		t.Fatalf("expected %d recovery slots after non-dialing checks, got %d", cfg.HalfOpenMax, granted)
	}
}
