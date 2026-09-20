package strategy

import (
	"context"
	"testing"
	"time"
)

// TestManager_ProbeDoesNotFeedBreaker proves S16: a successful Probe (a bare TCP
// connect) must NOT drive the circuit breaker. A censor that keeps the port open
// while killing the handshake would otherwise let every probe "recover" a
// strategy the real Connect cannot use.
//
// The breaker is put in half-open with HalfOpenSuccessReq=1, so a single stray
// RecordSuccess would close it - the discriminator between the broken and fixed
// paths. The positive control at the end shows the same breaker DOES close when
// a real Connect success is recorded, so the test can actually see the effect it
// claims is absent (verification.md rule 2).
func TestManager_ProbeDoesNotFeedBreaker(t *testing.T) {
	m := NewManager()
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 1 // a single breaker success would close a half-open
	m.circuitBreakers = NewCircuitBreakerManager(cfg)

	s := &mockStrategy{id: "s1", priority: 1, probeErr: nil} // reachable: probe "succeeds"
	m.Register(s)

	cb := m.circuitBreakers.Get(s.ID())

	// Open, then nudge to half-open so a stray RecordSuccess would close it.
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	if !cb.AllowRecoveryProbe() {
		t.Fatal("expected to nudge the Open circuit into half-open")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected half-open before probing, got %s", cb.State())
	}

	// A successful probe must NOT touch the breaker.
	m.ProbeAll(context.Background(), "192.0.2.1:443")

	if got := cb.State(); got != CircuitHalfOpen {
		t.Fatalf("probe success must not change breaker state; want half-open, got %s", got)
	}

	// Positive control: a real Connect success DOES close the breaker.
	m.mu.Lock()
	m.updateConfidenceWithLatency(s.ID(), true, 5*time.Millisecond)
	m.mu.Unlock()
	if got := cb.State(); got != CircuitClosed {
		t.Fatalf("a real Connect success should close the breaker; want closed, got %s", got)
	}
}
