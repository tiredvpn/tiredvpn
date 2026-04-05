package strategy

import (
	"testing"
	"time"
)

func TestCircuitBreaker_BasicStates(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())

	if cb.State() != CircuitClosed {
		t.Errorf("initial state should be Closed, got %s", cb.State())
	}

	if !cb.Allow() {
		t.Error("should allow requests when closed")
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.MinSamples = 5
	cb := NewCircuitBreaker(cfg)

	// 5 failures on a stable network should open (all failures => 100% failure rate >= 70%)
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}

	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after %d failures on stable network, got %s", 5, cb.State())
	}
	if cb.Allow() {
		t.Error("should not allow requests when open")
	}
}

func TestCircuitBreaker_DoesNotOpenBelowThreshold(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cb := NewCircuitBreaker(cfg)

	// Only 4 failures - below threshold
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}

	if cb.State() != CircuitClosed {
		t.Errorf("should remain Closed after 4 failures (threshold=5), got %s", cb.State())
	}
}

func TestCircuitBreaker_SuccessResetsConsecutiveFail(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cb := NewCircuitBreaker(cfg)

	// 4 failures, then success, then 4 more failures
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	cb.RecordSuccess()
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}

	// Should not open because success reset consecutive count
	if cb.State() != CircuitClosed {
		t.Errorf("should remain Closed after success resets counter, got %s", cb.State())
	}
}

func TestCircuitBreaker_MinSamples(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 5
	cb := NewCircuitBreaker(cfg)

	// 3 failures reach the consecutive threshold, but only 3 samples < MinSamples=5
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	if cb.State() != CircuitClosed {
		t.Error("should remain Closed: only 3 samples, need MinSamples=5")
	}

	// Add 2 more failures: now 5 samples >= MinSamples, 5 consecutive >= 3 threshold, 100% fail rate >= 70%
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != CircuitOpen {
		t.Errorf("should open after reaching MinSamples with enough failures, got %s", cb.State())
	}
}

// --- Half-open graduated recovery ---

func TestCircuitBreaker_HalfOpen_GraduatedRecovery(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.ResetTimeout = 10 * time.Millisecond
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	// Open the circuit
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatalf("expected Open, got %s", cb.State())
	}

	// Wait for reset timeout
	time.Sleep(15 * time.Millisecond)

	// Should allow up to 3 test requests in half-open
	if !cb.Allow() {
		t.Error("should allow 1st test request in half-open")
	}
	if !cb.Allow() {
		t.Error("should allow 2nd test request in half-open")
	}
	if !cb.Allow() {
		t.Error("should allow 3rd test request in half-open")
	}
	// 4th should be blocked
	if cb.Allow() {
		t.Error("should block 4th request in half-open (max=3)")
	}
}

func TestCircuitBreaker_HalfOpen_SuccessCloses(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.ResetTimeout = 10 * time.Millisecond
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	// Open the circuit
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	time.Sleep(15 * time.Millisecond)

	cb.Allow() // first test request
	cb.RecordSuccess()
	// 1 success, need 2 - should still be half-open
	if cb.State() != CircuitHalfOpen {
		t.Errorf("should remain half-open after 1 success (need 2), got %s", cb.State())
	}

	cb.Allow() // second test request
	cb.RecordSuccess()
	// 2 successes >= HalfOpenSuccessReq=2 - should close
	if cb.State() != CircuitClosed {
		t.Errorf("should close after 2 successes in half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_HalfOpen_FailureStillAllowsRecovery(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.ResetTimeout = 10 * time.Millisecond
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	// Open the circuit
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	time.Sleep(15 * time.Millisecond)

	// Test request 1: failure
	cb.Allow()
	cb.RecordFailure()
	// 0 successes, 1 failure, 2 remaining - can still reach 2 successes
	if cb.State() == CircuitOpen {
		t.Error("should NOT re-open: recovery still possible (0/1, 2 remaining, need 2)")
	}

	// Test request 2: success
	cb.Allow()
	cb.RecordSuccess()
	// 1 success, 1 failure, 1 remaining - can still reach 2 successes
	if cb.State() == CircuitOpen {
		t.Error("should NOT re-open: recovery still possible")
	}

	// Test request 3: success
	cb.Allow()
	cb.RecordSuccess()
	// 2 successes >= 2 required
	if cb.State() != CircuitClosed {
		t.Errorf("should close: 2/3 successes meets threshold, got %s", cb.State())
	}
}

func TestCircuitBreaker_HalfOpen_TooManyFailuresReOpens(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.ResetTimeout = 10 * time.Millisecond
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	// Open the circuit
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	time.Sleep(15 * time.Millisecond)

	// Test request 1: failure
	cb.Allow()
	cb.RecordFailure()
	// 0 successes, 1 failure, 2 remaining - can still reach 2 successes

	// Test request 2: failure
	cb.Allow()
	cb.RecordFailure()
	// 0 successes, 2 failures, 1 remaining - CANNOT reach 2 successes => re-open

	if cb.State() != CircuitOpen {
		t.Errorf("should re-open: impossible to reach 2 successes with 1 remaining, got %s", cb.State())
	}
}

// --- Exponential backoff ---

func TestCircuitBreaker_ExponentialBackoff(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	cfg.ResetTimeout = 10 * time.Millisecond
	cfg.MaxResetTimeout = 100 * time.Millisecond
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	// First open: backoff = 10ms
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	stats := cb.Stats()
	if stats.CurrentResetTimeout != 10*time.Millisecond {
		t.Errorf("first open: expected backoff=10ms, got %v", stats.CurrentResetTimeout)
	}
	if stats.OpenCount != 1 {
		t.Errorf("expected open_count=1, got %d", stats.OpenCount)
	}

	// Transition to half-open
	time.Sleep(15 * time.Millisecond)
	cb.Allow()
	// Fail the half-open test to re-open
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure() // 0 successes, 2 failures, 1 remaining < 2 needed => re-open

	// Second open: backoff = 20ms
	stats = cb.Stats()
	if stats.CurrentResetTimeout != 20*time.Millisecond {
		t.Errorf("second open: expected backoff=20ms, got %v", stats.CurrentResetTimeout)
	}
	if stats.OpenCount != 2 {
		t.Errorf("expected open_count=2, got %d", stats.OpenCount)
	}
}

func TestCircuitBreaker_BackoffResetsOnRecovery(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	cfg.ResetTimeout = 10 * time.Millisecond
	cfg.MaxResetTimeout = 100 * time.Millisecond
	cfg.HalfOpenMax = 3
	cfg.HalfOpenSuccessReq = 2
	cb := NewCircuitBreaker(cfg)

	// Open twice for backoff to grow
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	time.Sleep(15 * time.Millisecond)
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure() // re-opens (openCount=2, backoff=20ms)

	// Now recover: wait for half-open, succeed
	time.Sleep(25 * time.Millisecond)
	cb.Allow()
	cb.RecordSuccess()
	cb.Allow()
	cb.RecordSuccess() // 2 successes -> close

	if cb.State() != CircuitClosed {
		t.Fatalf("expected Closed after recovery, got %s", cb.State())
	}

	// After successful recovery, backoff should be reset
	stats := cb.Stats()
	if stats.CurrentResetTimeout != cfg.ResetTimeout {
		t.Errorf("expected backoff reset to %v after recovery, got %v", cfg.ResetTimeout, stats.CurrentResetTimeout)
	}
	if stats.OpenCount != 0 {
		t.Errorf("expected open_count=0 after recovery, got %d", stats.OpenCount)
	}
}

// --- Sliding window ---

func TestCircuitBreaker_SlidingWindow_FailureRate(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.WindowSize = 10
	cfg.MinFailureRate = 0.7
	cfg.MinSamples = 5
	cb := NewCircuitBreaker(cfg)

	// Record 7 successes then 5 failures
	// Window: 7 success + 5 failure = 41.6% failure rate < 70% MinFailureRate
	for i := 0; i < 7; i++ {
		cb.RecordSuccess()
	}
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}

	// Despite 5 consecutive failures reaching threshold, failure rate is too low to open
	if cb.State() != CircuitClosed {
		t.Error("should remain Closed because window failure rate (41.6%) < MinFailureRate (70%)")
	}
}

func TestCircuitBreaker_SlidingWindow_HighFailureRate_Opens(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.WindowSize = 10
	cfg.MinFailureRate = 0.7
	cfg.MinSamples = 5
	cb := NewCircuitBreaker(cfg)

	// Record 1 success then 9 failures
	// Window: 1 success + 9 failures = 90% failure rate >= 70% MinFailureRate
	cb.RecordSuccess()
	for i := 0; i < 9; i++ {
		cb.RecordFailure()
	}

	if cb.State() != CircuitOpen {
		t.Errorf("should open with 90%% failure rate, got %s", cb.State())
	}
}

func TestCircuitBreaker_WindowExpiry(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.WindowDuration = 50 * time.Millisecond
	cfg.WindowSize = 20
	cfg.MinSamples = 5
	cb := NewCircuitBreaker(cfg)

	// Record old failures
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for them to expire from window
	time.Sleep(60 * time.Millisecond)

	// Record one new success (should trigger window trim)
	cb.RecordSuccess()

	// Window should now only have the recent success
	stats := cb.Stats()
	if stats.WindowFailureRate > 0.01 {
		t.Errorf("old failures should have expired, failure rate = %.2f", stats.WindowFailureRate)
	}
}

// --- Network stability / adaptive failure rate ---

func TestCircuitBreaker_UnstableNetwork_HigherFailRateThreshold(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.MinSamples = 5
	cfg.MinFailureRate = 0.7
	cfg.UnstableFailRate = 0.85
	cb := NewCircuitBreaker(cfg)

	// Simulate unstable network with high RTT variance
	unstableRTTs := []time.Duration{
		50 * time.Millisecond,
		200 * time.Millisecond,
		30 * time.Millisecond,
		300 * time.Millisecond,
		10 * time.Millisecond,
	}
	for _, rtt := range unstableRTTs {
		cb.RecordSuccessWithRTT(rtt)
	}

	if cb.IsNetworkStable() {
		t.Error("network should be detected as unstable with high RTT variance")
	}

	// Now record failures. With unstable network, need 85% failure rate.
	// Current window: 5 success + N failures. Need total failure rate >= 85%.
	// 5 successes + 30 failures = 85.7% >= 85% and we need 5 consecutive failures
	for i := 0; i < 30; i++ {
		cb.RecordFailure()
	}

	if cb.State() != CircuitOpen {
		t.Errorf("should eventually open on unstable network with enough failures, got %s", cb.State())
	}
}

func TestCircuitBreaker_StableNetwork_NormalThreshold(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.MinSamples = 5
	cfg.MinFailureRate = 0.7
	cfg.UnstableFailRate = 0.85
	cb := NewCircuitBreaker(cfg)

	// Simulate stable network: RTTs are consistent (~100ms +/- 5ms)
	stableRTTs := []time.Duration{
		100 * time.Millisecond,
		102 * time.Millisecond,
		98 * time.Millisecond,
		101 * time.Millisecond,
		99 * time.Millisecond,
	}
	for _, rtt := range stableRTTs {
		cb.RecordSuccessWithRTT(rtt)
	}

	if !cb.IsNetworkStable() {
		t.Error("network should be detected as stable with low RTT variance")
	}

	// On stable network, need only 70% failure rate. 5 successes + 12 failures = 70.5%
	for i := 0; i < 12; i++ {
		cb.RecordFailure()
	}

	if cb.State() != CircuitOpen {
		t.Errorf("should open on stable network with 70%% failure rate, got %s", cb.State())
	}
}

func TestCircuitBreaker_RTTVariance_TransitionsToUnstable(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())

	// Start with stable RTTs
	for i := 0; i < 5; i++ {
		cb.RecordSuccessWithRTT(100 * time.Millisecond)
	}
	if !cb.IsNetworkStable() {
		t.Error("should be stable with consistent RTTs")
	}

	// Inject unstable RTTs (WiFi roaming simulation)
	unstableRTTs := []time.Duration{
		10 * time.Millisecond,
		500 * time.Millisecond,
		20 * time.Millisecond,
		800 * time.Millisecond,
		5 * time.Millisecond,
		600 * time.Millisecond,
		15 * time.Millisecond,
		700 * time.Millisecond,
		8 * time.Millisecond,
		900 * time.Millisecond,
	}
	for _, rtt := range unstableRTTs {
		cb.RecordSuccessWithRTT(rtt)
	}

	if cb.IsNetworkStable() {
		t.Error("should be unstable after high-variance RTTs")
	}
}

func TestCircuitBreaker_RTTVariance_RecoverToStable(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.WindowSize = 5 // Small window for fast recovery
	cb := NewCircuitBreaker(cfg)

	// Inject unstable RTTs
	cb.RecordSuccessWithRTT(10 * time.Millisecond)
	cb.RecordSuccessWithRTT(500 * time.Millisecond)
	cb.RecordSuccessWithRTT(20 * time.Millisecond)
	cb.RecordSuccessWithRTT(400 * time.Millisecond)
	cb.RecordSuccessWithRTT(15 * time.Millisecond)

	if cb.IsNetworkStable() {
		t.Error("should be unstable")
	}

	// Now inject stable RTTs (they push out old samples since window=5)
	for i := 0; i < 5; i++ {
		cb.RecordSuccessWithRTT(100 * time.Millisecond)
	}

	if !cb.IsNetworkStable() {
		t.Error("should recover to stable after consistent RTTs replace old samples")
	}
}

// --- Network-down detection ---

func TestCircuitBreaker_NetworkDown(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 3
	cfg.MinSamples = 3
	mgr := NewCircuitBreakerManager(cfg)

	// Register 3 strategies with initial success
	mgr.RecordSuccess("s1")
	mgr.RecordSuccess("s2")
	mgr.RecordSuccess("s3")

	// All 3 fail within 10 seconds => network-down
	mgr.RecordFailure("s1")
	mgr.RecordFailure("s2")
	mgr.RecordFailure("s3")

	if !mgr.IsNetworkDown() {
		t.Error("should detect network-down when all strategies fail within 10s")
	}

	// Individual circuit should NOT open due to network-down suppression
	// Record more failures on s1 (would normally open)
	mgr.RecordFailure("s1")
	mgr.RecordFailure("s1")

	cb := mgr.Get("s1")
	if cb.State() == CircuitOpen {
		t.Error("circuit should NOT open when network-down is set")
	}

	// Recovery: any success clears network-down
	mgr.RecordSuccess("s1")
	if mgr.IsNetworkDown() {
		t.Error("network-down should be cleared after a success")
	}
}

func TestCircuitBreaker_NetworkDown_PartialFailure(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	mgr := NewCircuitBreakerManager(cfg)

	// Register 2 strategies
	mgr.RecordSuccess("s1")
	mgr.RecordSuccess("s2")

	// Only s1 fails - should NOT trigger network-down
	mgr.RecordFailure("s1")

	if mgr.IsNetworkDown() {
		t.Error("should NOT detect network-down when only one strategy fails")
	}
}

// --- Timeout and Reset ---

func TestCircuitBreaker_TimeoutOpensCircuit(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.FailureThreshold = 5
	cfg.MinSamples = 5
	cb := NewCircuitBreaker(cfg)

	for i := 0; i < 5; i++ {
		cb.RecordTimeout()
	}

	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after 5 timeouts, got %s", cb.State())
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())

	// Open the circuit
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatalf("expected Open, got %s", cb.State())
	}

	cb.Reset()

	if cb.State() != CircuitClosed {
		t.Errorf("should be Closed after Reset, got %s", cb.State())
	}
	if !cb.Allow() {
		t.Error("should allow after Reset")
	}
	stats := cb.Stats()
	if stats.OpenCount != 0 {
		t.Errorf("open count should be 0 after reset, got %d", stats.OpenCount)
	}
	if stats.CurrentResetTimeout != DefaultCircuitBreakerConfig().ResetTimeout {
		t.Errorf("backoff should be reset to default")
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())

	cb.RecordSuccessWithRTT(100 * time.Millisecond)
	cb.RecordFailure()

	stats := cb.Stats()
	if stats.State != CircuitClosed {
		t.Errorf("state should be Closed, got %s", stats.State)
	}
	if stats.ConsecutiveFail != 1 {
		t.Errorf("consecutive fail should be 1, got %d", stats.ConsecutiveFail)
	}
	if stats.EffectiveThreshold != 5 {
		t.Errorf("effective threshold should be 5, got %d", stats.EffectiveThreshold)
	}
	if stats.RTTMean == 0 {
		t.Error("RTT mean should be non-zero after recording RTT")
	}
}

// --- CircuitBreakerManager tests ---

func TestCircuitBreakerManager_Get(t *testing.T) {
	mgr := NewCircuitBreakerManager(DefaultCircuitBreakerConfig())

	cb1 := mgr.Get("strategy1")
	cb2 := mgr.Get("strategy1")

	if cb1 != cb2 {
		t.Error("Get should return same instance for same ID")
	}

	cb3 := mgr.Get("strategy2")
	if cb1 == cb3 {
		t.Error("Get should return different instance for different IDs")
	}
}

func TestCircuitBreakerManager_Allow(t *testing.T) {
	mgr := NewCircuitBreakerManager(DefaultCircuitBreakerConfig())

	if !mgr.Allow("test") {
		t.Error("new strategy should be allowed")
	}

	// Open the circuit: 5 failures (default threshold)
	for i := 0; i < 5; i++ {
		mgr.RecordFailure("test")
	}

	if mgr.Allow("test") {
		t.Error("should not allow after circuit opens")
	}
}

func TestCircuitBreakerManager_RecordSuccessWithRTT(t *testing.T) {
	mgr := NewCircuitBreakerManager(DefaultCircuitBreakerConfig())

	mgr.RecordSuccessWithRTT("test", 50*time.Millisecond)
	mgr.RecordSuccessWithRTT("test", 150*time.Millisecond)

	stats := mgr.GetAllStats()
	if s, ok := stats["test"]; ok {
		if s.RTTMean == 0 {
			t.Error("RTT mean should be tracked via manager")
		}
	} else {
		t.Error("stats should contain 'test' strategy")
	}
}

func TestCircuitBreakerManager_GetAvailableStrategies(t *testing.T) {
	mgr := NewCircuitBreakerManager(DefaultCircuitBreakerConfig())

	mgr.RecordSuccess("s1")
	mgr.RecordSuccess("s2")

	// Open s2
	for i := 0; i < 5; i++ {
		mgr.RecordFailure("s2")
	}

	available := mgr.GetAvailableStrategies()
	found := false
	for _, id := range available {
		if id == "s1" {
			found = true
		}
		if id == "s2" {
			t.Error("s2 should not be available (circuit open)")
		}
	}
	if !found {
		t.Error("s1 should be available")
	}
}

// --- Benchmark ---

func BenchmarkCircuitBreaker_RecordFailure(b *testing.B) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	for i := 0; i < b.N; i++ {
		cb.RecordFailure()
		if i%10 == 0 {
			cb.RecordSuccess() // Prevent permanent open
		}
	}
}

func BenchmarkCircuitBreaker_RecordSuccessWithRTT(b *testing.B) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	for i := 0; i < b.N; i++ {
		cb.RecordSuccessWithRTT(time.Duration(50+i%100) * time.Millisecond)
	}
}

func BenchmarkCircuitBreaker_ShouldOpen(b *testing.B) {
	cfg := DefaultCircuitBreakerConfig()
	cfg.WindowSize = 100
	cb := NewCircuitBreaker(cfg)
	// Fill window
	for i := 0; i < 50; i++ {
		cb.RecordSuccessWithRTT(time.Duration(50+i%200) * time.Millisecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.RecordFailure()
		cb.RecordSuccess() // Reset to prevent open
	}
}
