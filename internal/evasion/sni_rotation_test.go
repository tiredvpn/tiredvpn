package evasion

import (
	"testing"
)

// TestSNIRotatorCooldownUsesCustomPool verifies that NextWithCooldown respects
// the custom pool passed to NewSNIRotatorWithPool.
//
// Bug: nextWithCooldown at sni_rotation.go:180 iterates global WhitelistedSNIs
// instead of r.pool. A rotator built with a single custom SNI will still return
// SNIs from the global list.
//
// This test FAILS on current code.
// After fix: nextWithCooldown iterates r.pool, test passes.
func TestSNIRotatorCooldownUsesCustomPool(t *testing.T) {
	customSNI := "my-custom-vpn-domain.internal"
	// This SNI is not in WhitelistedSNIs
	rotator := NewSNIRotatorWithPool([]string{customSNI}, StrategyCooldown)

	got := rotator.Next()
	if got != customSNI {
		t.Fatalf(
			"SNIRotator with StrategyCooldown ignored custom pool: got %q, want %q. "+
				"Bug: nextWithCooldown iterates global WhitelistedSNIs instead of r.pool",
			got, customSNI,
		)
	}
}

// TestNextWeightedZeroWeightPanic verifies that nextWeighted does not panic
// when all weights are 0 (totalWeight == 0), which would cause rand.Intn(0) to panic.
//
// This test FAILS on current code (panics in rand.Intn(0)).
// After fix: guard before rand.Intn returns a fallback SNI; test passes.
func TestNextWeightedZeroWeightPanic(t *testing.T) {
	rotator := NewSNIRotatorWithPool([]string{"a.example.com", "b.example.com"}, StrategyWeighted)
	// Override weights to 0 to trigger the bug
	for i := range rotator.weights {
		rotator.weights[i] = 0
	}

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = rotator.Next()
	}()

	if panicked {
		t.Fatal("nextWeighted panics when totalWeight==0 (rand.Intn(0)) - add guard before rand.Intn")
	}
}
