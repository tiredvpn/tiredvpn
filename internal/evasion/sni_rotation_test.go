package evasion

import (
	"testing"
)

// TestSNIRotatorCooldownUsesCustomPool guards nextWithCooldown against
// iterating the global WhitelistedSNIs instead of r.pool, which it used to do:
// a rotator built by NewSNIRotatorWithPool with a narrowed pool would hand back
// a donor from the global list the moment the cooldown path was taken, and a
// caller that had deliberately restricted its SNIs would never find out.
//
// The bug is fixed; this is the regression guard. Verified by reintroducing the
// global-list iteration, on which it reports "got yandex.ru".
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

// TestNextWeightedZeroWeightPanic guards the totalWeight == 0 case, where
// nextWeighted would reach rand.Intn(0) and panic. The guard that returns a
// fallback SNI is in place; this keeps it there.
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
