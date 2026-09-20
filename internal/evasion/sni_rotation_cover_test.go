package evasion

import (
	"sync"
	"testing"
	"time"
)

// contains reports whether s is present in list.
func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// maxShareExceeds returns true if any key in counts holds more than a `limit`
// fraction of total. It reports the FORM of the distribution (rule 3): a single
// value dominating is exactly what a DPI observer would key on, so we assert on
// the shape rather than on which value came back.
func maxShareExceeds(counts map[string]int, total int, limit float64) (string, float64, bool) {
	worst := ""
	worstShare := 0.0
	for k, c := range counts {
		share := float64(c) / float64(total)
		if share > worstShare {
			worst, worstShare = k, share
		}
	}
	return worst, worstShare, worstShare > limit
}

func TestNewSNIRotatorMirrorsGlobalList(t *testing.T) {
	r := NewSNIRotator(StrategyRoundRobin)
	if len(r.pool) != len(WhitelistedSNIs) {
		t.Fatalf("pool size %d, want %d", len(r.pool), len(WhitelistedSNIs))
	}
	if len(r.weights) != len(WhitelistedSNIs) {
		t.Fatalf("weights size %d, want %d", len(r.weights), len(WhitelistedSNIs))
	}
	for i, entry := range WhitelistedSNIs {
		if r.pool[i] != entry.SNI {
			t.Fatalf("pool[%d]=%q, want %q", i, r.pool[i], entry.SNI)
		}
		if r.weights[i] != entry.Weight {
			t.Fatalf("weights[%d]=%d, want %d for %q", i, r.weights[i], entry.Weight, entry.SNI)
		}
	}
}

func TestRoundRobinCyclesInOrderAndWraps(t *testing.T) {
	pool := []string{"a", "b", "c"}
	r := NewSNIRotatorWithPool(pool, StrategyRoundRobin)

	// Two full cycles: exact order, then wrap to the start.
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i, w := range want {
		if got := r.Next(); got != w {
			t.Fatalf("call %d: got %q, want %q", i, got, w)
		}
	}
}

func TestRandomCoversPoolAndStaysUniform(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e"}
	r := NewSNIRotatorWithPool(pool, StrategyRandom)

	const draws = 20000
	counts := map[string]int{}
	for i := 0; i < draws; i++ {
		got := r.Next()
		if !contains(pool, got) {
			t.Fatalf("Next returned %q outside pool", got)
		}
		counts[got]++
	}

	// Every pool member must appear (coverage of the pool, not just one value).
	for _, s := range pool {
		if counts[s] == 0 {
			t.Fatalf("random rotation never returned %q in %d draws", s, draws)
		}
	}

	// FORM check (rule 3): uniform over 5 members => ~20% each. Allow a wide
	// band; the point is that no single value dominates.
	if worst, share, bad := maxShareExceeds(counts, draws, 0.30); bad {
		t.Fatalf("random rotation skewed: %q took %.1f%% (>30%%)", worst, share*100)
	}
}

// TestUniformityCheckerCatchesSkew is the positive control (rule 2) for the
// maxShareExceeds detector used above: fed a deliberately lopsided sample, the
// same checker must flag it. Without this, a passing uniformity assertion could
// just mean the detector is blind.
func TestUniformityCheckerCatchesSkew(t *testing.T) {
	skewed := map[string]int{"a": 9000, "b": 200, "c": 200, "d": 300, "e": 300}
	total := 10000
	if _, _, bad := maxShareExceeds(skewed, total, 0.30); !bad {
		t.Fatal("maxShareExceeds failed to flag a 90% single-value skew - detector is blind")
	}
}

func TestWeightedFavorsHeavyEntry(t *testing.T) {
	pool := []string{"heavy", "light1", "light2"}
	r := NewSNIRotatorWithPool(pool, StrategyWeighted)
	// NewSNIRotatorWithPool assigns weight 50 to all; make "heavy" dominant.
	r.weights = []int{900, 50, 50}

	const draws = 20000
	counts := map[string]int{}
	for i := 0; i < draws; i++ {
		got := r.Next()
		if !contains(pool, got) {
			t.Fatalf("weighted returned %q outside pool", got)
		}
		counts[got]++
	}

	// heavy has 900/1000 = 90% of weight. Expect a large majority. Positive
	// control: the direction of the skew is known and must appear.
	if share := float64(counts["heavy"]) / draws; share < 0.80 {
		t.Fatalf("weighted did not favor heavy entry: %.1f%% (<80%%)", share*100)
	}
	// The light entries must still occasionally appear (weight 50 each != 0).
	if counts["light1"] == 0 || counts["light2"] == 0 {
		t.Fatalf("weighted starved non-zero-weight entries: light1=%d light2=%d", counts["light1"], counts["light2"])
	}
}

func TestCooldownReturnsDistinctUntilExhausted(t *testing.T) {
	pool := []string{"a", "b", "c"}
	r := NewSNIRotatorWithPool(pool, StrategyCooldown)

	seen := map[string]bool{}
	for i := 0; i < len(pool); i++ {
		got := r.Next()
		if seen[got] {
			t.Fatalf("cooldown returned %q twice before pool exhausted", got)
		}
		seen[got] = true
	}
	if len(seen) != len(pool) {
		t.Fatalf("cooldown covered %d of %d SNIs before exhaustion", len(seen), len(pool))
	}
}

func TestCooldownAllowsReuseAfterExpiry(t *testing.T) {
	r := NewSNIRotatorWithPool([]string{"only.example"}, StrategyCooldown)
	r.cooldown = 20 * time.Millisecond

	first := r.Next()
	// Immediately: single-member pool, all in cooldown -> falls back to random,
	// which can only return the one member.
	if first != "only.example" {
		t.Fatalf("first pick %q, want only.example", first)
	}

	time.Sleep(40 * time.Millisecond)
	// After expiry the cooldown path (not the random fallback) should hand it back.
	if got := r.Next(); got != "only.example" {
		t.Fatalf("post-expiry pick %q, want only.example", got)
	}
}

func TestEmptyPoolFallback(t *testing.T) {
	for _, strat := range []RotationStrategy{
		StrategyRoundRobin, StrategyRandom, StrategyWeighted, StrategyCooldown,
	} {
		r := NewSNIRotatorWithPool(nil, strat)
		if got := r.Next(); got != "google.com" {
			t.Fatalf("strategy %d empty-pool fallback: got %q, want google.com", strat, got)
		}
	}
}

func TestGetBySNI(t *testing.T) {
	if e := GetBySNI("yandex.ru"); e == nil || e.Category != "russian" {
		t.Fatalf("GetBySNI(yandex.ru) = %+v, want russian entry", e)
	}
	if e := GetBySNI("nonexistent.invalid"); e != nil {
		t.Fatalf("GetBySNI for missing SNI = %+v, want nil", e)
	}
}

func TestGetByCategory(t *testing.T) {
	russian := GetByCategory("russian")
	if len(russian) == 0 {
		t.Fatal("GetByCategory(russian) returned nothing")
	}
	for _, e := range russian {
		if e.Category != "russian" {
			t.Fatalf("GetByCategory(russian) leaked %q from category %q", e.SNI, e.Category)
		}
	}
	if got := GetByCategory("no-such-category"); got != nil {
		t.Fatalf("GetByCategory(unknown) = %+v, want nil", got)
	}
}

func TestGetRussianSNIsIncludesBankingExcludesGoogle(t *testing.T) {
	got := GetRussianSNIs()
	if !contains(got, "yandex.ru") {
		t.Fatal("GetRussianSNIs missing yandex.ru (russian)")
	}
	if !contains(got, "tinkoff.ru") {
		t.Fatal("GetRussianSNIs missing tinkoff.ru (banking must be included)")
	}
	if contains(got, "google.com") {
		t.Fatal("GetRussianSNIs leaked google.com (not russian/banking)")
	}
}

// TestRotatorConcurrentAccess runs every strategy from many goroutines to catch
// data races under -race. It also asserts every returned value is a real pool
// member, so a torn read would surface as a bad value, not just a race report.
func TestRotatorConcurrentAccess(t *testing.T) {
	pool := []string{"a.example", "b.example", "c.example", "d.example"}
	for _, strat := range []RotationStrategy{
		StrategyRoundRobin, StrategyRandom, StrategyWeighted, StrategyCooldown,
	} {
		r := NewSNIRotatorWithPool(pool, strat)
		var wg sync.WaitGroup
		for g := 0; g < 16; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 500; i++ {
					got := r.Next()
					if !contains(pool, got) {
						t.Errorf("strategy %d returned %q outside pool", strat, got)
						return
					}
				}
			}()
		}
		wg.Wait()
	}
}
