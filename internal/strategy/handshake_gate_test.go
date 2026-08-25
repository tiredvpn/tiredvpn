package strategy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHandshakeGateConcurrencyCap is the core guarantee: never more than
// maxConcurrent handshakes in flight to one SNI, whatever the caller does.
func TestHandshakeGateConcurrencyCap(t *testing.T) {
	const (
		callers = 16
		limit   = 2
	)
	g := newHandshakeGateWith(limit, 0, 0)

	var inFlight, peak int64
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.acquire(context.Background(), "github.com")
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			defer release()

			cur := atomic.AddInt64(&inFlight, 1)
			for {
				old := atomic.LoadInt64(&peak)
				if cur <= old || atomic.CompareAndSwapInt64(&peak, old, cur) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt64(&inFlight, -1)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&peak); got > limit {
		t.Fatalf("peak concurrent handshakes to one SNI = %d, want <= %d", got, limit)
	}
	if got := atomic.LoadInt64(&peak); got < 2 {
		t.Fatalf("peak = %d: gate serialised everything, the limit is not being used", got)
	}
}

// TestHandshakeGateEnforcesSpacing checks the half of the censor heuristic we
// actually break: consecutive handshake starts to one SNI must not land in the
// 20-50 ms band the per-SNI freeze keys on.
func TestHandshakeGateEnforcesSpacing(t *testing.T) {
	const (
		spacing = 30 * time.Millisecond
		starts  = 5
	)
	g := newHandshakeGateWith(2, spacing, 0)

	var mu sync.Mutex
	var at []time.Time

	var wg sync.WaitGroup
	for range starts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.acquire(context.Background(), "api.github.com")
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			mu.Lock()
			at = append(at, time.Now())
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	if len(at) != starts {
		t.Fatalf("recorded %d starts, want %d", len(at), starts)
	}
	for i := range at {
		for j := i + 1; j < len(at); j++ {
			if at[i].After(at[j]) {
				at[i], at[j] = at[j], at[i]
			}
		}
	}
	// Timer granularity makes the observed gap slightly noisy; allow 20% slack
	// so this does not flake on a loaded CI box.
	minGap := spacing - spacing/5
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < minGap {
			t.Fatalf("handshake starts %d and %d only %v apart, want >= %v", i-1, i, gap, minGap)
		}
	}
}

// TestHandshakeGatePerSNIIndependence verifies the throttle is per donor, not
// global: dialing a different donor must not queue behind an occupied one.
func TestHandshakeGatePerSNIIndependence(t *testing.T) {
	g := newHandshakeGateWith(1, time.Second, 0)

	first, err := g.acquire(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("acquire first: %v", err)
	}
	defer first()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	other, err := g.acquire(ctx, "raw.githubusercontent.com")
	if err != nil {
		t.Fatalf("second SNI blocked behind the first: %v", err)
	}
	other()
}

// TestHandshakeGateRespectsContext makes sure a queued dial dies with the
// request that asked for it instead of outliving its own deadline.
func TestHandshakeGateRespectsContext(t *testing.T) {
	g := newHandshakeGateWith(1, time.Hour, 0)

	held, err := g.acquire(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer held()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := g.acquire(ctx, "github.com"); err == nil {
		t.Fatal("acquire succeeded while the only slot was held")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("acquire ignored context cancellation for %v", elapsed)
	}
}

// TestHandshakeGateSpacingSurvivesCancel guards a subtle failure mode: a caller
// that gives up while waiting out its spacing must return its occupancy slot,
// otherwise the lane leaks capacity and eventually wedges.
func TestHandshakeGateSpacingSurvivesCancel(t *testing.T) {
	g := newHandshakeGateWith(1, 500*time.Millisecond, 0)

	first, err := g.acquire(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("acquire first: %v", err)
	}
	first()

	// Second caller has to wait out the spacing; cancel it mid-wait.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.acquire(ctx, "github.com"); err == nil {
		t.Fatal("acquire returned before its spacing elapsed")
	}

	// The slot must be free again.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	release, err := g.acquire(ctx2, "github.com")
	if err != nil {
		t.Fatalf("slot leaked after cancelled wait: %v", err)
	}
	release()
}

// TestHandshakeGateDefaultsOutsideCensorBand pins the production numbers: the
// spacing must sit well clear of the 20-50 ms inter-arrival band, and the
// concurrency cap must stay below the threshold of three.
func TestHandshakeGateDefaultsOutsideCensorBand(t *testing.T) {
	if maxConcurrentHandshakesPerSNI >= 3 {
		t.Fatalf("maxConcurrentHandshakesPerSNI = %d, must be < 3", maxConcurrentHandshakesPerSNI)
	}
	if minHandshakeSpacing <= 50*time.Millisecond {
		t.Fatalf("minHandshakeSpacing = %v, must exceed the 20-50ms band", minHandshakeSpacing)
	}

	g := newHandshakeGate()
	for range 8 {
		if s := g.spacing(); s < minHandshakeSpacing || s > minHandshakeSpacing+handshakeSpacingJitter {
			t.Fatalf("spacing() = %v, outside [%v, %v]", s, minHandshakeSpacing, minHandshakeSpacing+handshakeSpacingJitter)
		}
	}
}
