package metrics

import (
	"sync"
	"testing"
	"time"
)

func TestRTTTrackerStats(t *testing.T) {
	r := NewRTTTracker()

	// Empty tracker: every accessor must be zero, not garbage from the sentinel
	// min/max seeds.
	if r.GetMean() != 0 || r.GetMin() != 0 || r.GetMax() != 0 || r.GetJitter() != 0 {
		t.Fatalf("empty tracker not zero: mean=%v min=%v max=%v jitter=%v",
			r.GetMean(), r.GetMin(), r.GetMax(), r.GetJitter())
	}

	r.Observe(10 * time.Millisecond)
	r.Observe(20 * time.Millisecond)

	if got := r.GetMean(); got != 15 {
		t.Fatalf("mean = %v ms, want 15", got)
	}
	if got := r.GetMin(); got != 10 {
		t.Fatalf("min = %v ms, want 10", got)
	}
	if got := r.GetMax(); got != 20 {
		t.Fatalf("max = %v ms, want 20", got)
	}
	// GetJitter documents that it returns variance, not stddev:
	// ((10-15)^2 + (20-15)^2) / 2 = 25.
	if got := r.GetJitter(); got != 25 {
		t.Fatalf("jitter(variance) = %v, want 25", got)
	}

	// The histogram behind the tracker must have seen both samples.
	if snap := r.GetHistogram().GetSnapshot(); snap.Count != 2 {
		t.Fatalf("histogram count = %d, want 2", snap.Count)
	}
}

// TestRTTTrackerConcurrent runs Observe from many goroutines; the min/max CAS
// loops and the count/sum atomics plus the recent-window mutex all get exercised
// under -race.
func TestRTTTrackerConcurrent(t *testing.T) {
	r := NewRTTTracker()

	const goroutines = 20
	const perG = 500
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				r.Observe(time.Duration(id+1) * time.Millisecond)
			}
		}(g)
	}
	wg.Wait()

	if snap := r.GetHistogram().GetSnapshot(); snap.Count != goroutines*perG {
		t.Fatalf("count = %d, want %d", snap.Count, goroutines*perG)
	}
	if got := r.GetMin(); got != 1 {
		t.Fatalf("min = %v, want 1ms", got)
	}
	if got := r.GetMax(); got != float64(goroutines) {
		t.Fatalf("max = %v, want %dms", got, goroutines)
	}
}

func TestBandwidthTracker(t *testing.T) {
	// Zero state.
	b := NewBandwidthTracker(time.Second)
	if b.GetCurrentBps() != 0 || b.GetPeakBps() != 0 || b.GetCurrentMbps() != 0 {
		t.Fatalf("fresh tracker not zero")
	}

	// A short window so a single Observe after a small sleep closes it and
	// computes a positive rate. Exact bps depends on wall-clock elapsed, so we
	// only assert the rate became positive and peak tracks current.
	b = NewBandwidthTracker(time.Millisecond)
	time.Sleep(3 * time.Millisecond)
	b.Observe(10000)

	cur := b.GetCurrentBps()
	if cur == 0 {
		t.Fatal("current bps stayed zero after window elapsed")
	}
	if b.GetPeakBps() != cur {
		t.Fatalf("peak %d != current %d after first window", b.GetPeakBps(), cur)
	}
	if mbps := b.GetCurrentMbps(); mbps != float64(cur)*8/1000000 {
		t.Fatalf("mbps conversion mismatch: %v vs %v", mbps, float64(cur)*8/1000000)
	}
}

func TestBandwidthTrackerAccumulatesWithinWindow(t *testing.T) {
	// A long window: Observe accumulates but must not publish a rate yet.
	b := NewBandwidthTracker(time.Hour)
	b.Observe(1234)
	if b.GetCurrentBps() != 0 {
		t.Fatalf("bps published before window elapsed: %d", b.GetCurrentBps())
	}
}

func TestPacketLossEstimator(t *testing.T) {
	var p PacketLossEstimator

	if p.GetLossRate() != 0 || p.GetLossPercent() != 0 {
		t.Fatalf("empty estimator not zero")
	}

	p.ObservePackets(100, 5)
	if got := p.GetLossRate(); got != 0.05 {
		t.Fatalf("loss rate = %v, want 0.05", got)
	}
	if got := p.GetLossPercent(); got != 5 {
		t.Fatalf("loss percent = %v, want 5", got)
	}
	p.ObserveRetransmit() // counted internally; no getter, just must not panic
}

func TestPacketLossEstimatorConcurrent(t *testing.T) {
	var p PacketLossEstimator

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				p.ObservePackets(10, 1)
				p.ObserveRetransmit()
			}
		}()
	}
	wg.Wait()

	if got := p.GetLossRate(); got != 0.1 {
		t.Fatalf("loss rate = %v, want 0.1", got)
	}
}
