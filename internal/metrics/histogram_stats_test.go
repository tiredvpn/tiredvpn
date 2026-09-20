package metrics

import (
	"math"
	"sync"
	"testing"
)

func TestNewHistogramDefaultsAndSort(t *testing.T) {
	// Empty input falls back to the default latency buckets.
	h := NewHistogram(nil)
	if got := len(h.GetSnapshot().Buckets); got != 11 {
		t.Fatalf("default buckets = %d, want 11", got)
	}

	// Unsorted input is sorted; the caller's slice is not mutated.
	in := []float64{100, 1, 50, 10}
	h = NewHistogram(in)
	snap := h.GetSnapshot()
	want := []float64{1, 10, 50, 100}
	for i, b := range want {
		if snap.Buckets[i] != b {
			t.Fatalf("bucket[%d] = %v, want %v (not sorted)", i, snap.Buckets[i], b)
		}
	}
	if in[0] != 100 {
		t.Fatal("NewHistogram mutated the caller's bucket slice")
	}
}

func TestHistogramObserveBucketing(t *testing.T) {
	h := NewHistogram([]float64{1, 5, 10})
	// values -> bucket index: <=1, <=5, <=10, +Inf
	h.Observe(0.5) // bucket 0
	h.Observe(3)   // bucket 1
	h.Observe(5)   // bucket 1 (boundary is inclusive: value <= boundary)
	h.Observe(10)  // bucket 2
	h.Observe(100) // +Inf bucket (index 3)

	snap := h.GetSnapshot()
	wantCounts := []uint64{1, 2, 1, 1}
	for i, w := range wantCounts {
		if snap.Counts[i] != w {
			t.Fatalf("counts[%d] = %d, want %d (all: %v)", i, snap.Counts[i], w, snap.Counts)
		}
	}
	if snap.Count != 5 {
		t.Fatalf("count = %d, want 5", snap.Count)
	}
	if snap.Min != 0.5 || snap.Max != 100 {
		t.Fatalf("min/max = %v/%v, want 0.5/100", snap.Min, snap.Max)
	}
	if math.Abs(snap.Sum-118.5) > 1e-9 {
		t.Fatalf("sum = %v, want 118.5", snap.Sum)
	}
}

func TestHistogramMeanAndEmpty(t *testing.T) {
	h := NewHistogram([]float64{1, 10})
	if h.Mean() != 0 {
		t.Fatalf("empty mean = %v, want 0", h.Mean())
	}
	if h.Percentile(0.5) != 0 {
		t.Fatalf("empty percentile = %v, want 0", h.Percentile(0.5))
	}
	h.Observe(2)
	h.Observe(4)
	if h.Mean() != 3 {
		t.Fatalf("mean = %v, want 3", h.Mean())
	}
}

func TestHistogramPercentile(t *testing.T) {
	h := NewHistogram([]float64{10, 20, 30})
	// 10 samples in bucket<=10, 10 in <=20, 10 in <=30.
	for i := 0; i < 10; i++ {
		h.Observe(5)
		h.Observe(15)
		h.Observe(25)
	}
	// p50 -> targetCount 15; cumulative reaches 15 at bucket index 1 (<=20).
	if got := h.Percentile(0.5); got != 20 {
		t.Fatalf("p50 = %v, want 20", got)
	}
	// p10 -> targetCount 3; reached in bucket 0 -> buckets[0].
	if got := h.Percentile(0.1); got != 10 {
		t.Fatalf("p10 = %v, want 10", got)
	}
}

func TestHistogramReset(t *testing.T) {
	h := NewHistogram([]float64{1, 5})
	h.Observe(3)
	h.Observe(0.5)
	h.Reset()

	snap := h.GetSnapshot()
	if snap.Count != 0 || snap.Sum != 0 {
		t.Fatalf("after reset count=%d sum=%v, want 0/0", snap.Count, snap.Sum)
	}
	for i, c := range snap.Counts {
		if c != 0 {
			t.Fatalf("count[%d] = %d after reset, want 0", i, c)
		}
	}
	// Sentinels restored so the next Observe seeds min/max correctly.
	if snap.Min != math.MaxFloat64 || snap.Max != -math.MaxFloat64 {
		t.Fatalf("min/max sentinels not restored: %v/%v", snap.Min, snap.Max)
	}
	if h.Mean() != 0 {
		t.Fatalf("mean after reset = %v, want 0", h.Mean())
	}
}

func TestHistogramConcurrentObserve(t *testing.T) {
	h := NewHistogram([]float64{1, 10, 100})

	const goroutines = 16
	const perG = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				h.Observe(5)
				_ = h.Mean()
				_ = h.GetSnapshot()
			}
		}()
	}
	wg.Wait()

	if snap := h.GetSnapshot(); snap.Count != goroutines*perG {
		t.Fatalf("count = %d, want %d", snap.Count, goroutines*perG)
	}
}
