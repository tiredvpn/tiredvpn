package dist

import (
	"math"
	"testing"
)

func sampleHistogram() []HistogramBin {
	return []HistogramBin{
		{Value: 64, Weight: 0.2},
		{Value: 256, Weight: 0.5},
		{Value: 1024, Weight: 0.3},
	}
}

func TestHistogramDeterminism(t *testing.T) {
	const n = 1000
	a, err := NewHistogram(sampleHistogram(), 42)
	if err != nil {
		t.Fatalf("NewHistogram: %v", err)
	}
	b, err := NewHistogram(sampleHistogram(), 42)
	if err != nil {
		t.Fatalf("NewHistogram: %v", err)
	}
	for i := 0; i < n; i++ {
		x, y := a.Next(), b.Next()
		if x != y {
			t.Fatalf("sample %d differs: %v vs %v", i, x, y)
		}
	}
}

func TestHistogramReset(t *testing.T) {
	h, err := NewHistogram(sampleHistogram(), 7)
	if err != nil {
		t.Fatalf("NewHistogram: %v", err)
	}
	first := make([]float64, 200)
	for i := range first {
		first[i] = h.Next()
	}
	h.Reset()
	for i := range first {
		if got := h.Next(); got != first[i] {
			t.Fatalf("after reset sample %d differs: got %v want %v", i, got, first[i])
		}
	}
}

func TestHistogramFrequencies(t *testing.T) {
	bins := sampleHistogram()
	h, err := NewHistogram(bins, 1)
	if err != nil {
		t.Fatalf("NewHistogram: %v", err)
	}
	const N = 100_000
	counts := make(map[float64]int)
	for i := 0; i < N; i++ {
		counts[h.Next()]++
	}
	var total float64
	for _, b := range bins {
		total += b.Weight
	}
	for _, b := range bins {
		expected := b.Weight / total
		actual := float64(counts[b.Value]) / float64(N)
		if math.Abs(actual-expected) > 0.02 {
			t.Errorf("bin value=%v: actual freq %v deviates from expected %v by more than 2%%",
				b.Value, actual, expected)
		}
	}
}

func TestHistogramRandomizationRange(t *testing.T) {
	bins := []HistogramBin{{Value: 1000, Weight: 1}}
	h, err := NewHistogram(bins, 99)
	if err != nil {
		t.Fatalf("NewHistogram: %v", err)
	}
	if err := h.SetRandomizationRange(0.1); err != nil {
		t.Fatalf("SetRandomizationRange: %v", err)
	}
	for i := 0; i < 1000; i++ {
		v := h.Next()
		if v < 900 || v > 1100 {
			t.Fatalf("sample %v outside ±10%% jitter window", v)
		}
	}
}

func TestHistogramErrors(t *testing.T) {
	if _, err := NewHistogram(nil, 0); err == nil {
		t.Errorf("expected error for empty bins")
	}
	if _, err := NewHistogram([]HistogramBin{{Value: 1, Weight: -1}}, 0); err == nil {
		t.Errorf("expected error for negative weight")
	}
	if _, err := NewHistogram([]HistogramBin{{Value: 1, Weight: 0}}, 0); err == nil {
		t.Errorf("expected error for zero total weight")
	}
	h, err := NewHistogram(sampleHistogram(), 0)
	if err != nil {
		t.Fatalf("NewHistogram: %v", err)
	}
	if err := h.SetRandomizationRange(1.5); err == nil {
		t.Errorf("expected error for r>=1")
	}
	if err := h.SetRandomizationRange(-0.1); err == nil {
		t.Errorf("expected error for r<0")
	}
}

func BenchmarkHistogramNext(b *testing.B) {
	h, err := NewHistogram(sampleHistogram(), 1)
	if err != nil {
		b.Fatalf("NewHistogram: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.Next()
	}
}
