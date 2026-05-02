package dist

import (
	"math"
	"testing"
)

func TestParetoDeterminism(t *testing.T) {
	a := NewPareto(1, 3, 7)
	b := NewPareto(1, 3, 7)
	for i := 0; i < 1000; i++ {
		x, y := a.Next(), b.Next()
		if x != y {
			t.Fatalf("sample %d differs: %v vs %v", i, x, y)
		}
	}
}

func TestParetoReset(t *testing.T) {
	p := NewPareto(1, 2.5, 11)
	first := make([]float64, 200)
	for i := range first {
		first[i] = p.Next()
	}
	p.Reset()
	for i := range first {
		if got := p.Next(); got != first[i] {
			t.Fatalf("after reset sample %d differs: got %v want %v", i, got, first[i])
		}
	}
}

func TestParetoMean(t *testing.T) {
	xm, alpha := 2.0, 3.0
	p := NewPareto(xm, alpha, 13)
	const N = 200_000
	var sum float64
	for i := 0; i < N; i++ {
		sum += p.Next()
	}
	mean := sum / N
	expected := alpha * xm / (alpha - 1)

	if math.Abs(mean-expected)/expected > 0.05 {
		t.Errorf("mean %v deviates from theoretical %v by more than 5%%", mean, expected)
	}
}

func TestParetoLowerBound(t *testing.T) {
	xm := 100.0
	p := NewPareto(xm, 2, 1)
	for i := 0; i < 10_000; i++ {
		if v := p.Next(); v < xm {
			t.Fatalf("sample %v below scale %v", v, xm)
		}
	}
}

func BenchmarkParetoNext(b *testing.B) {
	p := NewPareto(1, 2.5, 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Next()
	}
}
