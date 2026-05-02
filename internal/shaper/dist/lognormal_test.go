package dist

import (
	"math"
	"testing"
)

func TestLogNormalDeterminism(t *testing.T) {
	a := NewLogNormal(0, 1, 123)
	b := NewLogNormal(0, 1, 123)
	for i := 0; i < 1000; i++ {
		x, y := a.Next(), b.Next()
		if x != y {
			t.Fatalf("sample %d differs: %v vs %v", i, x, y)
		}
	}
}

func TestLogNormalReset(t *testing.T) {
	l := NewLogNormal(1, 0.5, 8)
	first := make([]float64, 200)
	for i := range first {
		first[i] = l.Next()
	}
	l.Reset()
	for i := range first {
		if got := l.Next(); got != first[i] {
			t.Fatalf("after reset sample %d differs: got %v want %v", i, got, first[i])
		}
	}
}

func TestLogNormalMoments(t *testing.T) {
	mu, sigma := 1.0, 0.5
	l := NewLogNormal(mu, sigma, 42)
	const N = 100_000
	var sum, sumSq float64
	for i := 0; i < N; i++ {
		v := l.Next()
		sum += v
		sumSq += v * v
	}
	mean := sum / N
	variance := sumSq/N - mean*mean

	expectedMean := math.Exp(mu + sigma*sigma/2)
	expectedVar := (math.Exp(sigma*sigma) - 1) * math.Exp(2*mu+sigma*sigma)

	if math.Abs(mean-expectedMean)/expectedMean > 0.05 {
		t.Errorf("mean %v deviates from theoretical %v by more than 5%%", mean, expectedMean)
	}
	if math.Abs(variance-expectedVar)/expectedVar > 0.15 {
		t.Errorf("variance %v deviates from theoretical %v by more than 15%%", variance, expectedVar)
	}
}

func BenchmarkLogNormalNext(b *testing.B) {
	l := NewLogNormal(1, 0.5, 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = l.Next()
	}
}
