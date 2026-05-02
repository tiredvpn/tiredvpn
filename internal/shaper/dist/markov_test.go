package dist

import (
	"math"
	"testing"
)

func sampleMarkov() ([]MarkovState, [][]float64) {
	states := []MarkovState{
		{Name: "idle", Value: 0},
		{Name: "burst", Value: 1500},
	}
	transitions := [][]float64{
		{0.8, 0.2},
		{0.4, 0.6},
	}
	return states, transitions
}

func TestMarkovDeterminism(t *testing.T) {
	states, tr := sampleMarkov()
	a, err := NewMarkovBurst(states, tr, 5)
	if err != nil {
		t.Fatalf("NewMarkovBurst: %v", err)
	}
	b, err := NewMarkovBurst(states, tr, 5)
	if err != nil {
		t.Fatalf("NewMarkovBurst: %v", err)
	}
	for i := 0; i < 1000; i++ {
		x, y := a.Next(), b.Next()
		if x != y {
			t.Fatalf("sample %d differs: %v vs %v", i, x, y)
		}
	}
}

func TestMarkovReset(t *testing.T) {
	states, tr := sampleMarkov()
	m, err := NewMarkovBurst(states, tr, 17)
	if err != nil {
		t.Fatalf("NewMarkovBurst: %v", err)
	}
	first := make([]float64, 500)
	for i := range first {
		first[i] = m.Next()
	}
	m.Reset()
	for i := range first {
		if got := m.Next(); got != first[i] {
			t.Fatalf("after reset sample %d differs: got %v want %v", i, got, first[i])
		}
	}
}

// Stationary distribution for the 2-state chain
//
//	P = [[0.8, 0.2], [0.4, 0.6]]
//
// solves π = πP and is π = (2/3, 1/3).
func TestMarkovStationary(t *testing.T) {
	states, tr := sampleMarkov()
	m, err := NewMarkovBurst(states, tr, 99)
	if err != nil {
		t.Fatalf("NewMarkovBurst: %v", err)
	}
	const N = 200_000
	const burn = 5_000
	for i := 0; i < burn; i++ {
		m.Next()
	}
	counts := make(map[string]int)
	for i := 0; i < N; i++ {
		m.Next()
		counts[m.State()]++
	}
	expected := map[string]float64{"idle": 2.0 / 3.0, "burst": 1.0 / 3.0}
	for name, want := range expected {
		got := float64(counts[name]) / float64(N)
		if math.Abs(got-want) > 0.02 {
			t.Errorf("state %q frequency %v deviates from stationary %v by more than 2%%",
				name, got, want)
		}
	}
}

func TestMarkovErrors(t *testing.T) {
	if _, err := NewMarkovBurst(nil, nil, 0); err == nil {
		t.Errorf("expected error for empty states")
	}
	states := []MarkovState{{Name: "a", Value: 1}, {Name: "b", Value: 2}}
	if _, err := NewMarkovBurst(states, [][]float64{{1, 0}}, 0); err == nil {
		t.Errorf("expected error for wrong row count")
	}
	if _, err := NewMarkovBurst(states, [][]float64{{1, 0}, {0.5}}, 0); err == nil {
		t.Errorf("expected error for ragged row")
	}
	if _, err := NewMarkovBurst(states, [][]float64{{1, 0}, {0.4, 0.4}}, 0); err == nil {
		t.Errorf("expected error for row not summing to 1")
	}
	if _, err := NewMarkovBurst(states, [][]float64{{1, 0}, {-0.1, 1.1}}, 0); err == nil {
		t.Errorf("expected error for negative probability")
	}
}

func BenchmarkMarkovNext(b *testing.B) {
	states, tr := sampleMarkov()
	m, err := NewMarkovBurst(states, tr, 1)
	if err != nil {
		b.Fatalf("NewMarkovBurst: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Next()
	}
}
