package strategy

import (
	"context"
	"testing"
	"time"
)

func TestSingleFlightGateSerializesAcrossDonors(t *testing.T) {
	g := newSingleFlightHandshakeGate()
	first, err := g.acquire(context.Background(), "donor-one.example")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if release, err := g.acquire(ctx, "donor-two.example"); err == nil {
		release()
		first()
		t.Fatal("second donor bypassed occupied global slot")
	}
	first()

	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	second, err := g.acquire(ctx2, "donor-two.example")
	if err != nil {
		t.Fatalf("global slot leaked after cancellation: %v", err)
	}
	second()
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Fatalf("cross-donor spacing only %v", elapsed)
	}
}

func TestSingleFlightStrategyIsExplicitAndBaselineIsUnchanged(t *testing.T) {
	m := NewDefaultManager(DefaultManagerConfig{ServerAddr: "127.0.0.1:443", Secret: []byte("test-secret")})
	var baseline *REALITYStrategy
	var variant *SingleFlightREALITYStrategy
	for _, s := range m.GetOrderedStrategies() {
		switch s := s.(type) {
		case *REALITYStrategy:
			baseline = s
		case *SingleFlightREALITYStrategy:
			variant = s
		}
	}
	if baseline == nil || variant == nil {
		t.Fatal("both REALITY variants must be registered")
	}
	if baseline.gate.global != nil || variant.gate.global == nil {
		t.Fatal("single-flight gate changed the baseline or is missing on the variant")
	}
	if baseline.gate == variant.gate {
		t.Fatal("single-flight variant shares baseline gate")
	}
	if err := m.ForceStrategy("reality"); err != nil {
		t.Fatal(err)
	}
	selected := m.GetOrderedStrategies()
	if len(selected) != 1 || selected[0].ID() != "reality" {
		t.Fatalf("forcing reality selected %v", selected)
	}

	m2 := NewDefaultManager(DefaultManagerConfig{ServerAddr: "127.0.0.1:443", Secret: []byte("test-secret")})
	if err := m2.ForceStrategy("reality_singleflight"); err != nil {
		t.Fatal(err)
	}
	selected = m2.GetOrderedStrategies()
	if len(selected) != 1 || selected[0].ID() != "reality_singleflight" {
		t.Fatalf("forcing reality_singleflight selected %v", selected)
	}
}
