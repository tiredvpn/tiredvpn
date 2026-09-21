package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
)

// TestCollectorSetGet covers the basic single- and no-label round trip.
func TestCollectorSetGet(t *testing.T) {
	c := NewCollector()

	if _, ok := c.Get("missing", nil); ok {
		t.Fatal("Get on empty collector must report not-found")
	}

	c.Set("cpu", 42.5, nil)
	if v, ok := c.Get("cpu", nil); !ok || v != 42.5 {
		t.Fatalf("Get(cpu) = %v,%v want 42.5,true", v, ok)
	}

	c.Set("rtt", 12.0, map[string]string{"exit": "ams"})
	if v, ok := c.Get("rtt", map[string]string{"exit": "ams"}); !ok || v != 12.0 {
		t.Fatalf("Get(rtt{exit=ams}) = %v,%v want 12,true", v, ok)
	}
	// A different label value must be a different series.
	if _, ok := c.Get("rtt", map[string]string{"exit": "usa"}); ok {
		t.Fatal("Get with different label value must not hit the ams series")
	}
}

// TestCollectorMultiLabelRoundTrip pins the map-iteration-order bug: buildKey
// concatenated labels in Go map range order, which is randomised per call, so
// Set stored under one key and a later Get computed a different key for the
// same labels and missed. With >=2 labels the two orders diverge with high
// probability; the loop makes a stale (unsorted) implementation fail reliably.
//
// Positive control: the sorted key is deterministic, so on the fixed code every
// iteration hits. If this test ever passes on unsorted code it can only be by a
// 1-in-720 fluke per iteration, driven to ~0 across the loop.
func TestCollectorMultiLabelRoundTrip(t *testing.T) {
	labels := map[string]string{
		"proto": "reality", "exit": "ams", "family": "v6",
		"cipher": "chacha", "mux": "on", "region": "eu",
	}

	for i := 0; i < 200; i++ {
		c := NewCollector()
		c.Set("series", float64(i), cloneLabels(labels))
		v, ok := c.Get("series", cloneLabels(labels))
		if !ok {
			t.Fatalf("iter %d: Get missed a value Set with identical labels (key not order-stable)", i)
		}
		if v != float64(i) {
			t.Fatalf("iter %d: Get = %v want %v", i, v, i)
		}
	}
}

// TestBuildKeyDeterministic asserts the key for a fixed label set does not
// change between calls. On the unsorted implementation repeated calls yield
// different strings; 1000 calls make a divergence overwhelmingly likely.
func TestBuildKeyDeterministic(t *testing.T) {
	c := NewCollector()
	labels := map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"}

	first := c.buildKey("m", labels)

	// Independent expected value: name + sorted "k=v" segments.
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "m"
	for _, k := range keys {
		want += ";" + k + "=" + labels[k]
	}
	if first != want {
		t.Fatalf("buildKey = %q, want deterministic sorted %q", first, want)
	}

	for i := 0; i < 1000; i++ {
		if got := c.buildKey("m", labels); got != first {
			t.Fatalf("buildKey not deterministic: call %d gave %q, first gave %q", i, got, first)
		}
	}
}

func TestCollectorGetAllDeleteClear(t *testing.T) {
	c := NewCollector()
	c.Set("lat", 1, map[string]string{"exit": "ams"})
	c.Set("lat", 2, map[string]string{"exit": "usa"})
	c.Set("other", 9, nil)

	all := c.GetAll("lat")
	if len(all) != 2 {
		t.Fatalf("GetAll(lat) returned %d series, want 2", len(all))
	}

	c.Delete("lat", map[string]string{"exit": "ams"})
	if _, ok := c.Get("lat", map[string]string{"exit": "ams"}); ok {
		t.Fatal("Delete did not remove the ams series")
	}
	if _, ok := c.Get("lat", map[string]string{"exit": "usa"}); !ok {
		t.Fatal("Delete removed the wrong series")
	}

	c.Clear()
	if _, ok := c.Get("other", nil); ok {
		t.Fatal("Clear left metrics behind")
	}
}

func TestCounterVecBasic(t *testing.T) {
	cv := NewCounterVec()
	labels := map[string]string{"proto": "ssh"}

	if got := cv.Get(labels); got != 0 {
		t.Fatalf("unseen counter = %d, want 0", got)
	}
	cv.Inc(labels)
	cv.Add(labels, 4)
	if got := cv.Get(labels); got != 5 {
		t.Fatalf("counter = %d, want 5", got)
	}
	// Distinct label set is a distinct counter.
	if got := cv.Get(map[string]string{"proto": "quic"}); got != 0 {
		t.Fatalf("distinct-label counter = %d, want 0", got)
	}
}

// TestCounterVecConcurrentInc exercises the "Use atomic for the actual
// increment" claim. The single-label key is order-stable, so this isolates the
// atomicity defect: the plain `*counter += delta` is a read-modify-write and
// both races (caught by -race) and loses updates under contention.
func TestCounterVecConcurrentInc(t *testing.T) {
	cv := NewCounterVec()
	labels := map[string]string{"proto": "reality"}

	const goroutines = 50
	const perG = 2000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				cv.Inc(labels)
			}
		}()
	}
	wg.Wait()

	if got := cv.Get(labels); got != goroutines*perG {
		t.Fatalf("counter = %d, want %d (lost increments)", got, goroutines*perG)
	}
}

// TestCounterVecConcurrentDistinctKeys stresses map creation of new counters
// under contention (the locked map lookup path) alongside the atomic increment.
func TestCounterVecConcurrentDistinctKeys(t *testing.T) {
	cv := NewCounterVec()

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			l := map[string]string{"worker": fmt.Sprintf("%d", id%8)}
			for i := 0; i < 500; i++ {
				cv.Add(l, 2)
			}
		}(g)
	}
	wg.Wait()

	total := uint64(0)
	for i := 0; i < 8; i++ {
		total += cv.Get(map[string]string{"worker": fmt.Sprintf("%d", i)})
	}
	if total != goroutines*500*2 {
		t.Fatalf("summed counters = %d, want %d", total, goroutines*500*2)
	}
}

func TestBuildLabelsKeyEmpty(t *testing.T) {
	if got := buildLabelsKey(nil); got != "" {
		t.Fatalf("buildLabelsKey(nil) = %q, want empty", got)
	}
	if got := buildLabelsKey(map[string]string{}); got != "" {
		t.Fatalf("buildLabelsKey(empty) = %q, want empty", got)
	}
	// Multi-label key must be order-stable so Inc and Get agree.
	l := map[string]string{"b": "2", "a": "1", "c": "3"}
	first := buildLabelsKey(l)
	if !strings.Contains(first, "a=1") || !strings.Contains(first, "c=3") {
		t.Fatalf("buildLabelsKey dropped a segment: %q", first)
	}
	for i := 0; i < 500; i++ {
		if got := buildLabelsKey(l); got != first {
			t.Fatalf("buildLabelsKey not deterministic: %q vs %q", got, first)
		}
	}
}

func cloneLabels(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
