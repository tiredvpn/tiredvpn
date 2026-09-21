package metrics

import (
	"testing"
)

func TestRuntimeStatsUpdate(t *testing.T) {
	rs := NewRuntimeStats()
	// Before any Update the published percentage is zero.
	if got := rs.GetCPUPercent(); got != 0 {
		t.Fatalf("initial CPU%% = %v, want 0", got)
	}
	// Two updates drive the lastCPU branch; must not panic and stays finite.
	rs.Update()
	rs.Update()
	if got := rs.GetCPUPercent(); got < 0 {
		t.Fatalf("CPU%% = %v, want non-negative", got)
	}
}

func TestGetMemStats(t *testing.T) {
	m := GetMemStats()
	if m.Sys == 0 {
		t.Fatal("MemStats.Sys is zero, ReadMemStats did not populate")
	}
}

func TestGetGoroutineCount(t *testing.T) {
	// The test runner itself keeps several goroutines alive.
	if n := GetGoroutineCount(); n < 1 {
		t.Fatalf("goroutine count = %d, want >= 1", n)
	}
}

func TestGetGCStats(t *testing.T) {
	// Non-negative, structurally valid; NumGC and pauses are monotonic but we
	// only assert they are readable without panic.
	s := GetGCStats()
	if s.GCCPUFraction < 0 {
		t.Fatalf("GCCPUFraction = %v, want >= 0", s.GCCPUFraction)
	}
	if s.PauseTotal < 0 {
		t.Fatalf("PauseTotal = %v, want >= 0", s.PauseTotal)
	}
}

func TestGetAllocStats(t *testing.T) {
	a := GetAllocStats()
	if a.Sys == 0 {
		t.Fatal("AllocStats.Sys is zero")
	}
	// Mallocs must be at least the number of live+freed objects; sanity only.
	if a.Mallocs < a.Frees {
		t.Fatalf("Mallocs %d < Frees %d, impossible", a.Mallocs, a.Frees)
	}
}
