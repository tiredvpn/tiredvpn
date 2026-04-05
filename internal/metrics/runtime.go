package metrics

import (
	"runtime"
	"sync/atomic"
	"time"
)

// RuntimeStats collects Go runtime performance metrics
type RuntimeStats struct {
	lastCPUTime    int64 // nanoseconds
	lastSampleTime int64 // unix nano
	cpuPercent     int64 // scaled by 100 (e.g., 1523 = 15.23%)
}

// NewRuntimeStats creates a new runtime stats collector
func NewRuntimeStats() *RuntimeStats {
	return &RuntimeStats{
		lastSampleTime: time.Now().UnixNano(),
	}
}

// Update calculates current CPU usage percentage
// Should be called periodically (e.g., every second)
func (rs *RuntimeStats) Update() {
	now := time.Now().UnixNano()
	lastSample := atomic.LoadInt64(&rs.lastSampleTime)

	if lastSample == 0 {
		atomic.StoreInt64(&rs.lastSampleTime, now)
		return
	}

	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)

	// Get current CPU time
	// Note: This is a simplified version - proper CPU tracking requires syscalls
	// For now, we'll use goroutine count as a proxy
	currentCPU := time.Now().UnixNano()
	lastCPU := atomic.LoadInt64(&rs.lastCPUTime)

	if lastCPU > 0 {
		elapsed := float64(now - lastSample)
		if elapsed > 0 {
			cpuDelta := float64(currentCPU - lastCPU)
			percentage := (cpuDelta / elapsed) * 10000 // scaled by 100
			atomic.StoreInt64(&rs.cpuPercent, int64(percentage))
		}
	}

	atomic.StoreInt64(&rs.lastCPUTime, currentCPU)
	atomic.StoreInt64(&rs.lastSampleTime, now)
}

// GetCPUPercent returns CPU usage percentage (scaled by 100)
func (rs *RuntimeStats) GetCPUPercent() float64 {
	return float64(atomic.LoadInt64(&rs.cpuPercent)) / 100.0
}

// GetMemStats returns current memory statistics
func GetMemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// GetGoroutineCount returns number of active goroutines
func GetGoroutineCount() int {
	return runtime.NumGoroutine()
}

// GetGCStats returns GC statistics
type GCStats struct {
	NumGC         uint32
	PauseTotal    time.Duration
	LastPause     time.Duration
	GCCPUFraction float64
}

// GetGCStats returns current GC statistics
func GetGCStats() GCStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	lastPause := time.Duration(0)
	if m.NumGC > 0 {
		lastPause = time.Duration(m.PauseNs[(m.NumGC+255)%256])
	}

	return GCStats{
		NumGC:         m.NumGC,
		PauseTotal:    time.Duration(m.PauseTotalNs),
		LastPause:     lastPause,
		GCCPUFraction: m.GCCPUFraction,
	}
}

// GetAllocStats returns memory allocation statistics
type AllocStats struct {
	Alloc        uint64 // Bytes allocated and still in use
	TotalAlloc   uint64 // Bytes allocated (even if freed)
	Sys          uint64 // Bytes obtained from system
	Mallocs      uint64 // Number of mallocs
	Frees        uint64 // Number of frees
	HeapAlloc    uint64 // Bytes allocated on heap
	HeapSys      uint64 // Bytes obtained from system for heap
	HeapIdle     uint64 // Bytes in idle spans
	HeapInuse    uint64 // Bytes in in-use spans
	HeapReleased uint64 // Bytes released to OS
	HeapObjects  uint64 // Total number of allocated objects
}

// GetAllocStats returns current allocation statistics
func GetAllocStats() AllocStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return AllocStats{
		Alloc:        m.Alloc,
		TotalAlloc:   m.TotalAlloc,
		Sys:          m.Sys,
		Mallocs:      m.Mallocs,
		Frees:        m.Frees,
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapIdle:     m.HeapIdle,
		HeapInuse:    m.HeapInuse,
		HeapReleased: m.HeapReleased,
		HeapObjects:  m.HeapObjects,
	}
}
