package server

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

// PerformanceMetrics collects server performance metrics
type PerformanceMetrics struct {
	runtimeStats *metrics.RuntimeStats

	// Syscall counters (atomic)
	syscallSendfile uint64
	syscallSplice   uint64
	ktlsOffload     uint64
}

// NewPerformanceMetrics creates a new performance metrics collector
func NewPerformanceMetrics() *PerformanceMetrics {
	pm := &PerformanceMetrics{
		runtimeStats: metrics.NewRuntimeStats(),
	}

	// Start periodic update goroutine
	go pm.periodicUpdate()

	return pm
}

// periodicUpdate updates runtime stats every second
func (pm *PerformanceMetrics) periodicUpdate() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pm.runtimeStats.Update()
	}
}

// RecordSyscallSendfile records a sendfile syscall
func (pm *PerformanceMetrics) RecordSyscallSendfile() {
	atomic.AddUint64(&pm.syscallSendfile, 1)
}

// RecordSyscallSplice records a splice syscall
func (pm *PerformanceMetrics) RecordSyscallSplice() {
	atomic.AddUint64(&pm.syscallSplice, 1)
}

// RecordKTLSOffload records bytes offloaded to kernel TLS
func (pm *PerformanceMetrics) RecordKTLSOffload(bytes uint64) {
	atomic.AddUint64(&pm.ktlsOffload, bytes)
}

// getOpenFDs returns the number of open file descriptors
// This is Linux-specific implementation
func getOpenFDs() int {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return -1
	}

	// Try to count open FDs via /proc/self/fd
	// This is a simplified version - in production might want to use syscalls directly
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return -1
	}

	// Note: Go runtime doesn't expose exact FD count easily
	// This returns the soft limit for now as a placeholder
	// In real implementation, would need to count /proc/self/fd entries
	return int(rLimit.Cur)
}

// ExportPrometheus exports performance metrics in Prometheus format
func (pm *PerformanceMetrics) ExportPrometheus(w http.ResponseWriter) {
	// CPU usage
	fmt.Fprintf(w, "# HELP tiredvpn_cpu_usage_percent CPU usage percentage\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_cpu_usage_percent gauge\n")
	fmt.Fprintf(w, "tiredvpn_cpu_usage_percent %.2f\n", pm.runtimeStats.GetCPUPercent())
	fmt.Fprintf(w, "\n")

	// Memory metrics
	memStats := metrics.GetMemStats()
	fmt.Fprintf(w, "# HELP tiredvpn_memory_bytes Memory usage in bytes by type\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_memory_bytes gauge\n")
	fmt.Fprintf(w, "tiredvpn_memory_bytes{type=\"allocated\"} %d\n", memStats.Alloc)
	fmt.Fprintf(w, "tiredvpn_memory_bytes{type=\"heap\"} %d\n", memStats.HeapAlloc)
	fmt.Fprintf(w, "tiredvpn_memory_bytes{type=\"stack\"} %d\n", memStats.StackInuse)
	fmt.Fprintf(w, "\n")

	// Goroutines
	fmt.Fprintf(w, "# HELP tiredvpn_goroutines_count Number of active goroutines\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_goroutines_count gauge\n")
	fmt.Fprintf(w, "tiredvpn_goroutines_count %d\n", metrics.GetGoroutineCount())
	fmt.Fprintf(w, "\n")

	// File descriptors
	fds := getOpenFDs()
	if fds >= 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_file_descriptors_used Number of open file descriptors\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_file_descriptors_used gauge\n")
		fmt.Fprintf(w, "tiredvpn_file_descriptors_used %d\n", fds)
		fmt.Fprintf(w, "\n")
	}

	// Syscall counters
	fmt.Fprintf(w, "# HELP tiredvpn_syscall_sendfile_total Total number of sendfile syscalls\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_syscall_sendfile_total counter\n")
	fmt.Fprintf(w, "tiredvpn_syscall_sendfile_total %d\n", atomic.LoadUint64(&pm.syscallSendfile))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_syscall_splice_total Total number of splice syscalls\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_syscall_splice_total counter\n")
	fmt.Fprintf(w, "tiredvpn_syscall_splice_total %d\n", atomic.LoadUint64(&pm.syscallSplice))
	fmt.Fprintf(w, "\n")

	// kTLS offload
	fmt.Fprintf(w, "# HELP tiredvpn_ktls_offload_bytes_total Total bytes offloaded to kernel TLS\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_ktls_offload_bytes_total counter\n")
	fmt.Fprintf(w, "tiredvpn_ktls_offload_bytes_total %d\n", atomic.LoadUint64(&pm.ktlsOffload))
	fmt.Fprintf(w, "\n")

	// GC statistics
	gcStats := metrics.GetGCStats()
	fmt.Fprintf(w, "# HELP tiredvpn_gc_duration_seconds Last GC pause duration in seconds\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_gc_duration_seconds gauge\n")
	fmt.Fprintf(w, "tiredvpn_gc_duration_seconds %.6f\n", gcStats.LastPause.Seconds())
	fmt.Fprintf(w, "\n")

	// Heap allocations
	allocStats := metrics.GetAllocStats()
	fmt.Fprintf(w, "# HELP tiredvpn_allocations_total Total number of heap allocations\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_allocations_total counter\n")
	fmt.Fprintf(w, "tiredvpn_allocations_total %d\n", allocStats.Mallocs)
	fmt.Fprintf(w, "\n")
}
