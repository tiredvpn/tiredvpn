package client

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type ClientPerformanceMetrics struct {
	runtimeStats *metrics.RuntimeStats

	// DNS timing
	dnsResolution *metrics.Histogram
}

func NewClientPerformanceMetrics() *ClientPerformanceMetrics {
	// DNS timing buckets (ms): 1, 5, 10, 50, 100, 500, 1000, 5000
	dnsBuckets := []float64{1, 5, 10, 50, 100, 500, 1000, 5000}

	cpm := &ClientPerformanceMetrics{
		runtimeStats:  metrics.NewRuntimeStats(),
		dnsResolution: metrics.NewHistogram(dnsBuckets),
	}

	// Start periodic update
	go cpm.periodicUpdate()

	return cpm
}

func (cpm *ClientPerformanceMetrics) periodicUpdate() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cpm.runtimeStats.Update()
	}
}

func (cpm *ClientPerformanceMetrics) RecordDNSResolution(duration time.Duration) {
	cpm.dnsResolution.Observe(float64(duration.Milliseconds()))
}

func (cpm *ClientPerformanceMetrics) ExportPrometheus(w http.ResponseWriter) {
	// CPU
	fmt.Fprintf(w, "# HELP tiredvpn_local_cpu_usage_percent CPU usage\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_cpu_usage_percent gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_cpu_usage_percent %.2f\n", cpm.runtimeStats.GetCPUPercent())
	fmt.Fprintf(w, "\n")

	// Memory
	memStats := metrics.GetMemStats()
	fmt.Fprintf(w, "# HELP tiredvpn_local_memory_bytes Memory usage\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_memory_bytes gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_memory_bytes{type=\"allocated\"} %d\n", memStats.Alloc)
	fmt.Fprintf(w, "tiredvpn_local_memory_bytes{type=\"heap\"} %d\n", memStats.HeapAlloc)
	fmt.Fprintf(w, "\n")

	// Goroutines
	fmt.Fprintf(w, "# HELP tiredvpn_local_goroutines_count Goroutines\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_goroutines_count gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_goroutines_count %d\n", metrics.GetGoroutineCount())
	fmt.Fprintf(w, "\n")

	// DNS resolution histogram
	fmt.Fprintf(w, "# HELP tiredvpn_local_dns_resolution_duration_seconds DNS lookup time\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_dns_resolution_duration_seconds histogram\n")
	fmt.Fprint(w, cpm.dnsResolution.FormatPrometheus("tiredvpn_local_dns_resolution_duration_seconds", nil))
	fmt.Fprintf(w, "\n")

	// GC
	gcStats := metrics.GetGCStats()
	fmt.Fprintf(w, "# HELP tiredvpn_local_gc_duration_seconds GC pause time\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_gc_duration_seconds gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_gc_duration_seconds %.6f\n", gcStats.LastPause.Seconds())
	fmt.Fprintf(w, "\n")

	// Allocations
	allocStats := metrics.GetAllocStats()
	fmt.Fprintf(w, "# HELP tiredvpn_local_allocations_total Heap allocations\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_allocations_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_allocations_total %d\n", allocStats.Mallocs)
	fmt.Fprintf(w, "\n")

	// FDs (TODO: platform-specific)
	fmt.Fprintf(w, "# HELP tiredvpn_local_file_descriptors_used Open file descriptors\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_file_descriptors_used gauge\n")
	// TODO: implement GetOpenFDs()
	fmt.Fprintf(w, "tiredvpn_local_file_descriptors_used 0\n")
	fmt.Fprintf(w, "\n")
}
