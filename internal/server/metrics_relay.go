package server

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type RelayMetrics struct {
	mu sync.RWMutex

	// Upstream health (per upstream)
	upstreamHealth map[string]uint64 // upstream -> 0=down, 1=up

	// Latency overhead
	latencyOverhead uint64 // ms * 100 for precision

	// Hop count distribution
	hopCountHist *metrics.Histogram
}

func NewRelayMetrics() *RelayMetrics {
	// Hop count buckets: 0, 1, 2, 3, 4, 5, 6, 7, 8
	hopBuckets := []float64{0, 1, 2, 3, 4, 5, 6, 7, 8}

	return &RelayMetrics{
		upstreamHealth: make(map[string]uint64),
		hopCountHist:   metrics.NewHistogram(hopBuckets),
	}
}

func (rm *RelayMetrics) SetUpstreamHealth(upstream string, isUp bool) {
	rm.mu.Lock()
	if isUp {
		rm.upstreamHealth[upstream] = 1
	} else {
		rm.upstreamHealth[upstream] = 0
	}
	rm.mu.Unlock()
}

func (rm *RelayMetrics) UpdateLatencyOverhead(overheadMs float64) {
	atomic.StoreUint64(&rm.latencyOverhead, uint64(overheadMs*100))
}

func (rm *RelayMetrics) RecordHopCount(hops int) {
	rm.hopCountHist.Observe(float64(hops))
}

func (rm *RelayMetrics) ExportPrometheus(w http.ResponseWriter) {
	// Upstream health
	rm.mu.RLock()
	healthCopy := make(map[string]uint64, len(rm.upstreamHealth))
	for k, v := range rm.upstreamHealth {
		healthCopy[k] = v
	}
	rm.mu.RUnlock()

	if len(healthCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_relay_upstream_health Upstream health status (0=down, 1=up)\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_relay_upstream_health gauge\n")
		for upstream, health := range healthCopy {
			fmt.Fprintf(w, "tiredvpn_relay_upstream_health{upstream=\"%s\"} %d\n", upstream, health)
		}
		fmt.Fprintf(w, "\n")
	}

	// Latency overhead
	overhead := float64(atomic.LoadUint64(&rm.latencyOverhead)) / 100.0
	fmt.Fprintf(w, "# HELP tiredvpn_relay_latency_overhead_milliseconds Added latency by relay\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_relay_latency_overhead_milliseconds gauge\n")
	fmt.Fprintf(w, "tiredvpn_relay_latency_overhead_milliseconds %.2f\n", overhead)
	fmt.Fprintf(w, "\n")

	// Hop count histogram
	fmt.Fprintf(w, "# HELP tiredvpn_relay_hop_count Hop count distribution\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_relay_hop_count histogram\n")
	fmt.Fprint(w, rm.hopCountHist.FormatPrometheus("tiredvpn_relay_hop_count", nil))
	fmt.Fprintf(w, "\n")
}
