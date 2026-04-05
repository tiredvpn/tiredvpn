package server

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type QualityMetrics struct {
	mu sync.RWMutex

	// RTT tracking
	rttHistogram *metrics.Histogram
	rttTracker   *metrics.RTTTracker

	// Bandwidth
	bandwidthTracker *metrics.BandwidthTracker

	// Connection tracking
	connectionDurations *metrics.Histogram

	// Counters
	packetRetransmissions uint64
	idleTimeouts          uint64

	// Current throughput (bytes/sec)
	uploadThroughput   uint64
	downloadThroughput uint64

	// Bandwidth utilization tracking
	maxBandwidth       uint64 // bytes/sec capacity
	currentUtilization float64
}

func NewQualityMetrics() *QualityMetrics {
	// RTT buckets (ms): 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000
	rttBuckets := []float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000}

	// Connection duration buckets (seconds): 1, 10, 30, 60, 300, 600, 1800, 3600, 7200
	durationBuckets := []float64{1, 10, 30, 60, 300, 600, 1800, 3600, 7200}

	qm := &QualityMetrics{
		rttHistogram:        metrics.NewHistogram(rttBuckets),
		rttTracker:          metrics.NewRTTTracker(),
		bandwidthTracker:    metrics.NewBandwidthTracker(time.Second),
		connectionDurations: metrics.NewHistogram(durationBuckets),
		maxBandwidth:        1000 * 1000 * 1000, // 1 Gbps default
	}

	// Start periodic throughput calculation
	go qm.periodicThroughputUpdate()

	return qm
}

func (qm *QualityMetrics) periodicThroughputUpdate() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		qm.updateBandwidthUtilization()
	}
}

func (qm *QualityMetrics) updateBandwidthUtilization() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	currentBps := qm.bandwidthTracker.GetCurrentBps()
	maxBps := atomic.LoadUint64(&qm.maxBandwidth)

	if maxBps > 0 {
		qm.currentUtilization = float64(currentBps) / float64(maxBps) * 100.0
	}
}

// Recording methods
func (qm *QualityMetrics) RecordRTT(rtt time.Duration) {
	qm.rttTracker.Observe(rtt)
	qm.rttHistogram.Observe(float64(rtt.Milliseconds()))
}

func (qm *QualityMetrics) RecordBandwidth(bytes uint64) {
	qm.bandwidthTracker.Observe(bytes)
}

func (qm *QualityMetrics) RecordRetransmission() {
	atomic.AddUint64(&qm.packetRetransmissions, 1)
}

func (qm *QualityMetrics) RecordConnectionDuration(duration time.Duration) {
	qm.connectionDurations.Observe(duration.Seconds())
}

func (qm *QualityMetrics) RecordIdleTimeout() {
	atomic.AddUint64(&qm.idleTimeouts, 1)
}

func (qm *QualityMetrics) UpdateThroughput(uploadBps, downloadBps uint64) {
	atomic.StoreUint64(&qm.uploadThroughput, uploadBps)
	atomic.StoreUint64(&qm.downloadThroughput, downloadBps)
}

func (qm *QualityMetrics) SetMaxBandwidth(bytesPerSec uint64) {
	atomic.StoreUint64(&qm.maxBandwidth, bytesPerSec)
}

// Export to Prometheus
func (qm *QualityMetrics) ExportPrometheus(w http.ResponseWriter) {
	// RTT histogram
	fmt.Fprintf(w, "# HELP tiredvpn_rtt_milliseconds RTT distribution\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_rtt_milliseconds histogram\n")
	fmt.Fprint(w, qm.rttHistogram.FormatPrometheus("tiredvpn_rtt_milliseconds", nil))
	fmt.Fprintf(w, "\n")

	// Bandwidth utilization
	fmt.Fprintf(w, "# HELP tiredvpn_bandwidth_utilization_percent Bandwidth utilization percentage\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_bandwidth_utilization_percent gauge\n")
	qm.mu.RLock()
	util := qm.currentUtilization
	qm.mu.RUnlock()
	fmt.Fprintf(w, "tiredvpn_bandwidth_utilization_percent %.2f\n", util)
	fmt.Fprintf(w, "\n")

	// Packet retransmissions
	fmt.Fprintf(w, "# HELP tiredvpn_packet_retransmissions_total Packet retransmissions\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_packet_retransmissions_total counter\n")
	fmt.Fprintf(w, "tiredvpn_packet_retransmissions_total %d\n", atomic.LoadUint64(&qm.packetRetransmissions))
	fmt.Fprintf(w, "\n")

	// Connection duration histogram
	fmt.Fprintf(w, "# HELP tiredvpn_connection_duration_seconds Connection lifetime\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_connection_duration_seconds histogram\n")
	fmt.Fprint(w, qm.connectionDurations.FormatPrometheus("tiredvpn_connection_duration_seconds", nil))
	fmt.Fprintf(w, "\n")

	// Idle timeout events
	fmt.Fprintf(w, "# HELP tiredvpn_idle_timeout_events_total Idle timeout closures\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_idle_timeout_events_total counter\n")
	fmt.Fprintf(w, "tiredvpn_idle_timeout_events_total %d\n", atomic.LoadUint64(&qm.idleTimeouts))
	fmt.Fprintf(w, "\n")

	// Throughput
	fmt.Fprintf(w, "# HELP tiredvpn_throughput_mbps Current throughput in Mbps\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_throughput_mbps gauge\n")
	uploadMbps := float64(atomic.LoadUint64(&qm.uploadThroughput)) * 8 / 1000000
	downloadMbps := float64(atomic.LoadUint64(&qm.downloadThroughput)) * 8 / 1000000
	fmt.Fprintf(w, "tiredvpn_throughput_mbps{direction=\"upload\"} %.2f\n", uploadMbps)
	fmt.Fprintf(w, "tiredvpn_throughput_mbps{direction=\"download\"} %.2f\n", downloadMbps)
	fmt.Fprintf(w, "\n")
}
