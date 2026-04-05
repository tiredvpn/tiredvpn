package client

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type ClientQualityMetrics struct {
	// Network quality trackers
	rttTracker       *metrics.RTTTracker
	bandwidthTracker *metrics.BandwidthTracker
	packetLoss       *metrics.PacketLossEstimator

	// Jitter tracking (using RTT tracker)
	jitterMs uint64 // atomic, in milliseconds * 100

	// Bandwidth estimate
	bandwidthEstimateBps uint64 // atomic

	// Throughput
	uploadThroughput   uint64 // bytes/sec
	downloadThroughput uint64 // bytes/sec
}

func NewClientQualityMetrics() *ClientQualityMetrics {
	cqm := &ClientQualityMetrics{
		rttTracker:       metrics.NewRTTTracker(),
		bandwidthTracker: metrics.NewBandwidthTracker(time.Second),
		packetLoss:       &metrics.PacketLossEstimator{},
	}

	// Start periodic updates
	go cqm.periodicUpdate()

	return cqm
}

func (cqm *ClientQualityMetrics) periodicUpdate() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update jitter from RTT tracker
		jitter := cqm.rttTracker.GetJitter()
		atomic.StoreUint64(&cqm.jitterMs, uint64(jitter*100))

		// Update bandwidth estimate
		bps := cqm.bandwidthTracker.GetCurrentBps()
		atomic.StoreUint64(&cqm.bandwidthEstimateBps, bps)
	}
}

// Recording methods
func (cqm *ClientQualityMetrics) RecordRTT(rtt time.Duration) {
	cqm.rttTracker.Observe(rtt)
}

func (cqm *ClientQualityMetrics) RecordBandwidth(bytes uint64) {
	cqm.bandwidthTracker.Observe(bytes)
}

func (cqm *ClientQualityMetrics) RecordPacketLoss(sent, lost uint64) {
	cqm.packetLoss.ObservePackets(sent, lost)
}

func (cqm *ClientQualityMetrics) UpdateThroughput(uploadBps, downloadBps uint64) {
	atomic.StoreUint64(&cqm.uploadThroughput, uploadBps)
	atomic.StoreUint64(&cqm.downloadThroughput, downloadBps)
}

// Export to Prometheus
func (cqm *ClientQualityMetrics) ExportPrometheus(w http.ResponseWriter) {
	// Jitter
	fmt.Fprintf(w, "# HELP tiredvpn_local_jitter_milliseconds Network jitter\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_jitter_milliseconds gauge\n")
	jitter := float64(atomic.LoadUint64(&cqm.jitterMs)) / 100.0
	fmt.Fprintf(w, "tiredvpn_local_jitter_milliseconds %.2f\n", jitter)
	fmt.Fprintf(w, "\n")

	// Packet loss estimate
	fmt.Fprintf(w, "# HELP tiredvpn_local_packet_loss_estimate Estimated packet loss rate\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_packet_loss_estimate gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_packet_loss_estimate %.4f\n", cqm.packetLoss.GetLossRate())
	fmt.Fprintf(w, "\n")

	// RTT histogram
	fmt.Fprintf(w, "# HELP tiredvpn_local_rtt_milliseconds RTT distribution\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_rtt_milliseconds histogram\n")
	fmt.Fprint(w, cqm.rttTracker.GetHistogram().FormatPrometheus("tiredvpn_local_rtt_milliseconds", nil))
	fmt.Fprintf(w, "\n")

	// Bandwidth estimate
	fmt.Fprintf(w, "# HELP tiredvpn_local_bandwidth_estimate_mbps Estimated bandwidth\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_bandwidth_estimate_mbps gauge\n")
	bwMbps := float64(atomic.LoadUint64(&cqm.bandwidthEstimateBps)) * 8 / 1000000
	fmt.Fprintf(w, "tiredvpn_local_bandwidth_estimate_mbps %.2f\n", bwMbps)
	fmt.Fprintf(w, "\n")

	// Throughput
	fmt.Fprintf(w, "# HELP tiredvpn_local_throughput_mbps Current throughput\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_throughput_mbps gauge\n")
	uploadMbps := float64(atomic.LoadUint64(&cqm.uploadThroughput)) * 8 / 1000000
	downloadMbps := float64(atomic.LoadUint64(&cqm.downloadThroughput)) * 8 / 1000000
	fmt.Fprintf(w, "tiredvpn_local_throughput_mbps{direction=\"upload\"} %.2f\n", uploadMbps)
	fmt.Fprintf(w, "tiredvpn_local_throughput_mbps{direction=\"download\"} %.2f\n", downloadMbps)
	fmt.Fprintf(w, "\n")
}
