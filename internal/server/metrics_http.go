package server

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type HTTPMetrics struct {
	// HTTP/2 metrics
	http2StreamsPerConn *metrics.Histogram
	http2SettingsFrames uint64

	// WebSocket metrics
	wsUpgradesSuccess uint64
	wsUpgradesFailed  uint64
	wsPingLatency     uint64 // ms * 100 (for precision)
}

func NewHTTPMetrics() *HTTPMetrics {
	// Streams per connection buckets: 1, 2, 5, 10, 20, 50, 100
	streamBuckets := []float64{1, 2, 5, 10, 20, 50, 100}

	return &HTTPMetrics{
		http2StreamsPerConn: metrics.NewHistogram(streamBuckets),
	}
}

func (hm *HTTPMetrics) RecordHTTP2Streams(count int) {
	hm.http2StreamsPerConn.Observe(float64(count))
}

func (hm *HTTPMetrics) RecordHTTP2SettingsFrame() {
	atomic.AddUint64(&hm.http2SettingsFrames, 1)
}

func (hm *HTTPMetrics) RecordWebSocketUpgrade(success bool) {
	if success {
		atomic.AddUint64(&hm.wsUpgradesSuccess, 1)
	} else {
		atomic.AddUint64(&hm.wsUpgradesFailed, 1)
	}
}

func (hm *HTTPMetrics) UpdateWebSocketPingLatency(latencyMs float64) {
	atomic.StoreUint64(&hm.wsPingLatency, uint64(latencyMs*100))
}

func (hm *HTTPMetrics) ExportPrometheus(w http.ResponseWriter) {
	// HTTP/2 streams
	fmt.Fprintf(w, "# HELP tiredvpn_http2_streams_per_connection HTTP/2 streams per connection\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_http2_streams_per_connection histogram\n")
	fmt.Fprint(w, hm.http2StreamsPerConn.FormatPrometheus("tiredvpn_http2_streams_per_connection", nil))
	fmt.Fprintf(w, "\n")

	// HTTP/2 SETTINGS frames
	fmt.Fprintf(w, "# HELP tiredvpn_http2_settings_frames_total HTTP/2 SETTINGS frames\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_http2_settings_frames_total counter\n")
	fmt.Fprintf(w, "tiredvpn_http2_settings_frames_total %d\n", atomic.LoadUint64(&hm.http2SettingsFrames))
	fmt.Fprintf(w, "\n")

	// WebSocket upgrades
	fmt.Fprintf(w, "# HELP tiredvpn_websocket_upgrades_total WebSocket upgrade attempts\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_websocket_upgrades_total counter\n")
	fmt.Fprintf(w, "tiredvpn_websocket_upgrades_total{result=\"success\"} %d\n", atomic.LoadUint64(&hm.wsUpgradesSuccess))
	fmt.Fprintf(w, "tiredvpn_websocket_upgrades_total{result=\"failure\"} %d\n", atomic.LoadUint64(&hm.wsUpgradesFailed))
	fmt.Fprintf(w, "\n")

	// WebSocket ping latency
	latency := float64(atomic.LoadUint64(&hm.wsPingLatency)) / 100.0
	fmt.Fprintf(w, "# HELP tiredvpn_websocket_ping_latency_milliseconds WebSocket ping/pong RTT\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_websocket_ping_latency_milliseconds gauge\n")
	fmt.Fprintf(w, "tiredvpn_websocket_ping_latency_milliseconds %.2f\n", latency)
	fmt.Fprintf(w, "\n")
}
