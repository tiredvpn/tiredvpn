package server

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type ProtocolMetrics struct {
	mu sync.RWMutex

	// QUIC metrics (per client_id)
	quicPacketLoss map[string]float64 // client_id -> loss_rate
	quicRTT        map[string]float64 // client_id -> rtt_ms
	quicCongestion map[string]uint64  // client_id -> events

	// QUIC 0-RTT
	quic0RTTAccepted uint64

	// TLS metrics
	tlsHandshakeDuration *metrics.Histogram
	tlsCipherSuite       map[string]uint64 // suite -> count
	tlsVersion           map[string]uint64 // version -> count
}

func NewProtocolMetrics() *ProtocolMetrics {
	// TLS handshake buckets (ms): 1, 5, 10, 50, 100, 200, 500, 1000
	tlsBuckets := []float64{1, 5, 10, 50, 100, 200, 500, 1000}

	return &ProtocolMetrics{
		quicPacketLoss:       make(map[string]float64),
		quicRTT:              make(map[string]float64),
		quicCongestion:       make(map[string]uint64),
		tlsHandshakeDuration: metrics.NewHistogram(tlsBuckets),
		tlsCipherSuite:       make(map[string]uint64),
		tlsVersion:           make(map[string]uint64),
	}
}

// QUIC recording methods
func (pm *ProtocolMetrics) UpdateQUICPacketLoss(clientID string, lossRate float64) {
	pm.mu.Lock()
	pm.quicPacketLoss[clientID] = lossRate
	pm.mu.Unlock()
}

func (pm *ProtocolMetrics) UpdateQUICRTT(clientID string, rttMs float64) {
	pm.mu.Lock()
	pm.quicRTT[clientID] = rttMs
	pm.mu.Unlock()
}

func (pm *ProtocolMetrics) RecordQUICCongestion(clientID string) {
	pm.mu.Lock()
	pm.quicCongestion[clientID]++
	pm.mu.Unlock()
}

func (pm *ProtocolMetrics) RecordQUIC0RTTAccepted() {
	atomic.AddUint64(&pm.quic0RTTAccepted, 1)
}

// TLS recording methods
func (pm *ProtocolMetrics) RecordTLSHandshake(durationMs float64) {
	pm.tlsHandshakeDuration.Observe(durationMs)
}

func (pm *ProtocolMetrics) RecordTLSCipherSuite(suite string) {
	pm.mu.Lock()
	pm.tlsCipherSuite[suite]++
	pm.mu.Unlock()
}

func (pm *ProtocolMetrics) RecordTLSVersion(version string) {
	pm.mu.Lock()
	pm.tlsVersion[version]++
	pm.mu.Unlock()
}

// Export to Prometheus
func (pm *ProtocolMetrics) ExportPrometheus(w http.ResponseWriter) {
	// QUIC packet loss
	pm.mu.RLock()
	plCopy := make(map[string]float64, len(pm.quicPacketLoss))
	for k, v := range pm.quicPacketLoss {
		plCopy[k] = v
	}
	pm.mu.RUnlock()

	if len(plCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_quic_packet_loss_rate QUIC packet loss rate\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_quic_packet_loss_rate gauge\n")
		for clientID, rate := range plCopy {
			fmt.Fprintf(w, "tiredvpn_quic_packet_loss_rate{client_id=\"%s\"} %.4f\n", clientID, rate)
		}
		fmt.Fprintf(w, "\n")
	}

	// QUIC RTT
	pm.mu.RLock()
	rttCopy := make(map[string]float64, len(pm.quicRTT))
	for k, v := range pm.quicRTT {
		rttCopy[k] = v
	}
	pm.mu.RUnlock()

	if len(rttCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_quic_rtt_milliseconds QUIC RTT\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_quic_rtt_milliseconds gauge\n")
		for clientID, rtt := range rttCopy {
			fmt.Fprintf(w, "tiredvpn_quic_rtt_milliseconds{client_id=\"%s\"} %.2f\n", clientID, rtt)
		}
		fmt.Fprintf(w, "\n")
	}

	// QUIC congestion events
	pm.mu.RLock()
	congCopy := make(map[string]uint64, len(pm.quicCongestion))
	for k, v := range pm.quicCongestion {
		congCopy[k] = v
	}
	pm.mu.RUnlock()

	if len(congCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_quic_congestion_events_total QUIC congestion events\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_quic_congestion_events_total counter\n")
		for clientID, count := range congCopy {
			fmt.Fprintf(w, "tiredvpn_quic_congestion_events_total{client_id=\"%s\"} %d\n", clientID, count)
		}
		fmt.Fprintf(w, "\n")
	}

	// QUIC 0-RTT
	fmt.Fprintf(w, "# HELP tiredvpn_quic_0rtt_accepted_total QUIC 0-RTT handshakes accepted\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_quic_0rtt_accepted_total counter\n")
	fmt.Fprintf(w, "tiredvpn_quic_0rtt_accepted_total %d\n", atomic.LoadUint64(&pm.quic0RTTAccepted))
	fmt.Fprintf(w, "\n")

	// TLS handshake duration
	fmt.Fprintf(w, "# HELP tiredvpn_tls_handshake_duration_seconds TLS handshake duration\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_tls_handshake_duration_seconds histogram\n")
	fmt.Fprint(w, pm.tlsHandshakeDuration.FormatPrometheus("tiredvpn_tls_handshake_duration_seconds", nil))
	fmt.Fprintf(w, "\n")

	// TLS cipher suites
	pm.mu.RLock()
	cipherCopy := make(map[string]uint64, len(pm.tlsCipherSuite))
	for k, v := range pm.tlsCipherSuite {
		cipherCopy[k] = v
	}
	pm.mu.RUnlock()

	if len(cipherCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_tls_cipher_suite TLS cipher suite usage\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_tls_cipher_suite gauge\n")
		for suite, count := range cipherCopy {
			fmt.Fprintf(w, "tiredvpn_tls_cipher_suite{suite=\"%s\"} %d\n", suite, count)
		}
		fmt.Fprintf(w, "\n")
	}

	// TLS versions
	pm.mu.RLock()
	versionCopy := make(map[string]uint64, len(pm.tlsVersion))
	for k, v := range pm.tlsVersion {
		versionCopy[k] = v
	}
	pm.mu.RUnlock()

	if len(versionCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_tls_version TLS version usage\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_tls_version gauge\n")
		for version, count := range versionCopy {
			fmt.Fprintf(w, "tiredvpn_tls_version{version=\"%s\"} %d\n", version, count)
		}
		fmt.Fprintf(w, "\n")
	}
}
