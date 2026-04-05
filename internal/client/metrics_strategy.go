package client

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

// StrategyMetrics collects detailed strategy performance metrics
type StrategyMetrics struct {
	// Histograms
	tlsHandshakeDuration *metrics.Histogram
	connectRetries       *metrics.Histogram
	phasesDuration       map[string]*metrics.Histogram
	fallbackChainLength  *metrics.Histogram

	// Counters with labels (require mutex for map access)
	mu               sync.RWMutex
	selectionReasons map[string]uint64
	strategySwitches map[string]uint64
	protocolOverhead map[string]uint64
}

// NewStrategyMetrics creates a new strategy metrics collector
func NewStrategyMetrics() *StrategyMetrics {
	// TLS handshake duration buckets (milliseconds)
	// Covers 10ms to 5s for various network conditions
	tlsBuckets := []float64{10, 50, 100, 200, 500, 1000, 2000, 5000}

	// Connection retry buckets (count)
	retryBuckets := []float64{0, 1, 2, 3, 5, 10, 20}

	// Connection phase timing buckets (milliseconds)
	// For DNS, TCP, TLS, App layer phases
	phaseBuckets := []float64{1, 5, 10, 50, 100, 500, 1000}

	// Fallback chain depth buckets (strategy count)
	fallbackBuckets := []float64{0, 1, 2, 3, 4, 5}

	return &StrategyMetrics{
		tlsHandshakeDuration: metrics.NewHistogram(tlsBuckets),
		connectRetries:       metrics.NewHistogram(retryBuckets),
		fallbackChainLength:  metrics.NewHistogram(fallbackBuckets),
		phasesDuration: map[string]*metrics.Histogram{
			"dns": metrics.NewHistogram(phaseBuckets),
			"tcp": metrics.NewHistogram(phaseBuckets),
			"tls": metrics.NewHistogram(phaseBuckets),
			"app": metrics.NewHistogram(phaseBuckets),
		},
		selectionReasons: make(map[string]uint64),
		strategySwitches: make(map[string]uint64),
		protocolOverhead: make(map[string]uint64),
	}
}

// RecordTLSHandshake records TLS handshake duration for a strategy
func (sm *StrategyMetrics) RecordTLSHandshake(strategyID string, duration time.Duration) {
	sm.tlsHandshakeDuration.Observe(float64(duration.Milliseconds()))
}

// RecordConnectRetries records number of retry attempts for a connection
func (sm *StrategyMetrics) RecordConnectRetries(strategyID string, retries int) {
	sm.connectRetries.Observe(float64(retries))
}

// RecordSelectionReason records why a strategy was selected
func (sm *StrategyMetrics) RecordSelectionReason(reason string) {
	sm.mu.Lock()
	sm.selectionReasons[reason]++
	sm.mu.Unlock()
}

// RecordPhaseDuration records connection phase duration (dns/tcp/tls/app)
func (sm *StrategyMetrics) RecordPhaseDuration(phase string, duration time.Duration) {
	if hist, ok := sm.phasesDuration[phase]; ok {
		hist.Observe(float64(duration.Milliseconds()))
	}
}

// RecordStrategySwitch records a switch from one strategy to another
func (sm *StrategyMetrics) RecordStrategySwitch(fromID, toID string) {
	key := fmt.Sprintf("%s:%s", fromID, toID)
	sm.mu.Lock()
	sm.strategySwitches[key]++
	sm.mu.Unlock()
}

// RecordFallbackDepth records the depth of fallback chain used
func (sm *StrategyMetrics) RecordFallbackDepth(depth int) {
	sm.fallbackChainLength.Observe(float64(depth))
}

// RecordProtocolOverhead records protocol overhead in bytes for a strategy
func (sm *StrategyMetrics) RecordProtocolOverhead(strategyID string, bytes uint64) {
	sm.mu.Lock()
	sm.protocolOverhead[strategyID] += bytes
	sm.mu.Unlock()
}

// ExportPrometheus exports strategy metrics in Prometheus format
func (sm *StrategyMetrics) ExportPrometheus(w http.ResponseWriter) {
	// TLS handshake duration histogram
	fmt.Fprintf(w, "# HELP tiredvpn_local_tls_handshake_duration_seconds TLS handshake duration distribution\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_tls_handshake_duration_seconds histogram\n")
	fmt.Fprint(w, sm.tlsHandshakeDuration.FormatPrometheus("tiredvpn_local_tls_handshake_duration_seconds", nil))
	fmt.Fprintf(w, "\n")

	// Connect retries histogram
	fmt.Fprintf(w, "# HELP tiredvpn_local_connect_retries Connection retry attempts distribution\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_connect_retries histogram\n")
	fmt.Fprint(w, sm.connectRetries.FormatPrometheus("tiredvpn_local_connect_retries", nil))
	fmt.Fprintf(w, "\n")

	// Strategy selection reasons
	sm.mu.RLock()
	selectionReasonsCopy := make(map[string]uint64, len(sm.selectionReasons))
	for k, v := range sm.selectionReasons {
		selectionReasonsCopy[k] = v
	}
	sm.mu.RUnlock()

	if len(selectionReasonsCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_selection_reason Strategy selection reason counter\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_selection_reason counter\n")
		for reason, count := range selectionReasonsCopy {
			fmt.Fprintf(w, "tiredvpn_local_strategy_selection_reason{reason=\"%s\"} %d\n", reason, count)
		}
		fmt.Fprintf(w, "\n")
	}

	// Protocol overhead per strategy
	sm.mu.RLock()
	protocolOverheadCopy := make(map[string]uint64, len(sm.protocolOverhead))
	for k, v := range sm.protocolOverhead {
		protocolOverheadCopy[k] = v
	}
	sm.mu.RUnlock()

	if len(protocolOverheadCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_local_protocol_overhead_bytes Protocol overhead in bytes per strategy\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_protocol_overhead_bytes gauge\n")
		for strategyID, bytes := range protocolOverheadCopy {
			fmt.Fprintf(w, "tiredvpn_local_protocol_overhead_bytes{strategy_id=\"%s\"} %d\n", strategyID, bytes)
		}
		fmt.Fprintf(w, "\n")
	}

	// Connection phase durations
	for phase, hist := range sm.phasesDuration {
		fmt.Fprintf(w, "# HELP tiredvpn_local_connect_phases_duration_seconds Connection phase duration distribution\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_connect_phases_duration_seconds histogram\n")
		labels := map[string]string{"phase": phase}
		fmt.Fprint(w, hist.FormatPrometheus("tiredvpn_local_connect_phases_duration_seconds", labels))
		fmt.Fprintf(w, "\n")
	}

	// Strategy switches
	sm.mu.RLock()
	strategySwitchesCopy := make(map[string]uint64, len(sm.strategySwitches))
	for k, v := range sm.strategySwitches {
		strategySwitchesCopy[k] = v
	}
	sm.mu.RUnlock()

	if len(strategySwitchesCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_switch_total Strategy switch counter\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_switch_total counter\n")
		for key, count := range strategySwitchesCopy {
			parts := strings.Split(key, ":")
			if len(parts) == 2 {
				fmt.Fprintf(w, "tiredvpn_local_strategy_switch_total{from=\"%s\",to=\"%s\"} %d\n",
					parts[0], parts[1], count)
			}
		}
		fmt.Fprintf(w, "\n")
	}

	// Fallback chain length histogram
	fmt.Fprintf(w, "# HELP tiredvpn_local_fallback_chain_length Fallback chain depth distribution\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_fallback_chain_length histogram\n")
	fmt.Fprint(w, sm.fallbackChainLength.FormatPrometheus("tiredvpn_local_fallback_chain_length", nil))
	fmt.Fprintf(w, "\n")
}
