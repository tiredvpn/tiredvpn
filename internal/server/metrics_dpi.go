package server

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/tiredvpn/tiredvpn/internal/metrics"
)

type DPIMetrics struct {
	mu sync.RWMutex

	// DPI probe detection counters by type
	probesDetected map[string]uint64 // type -> count

	// Protocol confusion success rates by type
	confusionSuccess map[string]*metrics.Histogram

	// Geneva effectiveness tracking
	genevaEffectiveness map[string]float64 // "country:strategy_id" -> success_rate

	// Traffic morphing accuracy
	morphingScore map[string]float64 // profile -> score (0.0-1.0)

	// Counters
	sniFragmentation uint64
	realitySuccess   uint64
	realityRejected  uint64
	echUsage         uint64
	postQuantumHS    uint64
}

func NewDPIMetrics() *DPIMetrics {
	return &DPIMetrics{
		probesDetected:      make(map[string]uint64),
		confusionSuccess:    make(map[string]*metrics.Histogram),
		genevaEffectiveness: make(map[string]float64),
		morphingScore:       make(map[string]float64),
	}
}

// Recording methods
func (dm *DPIMetrics) RecordProbeDetected(probeType string) {
	dm.mu.Lock()
	dm.probesDetected[probeType]++
	dm.mu.Unlock()
}

func (dm *DPIMetrics) RecordProtocolConfusion(confusionType string, success bool) {
	dm.mu.Lock()
	if _, ok := dm.confusionSuccess[confusionType]; !ok {
		successBuckets := []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}
		dm.confusionSuccess[confusionType] = metrics.NewHistogram(successBuckets)
	}
	if success {
		dm.confusionSuccess[confusionType].Observe(1.0)
	} else {
		dm.confusionSuccess[confusionType].Observe(0.0)
	}
	dm.mu.Unlock()
}

func (dm *DPIMetrics) UpdateGenevaEffectiveness(country, strategyID string, successRate float64) {
	key := fmt.Sprintf("%s:%s", country, strategyID)
	dm.mu.Lock()
	dm.genevaEffectiveness[key] = successRate
	dm.mu.Unlock()
}

func (dm *DPIMetrics) UpdateMorphingScore(profile string, score float64) {
	dm.mu.Lock()
	dm.morphingScore[profile] = score
	dm.mu.Unlock()
}

func (dm *DPIMetrics) RecordSNIFragmentation() {
	atomic.AddUint64(&dm.sniFragmentation, 1)
}

func (dm *DPIMetrics) RecordREALITYHandshake(success bool) {
	if success {
		atomic.AddUint64(&dm.realitySuccess, 1)
	} else {
		atomic.AddUint64(&dm.realityRejected, 1)
	}
}

func (dm *DPIMetrics) RecordECHUsage() {
	atomic.AddUint64(&dm.echUsage, 1)
}

func (dm *DPIMetrics) RecordPostQuantumHandshake() {
	atomic.AddUint64(&dm.postQuantumHS, 1)
}

// Export to Prometheus
func (dm *DPIMetrics) ExportPrometheus(w http.ResponseWriter) {
	// DPI probes detected
	dm.mu.RLock()
	probesCopy := make(map[string]uint64, len(dm.probesDetected))
	for k, v := range dm.probesDetected {
		probesCopy[k] = v
	}
	dm.mu.RUnlock()

	if len(probesCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_dpi_probes_detected_total DPI probes detected by type\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_dpi_probes_detected_total counter\n")
		for probeType, count := range probesCopy {
			fmt.Fprintf(w, "tiredvpn_dpi_probes_detected_total{type=\"%s\"} %d\n", probeType, count)
		}
		fmt.Fprintf(w, "\n")
	}

	// Protocol confusion success rates
	dm.mu.RLock()
	confusionCopy := make(map[string]*metrics.Histogram, len(dm.confusionSuccess))
	for k, v := range dm.confusionSuccess {
		confusionCopy[k] = v
	}
	dm.mu.RUnlock()

	for confType, hist := range confusionCopy {
		fmt.Fprintf(w, "# HELP tiredvpn_protocol_confusion_success_rate Protocol confusion effectiveness\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_protocol_confusion_success_rate histogram\n")
		labels := map[string]string{"type": confType}
		fmt.Fprint(w, hist.FormatPrometheus("tiredvpn_protocol_confusion_success_rate", labels))
		fmt.Fprintf(w, "\n")
	}

	// Geneva effectiveness
	dm.mu.RLock()
	genevaCopy := make(map[string]float64, len(dm.genevaEffectiveness))
	for k, v := range dm.genevaEffectiveness {
		genevaCopy[k] = v
	}
	dm.mu.RUnlock()

	if len(genevaCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_geneva_effectiveness Geneva strategy effectiveness\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_geneva_effectiveness gauge\n")
		for key, rate := range genevaCopy {
			// Parse "country:strategy_id"
			fmt.Fprintf(w, "tiredvpn_geneva_effectiveness{key=\"%s\"} %.4f\n", key, rate)
		}
		fmt.Fprintf(w, "\n")
	}

	// Traffic morphing score
	dm.mu.RLock()
	morphCopy := make(map[string]float64, len(dm.morphingScore))
	for k, v := range dm.morphingScore {
		morphCopy[k] = v
	}
	dm.mu.RUnlock()

	if len(morphCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_traffic_morph_mimicry_score Traffic morphing accuracy\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_traffic_morph_mimicry_score gauge\n")
		for profile, score := range morphCopy {
			fmt.Fprintf(w, "tiredvpn_traffic_morph_mimicry_score{profile=\"%s\"} %.4f\n", profile, score)
		}
		fmt.Fprintf(w, "\n")
	}

	// SNI fragmentation
	fmt.Fprintf(w, "# HELP tiredvpn_sni_fragmentation_events_total SNI fragmentation events\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_sni_fragmentation_events_total counter\n")
	fmt.Fprintf(w, "tiredvpn_sni_fragmentation_events_total %d\n", atomic.LoadUint64(&dm.sniFragmentation))
	fmt.Fprintf(w, "\n")

	// REALITY handshakes
	fmt.Fprintf(w, "# HELP tiredvpn_reality_handshake_result_total REALITY handshake results\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_reality_handshake_result_total counter\n")
	fmt.Fprintf(w, "tiredvpn_reality_handshake_result_total{result=\"success\"} %d\n", atomic.LoadUint64(&dm.realitySuccess))
	fmt.Fprintf(w, "tiredvpn_reality_handshake_result_total{result=\"rejected\"} %d\n", atomic.LoadUint64(&dm.realityRejected))
	fmt.Fprintf(w, "\n")

	// ECH usage
	fmt.Fprintf(w, "# HELP tiredvpn_ech_usage_total ECH (Encrypted Client Hello) usage\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_ech_usage_total counter\n")
	fmt.Fprintf(w, "tiredvpn_ech_usage_total %d\n", atomic.LoadUint64(&dm.echUsage))
	fmt.Fprintf(w, "\n")

	// Post-quantum handshakes
	fmt.Fprintf(w, "# HELP tiredvpn_postquantum_handshakes_total Post-quantum crypto handshakes\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_postquantum_handshakes_total counter\n")
	fmt.Fprintf(w, "tiredvpn_postquantum_handshakes_total %d\n", atomic.LoadUint64(&dm.postQuantumHS))
	fmt.Fprintf(w, "\n")
}
