package client

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
)

type ClientDPIMetrics struct {
	mu sync.RWMutex

	// DPI blocks suspected
	dpiBlocksSuspected map[string]uint64 // pattern -> count

	// Fallback triggers
	fallbackTriggers map[string]uint64 // reason -> count

	// ECH enabled flag
	echEnabled uint64 // 0 or 1

	// SNI fragmentation events
	sniFragEvents uint64

	// Censorship detected by type
	censorshipDetected map[string]uint64 // type -> count
}

func NewClientDPIMetrics() *ClientDPIMetrics {
	return &ClientDPIMetrics{
		dpiBlocksSuspected: make(map[string]uint64),
		fallbackTriggers:   make(map[string]uint64),
		censorshipDetected: make(map[string]uint64),
	}
}

func (cdm *ClientDPIMetrics) RecordDPIBlockSuspected(pattern string) {
	cdm.mu.Lock()
	cdm.dpiBlocksSuspected[pattern]++
	cdm.mu.Unlock()
}

func (cdm *ClientDPIMetrics) RecordFallbackTrigger(reason string) {
	cdm.mu.Lock()
	cdm.fallbackTriggers[reason]++
	cdm.mu.Unlock()
}

func (cdm *ClientDPIMetrics) SetECHEnabled(enabled bool) {
	if enabled {
		atomic.StoreUint64(&cdm.echEnabled, 1)
	} else {
		atomic.StoreUint64(&cdm.echEnabled, 0)
	}
}

func (cdm *ClientDPIMetrics) RecordSNIFragmentation() {
	atomic.AddUint64(&cdm.sniFragEvents, 1)
}

func (cdm *ClientDPIMetrics) RecordCensorshipDetected(censorType string) {
	cdm.mu.Lock()
	cdm.censorshipDetected[censorType]++
	cdm.mu.Unlock()
}

func (cdm *ClientDPIMetrics) ExportPrometheus(w http.ResponseWriter) {
	// DPI blocks suspected
	cdm.mu.RLock()
	blocksCopy := make(map[string]uint64, len(cdm.dpiBlocksSuspected))
	for k, v := range cdm.dpiBlocksSuspected {
		blocksCopy[k] = v
	}
	cdm.mu.RUnlock()

	if len(blocksCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_local_dpi_blocks_suspected_total Suspected DPI blocks\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_dpi_blocks_suspected_total counter\n")
		for pattern, count := range blocksCopy {
			fmt.Fprintf(w, "tiredvpn_local_dpi_blocks_suspected_total{pattern=\"%s\"} %d\n", pattern, count)
		}
		fmt.Fprintf(w, "\n")
	}

	// Fallback triggers
	cdm.mu.RLock()
	triggersCopy := make(map[string]uint64, len(cdm.fallbackTriggers))
	for k, v := range cdm.fallbackTriggers {
		triggersCopy[k] = v
	}
	cdm.mu.RUnlock()

	if len(triggersCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_local_fallback_trigger Fallback trigger reasons\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_fallback_trigger counter\n")
		for reason, count := range triggersCopy {
			fmt.Fprintf(w, "tiredvpn_local_fallback_trigger{reason=\"%s\"} %d\n", reason, count)
		}
		fmt.Fprintf(w, "\n")
	}

	// ECH enabled
	fmt.Fprintf(w, "# HELP tiredvpn_local_ech_enabled ECH (Encrypted Client Hello) enabled\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_ech_enabled gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_ech_enabled %d\n", atomic.LoadUint64(&cdm.echEnabled))
	fmt.Fprintf(w, "\n")

	// SNI fragmentation
	fmt.Fprintf(w, "# HELP tiredvpn_local_sni_fragmentation_events_total SNI fragmentation events\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_sni_fragmentation_events_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_sni_fragmentation_events_total %d\n", atomic.LoadUint64(&cdm.sniFragEvents))
	fmt.Fprintf(w, "\n")

	// Censorship detected
	cdm.mu.RLock()
	censorCopy := make(map[string]uint64, len(cdm.censorshipDetected))
	for k, v := range cdm.censorshipDetected {
		censorCopy[k] = v
	}
	cdm.mu.RUnlock()

	if len(censorCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_local_censorship_detected_total Censorship detected by type\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_censorship_detected_total counter\n")
		for censorType, count := range censorCopy {
			fmt.Fprintf(w, "tiredvpn_local_censorship_detected_total{type=\"%s\"} %d\n", censorType, count)
		}
		fmt.Fprintf(w, "\n")
	}
}
