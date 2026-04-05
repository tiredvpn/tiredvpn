package server

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
)

type PortHoppingMetrics struct {
	mu sync.RWMutex

	// Active ports tracking
	activePorts uint64 // atomic

	// Port hop events
	hopEvents uint64 // atomic

	// Connections per port
	connectionsPerPort map[int]uint64 // port -> count
}

func NewPortHoppingMetrics() *PortHoppingMetrics {
	return &PortHoppingMetrics{
		connectionsPerPort: make(map[int]uint64),
	}
}

func (phm *PortHoppingMetrics) SetActivePorts(count uint64) {
	atomic.StoreUint64(&phm.activePorts, count)
}

func (phm *PortHoppingMetrics) RecordPortHop() {
	atomic.AddUint64(&phm.hopEvents, 1)
}

func (phm *PortHoppingMetrics) RecordConnectionOnPort(port int) {
	phm.mu.Lock()
	phm.connectionsPerPort[port]++
	phm.mu.Unlock()
}

func (phm *PortHoppingMetrics) ExportPrometheus(w http.ResponseWriter) {
	// Active ports
	fmt.Fprintf(w, "# HELP tiredvpn_porthopping_active_ports Currently listening ports\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_porthopping_active_ports gauge\n")
	fmt.Fprintf(w, "tiredvpn_porthopping_active_ports %d\n", atomic.LoadUint64(&phm.activePorts))
	fmt.Fprintf(w, "\n")

	// Hop events
	fmt.Fprintf(w, "# HELP tiredvpn_porthopping_hop_events_total Port hop events\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_porthopping_hop_events_total counter\n")
	fmt.Fprintf(w, "tiredvpn_porthopping_hop_events_total %d\n", atomic.LoadUint64(&phm.hopEvents))
	fmt.Fprintf(w, "\n")

	// Connections per port
	phm.mu.RLock()
	connCopy := make(map[int]uint64, len(phm.connectionsPerPort))
	for k, v := range phm.connectionsPerPort {
		connCopy[k] = v
	}
	phm.mu.RUnlock()

	if len(connCopy) > 0 {
		fmt.Fprintf(w, "# HELP tiredvpn_porthopping_connections_per_port Connection distribution per port\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_porthopping_connections_per_port gauge\n")
		for port, count := range connCopy {
			fmt.Fprintf(w, "tiredvpn_porthopping_connections_per_port{port=\"%d\"} %d\n", port, count)
		}
		fmt.Fprintf(w, "\n")
	}
}
