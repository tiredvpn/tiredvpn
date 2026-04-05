package server

import (
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"unsafe"
)

type IPv6Metrics struct {
	ipv6Connections uint64
	ipv4Connections uint64
	ipv6Fallbacks   uint64
	ipv6Preference  float64 // atomic stored as uint64
}

func NewIPv6Metrics() *IPv6Metrics {
	return &IPv6Metrics{}
}

func (im *IPv6Metrics) RecordIPv6Connection() {
	atomic.AddUint64(&im.ipv6Connections, 1)
	im.updatePreference()
}

func (im *IPv6Metrics) RecordIPv4Connection() {
	atomic.AddUint64(&im.ipv4Connections, 1)
	im.updatePreference()
}

func (im *IPv6Metrics) RecordIPv6Fallback() {
	atomic.AddUint64(&im.ipv6Fallbacks, 1)
}

func (im *IPv6Metrics) updatePreference() {
	v6 := atomic.LoadUint64(&im.ipv6Connections)
	v4 := atomic.LoadUint64(&im.ipv4Connections)
	total := v6 + v4
	if total > 0 {
		pref := float64(v6) / float64(total)
		// Store float64 as uint64 bits for atomic operations
		bits := math.Float64bits(pref)
		atomic.StoreUint64((*uint64)(unsafe.Pointer(&im.ipv6Preference)), bits)
	}
}

func (im *IPv6Metrics) ExportPrometheus(w http.ResponseWriter) {
	fmt.Fprintf(w, "# HELP tiredvpn_ipv6_connections_total IPv6 connections\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_ipv6_connections_total counter\n")
	fmt.Fprintf(w, "tiredvpn_ipv6_connections_total %d\n", atomic.LoadUint64(&im.ipv6Connections))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_ipv4_connections_total IPv4 connections\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_ipv4_connections_total counter\n")
	fmt.Fprintf(w, "tiredvpn_ipv4_connections_total %d\n", atomic.LoadUint64(&im.ipv4Connections))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_ipv6_fallback_events_total IPv6 to IPv4 fallback events\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_ipv6_fallback_events_total counter\n")
	fmt.Fprintf(w, "tiredvpn_ipv6_fallback_events_total %d\n", atomic.LoadUint64(&im.ipv6Fallbacks))
	fmt.Fprintf(w, "\n")

	bits := atomic.LoadUint64((*uint64)(unsafe.Pointer(&im.ipv6Preference)))
	pref := math.Float64frombits(bits)
	fmt.Fprintf(w, "# HELP tiredvpn_dualstack_preference Dual-stack preference (IPv6 ratio)\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_dualstack_preference gauge\n")
	fmt.Fprintf(w, "tiredvpn_dualstack_preference{version=\"6\"} %.4f\n", pref)
	fmt.Fprintf(w, "tiredvpn_dualstack_preference{version=\"4\"} %.4f\n", 1.0-pref)
	fmt.Fprintf(w, "\n")
}
