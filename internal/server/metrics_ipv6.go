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

	// In-tunnel dual-stack dispatch counters (SharedTUN downlink).
	tunnelV6Routed        uint64
	tunnelV6DropNotInPool uint64
	tunnelV6DropShortHdr  uint64

	// Dual-stack TUN session setups negotiated (handshake response carried the
	// v6 address block to a v0x04+ client, local or relayed). One per session
	// setup: a reconnect is a new session and counts again.
	tunnelDualStackSessions uint64
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

// RecordTunnelV6Routed counts an in-tunnel IPv6 packet accepted for dispatch
// to a client (destination inside the dual-stack pool prefix).
func (im *IPv6Metrics) RecordTunnelV6Routed() {
	atomic.AddUint64(&im.tunnelV6Routed, 1)
}

// RecordTunnelV6DropNotInPool counts an in-tunnel IPv6 packet dropped because
// its destination is outside the dual-stack pool prefix.
func (im *IPv6Metrics) RecordTunnelV6DropNotInPool() {
	atomic.AddUint64(&im.tunnelV6DropNotInPool, 1)
}

// RecordTunnelV6DropShortHeader counts an in-tunnel IPv6 packet dropped
// because it is shorter than the 40-byte IPv6 header.
func (im *IPv6Metrics) RecordTunnelV6DropShortHeader() {
	atomic.AddUint64(&im.tunnelV6DropShortHdr, 1)
}

// RecordTunnelDualStackSession counts a TUN session setup that negotiated
// dual-stack: the handshake response carried the IPv6 address block to a
// v0x04+ client, whether terminated locally or relayed from the exit. A
// reconnect establishes a new session and is counted again.
func (im *IPv6Metrics) RecordTunnelDualStackSession() {
	atomic.AddUint64(&im.tunnelDualStackSessions, 1)
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

	fmt.Fprintf(w, "# HELP tiredvpn_tunnel_ipv6_packets_routed_total In-tunnel IPv6 packets dispatched to clients\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_tunnel_ipv6_packets_routed_total counter\n")
	fmt.Fprintf(w, "tiredvpn_tunnel_ipv6_packets_routed_total %d\n", atomic.LoadUint64(&im.tunnelV6Routed))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_tunnel_ipv6_packets_dropped_total In-tunnel IPv6 packets dropped before dispatch\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_tunnel_ipv6_packets_dropped_total counter\n")
	fmt.Fprintf(w, "tiredvpn_tunnel_ipv6_packets_dropped_total{reason=\"not_in_pool\"} %d\n", atomic.LoadUint64(&im.tunnelV6DropNotInPool))
	fmt.Fprintf(w, "tiredvpn_tunnel_ipv6_packets_dropped_total{reason=\"short_header\"} %d\n", atomic.LoadUint64(&im.tunnelV6DropShortHdr))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_tunnel_dualstack_sessions_total TUN session setups that negotiated in-tunnel IPv6 dual-stack (one per handshake answered with the v6 address block, so a reconnect counts again)\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_tunnel_dualstack_sessions_total counter\n")
	fmt.Fprintf(w, "tiredvpn_tunnel_dualstack_sessions_total %d\n", atomic.LoadUint64(&im.tunnelDualStackSessions))
	fmt.Fprintf(w, "\n")

	bits := atomic.LoadUint64((*uint64)(unsafe.Pointer(&im.ipv6Preference)))
	pref := math.Float64frombits(bits)
	fmt.Fprintf(w, "# HELP tiredvpn_dualstack_preference Dual-stack preference (IPv6 ratio)\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_dualstack_preference gauge\n")
	fmt.Fprintf(w, "tiredvpn_dualstack_preference{version=\"6\"} %.4f\n", pref)
	fmt.Fprintf(w, "tiredvpn_dualstack_preference{version=\"4\"} %.4f\n", 1.0-pref)
	fmt.Fprintf(w, "\n")
}
