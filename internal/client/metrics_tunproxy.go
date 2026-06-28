package client

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type TunProxyMetrics struct {
	// TUN mode metrics
	tunDNSQueries uint64
	tunMTUIssues  uint64

	// Auto-MTU active probe metrics
	mtuProbedMTU   uint64 // gauge: last applied probed MTU
	mtuProbeCount  uint64 // gauge: probe frames sent in the last run
	mtuProbeTotal  uint64 // counter: completed probe runs
	mtuProbeFallbk uint64 // counter: probe runs that fell back to static/floor

	// Proxy mode metrics
	proxyProtocol uint64 // 0=none, 1=socks5, 2=http
	poolHitRate   uint64 // hit rate * 10000 for precision
}

func NewTunProxyMetrics() *TunProxyMetrics {
	return &TunProxyMetrics{}
}

// TUN mode methods
func (tpm *TunProxyMetrics) RecordTunDNSQuery() {
	atomic.AddUint64(&tpm.tunDNSQueries, 1)
}

func (tpm *TunProxyMetrics) RecordTunMTUIssue() {
	atomic.AddUint64(&tpm.tunMTUIssues, 1)
}

// RecordMTUProbe records the outcome of a completed auto-MTU probe run.
// appliedMTU is the MTU put into effect, probes is how many frames were sent,
// and fellBack is true when the run could not measure (no capability / floor).
func (tpm *TunProxyMetrics) RecordMTUProbe(appliedMTU, probes int, fellBack bool) {
	atomic.StoreUint64(&tpm.mtuProbedMTU, uint64(appliedMTU))
	atomic.StoreUint64(&tpm.mtuProbeCount, uint64(probes))
	atomic.AddUint64(&tpm.mtuProbeTotal, 1)
	if fellBack {
		atomic.AddUint64(&tpm.mtuProbeFallbk, 1)
	}
}

// Proxy mode methods
func (tpm *TunProxyMetrics) SetProxyProtocol(protocol string) {
	var protoVal uint64
	switch protocol {
	case "socks5":
		protoVal = 1
	case "http":
		protoVal = 2
	default:
		protoVal = 0
	}
	atomic.StoreUint64(&tpm.proxyProtocol, protoVal)
}

func (tpm *TunProxyMetrics) UpdatePoolHitRate(hitRate float64) {
	// Store as uint64 (multiply by 10000 for precision)
	if hitRate < 0.0 {
		hitRate = 0.0
	}
	if hitRate > 1.0 {
		hitRate = 1.0
	}
	atomic.StoreUint64(&tpm.poolHitRate, uint64(hitRate*10000))
}

func (tpm *TunProxyMetrics) ExportPrometheus(w http.ResponseWriter) {
	// TUN DNS queries
	fmt.Fprintf(w, "# HELP tiredvpn_local_tun_dns_queries_total DNS queries handled in TUN mode\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_tun_dns_queries_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_tun_dns_queries_total %d\n", atomic.LoadUint64(&tpm.tunDNSQueries))
	fmt.Fprintf(w, "\n")

	// TUN MTU issues
	fmt.Fprintf(w, "# HELP tiredvpn_local_tun_mtu_issues_total MTU/fragmentation issues in TUN mode\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_tun_mtu_issues_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_tun_mtu_issues_total %d\n", atomic.LoadUint64(&tpm.tunMTUIssues))
	fmt.Fprintf(w, "\n")

	// Auto-MTU probe
	fmt.Fprintf(w, "# HELP tiredvpn_local_mtu_probed The MTU put into effect by the auto-MTU probe\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_mtu_probed gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_mtu_probed %d\n", atomic.LoadUint64(&tpm.mtuProbedMTU))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_local_mtu_probe_frames Probe frames sent in the last auto-MTU run\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_mtu_probe_frames gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_mtu_probe_frames %d\n", atomic.LoadUint64(&tpm.mtuProbeCount))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_local_mtu_probe_total Completed auto-MTU probe runs\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_mtu_probe_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_mtu_probe_total %d\n", atomic.LoadUint64(&tpm.mtuProbeTotal))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP tiredvpn_local_mtu_probe_fallback_total Auto-MTU runs that fell back to static/floor\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_mtu_probe_fallback_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_mtu_probe_fallback_total %d\n", atomic.LoadUint64(&tpm.mtuProbeFallbk))
	fmt.Fprintf(w, "\n")

	// Proxy protocol
	protoVal := atomic.LoadUint64(&tpm.proxyProtocol)
	var protoStr string
	switch protoVal {
	case 1:
		protoStr = "socks5"
	case 2:
		protoStr = "http"
	default:
		protoStr = "none"
	}

	fmt.Fprintf(w, "# HELP tiredvpn_local_proxy_protocol Proxy protocol type\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_proxy_protocol gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_proxy_protocol{protocol=\"%s\"} 1\n", protoStr)
	fmt.Fprintf(w, "\n")

	// Pool hit rate
	hitRate := float64(atomic.LoadUint64(&tpm.poolHitRate)) / 10000.0
	fmt.Fprintf(w, "# HELP tiredvpn_local_pool_hit_rate Connection pool hit ratio\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_pool_hit_rate gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_pool_hit_rate %.4f\n", hitRate)
	fmt.Fprintf(w, "\n")
}
