package server

import (
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// renderMetrics runs the /metrics handler and returns its body. Every
// assertion below goes through the real handler rather than the individual
// exporters, because the handler is what Prometheus actually scrapes.
func renderMetrics(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler()(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("/metrics returned %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain (Prometheus rejects anything else)", ct)
	}
	return rec.Body.String()
}

// mustContain fails with the rendered body when a metric line is missing, so a
// dropped exporter is immediately visible instead of showing up as a silently
// empty dashboard.
func mustContain(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if !strings.Contains(body, line) {
			t.Errorf("missing from /metrics: %q", line)
		}
	}
}

// TestMetricsServerCounters covers the server-wide counters and their exported
// values. These feed the connection and traffic dashboards; a counter that
// stops moving looks exactly like an idle server.
func TestMetricsServerCounters(t *testing.T) {
	m := NewMetrics(nil)

	m.IncConnections()
	m.IncConnections()
	m.IncConnections()
	m.DecConnections()
	m.AddBytes(1500, 9000)
	m.AddBytes(500, 1000)
	m.IncAuthFailures()
	m.IncAuthFailures()
	m.IncConnectionErrors()

	if got := atomic.LoadInt64(&m.totalConnections); got != 3 {
		t.Errorf("totalConnections = %d, want 3", got)
	}
	if got := atomic.LoadInt64(&m.activeConnections); got != 2 {
		t.Errorf("activeConnections = %d, want 2 (3 opened, 1 closed)", got)
	}

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_connections_total 3",
		"tiredvpn_connections_active 2",
		"tiredvpn_bytes_received_total 2000", // up
		"tiredvpn_bytes_sent_total 10000",    // down
		"tiredvpn_auth_failures_total 2",
		"tiredvpn_connection_errors_total 1",
		"tiredvpn_clients_total 0", // nil registry must not omit the series
		"tiredvpn_info{version=",
		"tiredvpn_uptime_seconds ",
	)

	// DecConnections is allowed to run past zero on a restart race; it must not
	// panic or wedge the handler.
	m.DecConnections()
	m.DecConnections()
	m.DecConnections()
	if body := renderMetrics(t, m); !strings.Contains(body, "tiredvpn_connections_active -1") {
		t.Errorf("active connection gauge did not render a negative value:\n%s", body)
	}
}

// TestMetricsPerClientExport covers the registry-backed half of the handler:
// per-client series must appear with the client's own labels, otherwise a
// per-tenant dashboard silently aggregates everybody together.
func TestMetricsPerClientExport(t *testing.T) {
	r := NewClientRegistry(nil)
	var conns, up, down int64
	r.byID["c1"] = &ClientConfig{
		ID: "c1", Name: "alice", Secret: "s1", Enabled: true, MaxConns: 4,
		ExpiresAt: time.Unix(1893456000, 0),
	}
	r.bySecret["s1"] = r.byID["c1"]
	r.totalConns["c1"] = &conns
	r.bytesUp["c1"] = &up
	r.bytesDown["c1"] = &down

	m := NewMetrics(r)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := r.AddConnection("c1", a); err != nil {
		t.Fatalf("AddConnection: %v", err)
	}
	r.AddBytes("c1", 111, 222)

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_clients_total 1",
		`tiredvpn_client_connections_active{client_id="c1",client_name="alice"} 1`,
		`tiredvpn_client_connections_total{client_id="c1",client_name="alice"} 1`,
		`tiredvpn_client_bytes_received_total{client_id="c1",client_name="alice"} 111`,
		`tiredvpn_client_bytes_sent_total{client_id="c1",client_name="alice"} 222`,
		`tiredvpn_client_info{client_id="c1",client_name="alice",max_conns="4"} 1`,
		`tiredvpn_client_expires_timestamp_seconds{client_id="c1",client_name="alice"} 1893456000`,
	)

	// A disabled client still gets a series, with the info gauge at 0 — the
	// alternative (dropping the series) reads as "client deleted".
	r.byID["c2"] = &ClientConfig{ID: "c2", Name: "bob", Enabled: false}
	body = renderMetrics(t, m)
	mustContain(t, body, `tiredvpn_client_info{client_id="c2",client_name="bob",max_conns="0"} 0`)
	// A never-expiring client exports 0, not a negative or garbage timestamp.
	mustContain(t, body, `tiredvpn_client_expires_timestamp_seconds{client_id="c2",client_name="bob"} 0`)
}

// TestMetricsDPIExport covers the DPI counters and the map-keyed series. These
// are the numbers that say whether a censor is probing us, so a label that
// stops being emitted hides an active probe campaign.
func TestMetricsDPIExport(t *testing.T) {
	m := NewMetrics(nil)
	dm := m.dpiMetrics

	dm.RecordProbeDetected("active-probe")
	dm.RecordProbeDetected("active-probe")
	dm.RecordProbeDetected("tls-replay")
	dm.RecordProtocolConfusion("ssh", true)
	dm.RecordProtocolConfusion("ssh", false)
	dm.RecordProtocolConfusion("imap", true)
	dm.UpdateGenevaEffectiveness("RU", "strategy-7", 0.75)
	dm.UpdateMorphingScore("chrome-h2", 0.9)
	dm.RecordSNIFragmentation()
	dm.RecordREALITYHandshake(true)
	dm.RecordREALITYHandshake(true)
	dm.RecordREALITYHandshake(false)
	dm.RecordECHUsage()
	dm.RecordPostQuantumHandshake()

	body := renderMetrics(t, m)
	mustContain(t, body,
		`tiredvpn_dpi_probes_detected_total{type="active-probe"} 2`,
		`tiredvpn_dpi_probes_detected_total{type="tls-replay"} 1`,
		`tiredvpn_geneva_effectiveness{key="RU:strategy-7"} 0.7500`,
		`tiredvpn_traffic_morph_mimicry_score{profile="chrome-h2"} 0.9000`,
		"tiredvpn_sni_fragmentation_events_total 1",
		`tiredvpn_reality_handshake_result_total{result="success"} 2`,
		`tiredvpn_reality_handshake_result_total{result="rejected"} 1`,
		"tiredvpn_ech_usage_total 1",
		"tiredvpn_postquantum_handshakes_total 1",
		"tiredvpn_protocol_confusion_success_rate",
	)

	// The success/rejected split must be independent: a rejected handshake that
	// also bumped the success counter would make an outage look healthy.
	if got := atomic.LoadUint64(&dm.realitySuccess); got != 2 {
		t.Errorf("realitySuccess = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&dm.realityRejected); got != 1 {
		t.Errorf("realityRejected = %d, want 1", got)
	}
}

// TestMetricsEmptyMapsOmitSeries pins the "no data, no series" rule for the
// map-keyed exporters. Emitting a bare HELP/TYPE header with no samples is
// what makes Prometheus log a parse warning on every scrape.
func TestMetricsEmptyMapsOmitSeries(t *testing.T) {
	m := NewMetrics(nil)
	body := renderMetrics(t, m)

	for _, absent := range []string{
		"tiredvpn_dpi_probes_detected_total",
		"tiredvpn_geneva_effectiveness",
		"tiredvpn_traffic_morph_mimicry_score",
		"tiredvpn_relay_upstream_health",
	} {
		if strings.Contains(body, absent) {
			t.Errorf("%s exported with no data recorded", absent)
		}
	}

	// Plain counters, by contrast, must always be present at zero so a fresh
	// server does not look like a broken exporter.
	mustContain(t, body,
		"tiredvpn_sni_fragmentation_events_total 0",
		"tiredvpn_ech_usage_total 0",
		"tiredvpn_tunnel_dualstack_sessions_total 0",
		"tiredvpn_relay_latency_overhead_milliseconds 0.00",
	)
}

// TestMetricsProtocolExport covers the QUIC/TLS series.
func TestMetricsProtocolExport(t *testing.T) {
	m := NewMetrics(nil)
	pm := m.protocolMetrics

	pm.UpdateQUICPacketLoss("client-a", 0.05)
	pm.UpdateQUICRTT("client-a", 42.5)
	pm.RecordQUICCongestion("client-a")
	pm.RecordQUICCongestion("client-b")
	pm.RecordQUIC0RTTAccepted()
	pm.RecordTLSHandshake(12500 * time.Microsecond)
	pm.RecordTLSCipherSuite("TLS_AES_128_GCM_SHA256")
	pm.RecordTLSCipherSuite("TLS_AES_128_GCM_SHA256")
	pm.RecordTLSVersion("1.3")

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_quic_packet_loss_rate",
		"tiredvpn_quic_rtt_milliseconds",
		"tiredvpn_quic_congestion_events_total",
		"tiredvpn_quic_0rtt_accepted_total 1",
		"tiredvpn_tls_handshake_duration_seconds",
		`tiredvpn_tls_cipher_suite{suite="TLS_AES_128_GCM_SHA256"} 2`,
		`tiredvpn_tls_version{version="1.3"} 1`,
	)
}

// TestMetricsQualityExport covers the link-quality series and the bandwidth
// utilisation recomputation, which normally runs on a background ticker; it is
// called directly here so the assertion does not depend on wall-clock timing.
func TestMetricsQualityExport(t *testing.T) {
	m := NewMetrics(nil)
	qm := m.qualityMetrics

	qm.SetMaxBandwidth(1_000_000)
	qm.RecordRTT(25 * time.Millisecond)
	qm.RecordRTT(150 * time.Millisecond)
	qm.RecordBandwidth(500_000)
	qm.RecordRetransmission()
	qm.RecordRetransmission()
	qm.RecordConnectionDuration(90 * time.Second)
	qm.RecordIdleTimeout()
	qm.UpdateThroughput(1_000_000, 8_000_000)
	qm.updateBandwidthUtilization()

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_rtt_milliseconds",
		"tiredvpn_packet_retransmissions_total 2",
		"tiredvpn_connection_duration_seconds",
		"tiredvpn_idle_timeout_events_total 1",
		"tiredvpn_throughput_mbps",
		"tiredvpn_bandwidth_utilization_percent",
	)
}

// TestMetricsHTTPAndPortHoppingExport covers the transport-level series.
func TestMetricsHTTPAndPortHoppingExport(t *testing.T) {
	m := NewMetrics(nil)

	m.httpMetrics.RecordHTTP2Streams(7)
	m.httpMetrics.RecordHTTP2SettingsFrame()
	m.httpMetrics.RecordWebSocketUpgrade(true)
	m.httpMetrics.RecordWebSocketUpgrade(false)
	m.httpMetrics.UpdateWebSocketPingLatency(18.25)

	m.portHoppingMetrics.SetActivePorts(101)
	m.portHoppingMetrics.RecordPortHop()
	m.portHoppingMetrics.RecordPortHop()
	m.portHoppingMetrics.RecordConnectionOnPort(47000)

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_http2_streams_per_connection",
		"tiredvpn_http2_settings_frames_total 1",
		"tiredvpn_websocket_upgrades_total",
		"tiredvpn_websocket_ping_latency_milliseconds 18.25",
		"tiredvpn_porthopping_active_ports 101",
		"tiredvpn_porthopping_hop_events_total 2",
		"tiredvpn_porthopping_connections_per_port",
	)
}

// TestMetricsRelayExport covers the relay series, including the upstream health
// gauge that the chain RU -> AMS -> USA is monitored with.
func TestMetricsRelayExport(t *testing.T) {
	m := NewMetrics(nil)
	rm := m.relayMetrics

	rm.SetUpstreamHealth("38.54.6.76:443", true)
	rm.SetUpstreamHealth("38.54.6.152:995", false)
	rm.UpdateLatencyOverhead(12.34)
	rm.RecordHopCount(2)
	rm.RecordHopCount(3)

	body := renderMetrics(t, m)
	mustContain(t, body,
		`tiredvpn_relay_upstream_health{upstream="38.54.6.76:443"} 1`,
		`tiredvpn_relay_upstream_health{upstream="38.54.6.152:995"} 0`,
		"tiredvpn_relay_latency_overhead_milliseconds 12.34",
		"tiredvpn_relay_hop_count",
	)

	// Health has to be able to flip back, or a recovered upstream stays red
	// until the process restarts.
	rm.SetUpstreamHealth("38.54.6.152:995", true)
	body = renderMetrics(t, m)
	mustContain(t, body, `tiredvpn_relay_upstream_health{upstream="38.54.6.152:995"} 1`)
}

// TestMetricsPerformanceExport covers the syscall/kTLS counters and the runtime
// stats block.
func TestMetricsPerformanceExport(t *testing.T) {
	m := NewMetrics(nil)
	pm := m.performanceMetrics

	pm.RecordSyscallSendfile()
	pm.RecordSyscallSplice()
	pm.RecordSyscallSplice()
	pm.RecordKTLSOffload(4096)
	pm.RecordKTLSOffload(4096)

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_syscall_sendfile_total 1",
		"tiredvpn_syscall_splice_total 2",
		"tiredvpn_ktls_offload_bytes_total 8192",
		"tiredvpn_goroutines_count",
		"tiredvpn_memory_bytes",
		"tiredvpn_file_descriptors_used",
	)

	// getOpenFDs reads /proc; it must degrade rather than fail on a system
	// where that is unreadable.
	if got := getOpenFDs(); got < 0 {
		t.Errorf("getOpenFDs() = %d, want a non-negative count", got)
	}
}

// TestIPv6MetricsConnectionPreference covers the v4/v6 preference gauge, whose
// only writer is updatePreference on the connection recorders.
func TestIPv6MetricsConnectionPreference(t *testing.T) {
	m := NewMetrics(nil)
	im := m.ipv6Metrics

	// No connections yet: the gauge must render rather than divide by zero.
	mustContain(t, renderMetrics(t, m), `tiredvpn_dualstack_preference{version="6"} 0.0000`)

	im.RecordIPv6Connection()
	im.RecordIPv6Connection()
	im.RecordIPv6Connection()
	im.RecordIPv4Connection()
	im.RecordIPv6Fallback()
	im.RecordTunnelV6Routed()
	im.RecordTunnelV6DropNotInPool()
	im.RecordTunnelV6DropShortHeader()

	body := renderMetrics(t, m)
	mustContain(t, body,
		"tiredvpn_ipv6_connections_total 3",
		"tiredvpn_ipv4_connections_total 1",
		"tiredvpn_ipv6_fallback_events_total 1",
		"tiredvpn_tunnel_ipv6_packets_routed_total 1",
		`tiredvpn_tunnel_ipv6_packets_dropped_total{reason="not_in_pool"} 1`,
		`tiredvpn_tunnel_ipv6_packets_dropped_total{reason="short_header"} 1`,
		`tiredvpn_dualstack_preference{version="6"} 0.7500`,
		`tiredvpn_dualstack_preference{version="4"} 0.2500`,
	)
}

// TestRecordDualStackSessionCounterIsExact pins the exact increment for the
// session counter across the negotiation matrix. It is the only signal for how
// many clients actually got in-tunnel IPv6, so an off-by-one (or a count on a
// v4-only session) makes the rollout unmeasurable.
func TestRecordDualStackSessionCounterIsExact(t *testing.T) {
	dual := dualTestAddrs()

	tests := []struct {
		name    string
		version uint8
		dual    *dualStackAddrs
		want    uint64
	}{
		{"v4 client", 0x00, dual, 0},
		{"v1 client", 0x01, dual, 0},
		{"v2 client", 0x02, dual, 0},
		{"v3 client", 0x03, dual, 0},
		{"v4 dual client", 0x04, dual, 1},
		{"future client", 0xff, dual, 1},
		{"dual client, no addrs", 0x04, nil, 0},
		{"pre-dual client, no addrs", 0x03, nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvCtx := newTestServerContext(t)
			srvCtx.metrics = NewMetrics(nil)
			recordDualStackSession(srvCtx, tt.version, tt.dual)
			if got := dualStackSessionCount(srvCtx); got != tt.want {
				t.Errorf("sessions = %d, want %d", got, tt.want)
			}
		})
	}

	// Repeated setups accumulate: a reconnect is a new session.
	srvCtx := newTestServerContext(t)
	srvCtx.metrics = NewMetrics(nil)
	for i := 0; i < 5; i++ {
		recordDualStackSession(srvCtx, 0x04, dual)
	}
	if got := dualStackSessionCount(srvCtx); got != 5 {
		t.Errorf("sessions = %d after 5 setups, want 5", got)
	}

	// A context with no metrics at all (relay before wiring) must be a no-op,
	// not a nil dereference on the connect path.
	bare := newTestServerContext(t)
	recordDualStackSession(bare, 0x04, dual)
	recordRelayedDualStackSession(bare, 0x04,
		buildTUNHandshakeResponse(0x04, hsServerIP, hsClientIP, tunHandshakeCaps{}, dual))
}
