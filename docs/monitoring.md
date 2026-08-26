# Monitoring

TiredVPN 1.5.1 exposes Prometheus-compatible metrics and supports pprof
profiling.

The exposition format is written by hand (`fmt.Fprintf` into the HTTP
response), not by `prometheus/client_golang`. Two consequences:

- There are **no** `go_*` or `process_*` collectors. Runtime data is exposed
  under the project's own names — `tiredvpn_goroutines_count`,
  `tiredvpn_memory_bytes`, `tiredvpn_file_descriptors_used` and their
  `tiredvpn_local_*` twins.
- Series appear only when the subsystem that owns them has data. A server with
  no port hopping emits no `tiredvpn_porthopping_*`; a proxy-mode client emits
  no `tiredvpn_local_packets_*`. Alerts must tolerate an absent series.

The client and the server expose **different** metric sets:

- Client metrics use the `tiredvpn_local_*` prefix and are served on the
  client's `-api-addr`.
- Server metrics use the `tiredvpn_*` prefix and are served on the server's
  `-api-addr`.

## Enabling the metrics endpoint

### Server

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080 \
  -api-token "$(openssl rand -hex 32)"
```

**`-redis` is required.** The management API — and with it `/metrics` — is
started from the multi-client initialisation path in
`internal/server/server.go`. A server running on a single `-secret` never
starts an HTTP listener, whatever `-api-addr` says. There is no
single-client metrics endpoint.

`-api-addr` defaults to `127.0.0.1:8080`.

### Client

```bash
tiredvpn client \
  -server host:443 \
  -secret <secret> \
  -api-addr :9090
```

The client endpoint serves `/metrics` and nothing else — no `/health`, no
management API. It is off unless `-api-addr` is set.

### Authentication

When the server runs with `-api-token` (or `TIREDVPN_API_TOKEN`), the bearer
token is enforced by middleware in front of the whole mux, `/metrics` and
`/health` included. Prometheus needs the token too:

```yaml
scrape_configs:
  - job_name: tiredvpn-server
    static_configs:
      - targets: ['127.0.0.1:8080']
    authorization:
      credentials_file: /etc/prometheus/tiredvpn-api-token
```

Without a token every endpoint is unauthenticated. The server logs a warning at
startup if `-api-addr` is not on loopback and no token is set — anyone who can
reach it can create and delete clients and read their secrets.

## Server metrics

Served on the server's `-api-addr` at `/metrics`.

### Info and lifecycle

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_info` | gauge | `version` | Server information, always 1 |
| `tiredvpn_uptime_seconds` | counter | — | Server uptime |
| `tiredvpn_clients_total` | gauge | — | Registered clients in the registry |

### Connections and traffic

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_connections_total` | counter | — | Connections since start |
| `tiredvpn_connections_active` | gauge | — | Current active connections |
| `tiredvpn_bytes_sent_total` | counter | — | Bytes sent (download direction) |
| `tiredvpn_bytes_received_total` | counter | — | Bytes received (upload direction) |
| `tiredvpn_auth_failures_total` | counter | — | Authentication failures |
| `tiredvpn_connection_errors_total` | counter | — | Connection errors |

### Per-client

All carry `client_id` and `client_name`.

| Metric | Type | Extra labels | Description |
|---|---|---|---|
| `tiredvpn_client_connections_active` | gauge | — | Active connections per client |
| `tiredvpn_client_connections_total` | counter | — | Total connections per client |
| `tiredvpn_client_bytes_sent_total` | counter | — | Bytes sent per client |
| `tiredvpn_client_bytes_received_total` | counter | — | Bytes received per client |
| `tiredvpn_client_info` | gauge | `max_conns` | 1 when the client is enabled, 0 when disabled |
| `tiredvpn_client_expires_timestamp_seconds` | gauge | — | Expiry as a Unix timestamp, 0 = never |

### Node capacity ceilings

Populated whenever `-node-max-clients` or `-node-max-bytes` is in use. See
[deployment.md](deployment.md#admission-control).

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_node_clients` | gauge | — | Distinct authenticated clients on this node |
| `tiredvpn_node_bytes_window` | gauge | — | Bytes carried in the current window |
| `tiredvpn_node_ceiling_clients` | gauge | — | Configured client ceiling, 0 = off |
| `tiredvpn_node_ceiling_bytes` | gauge | — | Configured traffic ceiling per window, 0 = off |
| `tiredvpn_node_ceiling_used` | gauge | `limit` (`clients`, `bytes`) | Fraction of a ceiling in use |
| `tiredvpn_node_refused_total` | counter | `limit` | Sessions refused because a ceiling was full |

### REALITY authentication and donor mirroring

These five are the only metrics **without** the `tiredvpn_` prefix — they are
written directly by `internal/server/reality_b1.go` and `reality_mirror.go`.
Scrape rules matching on `tiredvpn_.*` will miss them.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `reality_auth_b1_total` | counter | — | Clients authenticated via the B1 transport |
| `reality_auth_legacy_total` | counter | — | Clients authenticated via the legacy padding-extension transport |
| `reality_reshape_capable_total` | counter | — | Authenticated B1 clients advertising tolerance for server-initiated reshaping |
| `reality_donor_dials_total` | counter | `when` (`eager`, `lazy`) | Connections opened to donor sites |
| `reality_donor_dial_fail_total` | counter | — | Unauthenticated connections that could not be handed to a donor because the dial failed |

### DPI and anti-censorship

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_dpi_probes_detected_total` | counter | `type` (e.g. `active-probe`, `tls-replay`) | DPI probes detected |
| `tiredvpn_reality_handshake_result_total` | counter | `result` (`success`, `rejected`) | REALITY handshake results |
| `tiredvpn_sni_fragmentation_events_total` | counter | — | SNI fragmentation events |
| `tiredvpn_ech_usage_total` | counter | — | Handshakes using Encrypted Client Hello |
| `tiredvpn_postquantum_handshakes_total` | counter | — | Post-quantum handshakes |
| `tiredvpn_geneva_effectiveness` | gauge | `key` | Geneva strategy effectiveness per key |
| `tiredvpn_traffic_morph_mimicry_score` | gauge | `profile` | Traffic morphing accuracy per profile |
| `tiredvpn_protocol_confusion_success_rate` | histogram | `type` | Protocol confusion effectiveness, buckets 0.0-1.0 |

### Burst reshaping

Emitted when `-burst-reshape on` is in effect.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_phase3_reshaped_total` | counter | — | Streams where the nudge/ack exchange completed |
| `tiredvpn_phase3_skipped_total` | counter | — | Streams served without reshaping (cap, ceiling or ack timeout) |
| `tiredvpn_phase3_hold_streams` | gauge | — | Streams currently waiting for a burst-reshape ack |
| `tiredvpn_phase3_hold_bytes` | gauge | — | Upstream reply bytes currently held for the exchange |

### TLS and QUIC

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_tls_version` | gauge | `version` | TLS version usage |
| `tiredvpn_tls_cipher_suite` | gauge | `suite` | Cipher suite usage |
| `tiredvpn_tls_handshake_duration_seconds` | histogram | — | TLS handshake duration, in seconds |
| `tiredvpn_quic_rtt_milliseconds` | gauge | `client_id` | QUIC RTT |
| `tiredvpn_quic_packet_loss_rate` | gauge | `client_id` | QUIC packet loss rate |
| `tiredvpn_quic_congestion_events_total` | counter | `client_id` | QUIC congestion events |
| `tiredvpn_quic_0rtt_accepted_total` | counter | — | QUIC 0-RTT handshakes accepted |

### HTTP/2 and WebSocket

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_http2_settings_frames_total` | counter | — | HTTP/2 SETTINGS frames |
| `tiredvpn_http2_streams_per_connection` | histogram | — | Streams per HTTP/2 connection |
| `tiredvpn_websocket_upgrades_total` | counter | `result` | WebSocket upgrade attempts |
| `tiredvpn_websocket_ping_latency_milliseconds` | gauge | — | WebSocket ping/pong RTT |

### IPv6 and dual-stack

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_ipv4_connections_total` | counter | — | Connections arriving over IPv4 |
| `tiredvpn_ipv6_connections_total` | counter | — | Connections arriving over IPv6 |
| `tiredvpn_ipv6_fallback_events_total` | counter | — | IPv6-to-IPv4 fallbacks |
| `tiredvpn_dualstack_preference` | gauge | `version` (`4`, `6`) | Share of connections per family |
| `tiredvpn_tunnel_dualstack_sessions_total` | counter | — | TUN sessions that negotiated in-tunnel IPv6; a reconnect counts again |
| `tiredvpn_tunnel_ipv6_packets_routed_total` | counter | — | In-tunnel IPv6 packets dispatched to clients |
| `tiredvpn_tunnel_ipv6_packets_dropped_total` | counter | `reason` (`not_in_pool`, `short_header`) | In-tunnel IPv6 packets dropped before dispatch |

### Port hopping

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_porthopping_active_ports` | gauge | — | Currently listening ports |
| `tiredvpn_porthopping_hop_events_total` | counter | — | Port hop events |
| `tiredvpn_porthopping_connections_per_port` | gauge | `port` | Connection distribution per port |

### Relay (multi-hop)

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_relay_hop_count` | histogram | — | Hop count distribution |
| `tiredvpn_relay_latency_overhead_milliseconds` | gauge | — | Latency added by the relay |
| `tiredvpn_relay_upstream_health` | gauge | `upstream` | 0 = down, 1 = up |

### Connection quality

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_rtt_milliseconds` | histogram | — | RTT distribution |
| `tiredvpn_connection_duration_seconds` | histogram | — | Connection lifetime, in seconds |
| `tiredvpn_throughput_mbps` | gauge | `direction` (`upload`, `download`) | Current throughput |
| `tiredvpn_bandwidth_utilization_percent` | gauge | — | Bandwidth utilisation |
| `tiredvpn_packet_retransmissions_total` | counter | — | Packet retransmissions |
| `tiredvpn_idle_timeout_events_total` | counter | — | Connections closed on idle timeout |

### Process and runtime

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_goroutines_count` | gauge | — | Active goroutines |
| `tiredvpn_memory_bytes` | gauge | `type` (`allocated`, `heap`, `stack`) | Memory usage |
| `tiredvpn_gc_duration_seconds` | gauge | — | Last GC pause |
| `tiredvpn_allocations_total` | counter | — | Heap allocations |
| `tiredvpn_file_descriptors_used` | gauge | — | Open file descriptors |
| `tiredvpn_cpu_usage_percent` | gauge | — | CPU usage |
| `tiredvpn_syscall_splice_total` | counter | — | `splice` syscalls |
| `tiredvpn_syscall_sendfile_total` | counter | — | `sendfile` syscalls |
| `tiredvpn_ktls_offload_bytes_total` | counter | — | Bytes offloaded to kernel TLS |

## Client metrics

Served on the client's `-api-addr` at `/metrics`.

### Info and lifecycle

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_info` | gauge | `version`, `mode` (`proxy`, `tun`) | Client information, always 1 |
| `tiredvpn_local_uptime_seconds` | counter | — | Client uptime |
| `tiredvpn_local_last_connect_timestamp_seconds` | gauge | — | Unix timestamp of the last successful connection |

### Connections and traffic

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_connections_total` | counter | — | Proxy connections handled |
| `tiredvpn_local_connections_active` | gauge | — | Currently active connections |
| `tiredvpn_local_connections_failed_total` | counter | — | Failed connection attempts |
| `tiredvpn_local_reconnects_total` | counter | `result` (`success`, `failure`) | Reconnection attempts |
| `tiredvpn_local_bytes_sent_total` | counter | — | Bytes sent through the tunnel |
| `tiredvpn_local_bytes_received_total` | counter | — | Bytes received through the tunnel |
| `tiredvpn_local_packets_sent_total` | counter | — | Packets sent — **TUN mode only** |
| `tiredvpn_local_packets_received_total` | counter | — | Packets received — **TUN mode only** |
| `tiredvpn_local_pool_total` | gauge | — | Live connections handed out by the tunnel pool |

### Strategy selection

`tiredvpn_local_strategy_current` is emitted only while a strategy is active;
the rest of this block requires the adaptive strategy manager to be running.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_strategy_current` | gauge | `id`, `name` | Active strategy, always 1 |
| `tiredvpn_local_strategy_available` | gauge | `id`, `name` | 1 = available, 0 = unavailable |
| `tiredvpn_local_strategy_confidence` | gauge | `id` | Confidence score, 0.0-1.0 |
| `tiredvpn_local_strategy_success_total` | counter | `id` | Successful connections per strategy |
| `tiredvpn_local_strategy_failure_total` | counter | `id` | Failed connections per strategy |
| `tiredvpn_local_strategy_latency_seconds` | gauge | `id` | Average connection latency (genuinely seconds) |
| `tiredvpn_local_strategy_switch_total` | counter | `from`, `to` | Strategy switches |
| `tiredvpn_local_strategy_selection_reason` | counter | `reason` | Why a strategy was picked |
| `tiredvpn_local_protocol_overhead_bytes` | gauge | `strategy_id` | Protocol overhead per strategy |
| `tiredvpn_local_circuit_state` | gauge | `id` | 0 = closed, 1 = open, 2 = half-open |
| `tiredvpn_local_circuit_failures` | gauge | `id` | Consecutive failures per strategy |

### Connect path timing

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_connect_phases_duration_seconds` | histogram | `phase` (`dns`, `tcp`, `tls`, `app`) | Per-phase connect duration, in seconds |
| `tiredvpn_local_tls_handshake_duration_seconds` | histogram | — | TLS handshake duration, in seconds |
| `tiredvpn_local_dns_resolution_duration_seconds` | histogram | — | DNS lookup time, in seconds |
| `tiredvpn_local_connect_retries` | histogram | — | Retry attempts per connect |
| `tiredvpn_local_fallback_chain_length` | histogram | — | Fallback chain depth |

### DPI observations

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_censorship_detected_total` | counter | `type` | Censorship detected, by kind |
| `tiredvpn_local_dpi_blocks_suspected_total` | counter | `pattern` | Suspected DPI blocks, by pattern |
| `tiredvpn_local_fallback_trigger` | counter | `reason` | What triggered a fallback |
| `tiredvpn_local_sni_fragmentation_events_total` | counter | — | SNI fragmentation events |
| `tiredvpn_local_ech_enabled` | gauge | — | 1 when ECH is in use |

### TUN and proxy

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_proxy_protocol` | gauge | `protocol` | Proxy protocol in use, always 1 |
| `tiredvpn_local_pool_hit_rate` | gauge | — | Connection pool hit ratio, 0.0-1.0 |
| `tiredvpn_local_tun_dns_queries_total` | counter | — | DNS queries handled in TUN mode |
| `tiredvpn_local_tun_mtu_issues_total` | counter | — | MTU/fragmentation issues in TUN mode |
| `tiredvpn_local_mtu_probed` | gauge | — | MTU put into effect by the auto-MTU probe |
| `tiredvpn_local_mtu_probe_total` | counter | — | Completed auto-MTU probe runs |
| `tiredvpn_local_mtu_probe_frames` | gauge | — | Probe frames sent in the last run |
| `tiredvpn_local_mtu_probe_fallback_total` | counter | — | Probe runs that fell back to the static value or the 1280 floor |

### Connection quality

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_rtt_milliseconds` | histogram | — | RTT distribution |
| `tiredvpn_local_jitter_milliseconds` | gauge | — | Network jitter |
| `tiredvpn_local_packet_loss_estimate` | gauge | — | Estimated packet loss rate |
| `tiredvpn_local_throughput_mbps` | gauge | `direction` | Current throughput |
| `tiredvpn_local_bandwidth_estimate_mbps` | gauge | — | Estimated bandwidth |

### Process and runtime

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_goroutines_count` | gauge | — | Goroutines |
| `tiredvpn_local_memory_bytes` | gauge | `type` (`allocated`, `heap`) | Memory usage |
| `tiredvpn_local_gc_duration_seconds` | gauge | — | Last GC pause |
| `tiredvpn_local_allocations_total` | counter | — | Heap allocations |
| `tiredvpn_local_file_descriptors_used` | gauge | — | Open file descriptors |
| `tiredvpn_local_cpu_usage_percent` | gauge | — | CPU usage |

### Android

Only populated by the Android client.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tiredvpn_local_android_network_type` | gauge | `type` | Current network type, always 1 |
| `tiredvpn_local_android_battery_level_percent` | gauge | — | Battery level |
| `tiredvpn_local_android_protect_calls_total` | counter | — | `VpnService.protect()` calls |

## Known quirks of the exposition

Read these before writing dashboards or alerts.

- **Every `_seconds` histogram is in seconds.** This was not always true.
  `tiredvpn_tls_handshake_duration_seconds`,
  `tiredvpn_local_tls_handshake_duration_seconds`,
  `tiredvpn_local_dns_resolution_duration_seconds` and
  `tiredvpn_local_connect_phases_duration_seconds` held milliseconds against
  millisecond bucket boundaries (1…5000) up to and including 1.5.1, so quantiles
  over them read 1000x too large. Their boundaries are now 0.001…5. Anything
  scraped across the upgrade has a discontinuity at that point; queries written
  for the old exposition need their thresholds divided by 1000.
- Series named `_milliseconds` (`tiredvpn_rtt_milliseconds`,
  `tiredvpn_local_rtt_milliseconds`, `tiredvpn_quic_rtt_milliseconds`,
  `tiredvpn_relay_latency_overhead_milliseconds`) are unaffected and stay in
  milliseconds.
- Histograms emit `_bucket{le=...}` (cumulative, plus `+Inf`), `_sum` and
  `_count`, as Prometheus expects. `le` and `_sum` are rendered in shortest
  round-trip form, so fractional boundaries survive:
  `tiredvpn_protocol_confusion_success_rate` exposes eleven distinct buckets
  across 0.0…1.0. Up to 1.5.1 they were printed with `%.0f` and collapsed onto
  `le="0"` and `le="1"`.
- **Five REALITY metrics have no `tiredvpn_` prefix** — see the table above.
- Counter/gauge typing follows the `# TYPE` line in the source; a few series
  typed `counter` are monotonic-by-construction rather than by a counter
  abstraction (`tiredvpn_uptime_seconds`, `tiredvpn_local_uptime_seconds`),
  so `rate()` on them is meaningful only as "1 per second while up".

## Prometheus configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: tiredvpn-server
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: /metrics

  - job_name: tiredvpn-client
    static_configs:
      - targets: ['127.0.0.1:9090']
    metrics_path: /metrics
```

In Kubernetes, the chart can create ServiceMonitors —
`server.metrics.serviceMonitor.enabled` and
`client.metrics.serviceMonitor.enabled`, both scraping `/metrics` on the `api`
port. See [the chart README](../deploy/helm/tiredvpn/README.md).

## Grafana panels

Example queries. Not a packaged dashboard — there is no dashboard JSON in the
repository.

**Strategy success rate (client):**

```promql
rate(tiredvpn_local_strategy_success_total[5m]) /
(rate(tiredvpn_local_strategy_success_total[5m]) + rate(tiredvpn_local_strategy_failure_total[5m]))
```

**Active strategy and its confidence (client):**

```promql
tiredvpn_local_strategy_current
tiredvpn_local_strategy_confidence
```

**Connect latency, p95 (client)** — the result is in seconds:

```promql
histogram_quantile(0.95, sum by (phase, le) (rate(tiredvpn_local_connect_phases_duration_seconds_bucket[5m])))
```

**Throughput:**

```promql
# client
rate(tiredvpn_local_bytes_sent_total[1m]) + rate(tiredvpn_local_bytes_received_total[1m])

# server
rate(tiredvpn_bytes_sent_total[1m]) + rate(tiredvpn_bytes_received_total[1m])
```

**Active connections:**

```promql
tiredvpn_local_connections_active
tiredvpn_connections_active
```

**Authentication failures vs. successful REALITY handshakes (server):**

```promql
rate(tiredvpn_auth_failures_total[5m])
rate(tiredvpn_reality_handshake_result_total{result="rejected"}[5m])
```

**Node ceilings — alert before they fill (server):**

```promql
max by (limit) (tiredvpn_node_ceiling_used) > 0.8
increase(tiredvpn_node_refused_total[15m]) > 0
```

**Transport mix (server):**

```promql
rate(tiredvpn_ipv6_connections_total[5m]) /
(rate(tiredvpn_ipv4_connections_total[5m]) + rate(tiredvpn_ipv6_connections_total[5m]))
```

**Relay upstream down (multi-hop):**

```promql
tiredvpn_relay_upstream_health == 0
```

**DPI probe activity (server):**

```promql
sum by (type) (rate(tiredvpn_dpi_probes_detected_total[5m]))
```

## REST API

The server's management API on `-api-addr`:

```bash
# Liveness; also pings Redis
curl http://127.0.0.1:8080/health
# {"status":"healthy","clients":3}

# Aggregate client statistics
curl http://127.0.0.1:8080/stats

# Raw Prometheus exposition
curl http://127.0.0.1:8080/metrics
```

`/health` returns 503 with `{"error":"Redis unhealthy: ..."}` when the Redis
ping fails, which makes it a usable readiness probe. Add
`-H "Authorization: Bearer <token>"` to all of these when `-api-token` is set.

Client management (`/clients`, `/clients/{id}`) is covered in
[admin.md](admin.md).

## pprof profiling

`-pprof <addr>` starts an HTTP server on that address using Go's default mux,
into which `net/http/pprof` has registered itself. It is independent of
`-api-addr` and works on both the server and the client, in single-secret mode
too.

```bash
tiredvpn server ... -pprof 127.0.0.1:6060
tiredvpn client ... -pprof 127.0.0.1:6061
```

The standard endpoints are available, and nothing else — there are no custom
handlers on that listener:

```bash
# CPU profile (30 seconds)
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30

# Heap profile
go tool pprof http://127.0.0.1:6060/debug/pprof/heap

# Goroutine dump
curl 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=1'

# Execution trace (5 seconds)
curl -o trace.out 'http://127.0.0.1:6060/debug/pprof/trace?seconds=5'
go tool trace trace.out
```

The pprof listener has **no authentication** — unlike the management API, there
is no token to set. Bind it to `127.0.0.1` and reach it over an SSH tunnel.
The same goes for `-api-addr` when no `-api-token` is configured.
