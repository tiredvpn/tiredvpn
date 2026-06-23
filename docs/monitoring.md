# Monitoring

TiredVPN exposes Prometheus-compatible metrics and supports pprof profiling.

The client and the server expose **different** metric sets:

- Client metrics use the `tiredvpn_local_*` prefix and are served on the client's `-api-addr`.
- Server metrics use the `tiredvpn_*` prefix and are served on the server's `-api-addr`.

Pick the matching section below depending on which endpoint you scrape.

## Enabling the Metrics Endpoint

### Server

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <secret> \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080   # metrics at /metrics
```

### Client

```bash
tiredvpn client \
  -server host:443 \
  -secret <secret> \
  -api-addr :9090   # metrics at http://localhost:9090/metrics
```

## Client Metrics (`tiredvpn_local_*`)

Served on the client's `-api-addr`.

### Info and lifecycle

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_local_info` | Gauge | Client info, labels: `version`, `mode` (`proxy` or `tun`) |
| `tiredvpn_local_uptime_seconds` | Counter | Client uptime in seconds |
| `tiredvpn_local_last_connect_timestamp_seconds` | Gauge | Unix timestamp of last successful connection |

### Connection metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_local_connections_total` | Counter | Total proxy connections handled |
| `tiredvpn_local_connections_active` | Gauge | Currently active connections |
| `tiredvpn_local_connections_failed_total` | Counter | Failed connection attempts |
| `tiredvpn_local_reconnects_total` | Counter | Reconnection attempts, label `result` (`success` or `failure`) |

### Traffic metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_local_bytes_sent_total` | Counter | Total bytes sent through tunnel |
| `tiredvpn_local_bytes_received_total` | Counter | Total bytes received through tunnel |
| `tiredvpn_local_packets_sent_total` | Counter | Total packets sent (TUN mode only) |
| `tiredvpn_local_packets_received_total` | Counter | Total packets received (TUN mode only) |

### Strategy metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_local_strategy_current` | Gauge | Current active strategy, labels `id`, `name` |
| `tiredvpn_local_strategy_available` | Gauge | Strategy availability (1=available, 0=unavailable), labels `id`, `name` |
| `tiredvpn_local_strategy_confidence` | Gauge | Strategy confidence score (0.0-1.0), label `id` |
| `tiredvpn_local_strategy_success_total` | Counter | Successful connections per strategy, label `id` |
| `tiredvpn_local_strategy_failure_total` | Counter | Failed connections per strategy, label `id` |
| `tiredvpn_local_strategy_latency_seconds` | Gauge | Average connection latency per strategy, label `id` |

### Circuit breaker metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_local_circuit_state` | Gauge | Circuit breaker state (0=closed, 1=open, 2=half-open), label `id` |
| `tiredvpn_local_circuit_failures` | Gauge | Consecutive failures per strategy, label `id` |

### Pool metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_local_pool_total` | Gauge | Total connections in pool |
| `tiredvpn_local_pool_idle` | Gauge | Idle connections in pool |

## Server Metrics (`tiredvpn_*`)

Served on the server's `-api-addr`.

### Info and lifecycle

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_info` | Gauge | Server info, label `version` |
| `tiredvpn_uptime_seconds` | Counter | Server uptime in seconds |
| `tiredvpn_clients_total` | Gauge | Number of registered clients |

### Connection metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_connections_total` | Counter | Total connections since start |
| `tiredvpn_connections_active` | Gauge | Current active connections |
| `tiredvpn_auth_failures_total` | Counter | Total authentication failures |
| `tiredvpn_connection_errors_total` | Counter | Total connection errors |

### Traffic metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_bytes_sent_total` | Counter | Total bytes sent (download direction) |
| `tiredvpn_bytes_received_total` | Counter | Total bytes received (upload direction) |

### Per-client metrics

All carry the labels `client_id` and `client_name`.

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_client_connections_active` | Gauge | Active connections per client |
| `tiredvpn_client_connections_total` | Counter | Total connections per client |
| `tiredvpn_client_bytes_sent_total` | Counter | Bytes sent per client |
| `tiredvpn_client_bytes_received_total` | Counter | Bytes received per client |
| `tiredvpn_client_info` | Gauge | Client enabled flag, extra label `max_conns` |
| `tiredvpn_client_expires_timestamp_seconds` | Gauge | Client expiry timestamp (0 = never) |

### DPI and anti-censorship metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_dpi_probes_detected_total` | Counter | DPI / active probes detected |
| `tiredvpn_reality_handshake_result_total` | Counter | REALITY handshake results |
| `tiredvpn_sni_fragmentation_events_total` | Counter | SNI fragmentation events |

### Runtime metrics

The Go runtime collectors are exposed on both endpoints under their own prefixes:

| Metric | Type | Description |
|--------|------|-------------|
| `go_goroutines` | Gauge | Number of goroutines |
| `go_memstats_alloc_bytes` | Gauge | Allocated heap bytes |
| `process_open_fds` | Gauge | Open file descriptors |

## Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: tiredvpn-server
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics

  - job_name: tiredvpn-client
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
```

## Grafana Dashboard

Example panels to create.

**Strategy success rate (client):**

```promql
# Success rate per strategy (last 5m)
rate(tiredvpn_local_strategy_success_total[5m]) /
(rate(tiredvpn_local_strategy_success_total[5m]) + rate(tiredvpn_local_strategy_failure_total[5m]))

# Current active strategy
tiredvpn_local_strategy_current
```

**Strategy latency (client):**

```promql
# Average connection latency per strategy
tiredvpn_local_strategy_latency_seconds
```

**Strategy confidence (client):**

```promql
tiredvpn_local_strategy_confidence
```

**Client throughput:**

```promql
# Throughput (bytes/sec)
rate(tiredvpn_local_bytes_sent_total[1m]) + rate(tiredvpn_local_bytes_received_total[1m])
```

**Server throughput:**

```promql
rate(tiredvpn_bytes_sent_total[1m]) + rate(tiredvpn_bytes_received_total[1m])
```

**Active connections:**

```promql
# Client
tiredvpn_local_connections_active

# Server
tiredvpn_connections_active
```

**DPI events (server):**

```promql
rate(tiredvpn_dpi_probes_detected_total[5m])
```

## REST API (Server)

The server's management API at `-api-addr` also exposes:

```bash
# Health check (also verifies Redis connectivity)
curl http://127.0.0.1:8080/health
# {"status":"healthy","clients":3}

# Raw Prometheus metrics
curl http://127.0.0.1:8080/metrics
```

## pprof Profiling

Enable pprof with `-pprof`:

```bash
# Server
tiredvpn server ... -pprof :6060

# Client
tiredvpn client ... -pprof :6061
```

Standard Go pprof endpoints are available:

```bash
# CPU profile (30 seconds)
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Heap profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine dump
curl http://localhost:6060/debug/pprof/goroutine?debug=1

# Trace (5 seconds)
curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=5
go tool trace trace.out
```

> **Security:** Never expose `-pprof` or `-api-addr` on a public interface. Both should be bound to `127.0.0.1` in production. Use SSH tunnels for remote access.
