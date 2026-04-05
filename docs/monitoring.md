# Monitoring

TiredVPN exposes Prometheus-compatible metrics and supports pprof profiling.

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

## Available Metrics

### Strategy metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_strategy_attempts_total` | Counter | Total connection attempts per strategy |
| `tiredvpn_strategy_success_total` | Counter | Successful connections per strategy |
| `tiredvpn_strategy_failures_total` | Counter | Failed connections per strategy |
| `tiredvpn_strategy_latency_seconds` | Histogram | Connection latency per strategy |
| `tiredvpn_strategy_active` | Gauge | Name of the currently active strategy |
| `tiredvpn_strategy_circuit_state` | Gauge | Circuit breaker state (0=closed, 1=open, 2=half-open) |
| `tiredvpn_strategy_dpi_events_total` | Counter | DPI detection events per strategy |

### Connection metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_connections_active` | Gauge | Currently active proxy connections |
| `tiredvpn_connections_total` | Counter | Total connections handled |
| `tiredvpn_bytes_sent_total` | Counter | Total bytes sent to server |
| `tiredvpn_bytes_received_total` | Counter | Total bytes received from server |

### smux metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_mux_streams_active` | Gauge | Active smux streams |
| `tiredvpn_mux_streams_total` | Counter | Total smux streams opened |
| `tiredvpn_mux_errors_total` | Counter | smux protocol errors |

### Server metrics (when `-api-addr` is set on server)

| Metric | Type | Description |
|--------|------|-------------|
| `tiredvpn_server_clients_active` | Gauge | Active authenticated clients |
| `tiredvpn_server_connections_total` | Counter | Total server-side connections |
| `tiredvpn_server_auth_failures_total` | Counter | Authentication failures |
| `tiredvpn_server_bytes_sent_total` | Counter | Bytes relayed to Internet |
| `tiredvpn_server_bytes_received_total` | Counter | Bytes relayed from Internet |

### Runtime metrics

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

Example panels to create:

**Strategy Health:**

```promql
# Success rate per strategy (last 5m)
rate(tiredvpn_strategy_success_total[5m]) /
rate(tiredvpn_strategy_attempts_total[5m])

# Active strategy
tiredvpn_strategy_active
```

**Latency:**

```promql
# p50/p95/p99 latency
histogram_quantile(0.95, rate(tiredvpn_strategy_latency_seconds_bucket[5m]))
```

**Traffic:**

```promql
# Throughput (bytes/sec)
rate(tiredvpn_bytes_sent_total[1m]) + rate(tiredvpn_bytes_received_total[1m])
```

**DPI Events:**

```promql
# DPI detection events (rate)
rate(tiredvpn_strategy_dpi_events_total[5m])
```

## REST API (Server)

The server's management API at `-api-addr` also exposes:

```bash
# Health check
curl http://127.0.0.1:8080/health
# {"status":"ok","version":"1.0.0","uptime":"2h34m"}

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
