package server

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics holds server-wide metrics for Prometheus
type Metrics struct {
	registry *ClientRegistry

	// Server-wide counters (atomic)
	totalConnections   int64
	activeConnections  int64
	totalBytesUp       int64
	totalBytesDown     int64
	authFailures       int64
	connectionErrors   int64

	// Timestamps
	startTime time.Time

	// Performance metrics
	performanceMetrics *PerformanceMetrics

	// Quality metrics
	qualityMetrics *QualityMetrics

	// DPI metrics
	dpiMetrics *DPIMetrics

	// Protocol metrics
	protocolMetrics *ProtocolMetrics

	// IPv6 metrics
	ipv6Metrics *IPv6Metrics

	// HTTP metrics
	httpMetrics *HTTPMetrics

	// Port hopping metrics
	portHoppingMetrics *PortHoppingMetrics

	// Relay metrics
	relayMetrics *RelayMetrics
}

// NewMetrics creates a new metrics collector
func NewMetrics(registry *ClientRegistry) *Metrics {
	return &Metrics{
		registry:           registry,
		startTime:          time.Now(),
		performanceMetrics: NewPerformanceMetrics(),
		qualityMetrics:     NewQualityMetrics(),
		dpiMetrics:         NewDPIMetrics(),
		protocolMetrics:    NewProtocolMetrics(),
		ipv6Metrics:        NewIPv6Metrics(),
		httpMetrics:        NewHTTPMetrics(),
		portHoppingMetrics: NewPortHoppingMetrics(),
		relayMetrics:       NewRelayMetrics(),
	}
}

// IncConnections increments connection counters
func (m *Metrics) IncConnections() {
	atomic.AddInt64(&m.totalConnections, 1)
	atomic.AddInt64(&m.activeConnections, 1)
}

// DecConnections decrements active connections
func (m *Metrics) DecConnections() {
	atomic.AddInt64(&m.activeConnections, -1)
}

// AddBytes adds to byte counters
func (m *Metrics) AddBytes(up, down int64) {
	atomic.AddInt64(&m.totalBytesUp, up)
	atomic.AddInt64(&m.totalBytesDown, down)
}

// IncAuthFailures increments auth failure counter
func (m *Metrics) IncAuthFailures() {
	atomic.AddInt64(&m.authFailures, 1)
}

// IncConnectionErrors increments connection error counter
func (m *Metrics) IncConnectionErrors() {
	atomic.AddInt64(&m.connectionErrors, 1)
}

// Handler returns HTTP handler for /metrics endpoint
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// Server info
		fmt.Fprintf(w, "# HELP tiredvpn_info Server information\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_info gauge\n")
		fmt.Fprintf(w, "tiredvpn_info{version=\"%s\"} 1\n", "0.2.0")
		fmt.Fprintf(w, "\n")

		// Uptime
		fmt.Fprintf(w, "# HELP tiredvpn_uptime_seconds Server uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_uptime_seconds counter\n")
		fmt.Fprintf(w, "tiredvpn_uptime_seconds %.0f\n", time.Since(m.startTime).Seconds())
		fmt.Fprintf(w, "\n")

		// Total clients
		var totalClients int
		if m.registry != nil {
			totalClients = m.registry.ClientCount()
		}
		fmt.Fprintf(w, "# HELP tiredvpn_clients_total Total number of registered clients\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_clients_total gauge\n")
		fmt.Fprintf(w, "tiredvpn_clients_total %d\n", totalClients)
		fmt.Fprintf(w, "\n")

		// Connections
		fmt.Fprintf(w, "# HELP tiredvpn_connections_total Total connections since start\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_connections_total counter\n")
		fmt.Fprintf(w, "tiredvpn_connections_total %d\n", atomic.LoadInt64(&m.totalConnections))
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP tiredvpn_connections_active Current active connections\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_connections_active gauge\n")
		fmt.Fprintf(w, "tiredvpn_connections_active %d\n", atomic.LoadInt64(&m.activeConnections))
		fmt.Fprintf(w, "\n")

		// Bytes
		fmt.Fprintf(w, "# HELP tiredvpn_bytes_sent_total Total bytes sent (download)\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_bytes_sent_total counter\n")
		fmt.Fprintf(w, "tiredvpn_bytes_sent_total %d\n", atomic.LoadInt64(&m.totalBytesDown))
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP tiredvpn_bytes_received_total Total bytes received (upload)\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_bytes_received_total counter\n")
		fmt.Fprintf(w, "tiredvpn_bytes_received_total %d\n", atomic.LoadInt64(&m.totalBytesUp))
		fmt.Fprintf(w, "\n")

		// Errors
		fmt.Fprintf(w, "# HELP tiredvpn_auth_failures_total Total authentication failures\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_auth_failures_total counter\n")
		fmt.Fprintf(w, "tiredvpn_auth_failures_total %d\n", atomic.LoadInt64(&m.authFailures))
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP tiredvpn_connection_errors_total Total connection errors\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_connection_errors_total counter\n")
		fmt.Fprintf(w, "tiredvpn_connection_errors_total %d\n", atomic.LoadInt64(&m.connectionErrors))
		fmt.Fprintf(w, "\n")

		// Per-client metrics (if registry available)
		if m.registry != nil {
			clients := m.registry.ListClients()

			// Per-client active connections
			fmt.Fprintf(w, "# HELP tiredvpn_client_connections_active Active connections per client\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_client_connections_active gauge\n")
			for _, cfg := range clients {
				active := m.registry.GetActiveConns(cfg.ID)
				fmt.Fprintf(w, "tiredvpn_client_connections_active{client_id=\"%s\",client_name=\"%s\"} %d\n",
					cfg.ID, cfg.Name, active)
			}
			fmt.Fprintf(w, "\n")

			// Per-client total connections
			fmt.Fprintf(w, "# HELP tiredvpn_client_connections_total Total connections per client\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_client_connections_total counter\n")
			for _, cfg := range clients {
				stats := m.registry.GetStats(cfg.ID)
				fmt.Fprintf(w, "tiredvpn_client_connections_total{client_id=\"%s\",client_name=\"%s\"} %d\n",
					cfg.ID, cfg.Name, stats.TotalConns)
			}
			fmt.Fprintf(w, "\n")

			// Per-client bytes
			fmt.Fprintf(w, "# HELP tiredvpn_client_bytes_sent_total Bytes sent per client\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_client_bytes_sent_total counter\n")
			for _, cfg := range clients {
				stats := m.registry.GetStats(cfg.ID)
				fmt.Fprintf(w, "tiredvpn_client_bytes_sent_total{client_id=\"%s\",client_name=\"%s\"} %d\n",
					cfg.ID, cfg.Name, stats.BytesDown)
			}
			fmt.Fprintf(w, "\n")

			fmt.Fprintf(w, "# HELP tiredvpn_client_bytes_received_total Bytes received per client\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_client_bytes_received_total counter\n")
			for _, cfg := range clients {
				stats := m.registry.GetStats(cfg.ID)
				fmt.Fprintf(w, "tiredvpn_client_bytes_received_total{client_id=\"%s\",client_name=\"%s\"} %d\n",
					cfg.ID, cfg.Name, stats.BytesUp)
			}
			fmt.Fprintf(w, "\n")

			// Client info (enabled, expires)
			fmt.Fprintf(w, "# HELP tiredvpn_client_info Client information\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_client_info gauge\n")
			for _, cfg := range clients {
				enabled := 0
				if cfg.Enabled {
					enabled = 1
				}
				fmt.Fprintf(w, "tiredvpn_client_info{client_id=\"%s\",client_name=\"%s\",max_conns=\"%d\"} %d\n",
					cfg.ID, cfg.Name, cfg.MaxConns, enabled)
			}
			fmt.Fprintf(w, "\n")

			// Client expiry (unix timestamp, 0 = never)
			fmt.Fprintf(w, "# HELP tiredvpn_client_expires_timestamp_seconds Client expiry timestamp (0 = never)\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_client_expires_timestamp_seconds gauge\n")
			for _, cfg := range clients {
				expires := int64(0)
				if !cfg.ExpiresAt.IsZero() {
					expires = cfg.ExpiresAt.Unix()
				}
				fmt.Fprintf(w, "tiredvpn_client_expires_timestamp_seconds{client_id=\"%s\",client_name=\"%s\"} %d\n",
					cfg.ID, cfg.Name, expires)
			}
		}

		// Performance metrics
		if m.performanceMetrics != nil {
			m.performanceMetrics.ExportPrometheus(w)
		}

		// Quality metrics
		if m.qualityMetrics != nil {
			m.qualityMetrics.ExportPrometheus(w)
		}

		// DPI metrics
		if m.dpiMetrics != nil {
			m.dpiMetrics.ExportPrometheus(w)
		}

		// Protocol metrics
		if m.protocolMetrics != nil {
			m.protocolMetrics.ExportPrometheus(w)
		}

		// IPv6 metrics
		if m.ipv6Metrics != nil {
			m.ipv6Metrics.ExportPrometheus(w)
		}

		// HTTP metrics
		if m.httpMetrics != nil {
			m.httpMetrics.ExportPrometheus(w)
		}

		// Port hopping metrics
		if m.portHoppingMetrics != nil {
			m.portHoppingMetrics.ExportPrometheus(w)
		}

		// Relay metrics
		if m.relayMetrics != nil {
			m.relayMetrics.ExportPrometheus(w)
		}
	}
}
