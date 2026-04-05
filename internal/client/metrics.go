package client

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/pool"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// ClientMetrics holds client-wide metrics for Prometheus
type ClientMetrics struct {
	manager    *strategy.Manager
	tunnelPool *pool.TunnelPool

	// Connection counters (atomic)
	totalConnections  int64
	activeConnections int64
	failedConnections int64

	// Traffic counters (atomic)
	totalBytesUp     int64
	totalBytesDown   int64
	totalPacketsUp   int64
	totalPacketsDown int64

	// Reconnection tracking
	reconnectsSuccess int64
	reconnectsFailed  int64

	// Timestamps
	startTime       time.Time
	lastConnectTime int64 // atomic unix timestamp

	// Strategy tracking
	currentStrategyID   string
	currentStrategyName string
	currentStrategyMu   sync.RWMutex

	// Mode
	tunMode bool

	// Strategy metrics
	strategyMetrics *StrategyMetrics

	// Quality metrics
	qualityMetrics *ClientQualityMetrics

	// Performance metrics
	performanceMetrics *ClientPerformanceMetrics

	// DPI metrics
	dpiMetrics *ClientDPIMetrics

	// Android metrics
	androidMetrics *AndroidMetrics

	// TUN/Proxy mode metrics
	tunProxyMetrics *TunProxyMetrics
}

// NewClientMetrics creates a new client metrics collector
func NewClientMetrics(mgr *strategy.Manager, tunnelPool *pool.TunnelPool) *ClientMetrics {
	return &ClientMetrics{
		manager:            mgr,
		tunnelPool:         tunnelPool,
		startTime:          time.Now(),
		strategyMetrics:    NewStrategyMetrics(),
		qualityMetrics:     NewClientQualityMetrics(),
		performanceMetrics: NewClientPerformanceMetrics(),
		dpiMetrics:         NewClientDPIMetrics(),
		androidMetrics:     NewAndroidMetrics(),
		tunProxyMetrics:    NewTunProxyMetrics(),
	}
}

// SetMode sets the client mode (TUN or proxy)
func (m *ClientMetrics) SetMode(tunMode bool) {
	m.tunMode = tunMode
}

// IncConnections increments connection counters
func (m *ClientMetrics) IncConnections() {
	atomic.AddInt64(&m.totalConnections, 1)
	atomic.AddInt64(&m.activeConnections, 1)
}

// DecConnections decrements active connections
func (m *ClientMetrics) DecConnections() {
	atomic.AddInt64(&m.activeConnections, -1)
}

// IncFailed increments failed connection counter
func (m *ClientMetrics) IncFailed() {
	atomic.AddInt64(&m.failedConnections, 1)
}

// AddBytes adds to byte counters
func (m *ClientMetrics) AddBytes(up, down int64) {
	atomic.AddInt64(&m.totalBytesUp, up)
	atomic.AddInt64(&m.totalBytesDown, down)
}

// AddPackets adds to packet counters (TUN mode)
func (m *ClientMetrics) AddPackets(up, down int64) {
	atomic.AddInt64(&m.totalPacketsUp, up)
	atomic.AddInt64(&m.totalPacketsDown, down)
}

// IncReconnect increments reconnection counter
func (m *ClientMetrics) IncReconnect(success bool) {
	if success {
		atomic.AddInt64(&m.reconnectsSuccess, 1)
	} else {
		atomic.AddInt64(&m.reconnectsFailed, 1)
	}
}

// RecordConnect records successful connection time and strategy
func (m *ClientMetrics) RecordConnect(strategyID, strategyName string) {
	atomic.StoreInt64(&m.lastConnectTime, time.Now().Unix())
	m.currentStrategyMu.Lock()
	m.currentStrategyID = strategyID
	m.currentStrategyName = strategyName
	m.currentStrategyMu.Unlock()
}

// SetCurrentStrategy sets the current active strategy
func (m *ClientMetrics) SetCurrentStrategy(id, name string) {
	m.currentStrategyMu.Lock()
	m.currentStrategyID = id
	m.currentStrategyName = name
	m.currentStrategyMu.Unlock()
}

// Handler returns HTTP handler for /metrics endpoint
func (m *ClientMetrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// Determine mode
		mode := "proxy"
		if m.tunMode {
			mode = "tun"
		}

		// Client info
		fmt.Fprintf(w, "# HELP tiredvpn_local_info Client information\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_info gauge\n")
		fmt.Fprintf(w, "tiredvpn_local_info{version=\"%s\",mode=\"%s\"} 1\n", Version, mode)
		fmt.Fprintf(w, "\n")

		// Uptime
		fmt.Fprintf(w, "# HELP tiredvpn_local_uptime_seconds Client uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_uptime_seconds counter\n")
		fmt.Fprintf(w, "tiredvpn_local_uptime_seconds %.0f\n", time.Since(m.startTime).Seconds())
		fmt.Fprintf(w, "\n")

		// Last connect timestamp
		lastConnect := atomic.LoadInt64(&m.lastConnectTime)
		fmt.Fprintf(w, "# HELP tiredvpn_local_last_connect_timestamp_seconds Last successful connection timestamp\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_last_connect_timestamp_seconds gauge\n")
		fmt.Fprintf(w, "tiredvpn_local_last_connect_timestamp_seconds %d\n", lastConnect)
		fmt.Fprintf(w, "\n")

		// Connections
		fmt.Fprintf(w, "# HELP tiredvpn_local_connections_total Total proxy connections handled\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_connections_total counter\n")
		fmt.Fprintf(w, "tiredvpn_local_connections_total %d\n", atomic.LoadInt64(&m.totalConnections))
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP tiredvpn_local_connections_active Currently active connections\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_connections_active gauge\n")
		fmt.Fprintf(w, "tiredvpn_local_connections_active %d\n", atomic.LoadInt64(&m.activeConnections))
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP tiredvpn_local_connections_failed_total Failed connection attempts\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_connections_failed_total counter\n")
		fmt.Fprintf(w, "tiredvpn_local_connections_failed_total %d\n", atomic.LoadInt64(&m.failedConnections))
		fmt.Fprintf(w, "\n")

		// Reconnects
		fmt.Fprintf(w, "# HELP tiredvpn_local_reconnects_total Reconnection attempts\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_reconnects_total counter\n")
		fmt.Fprintf(w, "tiredvpn_local_reconnects_total{result=\"success\"} %d\n", atomic.LoadInt64(&m.reconnectsSuccess))
		fmt.Fprintf(w, "tiredvpn_local_reconnects_total{result=\"failure\"} %d\n", atomic.LoadInt64(&m.reconnectsFailed))
		fmt.Fprintf(w, "\n")

		// Traffic - bytes
		fmt.Fprintf(w, "# HELP tiredvpn_local_bytes_sent_total Total bytes sent through tunnel\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_bytes_sent_total counter\n")
		fmt.Fprintf(w, "tiredvpn_local_bytes_sent_total %d\n", atomic.LoadInt64(&m.totalBytesUp))
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP tiredvpn_local_bytes_received_total Total bytes received through tunnel\n")
		fmt.Fprintf(w, "# TYPE tiredvpn_local_bytes_received_total counter\n")
		fmt.Fprintf(w, "tiredvpn_local_bytes_received_total %d\n", atomic.LoadInt64(&m.totalBytesDown))
		fmt.Fprintf(w, "\n")

		// Traffic - packets (TUN mode)
		if m.tunMode {
			fmt.Fprintf(w, "# HELP tiredvpn_local_packets_sent_total Total packets sent (TUN mode)\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_packets_sent_total counter\n")
			fmt.Fprintf(w, "tiredvpn_local_packets_sent_total %d\n", atomic.LoadInt64(&m.totalPacketsUp))
			fmt.Fprintf(w, "\n")

			fmt.Fprintf(w, "# HELP tiredvpn_local_packets_received_total Total packets received (TUN mode)\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_packets_received_total counter\n")
			fmt.Fprintf(w, "tiredvpn_local_packets_received_total %d\n", atomic.LoadInt64(&m.totalPacketsDown))
			fmt.Fprintf(w, "\n")
		}

		// Current strategy
		m.currentStrategyMu.RLock()
		currentID := m.currentStrategyID
		currentName := m.currentStrategyName
		m.currentStrategyMu.RUnlock()

		if currentID != "" {
			fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_current Current active strategy\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_current gauge\n")
			fmt.Fprintf(w, "tiredvpn_local_strategy_current{id=\"%s\",name=\"%s\"} 1\n", currentID, currentName)
			fmt.Fprintf(w, "\n")
		}

		// Strategy stats from manager
		if m.manager != nil {
			stats := m.manager.GetStats()

			// Available strategies
			fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_available Strategy availability (1=available, 0=unavailable)\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_available gauge\n")
			for id, result := range stats {
				available := 0
				if result.Success {
					available = 1
				}
				fmt.Fprintf(w, "tiredvpn_local_strategy_available{id=\"%s\",name=\"%s\"} %d\n",
					id, result.Strategy.Name(), available)
			}
			fmt.Fprintf(w, "\n")

			// Strategy confidence
			fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_confidence Strategy confidence score (0.0-1.0)\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_confidence gauge\n")
			for id, result := range stats {
				fmt.Fprintf(w, "tiredvpn_local_strategy_confidence{id=\"%s\"} %.2f\n", id, result.Confidence)
			}
			fmt.Fprintf(w, "\n")

			// Strategy success/failure counters
			fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_success_total Successful connections per strategy\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_success_total counter\n")
			for id, result := range stats {
				fmt.Fprintf(w, "tiredvpn_local_strategy_success_total{id=\"%s\"} %d\n", id, result.SuccessCount)
			}
			fmt.Fprintf(w, "\n")

			fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_failure_total Failed connections per strategy\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_failure_total counter\n")
			for id, result := range stats {
				fmt.Fprintf(w, "tiredvpn_local_strategy_failure_total{id=\"%s\"} %d\n", id, result.FailureCount)
			}
			fmt.Fprintf(w, "\n")

			// Strategy latency
			fmt.Fprintf(w, "# HELP tiredvpn_local_strategy_latency_seconds Average connection latency per strategy\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_strategy_latency_seconds gauge\n")
			for id, result := range stats {
				latency := result.AvgLatency.Seconds()
				fmt.Fprintf(w, "tiredvpn_local_strategy_latency_seconds{id=\"%s\"} %.3f\n", id, latency)
			}
			fmt.Fprintf(w, "\n")

			// Circuit breaker states
			cbStats := m.manager.GetCircuitBreakerStats()
			fmt.Fprintf(w, "# HELP tiredvpn_local_circuit_state Circuit breaker state (0=closed, 1=open, 2=half-open)\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_circuit_state gauge\n")
			for id, cb := range cbStats {
				fmt.Fprintf(w, "tiredvpn_local_circuit_state{id=\"%s\"} %d\n", id, cb.State)
			}
			fmt.Fprintf(w, "\n")

			fmt.Fprintf(w, "# HELP tiredvpn_local_circuit_failures Consecutive failures per strategy\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_circuit_failures gauge\n")
			for id, cb := range cbStats {
				fmt.Fprintf(w, "tiredvpn_local_circuit_failures{id=\"%s\"} %d\n", id, cb.ConsecutiveFail)
			}
			fmt.Fprintf(w, "\n")
		}

		// Pool stats
		if m.tunnelPool != nil {
			total, idle := m.tunnelPool.Stats()
			fmt.Fprintf(w, "# HELP tiredvpn_local_pool_total Total connections in pool\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_pool_total gauge\n")
			fmt.Fprintf(w, "tiredvpn_local_pool_total %d\n", total)
			fmt.Fprintf(w, "\n")

			fmt.Fprintf(w, "# HELP tiredvpn_local_pool_idle Idle connections in pool\n")
			fmt.Fprintf(w, "# TYPE tiredvpn_local_pool_idle gauge\n")
			fmt.Fprintf(w, "tiredvpn_local_pool_idle %d\n", idle)
			fmt.Fprintf(w, "\n")
		}

		// Strategy metrics
		if m.strategyMetrics != nil {
			m.strategyMetrics.ExportPrometheus(w)
		}

		// Quality metrics
		if m.qualityMetrics != nil {
			m.qualityMetrics.ExportPrometheus(w)
		}

		// Performance metrics
		if m.performanceMetrics != nil {
			m.performanceMetrics.ExportPrometheus(w)
		}

		// DPI metrics
		if m.dpiMetrics != nil {
			m.dpiMetrics.ExportPrometheus(w)
		}

		// Android metrics
		if m.androidMetrics != nil {
			m.androidMetrics.ExportPrometheus(w)
		}

		// TUN/Proxy metrics
		if m.tunProxyMetrics != nil {
			m.tunProxyMetrics.ExportPrometheus(w)
		}
	}
}
