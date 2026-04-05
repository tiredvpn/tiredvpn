package strategy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/control"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// HealthConfig configures health monitoring
type HealthConfig struct {
	ReadTimeout      time.Duration       // Max time to wait for any read (default 5s)
	WriteTimeout     time.Duration       // Max time for write (default 5s)
	IdleTimeout      time.Duration       // Max idle time before health check (default 30s)
	HealthCheckFreq  time.Duration       // How often to check health (default 10s)
	OnUnhealthy      func(reason string) // Callback when unhealthy
	NoPenaltyOnIdle  bool                // Don't reduce confidence on idle timeout
}

// DefaultHealthConfig returns default health configuration
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		IdleTimeout:     30 * time.Second,
		HealthCheckFreq: 10 * time.Second,
	}
}

// HealthMonitoredConn wraps a connection with health monitoring
type HealthMonitoredConn struct {
	net.Conn
	config       HealthConfig
	strategy     Strategy
	manager      *Manager
	serverAddr   string

	// State
	lastActivity  int64 // unix nano
	unhealthy     int32 // atomic bool
	closed        int32 // atomic bool
	mu            sync.Mutex

	// For reconnection
	targetAddr    string // The target we're proxying to

	// Control channel
	controller   *control.Controller
	ctrlBuf      []byte // Buffer for partial control messages
}

// NewHealthMonitoredConn wraps a connection with health monitoring
func NewHealthMonitoredConn(conn net.Conn, strategy Strategy, config HealthConfig) *HealthMonitoredConn {
	hc := &HealthMonitoredConn{
		Conn:         conn,
		config:       config,
		strategy:     strategy,
		lastActivity: time.Now().UnixNano(),
	}

	return hc
}

// SetManager sets the strategy manager for reconnection
func (hc *HealthMonitoredConn) SetManager(mgr *Manager, serverAddr string) {
	hc.manager = mgr
	hc.serverAddr = serverAddr
}

// SetTargetAddr sets the target address for reconnection
func (hc *HealthMonitoredConn) SetTargetAddr(addr string) {
	hc.targetAddr = addr
}

// Read with timeout monitoring and control message filtering
func (hc *HealthMonitoredConn) Read(p []byte) (int, error) {
	for {
		if atomic.LoadInt32(&hc.closed) == 1 {
			return 0, io.EOF
		}

		// Set read deadline
		deadline := time.Now().Add(hc.config.ReadTimeout)
		hc.SetReadDeadline(deadline)

		n, err := hc.Conn.Read(p)
		if n > 0 {
			atomic.StoreInt64(&hc.lastActivity, time.Now().UnixNano())

			// Check if this is a control message
			if control.IsControlMessage(p[:n]) {
				if hc.controller != nil {
					hc.controller.HandleMessage(p[:n])
				}
				// Control message handled, continue reading for data
				if err == nil {
					continue
				}
			}

			// Track bytes received
			if hc.controller != nil {
				hc.controller.AddBytesRecv(uint64(n))
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if we've been idle too long (only if no keepalive)
				if hc.controller == nil {
					lastAct := time.Unix(0, atomic.LoadInt64(&hc.lastActivity))
					if time.Since(lastAct) > hc.config.IdleTimeout {
						if hc.config.NoPenaltyOnIdle {
							// Don't penalize strategy confidence for idle timeout
							log.Debug("Idle timeout (no penalty): %s", hc.strategy.Name())
						} else {
							hc.markUnhealthy("read timeout after idle")
						}
					}
				}
			}
		}

		return n, err
	}
}

// Write with timeout monitoring
func (hc *HealthMonitoredConn) Write(p []byte) (int, error) {
	if atomic.LoadInt32(&hc.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	// Set write deadline
	deadline := time.Now().Add(hc.config.WriteTimeout)
	hc.SetWriteDeadline(deadline)

	n, err := hc.Conn.Write(p)
	if n > 0 {
		atomic.StoreInt64(&hc.lastActivity, time.Now().UnixNano())
		// Track bytes sent
		if hc.controller != nil {
			hc.controller.AddBytesSent(uint64(n))
		}
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			hc.markUnhealthy("write timeout")
		}
	}

	return n, err
}

// markUnhealthy marks connection as unhealthy and triggers callback
func (hc *HealthMonitoredConn) markUnhealthy(reason string) {
	if atomic.CompareAndSwapInt32(&hc.unhealthy, 0, 1) {
		log.Warn("Connection unhealthy: %s (strategy=%s)", reason, hc.strategy.Name())

		// Update strategy confidence
		if hc.manager != nil {
			hc.manager.mu.Lock()
			hc.manager.updateConfidence(hc.strategy.ID(), false)
			hc.manager.sortStrategies()
			hc.manager.mu.Unlock()
		}

		if hc.config.OnUnhealthy != nil {
			hc.config.OnUnhealthy(reason)
		}
	}
}

// IsHealthy returns whether connection is healthy
func (hc *HealthMonitoredConn) IsHealthy() bool {
	return atomic.LoadInt32(&hc.unhealthy) == 0
}

// Strategy returns the strategy used for this connection
func (hc *HealthMonitoredConn) Strategy() Strategy {
	return hc.strategy
}

// Close closes the connection
func (hc *HealthMonitoredConn) Close() error {
	atomic.StoreInt32(&hc.closed, 1)
	if hc.controller != nil {
		hc.controller.Stop()
	}
	return hc.Conn.Close()
}

// StartKeepalive starts the control channel keepalive
func (hc *HealthMonitoredConn) StartKeepalive(interval time.Duration) {
	cfg := control.Config{
		PingInterval:   interval,
		PingTimeout:    5 * time.Second,
		MaxMissedPings: 3,
		OnUnhealthy: func(reason string) {
			hc.markUnhealthy("keepalive: " + reason)
		},
	}

	hc.controller = control.NewController(hc.Conn, cfg)
	hc.controller.Start()
	log.Debug("Started keepalive for %s (interval=%v)", hc.strategy.Name(), interval)
}

// Controller returns the control channel controller
func (hc *HealthMonitoredConn) Controller() *control.Controller {
	return hc.controller
}

// ConnWithHealthCheck is a connection manager that auto-reconnects
type ConnWithHealthCheck struct {
	mu           sync.Mutex
	conn         *HealthMonitoredConn
	manager      *Manager
	serverAddr   string
	targetAddr   string
	config       HealthConfig

	// Reconnection state
	reconnecting int32
	reconnectCh  chan struct{}
}

// NewConnWithHealthCheck creates a health-checked connection
func NewConnWithHealthCheck(mgr *Manager, serverAddr string, config HealthConfig) *ConnWithHealthCheck {
	return &ConnWithHealthCheck{
		manager:     mgr,
		serverAddr:  serverAddr,
		config:      config,
		reconnectCh: make(chan struct{}, 1),
	}
}

// Connect establishes initial connection
func (c *ConnWithHealthCheck) Connect(ctx context.Context, targetAddr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.targetAddr = targetAddr
	return c.connectLocked(ctx)
}

func (c *ConnWithHealthCheck) connectLocked(ctx context.Context) error {
	conn, strategy, err := c.manager.Connect(ctx, c.serverAddr)
	if err != nil {
		return err
	}

	// Wrap with health monitoring
	healthConfig := c.config
	healthConfig.OnUnhealthy = func(reason string) {
		// Trigger reconnection
		select {
		case c.reconnectCh <- struct{}{}:
		default:
		}
	}

	hc := NewHealthMonitoredConn(conn, strategy, healthConfig)
	hc.SetManager(c.manager, c.serverAddr)
	hc.SetTargetAddr(c.targetAddr)

	c.conn = hc
	return nil
}

// Reconnect attempts to reconnect with a different strategy
func (c *ConnWithHealthCheck) Reconnect(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&c.reconnecting, 0, 1) {
		// Already reconnecting
		return nil
	}
	defer atomic.StoreInt32(&c.reconnecting, 0)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Close old connection
	if c.conn != nil {
		c.conn.Close()
	}

	log.Info("Reconnecting with new strategy...")
	return c.connectLocked(ctx)
}

// GetConn returns current connection (may be unhealthy)
func (c *ConnWithHealthCheck) GetConn() *HealthMonitoredConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

// WaitReconnect waits for reconnection signal
func (c *ConnWithHealthCheck) WaitReconnect() <-chan struct{} {
	return c.reconnectCh
}

// Close closes the connection
func (c *ConnWithHealthCheck) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// HealthyRelay relays data between two connections with health monitoring
// Returns reason for stopping (or empty string if normal close)
func HealthyRelay(client net.Conn, server *HealthMonitoredConn, readTimeout time.Duration) string {
	var wg sync.WaitGroup
	var stopReason string
	var reasonMu sync.Mutex

	setReason := func(r string) {
		reasonMu.Lock()
		if stopReason == "" {
			stopReason = r
		}
		reasonMu.Unlock()
	}

	// Client -> Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			client.SetReadDeadline(time.Now().Add(readTimeout))
			n, err := client.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Check server health on client idle
					if !server.IsHealthy() {
						setReason("server unhealthy")
						return
					}
					continue
				}
				return
			}

			_, err = server.Write(buf[:n])
			if err != nil {
				setReason("server write failed")
				return
			}
		}
	}()

	// Server -> Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			// Server read has its own timeout via HealthMonitoredConn
			n, err := server.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					if !server.IsHealthy() {
						setReason("server unhealthy")
						return
					}
					continue
				}
				return
			}

			client.SetWriteDeadline(time.Now().Add(readTimeout))
			_, err = client.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	return stopReason
}
