package strategy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

var (
	ErrMaxReconnectsReached = errors.New("max reconnection attempts reached")
	ErrNoAvailableStrategy  = errors.New("no available strategy for reconnection")
)

// ResilientConfig configures resilient connection behavior
type ResilientConfig struct {
	MaxReconnects    int           // Max reconnection attempts per session (default 2)
	ReconnectTimeout time.Duration // Timeout for each reconnection attempt (default 30s)
	ReadTimeout      time.Duration // Read timeout before considering connection unhealthy (default 30s)
	WriteTimeout     time.Duration // Write timeout (default 10s)
}

// DefaultResilientConfig returns sensible defaults
func DefaultResilientConfig() ResilientConfig {
	return ResilientConfig{
		MaxReconnects:    2,
		ReconnectTimeout: 30 * time.Second,
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     10 * time.Second,
	}
}

// ResilientConnection wraps a connection with automatic failover
type ResilientConnection struct {
	manager    *Manager
	serverAddr string
	config     ResilientConfig

	mu              sync.Mutex
	conn            net.Conn
	strategy        Strategy
	excludeIDs      []string // strategies that have failed in this session
	reconnectCount  int
	closed          int32
	lastActivity    time.Time

	// Callbacks
	onReconnect func(oldStrategy, newStrategy Strategy)
	onFailed    func(err error)
}

// NewResilientConnection creates a new resilient connection
func NewResilientConnection(mgr *Manager, serverAddr string, config ResilientConfig) *ResilientConnection {
	return &ResilientConnection{
		manager:      mgr,
		serverAddr:   serverAddr,
		config:       config,
		excludeIDs:   make([]string, 0),
		lastActivity: time.Now(),
	}
}

// Connect establishes the initial connection
func (rc *ResilientConnection) Connect(ctx context.Context) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	return rc.connectLocked(ctx)
}

func (rc *ResilientConnection) connectLocked(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, rc.config.ReconnectTimeout)
	defer cancel()

	conn, strategy, err := rc.manager.ConnectExcluding(connectCtx, rc.serverAddr, rc.excludeIDs)
	if err != nil {
		return err
	}

	rc.conn = conn
	rc.strategy = strategy
	rc.lastActivity = time.Now()

	log.Info("ResilientConnection established via %s", strategy.Name())
	return nil
}

// Read implements io.Reader with automatic reconnection
func (rc *ResilientConnection) Read(p []byte) (int, error) {
	if atomic.LoadInt32(&rc.closed) == 1 {
		return 0, io.EOF
	}

	rc.mu.Lock()
	conn := rc.conn
	rc.mu.Unlock()

	if conn == nil {
		return 0, io.ErrClosedPipe
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(rc.config.ReadTimeout))

	n, err := conn.Read(p)
	if n > 0 {
		rc.mu.Lock()
		rc.lastActivity = time.Now()
		rc.mu.Unlock()
	}

	if err != nil {
		if rc.shouldReconnect(err) {
			log.Warn("Read error, attempting reconnect: %v", err)
			if reconnErr := rc.reconnect(context.Background()); reconnErr != nil {
				return n, reconnErr
			}
			// After reconnect, caller should retry
			return n, err
		}
	}

	return n, err
}

// Write implements io.Writer with automatic reconnection
func (rc *ResilientConnection) Write(p []byte) (int, error) {
	if atomic.LoadInt32(&rc.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	rc.mu.Lock()
	conn := rc.conn
	rc.mu.Unlock()

	if conn == nil {
		return 0, io.ErrClosedPipe
	}

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(rc.config.WriteTimeout))

	n, err := conn.Write(p)
	if n > 0 {
		rc.mu.Lock()
		rc.lastActivity = time.Now()
		rc.mu.Unlock()
	}

	if err != nil {
		if rc.shouldReconnect(err) {
			log.Warn("Write error, attempting reconnect: %v", err)
			if reconnErr := rc.reconnect(context.Background()); reconnErr != nil {
				return n, reconnErr
			}
			// After reconnect, caller should retry
			return n, err
		}
	}

	return n, err
}

// shouldReconnect determines if error warrants reconnection attempt
func (rc *ResilientConnection) shouldReconnect(err error) bool {
	if atomic.LoadInt32(&rc.closed) == 1 {
		return false
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.reconnectCount >= rc.config.MaxReconnects {
		return false
	}

	// Check error types that warrant reconnection
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return true
		}
	}

	// Connection reset, broken pipe, etc.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Check for specific network errors
	errStr := err.Error()
	reconnectErrors := []string{
		"connection reset",
		"broken pipe",
		"connection refused",
		"network is unreachable",
		"no route to host",
	}
	for _, re := range reconnectErrors {
		if contains(errStr, re) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// reconnect attempts to establish a new connection with a different strategy
func (rc *ResilientConnection) reconnect(ctx context.Context) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.reconnectCount >= rc.config.MaxReconnects {
		log.Error("Max reconnects reached (%d)", rc.reconnectCount)
		if rc.onFailed != nil {
			rc.onFailed(ErrMaxReconnectsReached)
		}
		return ErrMaxReconnectsReached
	}

	oldStrategy := rc.strategy

	// Add current strategy to exclusion list
	if rc.strategy != nil {
		rc.excludeIDs = append(rc.excludeIDs, rc.strategy.ID())
		// Update confidence for failed strategy
		rc.manager.UpdateStrategyConfidence(rc.strategy.ID(), false)
	}

	// Close old connection
	if rc.conn != nil {
		rc.conn.Close()
		rc.conn = nil
	}

	rc.reconnectCount++
	log.Info("Attempting reconnect %d/%d (excluding %d strategies)",
		rc.reconnectCount, rc.config.MaxReconnects, len(rc.excludeIDs))

	err := rc.connectLocked(ctx)
	if err != nil {
		log.Error("Reconnect failed: %v", err)
		if rc.onFailed != nil {
			rc.onFailed(err)
		}
		return err
	}

	log.Info("Reconnected successfully via %s (was: %s)",
		rc.strategy.Name(), oldStrategy.Name())

	if rc.onReconnect != nil {
		rc.onReconnect(oldStrategy, rc.strategy)
	}

	return nil
}

// Close closes the connection
func (rc *ResilientConnection) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.conn != nil {
		return rc.conn.Close()
	}
	return nil
}

// LocalAddr returns local network address
func (rc *ResilientConnection) LocalAddr() net.Addr {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn != nil {
		return rc.conn.LocalAddr()
	}
	return nil
}

// RemoteAddr returns remote network address
func (rc *ResilientConnection) RemoteAddr() net.Addr {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn != nil {
		return rc.conn.RemoteAddr()
	}
	return nil
}

// SetDeadline sets read and write deadlines
func (rc *ResilientConnection) SetDeadline(t time.Time) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn != nil {
		return rc.conn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline sets read deadline
func (rc *ResilientConnection) SetReadDeadline(t time.Time) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn != nil {
		return rc.conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline sets write deadline
func (rc *ResilientConnection) SetWriteDeadline(t time.Time) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn != nil {
		return rc.conn.SetWriteDeadline(t)
	}
	return nil
}

// Strategy returns current strategy
func (rc *ResilientConnection) Strategy() Strategy {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.strategy
}

// ReconnectCount returns number of reconnections performed
func (rc *ResilientConnection) ReconnectCount() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.reconnectCount
}

// OnReconnect sets callback for successful reconnection
func (rc *ResilientConnection) OnReconnect(fn func(oldStrategy, newStrategy Strategy)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.onReconnect = fn
}

// OnFailed sets callback for when connection fails permanently
func (rc *ResilientConnection) OnFailed(fn func(err error)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.onFailed = fn
}

// GetUnderlyingConn returns the underlying connection (use with caution)
func (rc *ResilientConnection) GetUnderlyingConn() net.Conn {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.conn
}

// Ensure ResilientConnection implements net.Conn
var _ net.Conn = (*ResilientConnection)(nil)
