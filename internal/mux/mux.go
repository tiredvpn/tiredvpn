// Package mux provides connection multiplexing for DPI evasion
// Using smux (https://github.com/xtaci/smux) for efficient stream multiplexing
//
// Mux layer is placed between RTT Camouflage and the underlying transport:
//
//	[Application] -> [RTT Camouflage] -> [Mux Layer] -> [VLESS+Reality]
//
// Benefits for DPI evasion:
// - Multiple logical streams over single connection (confuses traffic analysis)
// - Interleaved frames make pattern detection harder
// - KeepAlive maintains connection even during idle periods
// - Stream multiplexing masks individual request timing
package mux

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/xtaci/smux"
)

// Client provides multiplexed connections over a single underlying connection
// Thread-safe for concurrent stream operations
type Client struct {
	config  *Config
	session *smux.Session
	conn    net.Conn // Underlying connection
	metrics *Metrics

	mu     sync.Mutex
	closed bool

	// Callback for connection recreation
	reconnectFn func() (net.Conn, error)
}

// NewClient creates a new mux client over an existing connection
// The connection should already be established (e.g., VLESS+Reality connected)
func NewClient(conn net.Conn, config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("mux: invalid config: %w", err)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.Version
	smuxConfig.KeepAliveInterval = config.KeepAliveInterval
	smuxConfig.KeepAliveTimeout = config.KeepAliveTimeout
	smuxConfig.MaxFrameSize = config.MaxFrameSize
	smuxConfig.MaxReceiveBuffer = config.MaxReceiveBuffer
	smuxConfig.MaxStreamBuffer = config.MaxStreamBuffer

	session, err := smux.Client(conn, smuxConfig)
	if err != nil {
		globalMetrics.RecordSessionFailed()
		return nil, fmt.Errorf("mux: failed to create client session: %w", err)
	}

	globalMetrics.RecordSessionCreate()
	log.Debug("Mux client created (version=%d, keepalive=%v)", config.Version, config.KeepAliveInterval)

	return &Client{
		config:  config,
		session: session,
		conn:    conn,
		metrics: globalMetrics,
	}, nil
}

// SetReconnectFunc sets a callback for recreating the underlying connection
// This is used for automatic reconnection when the session dies
func (c *Client) SetReconnectFunc(fn func() (net.Conn, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconnectFn = fn
}

// OpenStream opens a new multiplexed stream
// Returns a net.Conn that can be used like any other connection
func (c *Client) OpenStream() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrMuxClosed
	}

	// Check max streams limit
	if c.config.MaxStreams > 0 && c.session.NumStreams() >= c.config.MaxStreams {
		return nil, ErrMuxMaxStreamsReached
	}

	start := time.Now()
	stream, err := c.session.OpenStream()
	latency := time.Since(start)

	if err != nil {
		c.metrics.RecordStreamFailed()

		// Check if session is dead
		if c.session.IsClosed() {
			log.Warn("Mux session is dead, attempting reconnect...")
			if c.reconnectFn != nil {
				if err := c.reconnect(); err != nil {
					return nil, fmt.Errorf("mux: reconnect failed: %w", err)
				}
				// Retry stream open after reconnect
				stream, err = c.session.OpenStream()
				if err != nil {
					c.metrics.RecordStreamFailed()
					return nil, fmt.Errorf("mux: stream open failed after reconnect: %w", err)
				}
			} else {
				return nil, fmt.Errorf("mux: session closed, no reconnect handler: %w", err)
			}
		} else {
			return nil, fmt.Errorf("mux: failed to open stream: %w", err)
		}
	}

	c.metrics.RecordStreamOpen(latency)
	log.Debug("Mux stream opened (id=%d, latency=%v, active=%d)", stream.ID(), latency, c.session.NumStreams())

	// Wrap stream to track metrics on close
	return &trackedStream{
		Stream:  stream,
		metrics: c.metrics,
		client:  c,
	}, nil
}

// reconnect attempts to recreate the mux session
// Must be called with c.mu held
func (c *Client) reconnect() error {
	if c.reconnectFn == nil {
		return ErrMuxNoSession
	}

	// Close old session gracefully
	c.session.Close()
	c.metrics.RecordSessionClose()

	// Create new connection
	newConn, err := c.reconnectFn()
	if err != nil {
		c.metrics.RecordSessionFailed()
		return err
	}

	// Create new smux session
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = c.config.Version
	smuxConfig.KeepAliveInterval = c.config.KeepAliveInterval
	smuxConfig.KeepAliveTimeout = c.config.KeepAliveTimeout
	smuxConfig.MaxFrameSize = c.config.MaxFrameSize
	smuxConfig.MaxReceiveBuffer = c.config.MaxReceiveBuffer
	smuxConfig.MaxStreamBuffer = c.config.MaxStreamBuffer

	session, err := smux.Client(newConn, smuxConfig)
	if err != nil {
		newConn.Close()
		c.metrics.RecordSessionFailed()
		return err
	}

	c.conn = newConn
	c.session = session
	c.metrics.RecordSessionCreate()

	log.Info("Mux client reconnected successfully")
	return nil
}

// NumStreams returns the number of active streams
func (c *Client) NumStreams() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return 0
	}
	return c.session.NumStreams()
}

// IsClosed returns whether the mux client is closed
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.session.IsClosed()
}

// Close closes the mux client and all streams
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	err := c.session.Close()
	c.metrics.RecordSessionClose()

	log.Debug("Mux client closed")
	return err
}

// GetMetrics returns current metrics snapshot
func (c *Client) GetMetrics() MetricsSnapshot {
	return c.metrics.Snapshot()
}

// Server provides server-side multiplexing
// Accepts streams from a multiplexed connection
type Server struct {
	config  *Config
	session *smux.Session
	conn    net.Conn
	metrics *Metrics

	mu     sync.Mutex
	closed bool
}

// NewServer creates a new mux server over an existing connection
func NewServer(conn net.Conn, config *Config) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("mux: invalid config: %w", err)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.Version
	smuxConfig.KeepAliveInterval = config.KeepAliveInterval
	smuxConfig.KeepAliveTimeout = config.KeepAliveTimeout
	smuxConfig.MaxFrameSize = config.MaxFrameSize
	smuxConfig.MaxReceiveBuffer = config.MaxReceiveBuffer
	smuxConfig.MaxStreamBuffer = config.MaxStreamBuffer

	session, err := smux.Server(conn, smuxConfig)
	if err != nil {
		globalMetrics.RecordSessionFailed()
		return nil, fmt.Errorf("mux: failed to create server session: %w", err)
	}

	globalMetrics.RecordSessionCreate()
	log.Debug("Mux server created (version=%d)", config.Version)

	return &Server{
		config:  config,
		session: session,
		conn:    conn,
		metrics: globalMetrics,
	}, nil
}

// AcceptStream accepts an incoming stream
// Blocks until a stream is available or the session is closed
func (s *Server) AcceptStream() (net.Conn, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()

	if closed {
		return nil, ErrMuxClosed
	}

	start := time.Now()
	stream, err := s.session.AcceptStream()
	latency := time.Since(start)

	if err != nil {
		s.metrics.RecordStreamFailed()
		return nil, fmt.Errorf("mux: failed to accept stream: %w", err)
	}

	s.metrics.RecordStreamOpen(latency)
	log.Debug("Mux stream accepted (id=%d, active=%d)", stream.ID(), s.session.NumStreams())

	return &trackedStream{
		Stream:  stream,
		metrics: s.metrics,
	}, nil
}

// NumStreams returns the number of active streams
func (s *Server) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil {
		return 0
	}
	return s.session.NumStreams()
}

// IsClosed returns whether the mux server is closed
func (s *Server) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.session.IsClosed()
}

// Close closes the mux server
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	err := s.session.Close()
	s.metrics.RecordSessionClose()

	log.Debug("Mux server closed")
	return err
}

// GetMetrics returns current metrics snapshot
func (s *Server) GetMetrics() MetricsSnapshot {
	return s.metrics.Snapshot()
}

// trackedStream wraps smux.Stream to track metrics
type trackedStream struct {
	*smux.Stream
	metrics *Metrics
	client  *Client // For reconnection (client only)
	closed  bool
	mu      sync.Mutex
}

func (s *trackedStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if n > 0 {
		s.metrics.RecordBytesReceived(uint64(n))
		s.metrics.RecordFrameReceived()
	}
	if err != nil {
		s.metrics.RecordReadError()
	}
	return n, err
}

func (s *trackedStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	if n > 0 {
		s.metrics.RecordBytesSent(uint64(n))
		s.metrics.RecordFrameSent()
	}
	if err != nil {
		s.metrics.RecordWriteError()
	}
	return n, err
}

func (s *trackedStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	s.metrics.RecordStreamClose()
	return s.Stream.Close()
}

// Ensure interface compliance
var (
	_ net.Conn = (*trackedStream)(nil)
)
