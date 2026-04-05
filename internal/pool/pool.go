package pool

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// Config holds pool configuration
type Config struct {
	MaxConnections int           // Max total connections
	MaxIdle        int           // Max idle connections in pool
	IdleTimeout    time.Duration // Close idle connections after this
	ConnectTimeout time.Duration // Timeout for new connections
}

// DefaultConfig returns default pool configuration
func DefaultConfig() Config {
	return Config{
		MaxConnections: 1000, // Very high limit for heavy browsing
		MaxIdle:        50,
		IdleTimeout:    60 * time.Second,
		ConnectTimeout: 30 * time.Second,
	}
}

// PooledConn wraps a connection from the pool
type PooledConn struct {
	net.Conn
	pool       *TunnelPool
	strategy   strategy.Strategy
	createdAt  time.Time
	lastUsedAt time.Time
	inUse      bool
	mu         sync.Mutex
}

// Strategy returns the strategy used for this connection
func (pc *PooledConn) Strategy() strategy.Strategy {
	return pc.strategy
}

// Release returns the connection to the pool
func (pc *PooledConn) Release() {
	pc.pool.put(pc)
}

// Close closes the connection and removes from pool
func (pc *PooledConn) Close() error {
	pc.pool.remove(pc)
	return pc.Conn.Close()
}

// TunnelPool manages a pool of tunnel connections
type TunnelPool struct {
	config     Config
	manager    *strategy.Manager
	serverAddr string

	mu          sync.Mutex
	connections []*PooledConn
	totalConns  int32 // atomic counter

	closed   bool
	closedCh chan struct{}
}

// NewTunnelPool creates a new connection pool
func NewTunnelPool(mgr *strategy.Manager, serverAddr string, cfg Config) *TunnelPool {
	p := &TunnelPool{
		config:      cfg,
		manager:     mgr,
		serverAddr:  serverAddr,
		connections: make([]*PooledConn, 0, cfg.MaxIdle),
		closedCh:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go p.cleanupLoop()

	return p
}

// Get retrieves a connection from the pool or creates a new one
func (p *TunnelPool) Get(ctx context.Context) (*PooledConn, error) {
	p.mu.Lock()

	// Try to get an idle connection
	for i := len(p.connections) - 1; i >= 0; i-- {
		pc := p.connections[i]
		if !pc.inUse {
			pc.mu.Lock()
			pc.inUse = true
			pc.lastUsedAt = time.Now()
			pc.mu.Unlock()

			// Remove from idle list
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			p.mu.Unlock()

			log.Debug("Pool: reusing connection (strategy=%s, idle=%v)",
				pc.strategy.Name(), time.Since(pc.lastUsedAt))
			return pc, nil
		}
	}

	// Check if we can create a new connection
	if int(atomic.LoadInt32(&p.totalConns)) >= p.config.MaxConnections {
		p.mu.Unlock()
		return nil, ErrPoolExhausted
	}

	p.mu.Unlock()

	// Create new connection
	return p.createConn(ctx)
}

// createConn creates a new pooled connection
func (p *TunnelPool) createConn(ctx context.Context) (*PooledConn, error) {
	atomic.AddInt32(&p.totalConns, 1)

	connectCtx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
	defer cancel()

	conn, usedStrategy, err := p.manager.Connect(connectCtx, p.serverAddr)
	if err != nil {
		atomic.AddInt32(&p.totalConns, -1)
		return nil, err
	}

	// Enable TCP keepalive to detect dead connections faster
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	pc := &PooledConn{
		Conn:       conn,
		pool:       p,
		strategy:   usedStrategy,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		inUse:      true,
	}

	log.Debug("Pool: created new connection (strategy=%s, total=%d)",
		usedStrategy.Name(), atomic.LoadInt32(&p.totalConns))

	return pc, nil
}

// put returns a connection to the pool
func (p *TunnelPool) put(pc *PooledConn) {
	pc.mu.Lock()
	pc.inUse = false
	pc.lastUsedAt = time.Now()
	pc.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		pc.Conn.Close()
		atomic.AddInt32(&p.totalConns, -1)
		return
	}

	// Check if we have room in the pool
	if len(p.connections) >= p.config.MaxIdle {
		// Pool full, close the connection
		pc.Conn.Close()
		atomic.AddInt32(&p.totalConns, -1)
		log.Debug("Pool: discarded connection (pool full)")
		return
	}

	// Add to pool
	p.connections = append(p.connections, pc)
	log.Debug("Pool: returned connection (idle=%d)", len(p.connections))
}

// remove removes a connection from the pool
func (p *TunnelPool) remove(pc *PooledConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, c := range p.connections {
		if c == pc {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}
	atomic.AddInt32(&p.totalConns, -1)
}

// cleanupLoop periodically cleans up idle connections
func (p *TunnelPool) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.closedCh:
			return
		}
	}
}

// cleanup removes stale connections
func (p *TunnelPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	kept := make([]*PooledConn, 0, len(p.connections))

	for _, pc := range p.connections {
		pc.mu.Lock()
		idle := now.Sub(pc.lastUsedAt)
		pc.mu.Unlock()

		if idle > p.config.IdleTimeout {
			log.Debug("Pool: closing idle connection (idle=%v)", idle)
			pc.Conn.Close()
			atomic.AddInt32(&p.totalConns, -1)
		} else {
			kept = append(kept, pc)
		}
	}

	p.connections = kept
}

// Stats returns pool statistics
func (p *TunnelPool) Stats() (total, idle int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return int(atomic.LoadInt32(&p.totalConns)), len(p.connections)
}

// Close closes the pool and all connections
func (p *TunnelPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	close(p.closedCh)

	for _, pc := range p.connections {
		pc.Conn.Close()
	}
	p.connections = nil

	log.Info("Pool: closed")
	return nil
}

// Errors
var (
	ErrPoolExhausted = &poolError{"pool exhausted"}
	ErrPoolClosed    = &poolError{"pool closed"}
)

type poolError struct {
	msg string
}

func (e *poolError) Error() string {
	return e.msg
}

// PooledRelay relays data between client and pooled server connection
// Unlike HealthyRelay, it does NOT penalize strategy for idle timeouts
func PooledRelay(client net.Conn, server *PooledConn, idleTimeout time.Duration) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Track last activity to detect truly dead connections
	lastActivity := time.Now().UnixNano()
	maxIdleBeforeClose := 2 * time.Minute // If NO data in either direction for 2 min, close

	updateActivity := func() {
		atomic.StoreInt64(&lastActivity, time.Now().UnixNano())
	}

	checkActivity := func() bool {
		last := time.Unix(0, atomic.LoadInt64(&lastActivity))
		return time.Since(last) < maxIdleBeforeClose
	}

	// Force RST and close connection immediately
	forceReset := func() {
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.SetLinger(0)
			tcpConn.Close() // Close immediately with RST
		}
	}

	// Client -> Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			// Use shorter timeout for individual reads, check activity periodically
			client.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := client.Read(buf)
			if err != nil {
				if err != io.EOF {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// Check if we should give up (no activity in either direction)
						if !checkActivity() {
							log.Debug("Relay: closing due to inactivity (client side)")
							forceReset()
							errCh <- io.EOF
							return
						}
						continue
					}
				}
				errCh <- err
				return
			}

			updateActivity()
			server.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err = server.Write(buf[:n])
			if err != nil {
				errCh <- err
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
			// Use shorter timeout for individual reads
			server.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := server.Read(buf)
			if err != nil {
				if err != io.EOF {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// Check if we should give up
						if !checkActivity() {
							log.Debug("Relay: closing due to inactivity (server side)")
							forceReset()
							errCh <- io.EOF
							return
						}
						continue
					}
				}
				errCh <- err
				return
			}

			updateActivity()
			client.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err = client.Write(buf[:n])
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Wait for first error or completion
	err := <-errCh

	// Close connections to stop the other goroutine
	client.Close()
	server.Conn.Close()

	wg.Wait()
	return err
}

// PooledRelayLengthPrefixed relays data with length-prefixing for confusion protocol
func PooledRelayLengthPrefixed(client net.Conn, server *PooledConn, idleTimeout time.Duration) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	lastActivity := time.Now().UnixNano()
	maxIdleBeforeClose := 2 * time.Minute

	updateActivity := func() {
		atomic.StoreInt64(&lastActivity, time.Now().UnixNano())
	}

	checkActivity := func() bool {
		last := time.Unix(0, atomic.LoadInt64(&lastActivity))
		return time.Since(last) < maxIdleBeforeClose
	}

	// Client -> Server (add length prefix)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		lenBuf := make([]byte, 4)
		for {
			client.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := client.Read(buf)
			if err != nil {
				if err != io.EOF {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						if !checkActivity() {
							errCh <- io.EOF
							return
						}
						continue
					}
				}
				errCh <- err
				return
			}

			updateActivity()
			// Send length-prefixed data
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			server.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := server.Write(lenBuf); err != nil {
				errCh <- err
				return
			}
			if _, err := server.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Server -> Client (read length prefix)
	wg.Add(1)
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 4)
		for {
			server.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(server, lenBuf); err != nil {
				if err != io.EOF {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						if !checkActivity() {
							errCh <- io.EOF
							return
						}
						continue
					}
				}
				errCh <- err
				return
			}

			pktLen := binary.BigEndian.Uint32(lenBuf)
			if pktLen == 0 || pktLen > 64*1024 {
				errCh <- io.EOF
				return
			}

			buf := make([]byte, pktLen)
			if _, err := io.ReadFull(server.Conn, buf); err != nil {
				errCh <- err
				return
			}

			updateActivity()
			client.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := client.Write(buf); err != nil {
				errCh <- err
				return
			}
		}
	}()

	err := <-errCh
	client.Close()
	server.Conn.Close()
	wg.Wait()
	return err
}
