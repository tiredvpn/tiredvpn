package pool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// Connector establishes a fresh tunnel connection to the server using the best
// available strategy. *strategy.Manager satisfies it; tests inject a fake.
type Connector interface {
	Connect(ctx context.Context, target string) (net.Conn, strategy.Strategy, error)
}

// ErrServerRejected means the server was reached but refused to open the
// requested target (it returned a non-zero ack byte). The rejection is
// deliberate, so DialTarget does not retry it - the caller should surface a
// proxy-level error to the browser.
var ErrServerRejected = errors.New("pool: server rejected target connection")

// dialTargetTimeout bounds each write/read of the target-address handshake.
const dialTargetTimeout = 30 * time.Second

// Config holds pool configuration.
type Config struct {
	MaxConnections int           // Max total live connections (Get enforces it)
	ConnectTimeout time.Duration // Timeout for establishing a new connection
}

// DefaultConfig returns default pool configuration
func DefaultConfig() Config {
	return Config{
		MaxConnections: 1000, // Very high limit for heavy browsing
		ConnectTimeout: 30 * time.Second,
	}
}

// PooledConn wraps a tunnel connection handed out by the pool. Connections are
// never reused - a fresh TCP per request is deliberate, to dodge TSPU throttling
// of a second stream on the same TCP (see internal/strategy/reality.go) - so a
// PooledConn is single-use: the caller relays over it and Closes it.
type PooledConn struct {
	net.Conn
	pool     *TunnelPool
	strategy strategy.Strategy
}

// Strategy returns the strategy used for this connection
func (pc *PooledConn) Strategy() strategy.Strategy {
	return pc.strategy
}

// Close closes the underlying connection and releases its slot in the pool's
// live-connection count.
func (pc *PooledConn) Close() error {
	atomic.AddInt32(&pc.pool.totalConns, -1)
	return pc.Conn.Close()
}

// TunnelPool hands out fresh tunnel connections, bounded by MaxConnections.
// Connections are single-use and never returned for reuse (see PooledConn).
type TunnelPool struct {
	config     Config
	manager    Connector
	serverAddr string

	totalConns int32 // atomic counter of live connections
}

// manager-typed assertion: keep *strategy.Manager wired through the Connector
// seam so tests can substitute a scripted connector.
var _ Connector = (*strategy.Manager)(nil)

// NewTunnelPool creates a new connection pool
func NewTunnelPool(mgr *strategy.Manager, serverAddr string, cfg Config) *TunnelPool {
	return &TunnelPool{
		config:     cfg,
		manager:    mgr,
		serverAddr: serverAddr,
	}
}

// Get establishes a fresh tunnel connection, bounded by MaxConnections.
func (p *TunnelPool) Get(ctx context.Context) (*PooledConn, error) {
	if int(atomic.LoadInt32(&p.totalConns)) >= p.config.MaxConnections {
		return nil, ErrPoolExhausted
	}
	return p.createConn(ctx)
}

// DialTarget gets a tunnel connection, sends the length-prefixed target address
// and reads the server's 1-byte ack, returning a connection that is ready for
// relay. A fresh REALITY/smux handshake backs every Get (the strategy
// deliberately avoids session reuse for DPI reasons, see strategy/reality.go),
// so a just-opened connection occasionally loses the race against a transient
// server-side stream teardown and dies before the ack - surfacing to the user
// as "No response from server: EOF" -> 502. On any transient failure (Get
// error, write error, or EOF/read error before the ack) DialTarget discards the
// connection and retries ONCE with a brand-new one. It never reuses a
// connection, so the DPI-evasion property (one TCP per request) is preserved.
//
// A non-zero ack byte is a deliberate server-side rejection (e.g. the target is
// unreachable from the exit) and is returned as ErrServerRejected without retry.
// On success the returned PooledConn has its deadlines cleared; the caller owns
// it and must Close it when the relay finishes.
func (p *TunnelPool) DialTarget(ctx context.Context, targetAddr string) (*PooledConn, error) {
	addrBytes := []byte(targetAddr)
	if len(addrBytes) > 65535 {
		return nil, fmt.Errorf("pool: target address too long (%d bytes)", len(addrBytes))
	}
	addrPacket := make([]byte, 2+len(addrBytes))
	binary.BigEndian.PutUint16(addrPacket[:2], uint16(len(addrBytes)))
	copy(addrPacket[2:], addrBytes)

	const maxAttempts = 2 // initial try + one retry on a transient failure
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		serverConn, err := p.Get(ctx)
		if err != nil {
			lastErr = err
			log.Debug("Pool DialTarget %s: get attempt %d failed: %v", targetAddr, attempt, err)
			continue
		}

		serverConn.SetWriteDeadline(time.Now().Add(dialTargetTimeout))
		if _, err := serverConn.Write(addrPacket); err != nil {
			serverConn.Close()
			lastErr = err
			log.Debug("Pool DialTarget %s: send-target attempt %d failed: %v", targetAddr, attempt, err)
			continue
		}

		serverConn.SetReadDeadline(time.Now().Add(dialTargetTimeout))
		ack := make([]byte, 1)
		if _, err := io.ReadFull(serverConn.Conn, ack); err != nil {
			serverConn.Close()
			lastErr = err
			log.Debug("Pool DialTarget %s: ack attempt %d failed: %v", targetAddr, attempt, err)
			continue
		}

		if ack[0] != 0x00 {
			serverConn.Close()
			return nil, ErrServerRejected
		}

		// The preamble is over: target address sent, ack received. Everything
		// from here is payload, which is the only part burst reshaping may
		// touch - see internal/strategy/burst_reshape.go. Off by default, in
		// which case this returns the conn unchanged.
		// Asked for as a capability rather than widened into Connector, so the
		// test fakes that implement Connector keep compiling.
		if bc, ok := p.manager.(interface {
			BurstReshape() strategy.BurstReshapeConfig
		}); ok {
			serverConn.Conn = strategy.ReshapeClientStream(serverConn.Conn, bc.BurstReshape())
		}

		serverConn.SetReadDeadline(time.Time{})
		serverConn.SetWriteDeadline(time.Time{})
		if attempt > 1 {
			log.Debug("Pool DialTarget %s: succeeded on retry", targetAddr)
		}
		return serverConn, nil
	}

	return nil, fmt.Errorf("pool: dial %s failed after %d attempts: %w", targetAddr, maxAttempts, lastErr)
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
		Conn:     conn,
		pool:     p,
		strategy: usedStrategy,
	}

	log.Debug("Pool: created new connection (strategy=%s, total=%d)",
		usedStrategy.Name(), atomic.LoadInt32(&p.totalConns))

	return pc, nil
}

// Stats returns the number of live connections handed out by the pool.
func (p *TunnelPool) Stats() (total int) {
	return int(atomic.LoadInt32(&p.totalConns))
}

// Close is a no-op kept for API symmetry: the pool holds no idle connections of
// its own (every handed-out connection is owned and closed by its caller).
func (p *TunnelPool) Close() error {
	log.Info("Pool: closed")
	return nil
}

// Errors
var (
	ErrPoolExhausted = &poolError{"pool exhausted"}
)

type poolError struct {
	msg string
}

func (e *poolError) Error() string {
	return e.msg
}

// isRelayTimeout reports whether err is a transient timeout that should trigger
// an activity check rather than an immediate relay close.
//
// Handles both standard net.Error timeouts and smux v2's errTimeout which is
// defined as errors.New("timeout") and does not implement net.Error.
func isRelayTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	// smux v2 wraps its internal errTimeout ("timeout") via pkg/errors.WithStack;
	// the wrapper does not implement net.Error, so we fall back to string matching.
	msg := err.Error()
	return msg == "timeout" || msg == "i/o timeout"
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
					if isRelayTimeout(err) {
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
					if isRelayTimeout(err) {
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
					if isRelayTimeout(err) {
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
					if isRelayTimeout(err) {
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
