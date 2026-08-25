package strategy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Probe pacing for the connectivity wait loop. After a server-side reset the
// real outage is usually sub-second, so we retry quickly first and back off
// exponentially rather than polling on a flat 5s ticker (which turned a <1s
// reset into a ~5s freeze). See WaitForConnectivity.
const (
	defaultProbeInterval = 250 * time.Millisecond  // first retry after a failed check
	maxProbeInterval     = 2500 * time.Millisecond // backoff ceiling
	probeBackoffFactor   = 2                       // interval multiplier per miss
)

// ConnectivityResult holds the result of a connectivity check
type ConnectivityResult struct {
	TCP       bool          // TCP connect to server port succeeded
	UDP       bool          // UDP connectivity check passed
	ICMP      bool          // ICMP ping succeeded (optional)
	Latency   time.Duration // RTT to server
	Error     error         // Last error encountered
	CheckedAt time.Time     // When the check was performed
}

// HasBasicConnectivity returns true if at least TCP works
func (r ConnectivityResult) HasBasicConnectivity() bool {
	return r.TCP
}

// ConnectivityChecker performs pre-flight connectivity checks before trying strategies
type ConnectivityChecker struct {
	serverAddr  string        // full addr host:port
	altAddr     string        // same server on the other address family, optional
	timeout     time.Duration // timeout for the TCP gate (2-3 sec)
	auxTimeout  time.Duration // bounded timeout for the UDP/ICMP probes
	auxGrace    time.Duration // how long Check waits for UDP/ICMP after TCP lands
	androidMode bool          // skip ICMP check on Android (os/exec not allowed)

	mu         sync.RWMutex
	lastResult ConnectivityResult
}

// NewConnectivityChecker creates a new connectivity checker
func NewConnectivityChecker(serverAddr string, timeout time.Duration, androidMode bool) *ConnectivityChecker {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &ConnectivityChecker{
		serverAddr:  serverAddr,
		timeout:     timeout,
		auxTimeout:  700 * time.Millisecond,
		auxGrace:    300 * time.Millisecond,
		androidMode: androidMode,
	}
}

// SetAltAddr registers the same server's address on the other family (the
// IPv6 one when -server carries IPv4, or the reverse). The TCP gate then
// accepts either: the question it answers is "can this client reach its
// server", and with a dual-addressed server that is true as long as one family
// works. Without it a client configured with both addresses sat in
// "waiting for network" against a blocked IPv4 while its IPv6 transport was
// perfectly reachable. Empty or duplicate values are ignored.
func (c *ConnectivityChecker) SetAltAddr(addr string) {
	if addr == "" || addr == c.serverAddr {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.altAddr = addr
}

// addrsToTry returns the addresses the TCP gate probes, preferred one first.
func (c *ConnectivityChecker) addrsToTry() []string {
	c.mu.RLock()
	alt := c.altAddr
	c.mu.RUnlock()
	if alt == "" {
		return []string{c.serverAddr}
	}
	return []string{c.serverAddr, alt}
}

// checkTCPAny reports success as soon as any configured address answers, and
// returns the last error when none do.
func (c *ConnectivityChecker) checkTCPAny(ctx context.Context) error {
	var lastErr error
	for _, addr := range c.addrsToTry() {
		err := c.checkTCP(ctx, addr)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// Check performs TCP, UDP and ICMP connectivity checks
func (c *ConnectivityChecker) Check(ctx context.Context) ConnectivityResult {
	result := ConnectivityResult{
		CheckedAt: time.Now(),
	}

	// Parse host from server address
	host, port, err := net.SplitHostPort(c.serverAddr)
	if err != nil {
		result.Error = fmt.Errorf("invalid server address: %w", err)
		return result
	}

	// TCP is the only gate (HasBasicConnectivity == TCP), so it runs on the hot
	// reconnect path and decides the result. UDP/ICMP only gate QUIC selection,
	// so they run concurrently but must never delay the TCP verdict: we wait for
	// them just auxGrace, then fall back to the last known value and let them
	// finish updating the cache in the background.
	var tcpErr error
	var tcpLatency time.Duration
	tcpDone := make(chan struct{})
	go func() {
		start := time.Now()
		tcpErr = c.checkTCPAny(ctx)
		tcpLatency = time.Since(start)
		close(tcpDone)
	}()

	var udpOK, icmpOK atomic.Bool
	auxDone := make(chan struct{})
	go func() {
		defer close(auxDone)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			udpOK.Store(c.checkUDP(ctx, c.serverAddr) == nil)
		}()
		// ICMP check (optional, may fail without root).
		// Skip on Android - os/exec causes SIGSYS due to seccomp.
		if !c.androidMode {
			wg.Add(1)
			go func() {
				defer wg.Done()
				icmpOK.Store(c.checkICMP(ctx, host) == nil)
			}()
		}
		wg.Wait()
	}()

	<-tcpDone
	result.TCP = tcpErr == nil
	if result.TCP {
		result.Latency = tcpLatency
	}
	if tcpErr != nil {
		result.Error = tcpErr
	}

	select {
	case <-auxDone:
		result.UDP = udpOK.Load()
		result.ICMP = icmpOK.Load()
	case <-time.After(c.auxGrace):
		// Aux probes are slow this round; reuse the last known verdict and let
		// them refresh the cache once they land.
		c.mu.RLock()
		result.UDP = c.lastResult.UDP
		result.ICMP = c.lastResult.ICMP
		c.mu.RUnlock()
		go func() {
			<-auxDone
			c.mu.Lock()
			c.lastResult.UDP = udpOK.Load()
			c.lastResult.ICMP = icmpOK.Load()
			c.mu.Unlock()
		}()
	}

	// Log results
	log.Debug("Connectivity check to %s:%s - TCP:%v UDP:%v ICMP:%v (latency=%v)",
		host, port, result.TCP, result.UDP, result.ICMP, result.Latency)

	// Cache result
	c.mu.Lock()
	c.lastResult = result
	c.mu.Unlock()

	return result
}

// checkTCPOnly performs just the TCP gate, carrying forward the last known
// UDP/ICMP verdict. Used on the hot retry path (WaitForConnectivity) where the
// only thing that matters is whether the server's TCP port is back; pulling in
// UDP/ICMP probes there only adds latency to recovery.
func (c *ConnectivityChecker) checkTCPOnly(ctx context.Context) ConnectivityResult {
	result := ConnectivityResult{CheckedAt: time.Now()}

	start := time.Now()
	err := c.checkTCPAny(ctx)
	result.TCP = err == nil
	if err != nil {
		result.Error = err
	} else {
		result.Latency = time.Since(start)
	}

	// Carry forward last known UDP/ICMP (they gate QUIC and rarely flip).
	c.mu.Lock()
	result.UDP = c.lastResult.UDP
	result.ICMP = c.lastResult.ICMP
	c.lastResult = result
	c.mu.Unlock()

	return result
}

// checkTCP verifies that the server's TCP port is reachable.
// A plain TCP dial is enough — the server speaks a custom protocol, so a TLS
// handshake would always fail the connectivity check even when the port is up.
func (c *ConnectivityChecker) checkTCP(ctx context.Context, addr string) error {
	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP connect failed: %w", err)
	}
	conn.Close()
	return nil
}

// checkUDP sends a UDP packet and waits for any response
// Note: UDP is connectionless, so we just check if we can send and receive
func (c *ConnectivityChecker) checkUDP(ctx context.Context, addr string) error {
	dialer := &net.Dialer{
		Timeout: c.auxTimeout,
	}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("UDP dial failed: %w", err)
	}
	defer conn.Close()

	// Set short deadline for write/read
	deadline := time.Now().Add(c.auxTimeout)
	conn.SetDeadline(deadline)

	// Send a probe packet that won't trigger Salamander "ciphertext too short" errors
	// Salamander needs at least 8 bytes, so we send 16 random-looking bytes
	// This is NOT a valid QUIC packet, just checking if UDP can be sent/received
	probe := []byte{
		0xc0, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, // 8 bytes header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 bytes padding
	}
	_, err = conn.Write(probe)
	if err != nil {
		return fmt.Errorf("UDP write failed: %w", err)
	}

	// Try to read response (server probably won't respond, but ICMP errors might come)
	// Short timeout - we don't expect actual response
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)

	// Timeout is expected - it means no ICMP error came back
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is OK - UDP probably works, just no response
			return nil
		}
		// Other errors (like ICMP unreachable) indicate UDP is blocked
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "unreachable") {
			return fmt.Errorf("UDP blocked: %w", err)
		}
	}

	return nil
}

func (c *ConnectivityChecker) checkICMP(ctx context.Context, host string) error {
	d := net.Dialer{Timeout: c.auxTimeout}
	conn, err := d.DialContext(ctx, "tcp", host+":443")
	if err == nil {
		conn.Close()
		return nil
	}
	conn2, err2 := d.DialContext(ctx, "tcp", host+":80")
	if err2 == nil {
		conn2.Close()
		return nil
	}
	return fmt.Errorf("host unreachable: %w", err2)
}

// WaitForConnectivity waits in a loop until TCP connectivity is available.
//
// interval is the FIRST retry delay; on each miss it backs off by
// probeBackoffFactor up to maxProbeInterval. A short server-side reset is
// usually back within a few hundred ms, so the early retries are fast (recovery
// drops from the old flat ~5s to <1s) while the ceiling keeps a truly-down
// network from being hammered. Only the TCP gate is probed here — UDP/ICMP just
// gate QUIC selection and are carried forward from the cache.
func (c *ConnectivityChecker) WaitForConnectivity(ctx context.Context, interval time.Duration) ConnectivityResult {
	if interval <= 0 {
		interval = defaultProbeInterval
	}

	// First check immediately.
	result := c.checkTCPOnly(ctx)
	if result.TCP {
		return result
	}

	log.Warn("No connectivity to %s, waiting for network...", strings.Join(c.addrsToTry(), " or "))

	backoff := interval
	timer := time.NewTimer(backoff)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ConnectivityResult{
				Error:     ctx.Err(),
				CheckedAt: time.Now(),
			}
		case <-timer.C:
			result = c.checkTCPOnly(ctx)
			if result.TCP {
				log.Info("Connectivity restored to %s", c.serverAddr)
				return result
			}
			backoff = nextProbeBackoff(backoff)
			timer.Reset(backoff)
			log.Debug("Still no connectivity to %s, retrying in %v...", c.serverAddr, backoff)
		}
	}
}

// nextProbeBackoff advances the WaitForConnectivity retry delay: multiply by
// probeBackoffFactor, clamped at maxProbeInterval. A caller-supplied interval
// already at or above the ceiling is left alone rather than pulled down to it.
func nextProbeBackoff(cur time.Duration) time.Duration {
	if cur >= maxProbeInterval {
		return cur
	}
	next := cur * probeBackoffFactor
	if next > maxProbeInterval {
		next = maxProbeInterval
	}
	return next
}

// LastResult returns the last cached connectivity result
func (c *ConnectivityChecker) LastResult() ConnectivityResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastResult
}

// ServerAddr returns the server address being checked
func (c *ConnectivityChecker) ServerAddr() string {
	return c.serverAddr
}
