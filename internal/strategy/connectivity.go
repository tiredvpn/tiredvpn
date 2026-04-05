package strategy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
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
	timeout     time.Duration // timeout for each check (2-3 sec)
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
		androidMode: androidMode,
	}
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

	// Run checks in parallel
	var wg sync.WaitGroup
	var tcpLatency, udpLatency time.Duration
	var tcpErr, udpErr, icmpErr error

	// TCP check (required)
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		tcpErr = c.checkTCP(ctx, c.serverAddr)
		tcpLatency = time.Since(start)
		result.TCP = tcpErr == nil
	}()

	// UDP check (for QUIC)
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		udpErr = c.checkUDP(ctx, c.serverAddr)
		udpLatency = time.Since(start)
		result.UDP = udpErr == nil
	}()

	// ICMP check (optional, may fail without root)
	// Skip on Android - os/exec causes SIGSYS due to seccomp
	if !c.androidMode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			icmpErr = c.checkICMP(ctx, host)
			result.ICMP = icmpErr == nil
		}()
	}

	wg.Wait()

	// Use TCP latency as primary, fallback to UDP
	if result.TCP {
		result.Latency = tcpLatency
	} else if result.UDP {
		result.Latency = udpLatency
	}

	// Set last error (prefer TCP error as it's most important)
	if tcpErr != nil {
		result.Error = tcpErr
	} else if udpErr != nil {
		result.Error = udpErr
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

// checkTCP attempts a TLS connection to the server
// Note: Server requires TLS handshake, plain TCP connect will be rejected
func (c *ConnectivityChecker) checkTCP(ctx context.Context, addr string) error {
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	// Server requires TLS - do TLS handshake instead of plain TCP
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip cert validation for connectivity check
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS connect failed: %w", err)
	}
	conn.Close()
	return nil
}

// checkUDP sends a UDP packet and waits for any response
// Note: UDP is connectionless, so we just check if we can send and receive
func (c *ConnectivityChecker) checkUDP(ctx context.Context, addr string) error {
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("UDP dial failed: %w", err)
	}
	defer conn.Close()

	// Set short deadline for write/read
	deadline := time.Now().Add(c.timeout)
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

// checkICMP runs ping command to check ICMP connectivity
func (c *ConnectivityChecker) checkICMP(ctx context.Context, host string) error {
	// Use system ping command with 1 packet and 2 second timeout
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ICMP ping failed: %w (output: %s)", err, string(output))
	}
	return nil
}

// WaitForConnectivity waits in a loop until connectivity is available
func (c *ConnectivityChecker) WaitForConnectivity(ctx context.Context, interval time.Duration) ConnectivityResult {
	if interval == 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// First check immediately
	result := c.Check(ctx)
	if result.TCP {
		return result
	}

	log.Warn("No connectivity to %s, waiting for network...", c.serverAddr)

	for {
		select {
		case <-ctx.Done():
			return ConnectivityResult{
				Error:     ctx.Err(),
				CheckedAt: time.Now(),
			}
		case <-ticker.C:
			result = c.Check(ctx)
			if result.TCP {
				log.Info("Connectivity restored to %s", c.serverAddr)
				return result
			}
			log.Debug("Still no connectivity to %s, retrying in %v...", c.serverAddr, interval)
		}
	}
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
