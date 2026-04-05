package strategy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// HTTPPollingStrategy implements meek-style HTTP polling transport
// Each data chunk is sent as a short-lived HTTP/1.1 request
// This evades DPI that throttles long-lived connections (like TSPU)
type HTTPPollingStrategy struct {
	manager    *Manager // IPv6/IPv4 transport layer support
	serverAddr string   // Deprecated: use manager.GetServerAddr() instead
	secret     []byte
	host       string // Cover host for TLS SNI
	path       string
}

// NewHTTPPollingStrategy creates a new HTTP polling strategy
// manager is required for IPv6/IPv4 transport layer support
func NewHTTPPollingStrategy(manager *Manager, secret []byte) *HTTPPollingStrategy {
	return &HTTPPollingStrategy{
		manager:    manager,
		serverAddr: "", // Deprecated: use manager.GetServerAddr() instead
		secret:     secret,
		host:       "cdn.jsdelivr.net", // Looks like CDN traffic
		path:       "/npm/jquery/dist/jquery.min.js",
	}
}

func (s *HTTPPollingStrategy) Name() string {
	return "HTTP Polling (meek-style)"
}

func (s *HTTPPollingStrategy) ID() string {
	return "http_polling"
}

func (s *HTTPPollingStrategy) Priority() int {
	return 6 // Higher priority for restricted networks
}

func (s *HTTPPollingStrategy) RequiresServer() bool {
	return true
}

func (s *HTTPPollingStrategy) SupportsUDP() bool {
	return false
}

func (s *HTTPPollingStrategy) Description() string {
	return "HTTP/1.1 polling transport - short-lived requests to evade long-connection throttling"
}

func (s *HTTPPollingStrategy) Probe(ctx context.Context, target string) error {
	return nil // Always available if server supports it
}

// Connect establishes HTTP polling tunnel
func (s *HTTPPollingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv6 with automatic fallback)
	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("HTTP Polling: Connecting to %s via %s", target, serverAddr)

	// Generate session ID
	sessionID := generateSessionID(s.secret)

	// Create polling connection with parallel workers
	pollConn := &HTTPPollingConn{
		manager:         s.manager,
		serverAddr:      serverAddr,
		secret:          s.secret,
		host:            s.host,
		path:            s.path,
		sessionID:       sessionID,
		sendBuf:         bytes.NewBuffer(nil),
		recvBuf:         bytes.NewBuffer(nil),
		pollInterval:    50 * time.Millisecond,  // Optimal polling
		maxPollWait:     300 * time.Millisecond, // Max wait between polls
		numWorkers:      1,                      // Single worker to avoid race condition with ack sequences
		closed:          make(chan struct{}),
		tlsSessionCache: tls.NewLRUClientSessionCache(32), // TLS session resumption
		sendSignal:      make(chan struct{}, 1),
		ready:           make(chan struct{}), // Closed when first data written
	}

	// Initialize session (no target - SOCKS handler will write destination via Write())
	if err := pollConn.init(ctx); err != nil {
		return nil, fmt.Errorf("http_polling: init failed: %w", err)
	}

	// Start parallel poll workers with staggered timing
	for i := 0; i < pollConn.numWorkers; i++ {
		workerID := i
		// Stagger worker starts to avoid burst patterns
		go func() {
			time.Sleep(time.Duration(workerID) * 25 * time.Millisecond)
			pollConn.pollWorker(workerID)
		}()
	}

	log.Info("HTTP Polling: Connection established (session=%s, workers=%d)", sessionID[:8], pollConn.numWorkers)
	return pollConn, nil
}

// HTTPPollingConn wraps HTTP polling as net.Conn
type HTTPPollingConn struct {
	manager    *Manager // IPv6/IPv4 transport layer support
	serverAddr string   // Deprecated: use manager.GetServerAddr() instead
	secret     []byte
	host       string
	path       string
	sessionID  string

	// Buffers
	sendBuf  *bytes.Buffer
	recvBuf  *bytes.Buffer
	sendLock sync.Mutex
	recvLock sync.Mutex

	// Polling config
	pollInterval time.Duration
	maxPollWait  time.Duration
	numWorkers   int // Number of parallel poll workers

	// State
	closed    chan struct{}
	closeOnce sync.Once
	lastSend  time.Time
	lastRecv  time.Time

	// TLS session resumption
	tlsSessionCache tls.ClientSessionCache

	// Stats for adaptive behavior
	successfulPolls int64
	failedPolls     int64
	bytesReceived   int64
	statsMu         sync.Mutex

	// Acknowledgement tracking for reliable delivery
	ackSeq  int64 // Total bytes received (sent to server as ack)
	ackLock sync.Mutex

	// Signal when data is available to send
	sendSignal chan struct{}

	// Ready channel - closed when first data is written (broadcast to all workers)
	ready     chan struct{}
	readyOnce sync.Once

	// For LocalAddr/RemoteAddr
	localAddr  net.Addr
	remoteAddr net.Addr
}

// init performs initial handshake to establish session
func (c *HTTPPollingConn) init(ctx context.Context) error {
	// Send init request with session ID (no body - SOCKS handler writes target later)
	authToken := c.generateAuthToken()

	// Make first request to establish session on server (ackSeq=0 for init)
	resp, err := c.doRequest(ctx, authToken, nil, 0)
	if err != nil {
		return err
	}

	// Server should respond with OK
	if len(resp) < 2 || resp[0] != 'O' || resp[1] != 'K' {
		return errors.New("server did not acknowledge session")
	}

	return nil
}

// pollWorker is a parallel poll worker with adaptive timing
func (c *HTTPPollingConn) pollWorker(workerID int) {
	// Each worker polls at base interval, staggered from others
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	maxBackoff := 2 * time.Second

	// Wait for first data to be written before polling
	// (SOCKS handler needs to write destination address first)
	select {
	case <-c.closed:
		return
	case <-c.ready:
		// Data available, start polling
	}

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			// Only poll if there's data to send OR it's our turn
			c.sendLock.Lock()
			hasData := c.sendBuf.Len() > 0
			c.sendLock.Unlock()

			// Poll if we have data or if it's our turn (based on workerID to distribute load)
			shouldPoll := hasData || (time.Now().UnixMilli()/100)%int64(c.numWorkers) == int64(workerID)

			if shouldPoll {
				success := c.poll()
				if success {
					consecutiveFailures = 0
					ticker.Reset(c.pollInterval)
				} else {
					consecutiveFailures++
					// Exponential backoff on failure
					backoff := time.Duration(consecutiveFailures*consecutiveFailures) * 100 * time.Millisecond
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
					ticker.Reset(c.pollInterval + backoff)
				}
			}
		case <-c.sendSignal:
			// Immediate poll when data available
			c.poll()
		}
	}
}

// poll does one poll cycle, returns true on success
func (c *HTTPPollingConn) poll() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Atomically claim and remove data to send (prevents multiple workers sending same data)
	c.sendLock.Lock()
	var sendData []byte
	if c.sendBuf.Len() > 0 {
		// Limit chunk size to avoid TSPU detection of large transfers
		maxChunk := 8192 // 8KB upload chunks
		dataLen := c.sendBuf.Len()
		if dataLen > maxChunk {
			dataLen = maxChunk
		}
		// Extract and remove data atomically
		sendData = make([]byte, dataLen)
		copy(sendData, c.sendBuf.Bytes()[:dataLen])
		// Clear the claimed data immediately
		remaining := c.sendBuf.Bytes()[dataLen:]
		c.sendBuf.Reset()
		if len(remaining) > 0 {
			c.sendBuf.Write(remaining)
		}
	}
	c.sendLock.Unlock()

	// Get current ack sequence (bytes we've successfully received)
	c.ackLock.Lock()
	ackSeq := c.ackSeq
	c.ackLock.Unlock()

	// Do request with ack sequence
	authToken := c.generateAuthToken()
	resp, err := c.doRequest(ctx, authToken, sendData, ackSeq)
	if err != nil {
		log.Debug("HTTP Polling: poll error: %v", err)
		c.statsMu.Lock()
		c.failedPolls++
		c.statsMu.Unlock()
		// Re-add data to buffer on failure (prepend to preserve order)
		if len(sendData) > 0 {
			c.sendLock.Lock()
			newBuf := bytes.NewBuffer(sendData)
			newBuf.Write(c.sendBuf.Bytes())
			c.sendBuf.Reset()
			c.sendBuf.Write(newBuf.Bytes())
			c.sendLock.Unlock()
		}
		return false
	}

	// Buffer received data and update ack sequence
	if len(resp) > 0 {
		c.recvLock.Lock()
		c.recvBuf.Write(resp)
		c.recvLock.Unlock()
		c.lastRecv = time.Now()

		// Update ack sequence (total bytes received)
		c.ackLock.Lock()
		c.ackSeq += int64(len(resp))
		c.ackLock.Unlock()

		c.statsMu.Lock()
		c.bytesReceived += int64(len(resp))
		c.statsMu.Unlock()
	}

	c.statsMu.Lock()
	c.successfulPolls++
	c.statsMu.Unlock()

	return true
}

// doRequest performs a single HTTP request (new connection per request)
func (c *HTTPPollingConn) doRequest(ctx context.Context, authToken string, data []byte, ackSeq int64) ([]byte, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := c.manager.GetServerAddr(ctx)

	// Establish TLS connection (new connection each time - TSPU throttles persistent connections)
	// Use protected dialer to avoid VPN routing loop on Android
	protectedDialer := &protect.ProtectDialer{
		Dialer: &net.Dialer{Timeout: 3 * time.Second},
	}
	tcpConn, err := protectedDialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer tcpConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         c.host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"tired-polling"}, // Custom ALPN for HTTP Polling
		ClientSessionCache: c.tlsSessionCache,         // TLS session resumption
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer tlsConn.Close()

	// Build HTTP request
	var body []byte
	if len(data) > 0 {
		body = data
	}

	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Content-Length: %d\r\n"+
			"X-Session-ID: %s\r\n"+
			"X-Auth-Token: %s\r\n"+
			"X-Ack: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		c.path, c.host, len(body), c.sessionID, authToken, ackSeq)

	// Set deadline
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send request
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil, err
	}
	if len(body) > 0 {
		if _, err := tlsConn.Write(body); err != nil {
			return nil, err
		}
	}

	// Read response
	reader := bufio.NewReader(tlsConn)

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !bytes.Contains([]byte(statusLine), []byte("200")) {
		return nil, fmt.Errorf("bad status: %s", statusLine)
	}

	// Read headers
	contentLength := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if bytes.HasPrefix([]byte(line), []byte("Content-Length:")) {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
		}
	}

	// Read body
	if contentLength > 0 {
		respBody := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, respBody); err != nil {
			return nil, err
		}
		return respBody, nil
	}

	return nil, nil
}

// generateAuthToken creates HMAC auth token
func (c *HTTPPollingConn) generateAuthToken() string {
	timestamp := time.Now().Unix()
	data := fmt.Sprintf("%s:%d", c.sessionID, timestamp)

	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))[:16]
}

// Read implements net.Conn
func (c *HTTPPollingConn) Read(p []byte) (int, error) {
	// Wait for data with timeout
	deadline := time.Now().Add(30 * time.Second)

	for {
		select {
		case <-c.closed:
			return 0, io.EOF
		default:
		}

		c.recvLock.Lock()
		if c.recvBuf.Len() > 0 {
			n, err := c.recvBuf.Read(p)
			c.recvLock.Unlock()
			return n, err
		}
		c.recvLock.Unlock()

		if time.Now().After(deadline) {
			return 0, errors.New("read timeout")
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// Write implements net.Conn
func (c *HTTPPollingConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, errors.New("connection closed")
	default:
	}

	c.sendLock.Lock()
	n, err := c.sendBuf.Write(p)
	c.sendLock.Unlock()

	c.lastSend = time.Now()

	// Broadcast to all workers that first data is ready (once)
	c.readyOnce.Do(func() {
		close(c.ready)
	})

	// Signal workers that data is available (non-blocking)
	select {
	case c.sendSignal <- struct{}{}:
	default:
	}

	return n, err
}

// Close implements net.Conn
func (c *HTTPPollingConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *HTTPPollingConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *HTTPPollingConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	host, port, _ := net.SplitHostPort(c.serverAddr)
	p := 443
	fmt.Sscanf(port, "%d", &p)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

func (c *HTTPPollingConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *HTTPPollingConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *HTTPPollingConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// generateSessionID creates unique session ID
func generateSessionID(secret []byte) string {
	timestamp := time.Now().UnixNano()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	h := sha256.New()
	h.Write(secret)
	h.Write(buf)
	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:16]
}

// Ensure interface compliance
var _ net.Conn = (*HTTPPollingConn)(nil)
