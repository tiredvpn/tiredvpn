package strategy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// Meek keepalive feeder tuning. The shared TUN relay tears a session down if no
// framed packet arrives within tun.readTimeout (30s) - a sane signal for the
// persistent transports (REALITY/H2/WS) but wrong for meek, whose liveness is
// the poll round-trip, not the tunnel payload. On an idle or degraded channel
// the server's keepalive echo can take more than one poll round-trip to come
// back (each poll has its own 3s timeout plus up to 2s backoff), so the relay
// would tear down a perfectly healthy polling session and trigger a reconnect
// storm. The feeder injects a synthetic keepalive frame into the receive buffer
// while polls keep succeeding, so the relay stays up exactly as long as the
// poll layer - the real liveness signal for meek - is alive.
const (
	pollingKeepaliveFeed   = 10 * time.Second // inject a keepalive frame this often while idle
	pollingPollHealthGrace = 20 * time.Second // stop feeding if no poll has succeeded within this

	// pollingHandshakePeekGuard keeps the feeder quiet right after the reader
	// drained the TUN handshake response. The TUN client's handshake reader
	// (tun.readHandshakeResponse) waits up to handshakeFlagsGrace (300ms) for an
	// optional flags byte whenever the response stopped at 9 bytes - which is
	// exactly what a polling exit sends a v3 client. A keepalive spliced into
	// that window has its first zero read as the flags byte and desyncs every
	// frame after it. The guard is the peek budget with a wide margin; the feed
	// period is 10s, so it costs nothing.
	pollingHandshakePeekGuard = time.Second

	// maxPollingSendBuffered bounds the uplink queue. Write blocks while this
	// much is waiting to be polled out, so a fast local writer (a SOCKS upload,
	// the TUN device) gets backpressure instead of growing the queue without
	// limit. At 8 KiB per poll this is several seconds of uplink.
	maxPollingSendBuffered = 1 << 20
)

// errPollingDead is returned by Read and Write once no poll has succeeded for
// pollingPollHealthGrace. It is deliberately not a timeout: the SOCKS relay
// keeps a timed-out direction open, and a dead exit must end the relay rather
// than keep it (and the uplink queue) alive forever. It does match
// ErrServerSilent, which is what it means to the TUN client.
var errPollingDead error = &silentError{"http_polling: no successful poll within the health grace"}

// ErrServerSilent matches transport errors that mean the server stopped
// answering without being a net.Error timeout. The TUN client treats them like
// its own read deadline: the server may be gone (walk the pool), and a session
// that died this way right after connecting is an endpoint verdict.
var ErrServerSilent = errors.New("server went silent")

// silentError is an error that matches ErrServerSilent and is not a timeout.
type silentError struct{ msg string }

func (e *silentError) Error() string        { return e.msg }
func (e *silentError) Is(target error) bool { return target == ErrServerSilent }

// maxPollBody caps the response Content-Length we will allocate for. A poll
// response carries at most one relay buffer (tens of KB); 1 MiB leaves headroom
// while keeping a hostile server from naming a length that OOMs the client (or,
// if it announces a negative value, panics make()).
const maxPollBody = 1 << 20

// Idle polling backoff and connection-reuse bounds. The 1.10.x transport polled
// every 50ms round the clock (the numWorkers==1 turn condition was always true)
// and opened a fresh TCP+TLS connection with Connection: close on every request
// - a fixed-rate metronome plus ~20 handshakes/second even on a silent tunnel.
const (
	// pollIdleMax is the ceiling the poll interval backs off to while nothing is
	// moving. When data appears (Write -> sendSignal, or a poll that received
	// bytes) the interval snaps back to pollInterval.
	pollIdleMax = 4 * time.Second

	// pollingMaxReuse / pollingReuseMaxAge bound how far a single connection is
	// reused. Reuse amortises the TLS handshake across a burst of active polls,
	// but is deliberately bounded so a meek session never becomes one long-lived
	// flow - the pattern this transport exists to avoid, since TSPU throttles
	// persistent connections. Past either bound the request asks Connection:
	// close and the next poll dials afresh.
	pollingMaxReuse    = 16
	pollingReuseMaxAge = 20 * time.Second
)

// HTTPPollingStrategy implements meek-style HTTP polling transport
// Each data chunk is sent as a short-lived HTTP/1.1 request
// This evades DPI that throttles long-lived connections (like TSPU)
type HTTPPollingStrategy struct {
	manager *Manager // IPv6/IPv4 transport layer support
	secret  []byte
	host    string // Cover host for TLS SNI
	path    string
}

// NewHTTPPollingStrategy creates a new HTTP polling strategy
// manager is required for IPv6/IPv4 transport layer support
func NewHTTPPollingStrategy(manager *Manager, secret []byte) *HTTPPollingStrategy {
	return &HTTPPollingStrategy{
		manager: manager,
		secret:  secret,
		host:    "cdn.jsdelivr.net", // Looks like CDN traffic
		path:    "/npm/jquery/dist/jquery.min.js",
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
	// Shallow reachability check: a plain TCP connect against the same address
	// Connect uses (no TLS, no HTTP request). A full request here, multiplied
	// across ProbeAll's parallel strategies and periodic reprobes, would trip
	// server admission control.
	serverAddr := s.manager.GetServerAddr(ctx)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Connect establishes HTTP polling tunnel
func (s *HTTPPollingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv6 with automatic fallback)
	serverAddr := s.manager.GetServerAddr(ctx)
	secret := dialSecret(ctx, s.secret)
	log.Debug("HTTP Polling: Connecting to %s via %s", target, serverAddr)

	// Generate session ID
	sessionID := generateSessionID(secret)

	// Create polling connection with parallel workers
	pollConn := &HTTPPollingConn{
		manager:         s.manager,
		serverAddr:      serverAddr,
		secret:          secret,
		host:            coverNameFor(ctx, s.host), // SNI and Host of the whole session
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
	// recvCond coordinates Read() wakeups with poll()/Close() without busy-waiting.
	pollConn.recvCond = sync.NewCond(&pollConn.recvLock)
	pollConn.sendCond = sync.NewCond(&pollConn.sendLock)

	// Initialize session (no target - SOCKS handler will write destination via Write())
	if err := pollConn.init(ctx); err != nil {
		return nil, fmt.Errorf("http_polling: init failed: %w", err)
	}

	// Start parallel poll workers with staggered timing
	for i := 0; i < pollConn.numWorkers; i++ {
		workerID := i
		pollConn.workers.Add(1)
		// Stagger worker starts to avoid burst patterns
		go func() {
			defer pollConn.workers.Done()
			time.Sleep(time.Duration(workerID) * 25 * time.Millisecond)
			pollConn.pollWorker(workerID)
		}()
	}

	// Feed the TUN relay's read deadline off poll liveness so a healthy meek
	// session is never torn down waiting on a slow keepalive echo round-trip.
	go pollConn.runKeepaliveFeeder()

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

	// recvCond is signaled (under recvLock) whenever new data lands in
	// recvBuf or the connection is closed. Read waits on it instead of
	// busy-waiting with time.Sleep.
	recvCond *sync.Cond

	// sendCond is signalled (under sendLock) when poll() takes data out of
	// sendBuf or the connection closes; Write waits on it for room.
	sendCond *sync.Cond

	// now is the clock for liveness bookkeeping (lastPollOK, the handshake peek
	// guard). nil means time.Now; tests substitute a fake clock.
	now func() time.Time

	// feedEvery overrides pollingKeepaliveFeed (tests only; 0 = default).
	feedEvery time.Duration

	// hsDrainedAt is when a Read first emptied the receive buffer after the
	// TUN handshake response was complete - the moment the handshake reader's
	// flags peek can start. Guarded by recvLock.
	hsDrainedAt time.Time

	// stream follows what kind of byte stream this session carries and, in TUN
	// mode, its framing, so the keepalive feeder only ever splices a whole
	// keepalive frame between frames. Guarded by recvLock; uplinkSeen lets
	// Write skip the lock once the uplink prefix it needs has been recorded.
	stream     meekStreamTracker
	uplinkSeen atomic.Bool

	// Read deadline support (honors SetReadDeadline/SetDeadline).
	deadlineMu   sync.Mutex
	readDeadline time.Time
	// writeDeadline bounds Close's sending of the uplink left (Close).
	writeDeadline time.Time

	// Polling config
	pollInterval time.Duration
	maxPollWait  time.Duration
	numWorkers   int // Number of parallel poll workers

	// State
	closed    chan struct{}
	closeOnce sync.Once
	// closeErr is what Close reports, for every call: the uplink bytes it
	// could not send.
	closeErr error
	// workers counts the running poll workers, so Close sends what is left
	// only once none of them holds part of it.
	workers sync.WaitGroup
	// pollFailing is set by a poll that failed and cleared by one that went
	// through: Close does not wait on a peer that is not taking polls.
	pollFailing atomic.Bool
	// aborted is set, and abortC closed, when Close's bound runs out or
	// CloseNow is called: the poll in flight is cut (inflight is its
	// connection) and no new one starts. abortC is made by abortChan.
	aborted   atomic.Bool
	abortOnce sync.Once
	abortInit sync.Once
	abortC    chan struct{}
	inflight  atomic.Pointer[tls.Conn]

	lastSend time.Time
	lastRecv time.Time

	// TLS session resumption
	tlsSessionCache tls.ClientSessionCache

	// Connection reuse. A poll normally reuses the previous request's TLS
	// connection (HTTP/1.1 keep-alive) instead of dialling a fresh one, up to
	// pollingMaxReuse requests / pollingReuseMaxAge. reuseMu serialises the
	// whole request against the single poll worker and the init() call.
	reuseMu     sync.Mutex
	reuseConn   *tls.Conn
	reuseReader *bufio.Reader
	reuseCount  int
	reuseOpened time.Time

	// Stats for adaptive behavior
	successfulPolls int64
	failedPolls     int64
	bytesReceived   int64
	statsMu         sync.Mutex

	// Acknowledgement tracking for reliable delivery
	ackSeq  int64 // Total bytes received (sent to server as ack)
	ackLock sync.Mutex

	// uplinkAccepted counts the bytes Write has queued, uplinkSent those a
	// poll has delivered to the server, in order (see UplinkProgress).
	uplinkAccepted atomic.Uint64
	uplinkSent     atomic.Uint64

	// lastPollOK is the unix-nano time of the most recent successful poll. It is
	// meek's true liveness signal: the poll layer round-trips every ~50ms-2s
	// independent of tunnel payload. runKeepaliveFeeder reads it to decide
	// whether the connection is alive enough to keep the TUN relay's read
	// deadline fed.
	lastPollOK atomic.Int64

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
	// Send init request with session ID (no body - SOCKS handler writes target later).
	// The auth token is derived inside doRequest, once the TLS connection this
	// request rides is known, so it binds to that session's exporter (S22).

	// Make first request to establish session on server (ackSeq=0 for init)
	resp, err := c.doRequest(ctx, nil, 0)
	if err != nil {
		return err
	}

	// Server should respond with OK
	if len(resp) < 2 || resp[0] != 'O' || resp[1] != 'K' {
		return errors.New("server did not acknowledge session")
	}
	// The init round-trip is the first proof of liveness; without it a session
	// whose polls never succeed would never count as dead (pollDead treats "no
	// poll recorded" as alive).
	c.lastPollOK.Store(c.clock().UnixNano())

	return nil
}

// pollWorker drives the poll loop with a data-aware interval: it polls fast
// while bytes are moving and backs off exponentially toward pollIdleMax while
// the tunnel is silent, instead of the old fixed 50ms metronome. A Write signals
// sendSignal, which polls immediately and snaps the interval back to fast.
func (c *HTTPPollingConn) pollWorker(workerID int) {
	// Wait for first data to be written before polling
	// (SOCKS handler needs to write destination address first)
	select {
	case <-c.closed:
		return
	case <-c.ready:
		// Data available, start polling
	}

	consecutiveFailures := 0
	maxBackoff := 2 * time.Second
	idleRounds := 0

	timer := time.NewTimer(jitterDuration(c.pollInterval))
	defer timer.Stop()

	for {
		// Closed first: the select below picks at random among ready
		// cases, and a pending sendSignal started a poll after Close, on
		// its own 3 s rather than Close's bound (P2-1 of the round-18
		// review).
		if c.isClosed() {
			return
		}
		select {
		case <-c.closed:
			return
		case <-c.sendSignal:
			// New outbound data: poll now and return to the fast interval.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if c.isClosed() {
				return
			}
			c.poll()
			idleRounds = 0
			timer.Reset(jitterDuration(c.pollInterval))
		case <-timer.C:
			if c.isClosed() {
				return
			}
			ok, moved := c.poll()
			switch {
			case !ok:
				consecutiveFailures++
				backoff := time.Duration(consecutiveFailures*consecutiveFailures) * 100 * time.Millisecond
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				timer.Reset(jitterDuration(c.pollInterval + backoff))
			case moved:
				// Data flowed: stay fast.
				consecutiveFailures = 0
				idleRounds = 0
				timer.Reset(jitterDuration(c.pollInterval))
			default:
				// Successful but empty poll: the tunnel is idle, back off.
				consecutiveFailures = 0
				idleRounds++
				timer.Reset(jitterDuration(c.idleInterval(idleRounds)))
			}
		}
	}
}

// isClosed reports whether Close has been called.
func (c *HTTPPollingConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// abortChan is closed when the conn is aborted (abortNow).
func (c *HTTPPollingConn) abortChan() chan struct{} {
	c.abortInit.Do(func() { c.abortC = make(chan struct{}) })
	return c.abortC
}

// abortNow cuts the poll in flight and keeps any other from starting.
func (c *HTTPPollingConn) abortNow() {
	ch := c.abortChan()
	c.abortOnce.Do(func() {
		c.aborted.Store(true)
		close(ch)
	})
	if tc := c.inflight.Load(); tc != nil {
		_ = tc.Close()
	}
}

// idleInterval grows the poll interval geometrically from pollInterval toward
// pollIdleMax as consecutive polls come back empty.
func (c *HTTPPollingConn) idleInterval(rounds int) time.Duration {
	d := c.pollInterval
	for i := 0; i < rounds && d < pollIdleMax; i++ {
		d *= 2
	}
	if d > pollIdleMax {
		d = pollIdleMax
	}
	return d
}

// jitterDuration applies ±25% multiplicative jitter from crypto/rand.
//
// Purpose (verification rules 3 and 8): break the exact metronome and keep
// independent clients from polling in phase. It is NOT an attempt to mimic a
// measured inter-request distribution - there is no such measured population to
// match, so "what distribution is this checked against" is "nothing", recorded
// here on purpose. Rule 8 warns that smearing silence with uniform jitter is
// itself a shape; the real anti-metronome move here is idleInterval, which
// stretches the gap, and the jitter is only a small decorrelation on top.
func jitterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return d
	}
	frac := float64(binary.BigEndian.Uint32(b[:])) / float64(1<<32) // [0,1)
	return time.Duration(float64(d) * (0.75 + 0.5*frac))
}

// poll does one poll cycle. ok reports the request succeeded; moved reports the
// cycle actually carried tunnel bytes (sent or received), which the caller uses
// to tell an active tunnel from an idle keepalive round.
func (c *HTTPPollingConn) poll() (ok bool, moved bool) {
	return c.pollBy(time.Now().Add(pollTimeout))
}

// pollTimeout bounds one poll request: the dial, the TLS handshake, and the
// request's write and read.
const pollTimeout = 3 * time.Second

// pollBy is poll bounded by deadline as well as pollTimeout.
func (c *HTTPPollingConn) pollBy(deadline time.Time) (ok bool, moved bool) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	// An abort cuts a dial or a TLS handshake in progress too.
	go func() {
		select {
		case <-c.abortChan():
			cancel()
		case <-ctx.Done():
		}
	}()

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
		if c.sendCond != nil {
			c.sendCond.Broadcast() // room for a Write blocked on the bound
		}
	}
	c.sendLock.Unlock()

	// Get current ack sequence (bytes we've successfully received)
	c.ackLock.Lock()
	ackSeq := c.ackSeq
	c.ackLock.Unlock()

	// Do request with ack sequence. The auth token is derived inside doRequest,
	// bound to the exporter of the TLS session the request actually rides (S22).
	resp, err := c.doRequest(ctx, sendData, ackSeq)
	c.pollFailing.Store(err != nil)
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
		return false, false
	}

	// Buffer received data and update ack sequence
	if len(resp) > 0 {
		c.recvLock.Lock()
		c.stream.observeDownlink(resp)
		c.recvBuf.Write(resp)
		// Wake any goroutine blocked in Read waiting for data.
		c.recvCond.Broadcast()
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

	c.uplinkSent.Add(uint64(len(sendData)))

	c.statsMu.Lock()
	c.successfulPolls++
	c.statsMu.Unlock()

	// Record liveness for the keepalive feeder: a completed poll round-trip is
	// proof the meek transport is alive even when no tunnel payload is flowing.
	c.lastPollOK.Store(c.clock().UnixNano())

	return true, len(sendData) > 0 || len(resp) > 0
}

// runKeepaliveFeeder keeps the TUN relay's read deadline fed while the poll
// layer is healthy. See the pollingKeepaliveFeed comment for why meek needs
// this. If polls stop succeeding the connection is genuinely dead, the feeder
// goes quiet, and the relay's own read deadline fires to tear the session down.
func (c *HTTPPollingConn) runKeepaliveFeeder() {
	every := c.feedEvery
	if every <= 0 {
		every = pollingKeepaliveFeed
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			c.feedKeepalive()
		}
	}
}

// clock returns the liveness clock's current time.
func (c *HTTPPollingConn) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// pollDead reports that no poll has succeeded for pollingPollHealthGrace.
// A connection that has not recorded any poll yet is not dead.
func (c *HTTPPollingConn) pollDead() bool {
	last := c.lastPollOK.Load()
	return last != 0 && c.clock().Sub(time.Unix(0, last)) > pollingPollHealthGrace
}

// feedKeepalive splices one synthetic keepalive frame into the receive buffer
// if, and only if, that cannot change the stream the reader sees: the session
// is in TUN mode, the reader has drained the buffer, and what it drained ends
// on a frame boundary, and the handshake reader's flags peek is over
// (pollingHandshakePeekGuard). It reports whether a frame was spliced.
//
// The old condition was "receive buffer empty" alone. That spliced four zero
// bytes into every SOCKS download that ran past the first feeder tick, and in
// TUN mode it fired whenever the reader was parked inside a frame split
// across two poll responses.
func (c *HTTPPollingConn) feedKeepalive() bool {
	last := c.lastPollOK.Load()
	now := c.clock()
	if last == 0 || now.Sub(time.Unix(0, last)) > pollingPollHealthGrace {
		return false // poll layer is not proving liveness - let the relay time out
	}
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	if c.recvBuf.Len() != 0 || !c.stream.atFrameBoundary() {
		return false
	}
	if c.hsDrainedAt.IsZero() || now.Sub(c.hsDrainedAt) < pollingHandshakePeekGuard {
		return false // the handshake reader may still be waiting for a flags byte
	}
	// A zero-length frame. It is kept out of the tracker on purpose: on the
	// boundary a zero frame leaves it where it is anyway, and the tracker's
	// count of keepalives is the server's alone (ServerKeepalives).
	c.recvBuf.Write([]byte{0, 0, 0, 0})
	c.recvCond.Broadcast()
	return true
}

// UplinkProgress reports how many bytes Write has accepted and how many of
// them a poll has delivered so far. A Write returns once its bytes are
// queued, up to 1 MiB ahead of the polls; the bytes of a given Write are on
// their way to the server once sent has reached accepted as it stood after
// that Write.
func (c *HTTPPollingConn) UplinkProgress() (accepted, sent uint64) {
	return c.uplinkAccepted.Load(), c.uplinkSent.Load()
}

// ServerKeepalives counts the zero-length frames the server really sent:
// keepalive echoes. The feeder splices frames that look the same into what
// Read returns, so a reader that counts those as echoes hears an answer from a
// server that may be saying nothing (see strategy.ServerKeepaliveCounter).
//
// tracked is false outside the TUN frame stream: on a SOCKS stream, before
// the handshake is through, or after the tracker lost the framing - then no
// count can be had, and an echo judged without one would be judged wrong.
func (c *HTTPPollingConn) ServerKeepalives() (n uint64, tracked bool) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	return c.stream.keepalives, c.stream.state == meekDownFrames
}

// MakesUpKeepalives: the feeder splices keepalive frames of its own.
func (*HTTPPollingStrategy) MakesUpKeepalives() bool { return true }

// doRequest performs one HTTP poll request, reusing the previous request's TLS
// connection (HTTP/1.1 keep-alive) when one is live and within the reuse bounds,
// otherwise dialling fresh. reuseMu serialises the whole exchange.
func (c *HTTPPollingConn) doRequest(ctx context.Context, data []byte, ackSeq int64) ([]byte, error) {
	c.reuseMu.Lock()
	defer c.reuseMu.Unlock()

	if c.aborted.Load() {
		return nil, errPollingAborted
	}
	tlsConn, reader, err := c.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	// Abortable from here on (abortNow); an abort that came between the
	// check above and this store finds the conn on the re-check.
	c.inflight.Store(tlsConn)
	defer c.inflight.CompareAndSwap(tlsConn, nil)
	if c.aborted.Load() {
		c.dropReuseLocked()
		return nil, errPollingAborted
	}

	// Bind the auth token to the exporter of the TLS session this request rides
	// (S22). Derived here, after acquireConn, so a reused keep-alive session and
	// a freshly dialled one each get a token that matches their own exporter.
	authToken, err := c.generateAuthTokenForConn(tlsConn)
	if err != nil {
		c.dropReuseLocked()
		return nil, fmt.Errorf("http_polling: export keying material: %w", err)
	}

	c.reuseCount++
	keepAlive := c.reuseCount < pollingMaxReuse && time.Since(c.reuseOpened) < pollingReuseMaxAge
	connHeader := "keep-alive"
	if !keepAlive {
		connHeader = "close"
	}

	deadline := time.Now().Add(pollTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	resp, err := c.exchange(tlsConn, reader, authToken, data, ackSeq, connHeader, deadline)
	if err != nil {
		// Drop the connection; poll() re-queues any send data and the next poll
		// dials fresh. We do NOT retry here - a retry on a half-sent request
		// would double-write client bytes into the server's fromClient stream.
		c.dropReuseLocked()
		return nil, err
	}
	if !keepAlive {
		c.dropReuseLocked()
	}
	return resp, nil
}

// acquireConn returns the reusable connection, dialling and handshaking a new
// one (and sending the once-per-connection protocol dispatch) if none is live.
// Caller holds reuseMu.
func (c *HTTPPollingConn) acquireConn(ctx context.Context) (*tls.Conn, *bufio.Reader, error) {
	if c.reuseConn != nil {
		return c.reuseConn, c.reuseReader, nil
	}

	serverAddr := c.manager.GetServerAddr(ctx)
	// Protected dialer avoids the VPN routing loop on Android.
	protectedDialer := &protect.ProtectDialer{
		Dialer: &net.Dialer{Timeout: 3 * time.Second},
	}
	tcpConn, err := protectedDialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		ServerName:         c.host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		ClientSessionCache: c.tlsSessionCache, // TLS session resumption
	}
	tlsConn := tls.Client(tcpConn, customtls.WithFallbackTag(tlsConfig, c.secret))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, nil, err
	}

	// Protocol discriminator, once per connection (encrypted, not visible to DPI).
	// It precedes the first HTTP request; keep-alive then carries further
	// requests over the same already-dispatched connection.
	if err := protocol.WriteDispatch(tlsConn, protocol.TypePolling); err != nil {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("http_polling: dispatch failed: %w", err)
	}

	c.reuseConn = tlsConn
	c.reuseReader = bufio.NewReader(tlsConn)
	c.reuseOpened = time.Now()
	c.reuseCount = 0
	return tlsConn, c.reuseReader, nil
}

// exchange writes one request and reads its response on an already-established
// connection. reader must be the persistent reader for that connection so the
// stream stays aligned for the next keep-alive request. Caller holds reuseMu.
func (c *HTTPPollingConn) exchange(tlsConn *tls.Conn, reader *bufio.Reader, authToken string, data []byte, ackSeq int64, connHeader string, deadline time.Time) ([]byte, error) {
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
			"Connection: %s\r\n"+
			"\r\n",
		c.path, c.host, len(body), c.sessionID, authToken, ackSeq, connHeader)

	// Refresh the deadline every request - a reused connection may have sat idle
	// past the previous request's deadline.
	tlsConn.SetDeadline(deadline)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil, err
	}
	if len(body) > 0 {
		if _, err := tlsConn.Write(body); err != nil {
			return nil, err
		}
	}

	return readPollResponse(reader)
}

// readPollResponse reads the status line, headers and body of one poll response
// off reader. It caps the peer-announced Content-Length before allocating, so a
// hostile server cannot name a length that OOMs the client (or, if negative,
// panics make()).
func readPollResponse(reader *bufio.Reader) ([]byte, error) {
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

	// Read exactly Content-Length body bytes so the reader is aligned for the
	// next keep-alive response.
	if contentLength > maxPollBody {
		return nil, fmt.Errorf("poll response Content-Length %d exceeds the %d byte cap", contentLength, maxPollBody)
	}
	if contentLength > 0 {
		respBody := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, respBody); err != nil {
			return nil, err
		}
		return respBody, nil
	}
	return nil, nil
}

// dropReuseLocked closes and forgets the reusable connection. Caller holds
// reuseMu.
func (c *HTTPPollingConn) dropReuseLocked() {
	if c.reuseConn != nil {
		c.reuseConn.Close()
		c.reuseConn = nil
		c.reuseReader = nil
	}
}

// generateAuthTokenForConn creates the HMAC auth token bound to tlsConn's
// session exporter (S22). Folding the exporter into the HMAC makes a token
// captured on one poll session useless on another; the server rederives it from
// its own side of the same session (server.go verifyPollingAuth). Unlike the
// stego/morph family this token keys on sessionID plus a per-second timestamp,
// which the server tolerates to 60s — the exporter binding rides on top.
func (c *HTTPPollingConn) generateAuthTokenForConn(tlsConn *tls.Conn) (string, error) {
	ekm, err := sessionExporterKey(tlsConn)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Unix()
	data := fmt.Sprintf("%s:%d", c.sessionID, timestamp)

	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(data))
	h.Write(ekm) // TLS-session binding
	return base64.StdEncoding.EncodeToString(h.Sum(nil))[:16], nil
}

// Read implements net.Conn.
//
// Blocks on recvCond until data is available, the connection is closed, or the
// read deadline expires - no busy-waiting. The effective deadline is whatever
// SetReadDeadline/SetDeadline set; if unset, a 30s fallback preserves the
// previous behavior of never blocking forever.
func (c *HTTPPollingConn) Read(p []byte) (int, error) {
	// Resolve the effective deadline.
	c.deadlineMu.Lock()
	deadline := c.readDeadline
	c.deadlineMu.Unlock()
	if deadline.IsZero() {
		deadline = time.Now().Add(30 * time.Second)
	}

	// Watcher broadcasts the cond when the connection closes or the deadline
	// fires, so a Read blocked in cond.Wait() is woken in those cases too.
	done := make(chan struct{})
	defer close(done)
	go func() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-done:
		case <-c.closed:
		case <-timer.C:
		}
		c.recvLock.Lock()
		c.recvCond.Broadcast()
		c.recvLock.Unlock()
	}()

	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	for {
		if c.recvBuf.Len() > 0 {
			n, err := c.recvBuf.Read(p)
			if c.recvBuf.Len() == 0 && c.hsDrainedAt.IsZero() && c.stream.pastHandshake() {
				c.hsDrainedAt = c.clock()
			}
			return n, err
		}

		// Closed connection: report EOF once buffer is drained.
		select {
		case <-c.closed:
			return 0, io.EOF
		default:
		}

		if !time.Now().Before(deadline) {
			if c.pollDead() {
				return 0, errPollingDead
			}
			// The net.Conn deadline error: callers (the SOCKS relay among them)
			// recognise a timeout through net.Error.Timeout() and keep an idle
			// direction open. A plain error made every download-silent stream -
			// an upload, an idle interactive session - die after 30s.
			return 0, os.ErrDeadlineExceeded
		}

		c.recvCond.Wait()
	}
}

// Write implements net.Conn
func (c *HTTPPollingConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, errors.New("connection closed")
	default:
	}

	// Record the uplink prefix before the bytes can be polled out, so the
	// stream kind is known by the time any reply lands in recvBuf.
	if !c.uplinkSeen.Load() {
		c.recvLock.Lock()
		c.stream.observeUplink(p)
		if c.stream.uplinkSettled() {
			c.uplinkSeen.Store(true)
		}
		c.recvLock.Unlock()
	}

	c.sendLock.Lock()
	if err := c.waitSendRoomLocked(); err != nil {
		c.sendLock.Unlock()
		return 0, err
	}
	// Again under sendLock: a Close since the check above counts what is
	// left under it, and bytes appended after that count would be neither
	// sent nor reported (P3-1 of the round-18 review).
	if c.isClosed() {
		c.sendLock.Unlock()
		return 0, errors.New("connection closed")
	}
	n, err := c.sendBuf.Write(p)
	c.uplinkAccepted.Add(uint64(n))
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

// waitSendRoomLocked blocks while the uplink queue is at its bound, until a
// poll drains it, the connection closes, or the poll layer is declared dead.
// Caller holds sendLock.
func (c *HTTPPollingConn) waitSendRoomLocked() error {
	for c.sendBuf.Len() >= maxPollingSendBuffered {
		select {
		case <-c.closed:
			return errors.New("connection closed")
		default:
		}
		if c.pollDead() {
			return errPollingDead
		}
		// Re-check liveness periodically even if no poll ever wakes us.
		wake := time.AfterFunc(250*time.Millisecond, func() {
			c.sendLock.Lock()
			c.sendCond.Broadcast()
			c.sendLock.Unlock()
		})
		c.sendCond.Wait()
		wake.Stop()
	}
	return nil
}

// errPollingAborted is a poll refused or cut by an abort (abortNow).
var errPollingAborted = errors.New("http_polling: aborted")

// ErrPollingCloseIncomplete is what Close returns when uplink bytes Write had
// accepted could not be sent before the conn closed.
var ErrPollingCloseIncomplete = errors.New("http_polling: close left uplink bytes unsent")

// pollingCloseTimeout bounds how long Close spends sending what Write
// accepted. A var so tests can scale it.
var pollingCloseTimeout = 5 * time.Second

// Close implements net.Conn. It sends what Write accepted and no poll has
// sent yet, for at most pollingCloseTimeout, and reports the bytes it could
// not send. It dropped them: up to 1 MiB of uplink a Write had answered for
// was lost without a word (issue #131, as MorphedConn.Close in #129). Write
// fails from the moment Close is called.
func (c *HTTPPollingConn) Close() error {
	now := time.Now()
	closeBy := now.Add(pollingCloseTimeout)
	// A write deadline still ahead shortens the wait; one already past is
	// left over from an earlier write - a keepalive's, the TUN writer's -
	// and would turn every Close into CloseNow (as P2 of the round-3 review
	// of #129 found for MorphedConn). CloseNow is the abort.
	c.deadlineMu.Lock()
	if wd := c.writeDeadline; wd.After(now) && wd.Before(closeBy) {
		closeBy = wd
	}
	c.deadlineMu.Unlock()
	return c.closeBy(closeBy)
}

// CloseNow closes the conn without sending what Write accepted, and reports
// those bytes: for a caller that is stopping, or leaving a dead session, and
// will not wait on the peer. It cuts the poll in flight, and a Close already
// sending - which waits on its own bound - with it.
func (c *HTTPPollingConn) CloseNow() error {
	c.abortNow()
	return c.closeBy(time.Now())
}

// closeBy is Close with its sending bounded by closeBy.
func (c *HTTPPollingConn) closeBy(closeBy time.Time) error {
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.sendCond != nil {
			c.sendLock.Lock()
			c.sendCond.Broadcast()
			c.sendLock.Unlock()
		}
		// Wake any Read blocked on recvCond so it can return EOF.
		c.recvLock.Lock()
		c.recvCond.Broadcast()
		c.recvLock.Unlock()
		c.closeErr = c.flushOnClose(closeBy)
		// Tear down any reused keep-alive connection.
		c.reuseMu.Lock()
		c.dropReuseLocked()
		c.reuseMu.Unlock()
	})
	return c.closeErr
}

// flushOnClose sends what is left in sendBuf by closeBy, with the polls the
// workers would have made: the same chunks, one request each.
//
// It counts what is left only once the workers have stopped: a worker in a
// poll holds a chunk outside sendBuf, and puts it back if the poll fails.
// Counted earlier, an empty sendBuf read as all sent while the worker's poll
// was about to fail - the silent loss this exists to stop - and the count
// left that chunk out (P2-1 of the round-18 review). At closeBy, or on
// CloseNow, the poll in flight is cut, so the wait stays inside the bound.
func (c *HTTPPollingConn) flushOnClose(closeBy time.Time) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTimer(time.Until(closeBy))
		defer t.Stop()
		select {
		case <-t.C:
			c.abortNow()
		case <-c.abortChan():
		case <-done:
		}
	}()
	c.workers.Wait()
	triedOwn := false
	for {
		c.sendLock.Lock()
		left := c.sendBuf.Len()
		c.sendLock.Unlock()
		if left == 0 {
			return nil
		}
		// Out of time, aborted, or the peer is not taking polls and one poll
		// of our own did not go through either: a conn closed after its
		// server went silent must not spend the whole bound on it. One
		// failed poll is not enough - a stale keep-alive fails once (P3-2
		// of the round-18 review).
		if c.aborted.Load() || !time.Now().Before(closeBy) || (c.pollFailing.Load() && triedOwn) {
			return fmt.Errorf("%w: %d bytes", ErrPollingCloseIncomplete, left)
		}
		triedOwn = true
		by := time.Now().Add(pollTimeout)
		if closeBy.Before(by) {
			by = closeBy
		}
		c.pollBy(by)
	}
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
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *HTTPPollingConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	// Wake a blocked Read so it re-evaluates the new deadline.
	c.recvLock.Lock()
	c.recvCond.Broadcast()
	c.recvLock.Unlock()
	return nil
}

// SetWriteDeadline bounds what Close spends sending the uplink Write
// accepted. Write itself only queues.
func (c *HTTPPollingConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
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
