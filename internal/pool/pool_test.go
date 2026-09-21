package pool

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// fakeStrategy is a no-op strategy.Strategy so createConn's logging and the
// caller's metrics have a non-nil value to query.
type fakeStrategy struct{}

func (fakeStrategy) Name() string                        { return "fake" }
func (fakeStrategy) ID() string                          { return "fake" }
func (fakeStrategy) Priority() int                       { return 0 }
func (fakeStrategy) Probe(context.Context, string) error { return nil }
func (fakeStrategy) Connect(context.Context, string) (net.Conn, error) {
	return nil, errors.New("fakeStrategy: not dialable")
}
func (fakeStrategy) RequiresServer() bool { return false }
func (fakeStrategy) Description() string  { return "fake strategy for tests" }

// attemptScript drives one Connect attempt: either it fails to connect, or it
// returns a pipe whose server end is driven by serverFn.
type attemptScript struct {
	connectErr bool
	serverFn   func(server net.Conn)
}

// fakeConnector hands out scripted connections, one per Connect call, so a test
// can model a connection that dies before the ack and a retry that succeeds.
type fakeConnector struct {
	mu      sync.Mutex
	scripts []attemptScript
	calls   int
}

func (f *fakeConnector) Connect(_ context.Context, _ string) (net.Conn, strategy.Strategy, error) {
	f.mu.Lock()
	i := f.calls
	f.calls++
	f.mu.Unlock()

	if i >= len(f.scripts) {
		return nil, nil, errors.New("fakeConnector: no script for attempt")
	}
	s := f.scripts[i]
	if s.connectErr {
		return nil, nil, errors.New("fakeConnector: connect failed")
	}
	client, server := net.Pipe()
	go s.serverFn(server)
	return client, fakeStrategy{}, nil
}

func (f *fakeConnector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// readTarget reads the length-prefixed target address the client sends first.
func readTarget(t *testing.T, server net.Conn) string {
	t.Helper()
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(server, lenBuf); err != nil {
		return ""
	}
	n := binary.BigEndian.Uint16(lenBuf)
	addr := make([]byte, n)
	if _, err := io.ReadFull(server, addr); err != nil {
		return ""
	}
	return string(addr)
}

// newTestPool builds a pool wired to a fake connector without starting the
// background cleanup loop.
func newTestPool(c Connector) *TunnelPool {
	return &TunnelPool{
		config:  DefaultConfig(),
		manager: c,
	}
}

func TestDialTargetFirstTrySuccess(t *testing.T) {
	gotTarget := make(chan string, 1)
	fc := &fakeConnector{scripts: []attemptScript{
		{serverFn: func(s net.Conn) {
			gotTarget <- readTarget(t, s)
			s.Write([]byte{0x00})
		}},
	}}
	p := newTestPool(fc)

	conn, err := p.DialTarget(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("DialTarget: unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("DialTarget: nil conn on success")
	}
	if got := <-gotTarget; got != "example.com:443" {
		t.Fatalf("server saw target %q, want example.com:443", got)
	}
	if fc.callCount() != 1 {
		t.Fatalf("Connect called %d times, want 1", fc.callCount())
	}
	conn.Close()
	if got := atomic.LoadInt32(&p.totalConns); got != 0 {
		t.Fatalf("totalConns=%d after close, want 0", got)
	}
}

func TestDialTargetRetriesOnEOFBeforeAck(t *testing.T) {
	fc := &fakeConnector{scripts: []attemptScript{
		// Attempt 1: read the target, then vanish before the ack (the
		// "No response from server: EOF" case).
		{serverFn: func(s net.Conn) {
			readTarget(t, s)
			s.Close()
		}},
		// Attempt 2: a healthy connection.
		{serverFn: func(s net.Conn) {
			readTarget(t, s)
			s.Write([]byte{0x00})
		}},
	}}
	p := newTestPool(fc)

	conn, err := p.DialTarget(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("DialTarget: expected success on retry, got %v", err)
	}
	if conn == nil {
		t.Fatal("DialTarget: nil conn after successful retry")
	}
	if fc.callCount() != 2 {
		t.Fatalf("Connect called %d times, want 2 (one retry)", fc.callCount())
	}
	conn.Close()
	if got := atomic.LoadInt32(&p.totalConns); got != 0 {
		t.Fatalf("totalConns=%d after close, want 0 (no leak across retry)", got)
	}
}

// nilStrategyConnector hands back a live connection but a nil strategy, which is
// what the mux fast-path returns after storm parking clears the manager's last
// successful strategy out from under it.
type nilStrategyConnector struct{}

func (nilStrategyConnector) Connect(context.Context, string) (net.Conn, strategy.Strategy, error) {
	client, server := net.Pipe()
	go func() { io.Copy(io.Discard, server); server.Close() }()
	return client, nil, nil
}

// TestCreateConnSurvivesNilStrategy guards the log-arg panic: usedStrategy.Name()
// on a nil interface (evaluated unconditionally as a log argument) crashed Get.
//
// Predicated against the broken code: call usedStrategy.Name() directly in the
// log and this panics with a nil-pointer dereference.
func TestCreateConnSurvivesNilStrategy(t *testing.T) {
	p := newTestPool(nilStrategyConnector{})

	conn, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get with nil strategy: %v", err)
	}
	if conn == nil {
		t.Fatal("Get returned nil conn")
	}
	if conn.Strategy() != nil {
		t.Fatal("expected the nil strategy to pass through unchanged")
	}
	conn.Close()
}

func TestDialTargetRetriesOnConnectError(t *testing.T) {
	fc := &fakeConnector{scripts: []attemptScript{
		{connectErr: true},
		{serverFn: func(s net.Conn) {
			readTarget(t, s)
			s.Write([]byte{0x00})
		}},
	}}
	p := newTestPool(fc)

	conn, err := p.DialTarget(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("DialTarget: expected success after connect retry, got %v", err)
	}
	if fc.callCount() != 2 {
		t.Fatalf("Connect called %d times, want 2", fc.callCount())
	}
	conn.Close()
}

func TestDialTargetServerRejectionNotRetried(t *testing.T) {
	fc := &fakeConnector{scripts: []attemptScript{
		{serverFn: func(s net.Conn) {
			readTarget(t, s)
			s.Write([]byte{0x01}) // deliberate rejection
		}},
		// A second script exists; it must NOT be used.
		{serverFn: func(s net.Conn) {
			readTarget(t, s)
			s.Write([]byte{0x00})
		}},
	}}
	p := newTestPool(fc)

	conn, err := p.DialTarget(context.Background(), "blocked.example:443")
	if !errors.Is(err, ErrServerRejected) {
		t.Fatalf("DialTarget: err=%v, want ErrServerRejected", err)
	}
	if conn != nil {
		t.Fatal("DialTarget: conn must be nil on rejection")
	}
	if fc.callCount() != 1 {
		t.Fatalf("Connect called %d times, want 1 (rejection is not retried)", fc.callCount())
	}
	if got := atomic.LoadInt32(&p.totalConns); got != 0 {
		t.Fatalf("totalConns=%d after rejection, want 0", got)
	}
}

func TestDialTargetFailsAfterRetryExhausted(t *testing.T) {
	dead := attemptScript{serverFn: func(s net.Conn) {
		readTarget(t, s)
		s.Close()
	}}
	fc := &fakeConnector{scripts: []attemptScript{dead, dead}}
	p := newTestPool(fc)

	conn, err := p.DialTarget(context.Background(), "example.com:443")
	if err == nil {
		t.Fatal("DialTarget: expected error after both attempts fail")
	}
	if errors.Is(err, ErrServerRejected) {
		t.Fatalf("DialTarget: transient failure misreported as rejection: %v", err)
	}
	if conn != nil {
		t.Fatal("DialTarget: conn must be nil on failure")
	}
	if fc.callCount() != 2 {
		t.Fatalf("Connect called %d times, want exactly 2 (no third attempt)", fc.callCount())
	}
	if got := atomic.LoadInt32(&p.totalConns); got != 0 {
		t.Fatalf("totalConns=%d after failure, want 0", got)
	}
}

// sanity: a tunnel address that overflows the 16-bit length prefix is rejected
// before any Connect.
func TestDialTargetAddressTooLong(t *testing.T) {
	fc := &fakeConnector{}
	p := newTestPool(fc)
	long := make([]byte, 70000)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := p.DialTarget(context.Background(), string(long)); err == nil {
		t.Fatal("DialTarget: expected error for over-long target")
	}
	if fc.callCount() != 0 {
		t.Fatalf("Connect called %d times for invalid target, want 0", fc.callCount())
	}
}

// --- Get / bookkeeping ---------------------------------------------------

// TestNewTunnelPool checks the documented contract that serverAddr is ignored
// and a fresh pool reports zero live connections.
func TestNewTunnelPool(t *testing.T) {
	p := NewTunnelPool(nil, "ignored.example:443", DefaultConfig())
	if p == nil {
		t.Fatal("NewTunnelPool returned nil")
	}
	if got := p.Stats(); got != 0 {
		t.Fatalf("fresh pool Stats()=%d, want 0", got)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestGetEnforcesMaxConnections predicates the MaxConnections guard: with the
// limit at 1 and one connection outstanding, the second Get must be refused
// without a connector call. Positive control: with the outstanding connection
// closed (slot freed), the same Get succeeds - so the refusal is the limit, not
// a broken connector.
func TestGetEnforcesMaxConnections(t *testing.T) {
	fc := &fakeConnector{scripts: []attemptScript{
		{serverFn: func(s net.Conn) { io.Copy(io.Discard, s) }},
		{serverFn: func(s net.Conn) { io.Copy(io.Discard, s) }},
	}}
	p := newTestPool(fc)
	p.config.MaxConnections = 1

	first, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if got := p.Stats(); got != 1 {
		t.Fatalf("Stats after first Get=%d, want 1", got)
	}

	// Limit reached: second Get is refused and never touches the connector.
	if _, err := p.Get(context.Background()); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("second Get err=%v, want ErrPoolExhausted", err)
	}
	if fc.callCount() != 1 {
		t.Fatalf("connector called %d times, want 1 (refused Get must not dial)", fc.callCount())
	}

	// Positive control: free the slot, the same call now succeeds.
	first.Close()
	if got := p.Stats(); got != 0 {
		t.Fatalf("Stats after close=%d, want 0", got)
	}
	second, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get after slot freed: %v", err)
	}
	if fc.callCount() != 2 {
		t.Fatalf("connector called %d times, want 2", fc.callCount())
	}
	second.Close()
}

// TestStatsTracksLiveConns checks the counter rises per handout and falls per
// Close, and that createConn undoes its increment when the connector errors.
func TestStatsTracksLiveConns(t *testing.T) {
	fc := &fakeConnector{scripts: []attemptScript{
		{serverFn: func(s net.Conn) { io.Copy(io.Discard, s) }},
		{serverFn: func(s net.Conn) { io.Copy(io.Discard, s) }},
		{connectErr: true},
	}}
	p := newTestPool(fc)

	a, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	b, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get b: %v", err)
	}
	if got := p.Stats(); got != 2 {
		t.Fatalf("Stats=%d, want 2", got)
	}

	// A failed dial must not leak a slot.
	if _, err := p.Get(context.Background()); err == nil {
		t.Fatal("Get with connectErr script: expected error")
	}
	if got := p.Stats(); got != 2 {
		t.Fatalf("Stats after failed dial=%d, want 2 (no leak)", got)
	}

	a.Close()
	b.Close()
	if got := p.Stats(); got != 0 {
		t.Fatalf("Stats after closing both=%d, want 0", got)
	}
}

// TestPoolExhaustedError locks the sentinel's message and errors.Is identity.
func TestPoolExhaustedError(t *testing.T) {
	if ErrPoolExhausted.Error() != "pool exhausted" {
		t.Fatalf("ErrPoolExhausted.Error()=%q", ErrPoolExhausted.Error())
	}
	wrapped := fmt.Errorf("get failed: %w", ErrPoolExhausted)
	if !errors.Is(wrapped, ErrPoolExhausted) {
		t.Fatal("wrapped ErrPoolExhausted must satisfy errors.Is")
	}
}

// TestGetConcurrent hammers createConn from many goroutines under -race: the
// atomic counter must return to exactly zero after every handed-out connection
// is closed, and the connector must be called once per successful Get.
func TestGetConcurrent(t *testing.T) {
	const n = 64
	scripts := make([]attemptScript, n)
	for i := range scripts {
		scripts[i] = attemptScript{serverFn: func(s net.Conn) { io.Copy(io.Discard, s); s.Close() }}
	}
	fc := &fakeConnector{scripts: scripts}
	p := newTestPool(fc)

	var wg sync.WaitGroup
	conns := make([]*PooledConn, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = p.Get(context.Background())
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("Get[%d]: %v", i, errs[i])
		}
	}
	if got := p.Stats(); got != n {
		t.Fatalf("Stats after %d concurrent Get=%d, want %d", n, got, n)
	}
	if fc.callCount() != n {
		t.Fatalf("connector called %d times, want %d", fc.callCount(), n)
	}

	var cwg sync.WaitGroup
	for i := 0; i < n; i++ {
		cwg.Add(1)
		go func(i int) { defer cwg.Done(); conns[i].Close() }(i)
	}
	cwg.Wait()
	if got := atomic.LoadInt32(&p.totalConns); got != 0 {
		t.Fatalf("totalConns=%d after closing all, want 0", got)
	}
}

// tcpConnector dials a loopback listener so createConn takes the *net.TCPConn
// keepalive branch that net.Pipe fakes never reach.
type tcpConnector struct{ addr string }

func (c tcpConnector) Connect(ctx context.Context, _ string) (net.Conn, strategy.Strategy, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, nil, err
	}
	return conn, fakeStrategy{}, nil
}

// TestCreateConnEnablesKeepAlive covers the *net.TCPConn keepalive branch with a
// real loopback socket.
func TestCreateConnEnablesKeepAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()

	p := newTestPool(tcpConnector{addr: ln.Addr().String()})
	conn, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get over TCP: %v", err)
	}
	if _, ok := conn.Conn.(*net.TCPConn); !ok {
		t.Fatalf("expected *net.TCPConn, got %T", conn.Conn)
	}
	conn.Close()
	if got := p.Stats(); got != 0 {
		t.Fatalf("Stats after close=%d, want 0", got)
	}
}

// --- isRelayTimeout ------------------------------------------------------

// timeoutErr is a net.Error whose Timeout() answer the test controls.
type timeoutErr struct{ timeout bool }

func (e timeoutErr) Error() string   { return "timeoutErr" }
func (e timeoutErr) Timeout() bool   { return e.timeout }
func (e timeoutErr) Temporary() bool { return false }

// TestIsRelayTimeout locks each branch. The two string cases exist because
// smux v2's errTimeout does not implement net.Error; drop the string match and
// those two rows go red.
func TestIsRelayTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"net.Error timeout", timeoutErr{timeout: true}, true},
		{"net.Error non-timeout", timeoutErr{timeout: false}, false},
		{"smux bare timeout string", errors.New("timeout"), true},
		{"io timeout string", errors.New("i/o timeout"), true},
		{"unrelated error", errors.New("connection reset by peer"), false},
		{"eof is not a timeout", io.EOF, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRelayTimeout(tc.err); got != tc.want {
				t.Fatalf("isRelayTimeout(%v)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- PooledRelay ---------------------------------------------------------

// relayHarness wires a browser<->relay<->exit chain out of two net.Pipes.
// clientEnd is the browser side; serverEnd is the exit side.
type relayHarness struct {
	clientEnd  net.Conn // test writes/reads as the browser
	serverEnd  net.Conn // test writes/reads as the exit server
	pooled     *PooledConn
	relayLocal net.Conn // the relay's view of the client
}

func newRelayHarness() *relayHarness {
	clientLocal, clientEnd := net.Pipe()
	serverLocal, serverEnd := net.Pipe()
	return &relayHarness{
		clientEnd:  clientEnd,
		serverEnd:  serverEnd,
		pooled:     &PooledConn{Conn: serverLocal},
		relayLocal: clientLocal,
	}
}

// TestPooledRelayBidirectional checks bytes flow both ways and that a client
// EOF ends the relay.
func TestPooledRelayBidirectional(t *testing.T) {
	h := newRelayHarness()
	done := make(chan error, 1)
	go func() { done <- PooledRelay(h.relayLocal, h.pooled, time.Minute) }()

	// browser -> exit
	up := []byte("GET / HTTP/1.1")
	go h.clientEnd.Write(up)
	got := make([]byte, len(up))
	h.serverEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(h.serverEnd, got); err != nil {
		t.Fatalf("exit read: %v", err)
	}
	if !bytes.Equal(got, up) {
		t.Fatalf("exit saw %q, want %q", got, up)
	}

	// exit -> browser
	down := []byte("HTTP/1.1 200 OK")
	go h.serverEnd.Write(down)
	got2 := make([]byte, len(down))
	h.clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(h.clientEnd, got2); err != nil {
		t.Fatalf("browser read: %v", err)
	}
	if !bytes.Equal(got2, down) {
		t.Fatalf("browser saw %q, want %q", got2, down)
	}

	// browser hangs up -> relay returns.
	h.clientEnd.Close()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("relay returned %v, want io.EOF on client hangup", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return after client close")
	}
}

// TestPooledRelayServerCloseEndsRelay checks the exit side closing terminates
// the relay too (the other half of the teardown path).
func TestPooledRelayServerCloseEndsRelay(t *testing.T) {
	h := newRelayHarness()
	done := make(chan error, 1)
	go func() { done <- PooledRelay(h.relayLocal, h.pooled, time.Minute) }()

	h.serverEnd.Close()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("relay returned %v, want io.EOF on server hangup", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return after server close")
	}
	// The browser side must be closed by the relay on teardown.
	h.clientEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := h.clientEnd.Read(make([]byte, 1)); err == nil {
		t.Fatal("relay left the client side open after teardown")
	}
}

// --- PooledRelayLengthPrefixed ------------------------------------------

// TestPooledRelayLengthPrefixedFraming checks the 4-byte length framing in both
// directions.
func TestPooledRelayLengthPrefixedFraming(t *testing.T) {
	h := newRelayHarness()
	done := make(chan error, 1)
	go func() { done <- PooledRelayLengthPrefixed(h.relayLocal, h.pooled, time.Minute) }()

	// browser -> exit: relay prepends a 4-byte length.
	up := []byte("abcde")
	go h.clientEnd.Write(up)
	lenBuf := make([]byte, 4)
	h.serverEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(h.serverEnd, lenBuf); err != nil {
		t.Fatalf("exit read len: %v", err)
	}
	if n := binary.BigEndian.Uint32(lenBuf); n != uint32(len(up)) {
		t.Fatalf("framed length=%d, want %d", n, len(up))
	}
	body := make([]byte, len(up))
	if _, err := io.ReadFull(h.serverEnd, body); err != nil {
		t.Fatalf("exit read body: %v", err)
	}
	if !bytes.Equal(body, up) {
		t.Fatalf("exit body %q, want %q", body, up)
	}

	// exit -> browser: relay strips the length prefix.
	down := []byte("world!")
	frame := make([]byte, 4+len(down))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(down)))
	copy(frame[4:], down)
	go h.serverEnd.Write(frame)
	got := make([]byte, len(down))
	h.clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(h.clientEnd, got); err != nil {
		t.Fatalf("browser read: %v", err)
	}
	if !bytes.Equal(got, down) {
		t.Fatalf("browser saw %q, want %q", got, down)
	}

	h.clientEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("length-prefixed relay did not return after client close")
	}
}

// TestPooledRelayLengthPrefixedRejectsBadFrame checks the length guard. An
// oversized declared length must end the relay WITHOUT reading the (never sent)
// body. Predicate against a missing guard: without it the read side blocks in
// io.ReadFull on a 70000-byte body that never arrives and the relay hangs until
// the test's 5s deadline fires. A zero length is treated the same way.
func TestPooledRelayLengthPrefixedRejectsBadFrame(t *testing.T) {
	for _, declared := range []uint32{0, 70000} {
		t.Run(map[bool]string{true: "zero", false: "oversized"}[declared == 0], func(t *testing.T) {
			h := newRelayHarness()
			done := make(chan error, 1)
			go func() { done <- PooledRelayLengthPrefixed(h.relayLocal, h.pooled, time.Minute) }()

			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, declared)
			go h.serverEnd.Write(lenBuf)

			select {
			case err := <-done:
				if err != io.EOF {
					t.Fatalf("relay returned %v, want io.EOF on bad frame", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("relay did not reject declared length %d", declared)
			}
		})
	}
}

// --- Defect 1: atomic reserve honours MaxConnections under load ----------

// barrierConnector reserves and then parks every Connect on a release channel,
// so no slot is freed while the test measures how many connections got in. It
// records the peak number of concurrent in-flight Connects, which equals the
// number of Get calls that passed the pool's capacity guard.
type barrierConnector struct {
	inFlight int32
	peak     int32
	release  chan struct{}
}

func (b *barrierConnector) Connect(context.Context, string) (net.Conn, strategy.Strategy, error) {
	n := atomic.AddInt32(&b.inFlight, 1)
	for {
		p := atomic.LoadInt32(&b.peak)
		if n <= p || atomic.CompareAndSwapInt32(&b.peak, p, n) {
			break
		}
	}
	<-b.release
	atomic.AddInt32(&b.inFlight, -1)
	client, server := net.Pipe()
	go func() { io.Copy(io.Discard, server); server.Close() }()
	return client, fakeStrategy{}, nil
}

// runAdmissionRound fires `goroutines` concurrent Get calls at a pool capped at
// maxConns, holding every admitted connection parked in Connect so that the
// admitted count equals the peak simultaneously-live count. It returns that peak
// and leaves the pool counter back at zero.
func runAdmissionRound(t *testing.T, maxConns, goroutines int) int32 {
	t.Helper()
	bc := &barrierConnector{release: make(chan struct{})}
	p := newTestPool(bc)
	p.config.MaxConnections = maxConns

	var rejected int32
	conns := make(chan *PooledConn, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := p.Get(context.Background())
			if errors.Is(err, ErrPoolExhausted) {
				atomic.AddInt32(&rejected, 1)
				return
			}
			if err != nil {
				t.Errorf("unexpected Get error: %v", err)
				return
			}
			conns <- c
		}()
	}
	close(start)

	// Wait until every caller has either reserved a slot (now parked in Connect)
	// or been refused, then freeze and read the peak.
	deadline := time.After(5 * time.Second)
	for atomic.LoadInt32(&bc.inFlight)+atomic.LoadInt32(&rejected) < int32(goroutines) {
		select {
		case <-deadline:
			t.Fatalf("timed out: inFlight=%d rejected=%d, want sum=%d",
				atomic.LoadInt32(&bc.inFlight), atomic.LoadInt32(&rejected), goroutines)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	peak := atomic.LoadInt32(&bc.peak)

	close(bc.release)
	wg.Wait()
	close(conns)
	for c := range conns {
		c.Close()
	}
	if got := p.Stats(); got != 0 {
		t.Fatalf("totalConns=%d after closing all, want 0", got)
	}
	return peak
}

// TestGetAtomicReserveHonoursMaxUnderLoad predicates the TOCTOU fix. With the
// limit at maxConns and far more concurrent callers, the pool must never admit
// more than maxConns simultaneously - the connector holds every admitted
// connection open, so admitted == peak concurrent Connects.
//
// The old Load-then-Add code split the guard from the increment across two
// atomics: callers that read the same under-limit value before any of them
// incremented all got in, overshooting maxConns. That overshoot needs several
// callers inside the tiny Load->Add window at once, so a single burst catches it
// only sometimes. We run many bursts and fail on the first overshoot: the fixed
// code (atomic reserve) can never overshoot in ANY burst, so it stays green
// across all rounds; the broken code overshoots within a handful of rounds.
// -race does not flag the bug - both operations are atomic, the race is logical.
//
// Positive control: at least one round must admit the full maxConns (the last
// round asserts exactly maxConns), so the cap is what refuses excess callers,
// not a dead connector that admits nobody.
func TestGetAtomicReserveHonoursMaxUnderLoad(t *testing.T) {
	const (
		maxConns   = 2
		goroutines = 128
		rounds     = 200
	)
	for r := 0; r < rounds; r++ {
		if peak := runAdmissionRound(t, maxConns, goroutines); peak > maxConns {
			t.Fatalf("round %d: peak concurrent connections=%d exceeded MaxConnections=%d (TOCTOU overshoot)",
				r, peak, maxConns)
		}
	}
	// Positive control: the cap admits exactly maxConns under load, not zero.
	if peak := runAdmissionRound(t, maxConns, goroutines); peak != maxConns {
		t.Fatalf("positive control: peak admitted=%d, want exactly %d", peak, maxConns)
	}
}

// --- Defect 2: relay honours the caller's idle timeout -------------------

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

// idleTimeoutConn is a net.Conn that never delivers data: every Read waits
// readGap then reports a timeout, so the relay's inactivity path drives the
// test. Writes are swallowed. It ignores deadlines (the relay's hardcoded 30s
// per-read deadline would otherwise make the test take 30s).
type idleTimeoutConn struct {
	readGap time.Duration
	mu      sync.Mutex
	closed  bool
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	time.Sleep(c.readGap)
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	return 0, timeoutErr{timeout: true}
}
func (c *idleTimeoutConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *idleTimeoutConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *idleTimeoutConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *idleTimeoutConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *idleTimeoutConn) SetDeadline(time.Time) error      { return nil }
func (c *idleTimeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (c *idleTimeoutConn) SetWriteDeadline(time.Time) error { return nil }

// TestPooledRelayHonoursIdleTimeout predicates the idle-timeout fix: a 30ms
// idle timeout must close an idle relay promptly. The old code hardcoded 2m and
// ignored the parameter, so nothing closes within the 2s window (red).
func TestPooledRelayHonoursIdleTimeout(t *testing.T) {
	client := &idleTimeoutConn{readGap: 5 * time.Millisecond}
	server := &PooledConn{Conn: &idleTimeoutConn{readGap: 5 * time.Millisecond}}
	done := make(chan error, 1)
	go func() { done <- PooledRelay(client, server, 30*time.Millisecond) }()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("relay returned %v, want io.EOF on idle close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay ignored the 30ms idle timeout (old code hardcoded 2m)")
	}
}

// TestPooledRelayKeepsOpenUnderLargeIdleTimeout is the positive control for the
// above: with a 10s idle timeout the relay must NOT close within 300ms. Without
// it, a "fix" that always closes fast would pass the previous test spuriously.
func TestPooledRelayKeepsOpenUnderLargeIdleTimeout(t *testing.T) {
	client := &idleTimeoutConn{readGap: 5 * time.Millisecond}
	server := &PooledConn{Conn: &idleTimeoutConn{readGap: 5 * time.Millisecond}}
	done := make(chan error, 1)
	go func() { done <- PooledRelay(client, server, 10*time.Second) }()

	select {
	case err := <-done:
		t.Fatalf("relay closed early (%v) under a 10s idle timeout", err)
	case <-time.After(300 * time.Millisecond):
		// still open, as expected
	}
	client.Close()
	server.Conn.Close()
	<-done
}

// TestPooledRelayLengthPrefixedHonoursIdleTimeout covers the second edited site
// (the length-prefixed relay carried the same hardcoded 2m).
func TestPooledRelayLengthPrefixedHonoursIdleTimeout(t *testing.T) {
	client := &idleTimeoutConn{readGap: 5 * time.Millisecond}
	server := &PooledConn{Conn: &idleTimeoutConn{readGap: 5 * time.Millisecond}}
	done := make(chan error, 1)
	go func() { done <- PooledRelayLengthPrefixed(client, server, 30*time.Millisecond) }()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("relay returned %v, want io.EOF on idle close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("length-prefixed relay ignored the 30ms idle timeout (old code hardcoded 2m)")
	}
}

// --- Defect 3: partial length prefix survives a read timeout -------------

// scriptedReadConn returns one scripted (chunk, err) pair per Read call, so a
// test can model a length prefix that arrives split by a timeout.
type scriptedReadConn struct {
	chunks [][]byte
	errs   []error
	idx    int
	mu     sync.Mutex
	closed bool
}

func (c *scriptedReadConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.idx >= len(c.chunks) {
		return 0, io.EOF
	}
	data := c.chunks[c.idx]
	err := c.errs[c.idx]
	c.idx++
	return copy(p, data), err
}
func (c *scriptedReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *scriptedReadConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *scriptedReadConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *scriptedReadConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *scriptedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedReadConn) SetWriteDeadline(time.Time) error { return nil }

// TestPooledRelayLengthPrefixedKeepsPartialPrefixAcrossTimeout predicates the
// frame-desync fix. The 4-byte length prefix (00 00 00 05) arrives as two bytes,
// then a timeout, then the remaining two, then the "hello" payload. The relay
// must reassemble the prefix and deliver exactly "hello".
//
// On the old code the timeout dropped the two prefix bytes already read and the
// next ReadFull started fresh, consuming [00 05 'h' 'e'] as the length -> a huge
// pktLen that trips the size guard and ends the relay before any payload reaches
// the browser (red: the read below times out).
func TestPooledRelayLengthPrefixedKeepsPartialPrefixAcrossTimeout(t *testing.T) {
	payload := []byte("hello")
	server := &scriptedReadConn{
		chunks: [][]byte{{0, 0}, nil, {0, 5}, payload},
		errs:   []error{nil, timeoutErr{timeout: true}, nil, nil},
	}
	clientLocal, clientEnd := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- PooledRelayLengthPrefixed(clientLocal, &PooledConn{Conn: server}, time.Minute)
	}()

	got := make([]byte, len(payload))
	clientEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientEnd, got); err != nil {
		t.Fatalf("browser read: %v (frame desynced by dropped prefix bytes)", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("browser saw %q, want %q", got, payload)
	}

	clientEnd.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not terminate")
	}
}
