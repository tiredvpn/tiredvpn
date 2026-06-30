package pool

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

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
		config:      DefaultConfig(),
		manager:     c,
		serverAddr:  "test-server:443",
		connections: make([]*PooledConn, 0),
		closedCh:    make(chan struct{}),
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
