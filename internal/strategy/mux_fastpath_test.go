package strategy

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/mux"
)

// closeTrackingConn is a no-op net.Conn that records whether Close was called.
// The mux reuse path never reads or writes it (it multiplexes over the live
// carrier), so only Close needs real behaviour.
type closeTrackingConn struct {
	mu     sync.Mutex
	closed bool
}

func (c *closeTrackingConn) Read([]byte) (int, error)    { return 0, nil }
func (c *closeTrackingConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *closeTrackingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *closeTrackingConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *closeTrackingConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *closeTrackingConn) SetDeadline(time.Time) error      { return nil }
func (c *closeTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeTrackingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *closeTrackingConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

// liveMuxManager wires a Manager to a live mux session over an in-memory pipe.
// The returned cleanup closes both ends.
func liveMuxManager(t *testing.T) (*Manager, func()) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg := mux.DefaultConfig()

	server, err := mux.NewServer(c2, cfg)
	if err != nil {
		t.Fatalf("mux.NewServer: %v", err)
	}
	client, err := mux.NewClient(c1, cfg)
	if err != nil {
		t.Fatalf("mux.NewClient: %v", err)
	}

	m := NewManager()
	m.muxEnabled = true
	m.muxClient = client
	m.muxConn = c1

	cleanup := func() {
		client.Close()
		server.Close()
		c1.Close()
		c2.Close()
	}
	return m, cleanup
}

// TestWrapWithMuxReuseClosesOrphanConn is the regression guard for the OOM
// storm: when the reuse branch multiplexes over the live carrier, the freshly
// dialed transport handed in must be closed, not orphaned pre-auth on the server.
func TestWrapWithMuxReuseClosesOrphanConn(t *testing.T) {
	m, cleanup := liveMuxManager(t)
	defer cleanup()
	carrier := m.muxConn

	orphan := &closeTrackingConn{}
	stream, err := m.wrapWithMux(orphan, mux.DefaultConfig())
	if err != nil {
		t.Fatalf("wrapWithMux reuse: %v", err)
	}
	if stream == nil {
		t.Fatal("wrapWithMux returned nil stream")
	}
	if !orphan.isClosed() {
		t.Error("reuse branch did not close the orphaned transport - it would hang pre-auth on the server")
	}
	if m.muxConn != carrier {
		t.Error("reuse branch replaced the live carrier connection")
	}
}

// TestTryMuxFastPath covers the reorder that avoids dialing a throwaway
// transport when a live mux session already exists.
func TestTryMuxFastPath(t *testing.T) {
	// Mux disabled: fast-path must decline so the caller does a normal dial.
	m := NewManager()
	if _, _, ok := m.tryMuxFastPath(); ok {
		t.Error("fast-path should decline when mux is disabled")
	}

	// Mux enabled but no session yet: still decline.
	m.muxEnabled = true
	if _, _, ok := m.tryMuxFastPath(); ok {
		t.Error("fast-path should decline with no live session")
	}

	// Live session: fast-path takes it, opening a stream without a new dial.
	lm, cleanup := liveMuxManager(t)
	defer cleanup()

	stream, _, ok := lm.tryMuxFastPath()
	if !ok {
		t.Fatal("fast-path should succeed on a live session")
	}
	if stream == nil {
		t.Fatal("fast-path returned nil stream")
	}

	// A second call reuses the same carrier (stream count grows on one session),
	// proving no fresh transport was dialed.
	stream2, _, ok := lm.tryMuxFastPath()
	if !ok || stream2 == nil {
		t.Fatal("second fast-path call should also succeed on the same session")
	}
	if got := lm.muxClient.NumStreams(); got < 2 {
		t.Errorf("expected >=2 streams on the reused session, got %d", got)
	}
}
