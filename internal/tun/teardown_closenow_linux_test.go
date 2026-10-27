package tun

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// P2-2 of the round-18 review: every teardown drained. Close on HTTP
// polling and on the ICMP tunnel sends what is queued for up to 5 s, and
// Stop, a dead session, a forced reconnect and the Android core's
// disconnect all called it - a user's disconnect, or a failover off a dead
// path, waited that long, under v.mu or cs.mu. They abort now (closeNow).

// drainingConn is a transport conn whose Close drains for slowClose and
// whose CloseNow returns at once, as HTTP polling's and the ICMP tunnel's
// do.
type drainingConn struct {
	slowClose time.Duration
	closed    atomic.Int64
	aborted   atomic.Int64
}

func (c *drainingConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (c *drainingConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *drainingConn) Close() error {
	c.closed.Add(1)
	time.Sleep(c.slowClose)
	return nil
}
func (c *drainingConn) CloseNow() error {
	c.aborted.Add(1)
	return nil
}
func (c *drainingConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (c *drainingConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (c *drainingConn) SetDeadline(time.Time) error      { return nil }
func (c *drainingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *drainingConn) SetWriteDeadline(time.Time) error { return nil }

// tearDownWithin runs teardown and fails if it took longer than limit, or
// if inner was drained instead of aborted.
func tearDownWithin(t *testing.T, inner *drainingConn, limit time.Duration, teardown func()) {
	t.Helper()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		teardown()
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		if took > limit {
			t.Fatalf("teardown took %v, want the conn aborted instead of drained", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("teardown hung on the conn's drain")
	}
	if inner.aborted.Load() != 1 || inner.closed.Load() != 0 {
		t.Fatalf("CloseNow %d times, Close %d times: want one abort and no drain", inner.aborted.Load(), inner.closed.Load())
	}
}

func stoppableClient(t *testing.T, conn net.Conn) *VPNClient {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	v := &VPNClient{stopCh: make(chan struct{}), tun: &TUNDevice{file: r, hostOwnedLink: true}, conn: conn}
	atomic.StoreInt32(&v.running, 1)
	return v
}

// TestStopAbortsTheTransport: a user's disconnect on the desktop, the
// transport conn behind the handshake reader's replayConn as it often is.
func TestStopAbortsTheTransport(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	v := stoppableClient(t, &replayConn{Conn: inner})
	tearDownWithin(t, inner, time.Second, v.Stop)
}

// TestADeadSessionAbortsTheTransport: the session's read failed; the
// failover does not wait for the dead path to take a drain.
func TestADeadSessionAbortsTheTransport(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	v := stoppableClient(t, inner)
	atomic.StoreInt32(&v.running, 0) // no reconnect after it: only the close is measured
	tearDownWithin(t, inner, time.Second, func() { v.disconnect(inner, "server read", io.EOF) })
}

// TestAForcedReconnectAbortsTheTransport: a network change forces a
// reconnect; the old path is not waited on.
func TestAForcedReconnectAbortsTheTransport(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	v := stoppableClient(t, inner)
	tearDownWithin(t, inner, time.Second, v.ForceReconnect)
}

// TestAnAndroidDisconnectAbortsTheTransport: the Android core's disconnect
// closes the server conn holding cs.mu, so a drain there held every other
// command - status included - for as long.
func TestAnAndroidDisconnectAbortsTheTransport(t *testing.T) {
	h := newCtlHarnessWith(t, &ControlConfig{MTU: 1280})
	inner := &drainingConn{slowClose: 3 * time.Second}
	h.cs.mu.Lock()
	h.cs.serverConn = inner
	h.cs.mu.Unlock()
	tearDownWithin(t, inner, time.Second, func() {
		select {
		case <-h.sendAsync(`{"command":"disconnect"}`+"\n", -1):
		case <-time.After(5 * time.Second):
		}
	})
}

// TestStopAbortsThroughTheRTTWrapper is P3-3 of the round-19 review: with
// RTT masking on, every transport sits behind an RTTMaskingConn, which had
// no CloseNow, so every abort above became a drain again.
func TestStopAbortsThroughTheRTTWrapper(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	cfg := strategy.DefaultRTTMaskingConfig()
	v := stoppableClient(t, &replayConn{Conn: strategy.NewRTTMaskingConn(inner, cfg)})
	tearDownWithin(t, inner, time.Second, v.Stop)
}

// abortRecConn is a pipe end that records how it was closed.
type abortRecConn struct {
	net.Conn
	slowClose time.Duration
	closed    atomic.Int64
	aborted   atomic.Int64
}

func (c *abortRecConn) Close() error {
	c.closed.Add(1)
	time.Sleep(c.slowClose)
	return c.Conn.Close()
}

func (c *abortRecConn) CloseNow() error {
	c.aborted.Add(1)
	return c.Conn.Close()
}

// recordingStrategy dials pipes whose exit is played by playExit (or never
// answers, mute), each wrapped to record how it is closed.
type recordingStrategy struct {
	pipeStrategy
	mute  bool
	conns []*abortRecConn
}

func (s *recordingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	var conn net.Conn
	if s.mute {
		cli, srv := net.Pipe()
		s.t.Cleanup(func() { cli.Close(); srv.Close() })
		go func() { _, _ = io.Copy(io.Discard, srv) }()
		conn = cli
	} else {
		c, err := s.pipeStrategy.Connect(ctx, target)
		if err != nil {
			return nil, err
		}
		conn = c
	}
	rc := &abortRecConn{Conn: conn}
	s.conns = append(s.conns, rc)
	return rc, nil
}

// TestAPortHopWhoseHandshakeFailsAbortsTheNewConn is P3-2 of the round-19
// review: the new conn of a hop whose handshake failed was closed with the
// draining Close, under sessionMu with portHopInProgress set.
func TestAPortHopWhoseHandshakeFailsAbortsTheNewConn(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	m := strategy.NewManager()
	rs := &recordingStrategy{pipeStrategy: pipeStrategy{t: t, resp: bareV3Response()}, mute: true}
	m.Register(rs)
	v := newCallsiteClient(m)
	old, oldPeer := net.Pipe()
	t.Cleanup(func() { old.Close(); oldPeer.Close() })
	v.conn = old
	v.seamlessPortHop(8443)
	if len(rs.conns) == 0 {
		t.Fatal("the hop dialled nothing - the test proves nothing")
	}
	if c := rs.conns[0]; c.aborted.Load() != 1 || c.closed.Load() != 0 {
		t.Fatalf("the failed hop's conn: CloseNow %d, Close %d - want one abort", c.aborted.Load(), c.closed.Load())
	}
}

// TestAPortHopClosesTheOldSessionGracefullyAndAside is P3-4 of the round-19
// review, and pins the graceful close: after a hop the old session's Close
// still sends what it has queued - it is not aborted - but in the
// background, not under sessionMu with portHopInProgress set.
func TestAPortHopClosesTheOldSessionGracefullyAndAside(t *testing.T) {
	v := newCallsiteClient(newPipeManager(t))
	oldPipe, oldPeer := net.Pipe()
	t.Cleanup(func() { oldPipe.Close(); oldPeer.Close() })
	old := &abortRecConn{Conn: oldPipe, slowClose: 2 * time.Second}
	v.conn = old
	start := time.Now()
	v.seamlessPortHop(8443)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the hop took %v: it waited for the old session's drain", took)
	}
	if v.conn == old {
		t.Fatal("the hop did not swap the connection - the test proves nothing")
	}
	deadline := time.Now().Add(3 * time.Second)
	for old.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if old.closed.Load() != 1 || old.aborted.Load() != 0 {
		t.Fatalf("the old session: Close %d, CloseNow %d - want one graceful Close", old.closed.Load(), old.aborted.Load())
	}
}

// TestAnUpgradeWhoseHandshakeFailsAbortsTheNewConn is P3-2 of the round-19
// review on the upgrade path: the new conn of an upgrade whose handshake
// failed was closed with the draining Close.
func TestAnUpgradeWhoseHandshakeFailsAbortsTheNewConn(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	v := newCallsiteClient(newPipeManager(t))
	old, oldPeer := net.Pipe()
	t.Cleanup(func() { old.Close(); oldPeer.Close() })
	v.conn = old
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() { _, _ = io.Copy(io.Discard, srv) }()
	conn := &abortRecConn{Conn: cli}
	cur := &pipeStrategy{t: t}
	next := &pipeStrategy{t: t}
	v.handshakeUpgrade(old, conn, cur, next, callsiteClientIP, endpoint.Candidate{})
	if conn.aborted.Load() != 1 || conn.closed.Load() != 0 {
		t.Fatalf("the failed upgrade's conn: CloseNow %d, Close %d - want one abort", conn.aborted.Load(), conn.closed.Load())
	}
}

// TestAnUpgradeClosesTheOldSessionGracefully pins the other side: after a
// successful upgrade the old session gets the graceful Close, which still
// sends what it has queued, not an abort.
func TestAnUpgradeClosesTheOldSessionGracefully(t *testing.T) {
	v := newCallsiteClient(newPipeManager(t))
	oldPipe, oldPeer := net.Pipe()
	t.Cleanup(func() { oldPipe.Close(); oldPeer.Close() })
	old := &abortRecConn{Conn: oldPipe}
	v.conn = old
	next := &pipeStrategy{t: t, resp: bareV3Response()}
	conn, err := next.Connect(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	v.handshakeUpgrade(old, conn, &pipeStrategy{t: t}, next, callsiteClientIP, endpoint.Candidate{})
	if v.conn == old {
		t.Fatal("the upgrade did not swap the connection - the test proves nothing")
	}
	deadline := time.Now().Add(2 * time.Second)
	for old.closed.Load()+old.aborted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if old.closed.Load() != 1 || old.aborted.Load() != 0 {
		t.Fatalf("the old session: Close %d, CloseNow %d - want one graceful Close", old.closed.Load(), old.aborted.Load())
	}
}
