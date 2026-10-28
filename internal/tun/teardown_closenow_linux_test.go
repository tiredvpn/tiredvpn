package tun

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
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

// closeRecorder is a test conn that counts how it was torn down: CloseNow
// (abort) versus Close (drain).
type closeRecorder interface {
	counts() (aborted, closed int64)
}

func (c *drainingConn) counts() (int64, int64)      { return c.aborted.Load(), c.closed.Load() }
func (c *blockingWriteConn) counts() (int64, int64) { return c.aborted.Load(), c.closed.Load() }

// tearDownWithin runs teardown and fails if it took longer than limit, or
// if inner was drained instead of aborted.
func tearDownWithin(t *testing.T, inner closeRecorder, limit time.Duration, teardown func()) {
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
	if aborted, closed := inner.counts(); aborted != 1 || closed != 0 {
		t.Fatalf("CloseNow %d times, Close %d times: want one abort and no drain", aborted, closed)
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
	rtt := strategy.NewRTTMaskingConn(inner, cfg)
	// Buffer a packet so Close has a non-empty burst to flush, not the empty
	// one the abort can skip past: without it the test passes even when the
	// flush path leaks the drain.
	_, _ = rtt.Write([]byte("queued"))
	v := stoppableClient(t, &replayConn{Conn: rtt})
	tearDownWithin(t, inner, time.Second, v.Stop)
}

// blockingWriteConn is a transport whose Write blocks until the conn is
// closed - HTTP polling with a full queue, where RTTMaskingConn's burst
// flush waits on the Write and ignores the write deadline. CloseNow unblocks
// it at once; Close drains for slowClose first. It exposes no NetConn, so
// closeSocket's chain walk stops at it and must abort it directly.
type blockingWriteConn struct {
	slowClose time.Duration
	release   chan struct{}
	entered   chan struct{}
	relOnce   sync.Once
	entOnce   sync.Once
	closed    atomic.Int64
	aborted   atomic.Int64
}

func newBlockingWriteConn(slowClose time.Duration) *blockingWriteConn {
	return &blockingWriteConn{slowClose: slowClose, release: make(chan struct{}), entered: make(chan struct{})}
}

func (c *blockingWriteConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *blockingWriteConn) Write(p []byte) (int, error) {
	c.entOnce.Do(func() { close(c.entered) })
	<-c.release
	return 0, net.ErrClosed
}

// Close drains for slowClose - unless the conn was already aborted, in which
// case abortNow has cut the drain and Close is a fast no-op, as HTTP
// polling's and the ICMP tunnel's are once abortNow ran. closed counts a real
// drain only, so RTTMaskingConn.close's trailing Close of an already-aborted
// conn does not register as one.
func (c *blockingWriteConn) Close() error {
	select {
	case <-c.release:
		return nil
	default:
	}
	c.closed.Add(1)
	time.Sleep(c.slowClose)
	c.relOnce.Do(func() { close(c.release) })
	return nil
}
func (c *blockingWriteConn) CloseNow() error {
	c.aborted.Add(1)
	c.relOnce.Do(func() { close(c.release) })
	return nil
}
func (c *blockingWriteConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (c *blockingWriteConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (c *blockingWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingWriteConn) SetWriteDeadline(time.Time) error { return nil }

// TestStopAbortsThroughABlockedRTTFlush covers the gap the NetConn method
// alone does not: RTT masking over a transport whose Write blocks (a full
// HTTP polling queue) and that exposes no NetConn. The burst flush parks in
// that Write holding writeMu, so Close cannot reach its own CloseNow of the
// inner conn - only the abort timer's closeSocket runs, and it must abort
// the inner conn instead of taking its 5 s drain. Rule 1: drop the
// closeNower branch in closeSocket and this drains (closed == 1, took
// ~slowClose) instead of aborting.
func TestStopAbortsThroughABlockedRTTFlush(t *testing.T) {
	inner := newBlockingWriteConn(3 * time.Second)
	// BurstInterval 0 and Profile nil: every write flushes at once with no
	// delay, so this Write reaches inner.Write and parks there.
	cfg := strategy.RTTMaskingConfig{Enabled: true, BurstMode: true, BurstSize: 8}
	rtt := strategy.NewRTTMaskingConn(inner, cfg)
	go func() { _, _ = rtt.Write([]byte("packet")) }()
	<-inner.entered // the flush is parked in inner.Write before Stop
	v := stoppableClient(t, &replayConn{Conn: rtt})
	tearDownWithin(t, inner, 1500*time.Millisecond, v.Stop)
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

// hangingConn's Close blocks until CloseNow is called (or for hang), as
// RTTMaskingConn's did behind a Write blocked on a full polling queue.
type hangingConn struct {
	abortRecConn
	release chan struct{}
	once    sync.Once
	hang    time.Duration
}

func newHangingConn(t *testing.T, hang time.Duration) *hangingConn {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return &hangingConn{abortRecConn: abortRecConn{Conn: cli}, release: make(chan struct{}), hang: hang}
}

func (c *hangingConn) Close() error {
	c.closed.Add(1)
	select {
	case <-c.release:
	case <-time.After(c.hang):
	}
	return c.Conn.Close()
}

func (c *hangingConn) CloseNow() error {
	c.aborted.Add(1)
	c.once.Do(func() { close(c.release) })
	return c.Conn.Close()
}

func setGracefulCloseLimit(t *testing.T, d time.Duration) {
	t.Helper()
	old := gracefulCloseLimitNs.Swap(int64(d))
	t.Cleanup(func() { gracefulCloseLimitNs.Store(old) })
}

// TestAGracefulCloseThatHangsIsAbortedAtItsLimit is #2 of the round-20
// review: a graceful close had no bound of its own - a wrapper could wait
// about 20 s before the transport's bounded drain even started. At its
// limit it is aborted.
func TestAGracefulCloseThatHangsIsAbortedAtItsLimit(t *testing.T) {
	setGracefulCloseLimit(t, 300*time.Millisecond)
	c := newHangingConn(t, 20*time.Second)
	start := time.Now()
	done := make(chan struct{})
	go func() { closeGracefully(c); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the graceful close is still running 3 s in, against a 300 ms limit")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the graceful close took %v against a 300 ms limit", took)
	}
	if c.closed.Load() != 1 || c.aborted.Load() != 1 {
		t.Fatalf("Close %d, CloseNow %d - want the graceful close, then the abort", c.closed.Load(), c.aborted.Load())
	}
}

// TestAGracefulCloseThatFinishesIsNotAborted: a drain that ends inside the
// limit is left alone, and the limit is above the 5 s the transports give
// their own drain, so a live drain is never cut by it.
func TestAGracefulCloseThatFinishesIsNotAborted(t *testing.T) {
	if limit := time.Duration(gracefulCloseLimitNs.Load()); limit <= 5*time.Second {
		t.Fatalf("the graceful close limit %v does not leave the transports their 5 s drain", limit)
	}
	setGracefulCloseLimit(t, time.Second)
	c := newHangingConn(t, 400*time.Millisecond)
	closeGracefully(c)
	if c.closed.Load() != 1 || c.aborted.Load() != 0 {
		t.Fatalf("Close %d, CloseNow %d - want one graceful Close and no abort", c.closed.Load(), c.aborted.Load())
	}
}

// TestAPortHopAbortsAnOldSessionWhoseCloseHangs: the old session of a hop,
// closed in the background, is aborted at the limit rather than left
// running.
func TestAPortHopAbortsAnOldSessionWhoseCloseHangs(t *testing.T) {
	setGracefulCloseLimit(t, 300*time.Millisecond)
	v := newCallsiteClient(newPipeManager(t))
	old := newHangingConn(t, 20*time.Second)
	v.conn = old
	v.seamlessPortHop(8443)
	deadline := time.Now().Add(2 * time.Second)
	for old.aborted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if old.closed.Load() != 1 || old.aborted.Load() != 1 {
		t.Fatalf("the old session: Close %d, CloseNow %d - want the graceful close, then the abort", old.closed.Load(), old.aborted.Load())
	}
}

// TestADroppedSessionIsAbortedWhenTheTunnelMovedOn is #1 of the round-20
// review: publishSession dropped a session whose tunnel had moved on - a
// return finding a reconnect in progress - with the draining Close, under
// sessionMu that the reconnect waited on.
func TestADroppedSessionIsAbortedWhenTheTunnelMovedOn(t *testing.T) {
	v := newCallsiteClient(newPipeManager(t))
	cur, curPeer := net.Pipe()
	t.Cleanup(func() { cur.Close(); curPeer.Close() })
	v.conn = cur
	other, otherPeer := net.Pipe()
	t.Cleanup(func() { other.Close(); otherPeer.Close() })
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	conn := &abortRecConn{Conn: cli, slowClose: 3 * time.Second}
	start := time.Now()
	err := v.publishSession(conn, &pipeStrategy{t: t}, endpoint.Candidate{}, false, bareV3Response(), 9, other)
	if err == nil {
		t.Fatal("published over a tunnel that had moved on - the test proves nothing")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("dropping the session took %v", took)
	}
	if conn.aborted.Load() != 1 || conn.closed.Load() != 0 {
		t.Fatalf("CloseNow %d, Close %d - want one abort", conn.aborted.Load(), conn.closed.Load())
	}
}

// TestAnUpgradeDoesNotWaitForTheOldSessionsDrain is #3 of the round-20
// review on the upgrade path: the old session's graceful close held the
// upgrade - and the outcome it books after - for its whole drain. It runs
// aside now, still graceful.
func TestAnUpgradeDoesNotWaitForTheOldSessionsDrain(t *testing.T) {
	v := newCallsiteClient(newPipeManager(t))
	oldPipe, oldPeer := net.Pipe()
	t.Cleanup(func() { oldPipe.Close(); oldPeer.Close() })
	old := &abortRecConn{Conn: oldPipe, slowClose: 2 * time.Second}
	v.conn = old
	next := &pipeStrategy{t: t, resp: bareV3Response()}
	conn, err := next.Connect(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	v.handshakeUpgrade(old, conn, &pipeStrategy{t: t}, next, callsiteClientIP, endpoint.Candidate{})
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the upgrade took %v: it waited for the old session's drain", took)
	}
	if v.conn == old {
		t.Fatal("the upgrade did not swap the connection - the test proves nothing")
	}
}

func setWrappedCloseAllowance(t *testing.T, d time.Duration) {
	t.Helper()
	old := wrappedCloseAllowanceNs.Swap(int64(d))
	t.Cleanup(func() { wrappedCloseAllowanceNs.Store(old) })
}

// TestAGracefulCloseBehindRTTMaskingGetsTheFlushOnTop is P3-1 of the
// round-21 review: behind RTT masking the transport's drain starts only
// after the wrapper's flush, and a limit counted from the outer Close cut a
// drain that was still going. The same 450 ms drain is left alone behind
// the wrapper, where the limit has the flush allowance on top, and aborted
// without it.
func TestAGracefulCloseBehindRTTMaskingGetsTheFlushOnTop(t *testing.T) {
	setGracefulCloseLimit(t, 300*time.Millisecond)
	setWrappedCloseAllowance(t, 300*time.Millisecond)

	wrapped := newHangingConn(t, 450*time.Millisecond)
	closeGracefully(&replayConn{Conn: strategy.NewRTTMaskingConn(wrapped, strategy.DefaultRTTMaskingConfig())})
	if wrapped.closed.Load() != 1 || wrapped.aborted.Load() != 0 {
		t.Fatalf("behind RTT masking: Close %d, CloseNow %d - a live drain was cut", wrapped.closed.Load(), wrapped.aborted.Load())
	}

	bare := newHangingConn(t, 450*time.Millisecond)
	closeGracefully(bare)
	if bare.aborted.Load() != 1 {
		t.Fatal("with no wrapper the 450 ms drain was not aborted at the 300 ms limit - the test proves nothing")
	}
}

// lockedCloseConn has no CloseNow and writes its close frame holding a
// lock with no deadline of its own, as Salamander and the QUIC conn do: a
// second Close waits on the lock until the first one's write gives up -
// here, until a deadline is set.
type lockedCloseConn struct {
	net.Conn
	mu       sync.Mutex
	deadline chan struct{}
	once     sync.Once
}

func (c *lockedCloseConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.deadline:
	case <-time.After(20 * time.Second):
	}
	return nil
}

func (c *lockedCloseConn) SetDeadline(time.Time) error {
	c.once.Do(func() { close(c.deadline) })
	return nil
}

// TestAGracefulCloseOfAConnWithNoAbortIsCutByItsDeadline is P3-2 of the
// round-21 review: with no CloseNow, the watchdog's abort was a second
// Close, held on the lock of the first.
func TestAGracefulCloseOfAConnWithNoAbortIsCutByItsDeadline(t *testing.T) {
	setGracefulCloseLimit(t, 300*time.Millisecond)
	c := &lockedCloseConn{deadline: make(chan struct{})}
	done := make(chan struct{})
	go func() { closeGracefully(c); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the graceful close of a conn with no CloseNow is still running 3 s in, against a 300 ms limit")
	}
}
