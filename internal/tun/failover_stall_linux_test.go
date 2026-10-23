//go:build linux

package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// shortStallClocks scales the detector down: T 300 ms, echo wait 150 ms.
func shortStallClocks(t *testing.T) {
	t.Helper()
	old := stallClocks()
	stallClocksNow.Store(&stallClockSet{threshold: 300 * time.Millisecond, echoWait: 150 * time.Millisecond,
		checkEvery: 20 * time.Millisecond, pause: func() time.Duration { return 50 * time.Millisecond }})
	oldLimiter := stallVerdicts()
	stallVerdictsNow.Store(&verdictLimiter{})
	t.Cleanup(func() {
		stallClocksNow.Store(old)
		stallVerdictsNow.Store(oldLimiter)
	})
}

// stallExit is the far side of a tunnel conn: it answers data with the
// stand's own ACK for the flow (fixture frame 9) when answerData is set,
// echoes keepalives when echo is set, and with feeder set splices a
// zero-length frame into the downlink every 100 ms, as HTTP Polling's feeder
// does on the client.
type stallExit struct {
	conn       net.Conn
	answer     []byte
	answerData atomic.Bool
	echo       atomic.Bool
	echoDelay  atomic.Int64 // ns before an echo goes out
	feeder     atomic.Bool
	gotData    atomic.Int64
	gotEcho    atomic.Int64 // keepalives received
}

func (e *stallExit) writeFrame(p []byte) error {
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame, uint32(len(p)))
	copy(frame[4:], p)
	_, err := e.conn.Write(frame)
	return err
}

func (e *stallExit) serve() {
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			if e.feeder.Load() && e.writeFrame(nil) != nil {
				return
			}
		}
	}()
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(e.conn, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		if _, err := io.ReadFull(e.conn, make([]byte, n)); err != nil {
			return
		}
		switch {
		case n == 0:
			e.gotEcho.Add(1)
			if e.echo.Load() {
				if d := time.Duration(e.echoDelay.Load()); d > 0 {
					go func() { time.Sleep(d); _ = e.writeFrame(nil) }()
				} else {
					_ = e.writeFrame(nil)
				}
			}
		case n > 0:
			e.gotData.Add(1)
			if e.answerData.Load() {
				_ = e.writeFrame(e.answer)
			}
		}
	}
}

// pollingLike is a tunnel conn that makes up keepalives of its own and says
// so: the server itself sent none.
type pollingLike struct{ net.Conn }

func (pollingLike) ServerKeepalives() (uint64, bool) { return 0, true }

// lostTrackConn is a Polling-like conn whose tracker lost the framing.
type lostTrackConn struct{ net.Conn }

func (lostTrackConn) ServerKeepalives() (uint64, bool) { return 0, false }

// keepaliveMakingStrategy is a strategy that says its conns make up
// keepalives, as HTTP Polling does.
type keepaliveMakingStrategy struct{ rankedPipeStrategy }

func (*keepaliveMakingStrategy) MakesUpKeepalives() bool { return true }

type stallHarness struct {
	v    *VPNClient
	m    *strategy.Manager
	exit *stallExit
	app  *os.File // the application side of the TUN
	out  *stopOnDisconnectLog
	addr string
}

// newStallHarness runs a VPNClient's packet loops and stall watcher over a
// scripted exit and a TUN made of a seqpacket socket pair, on a pool of two
// servers, with the session riding the first.
func newStallHarness(t *testing.T, wrap func(net.Conn) net.Conn) *stallHarness {
	t.Helper()
	h := newQuietStallHarness(t, wrap)
	// The flow is answered once (the stand's SYN-ACK, frame 3), then the
	// application sends its GET (frame 6) into it.
	pkts := fixtureFlows(t)
	if err := h.exit.writeFrame(pkts[2].data); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := h.app.Write(pkts[5].data); err != nil {
		t.Fatal(err)
	}
	return h
}

// newQuietStallHarness is newStallHarness before anything has crossed the
// tunnel.
func newQuietStallHarness(t *testing.T, wrap func(net.Conn) net.Conn) *stallHarness {
	t.Helper()
	shortStallClocks(t)
	oldLink := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = oldLink })

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := &TUNDevice{file: os.NewFile(uintptr(fds[0]), "tun"), mtu: 1500, atomicMTU: 1500}
	app := os.NewFile(uintptr(fds[1]), "app")

	pkts := fixtureFlows(t)
	cli, srv := net.Pipe()
	exit := &stallExit{conn: srv, answer: pkts[8].data}
	go exit.serve()

	m, addrs, _ := poolManager(t, 2)
	m.SetConnectivityChecker(strategy.NewConnectivityChecker(addrs[0], time.Second, true))
	cand, ok := m.CurrentCandidate()
	if !ok {
		t.Fatal("no candidate")
	}
	conn := cli
	if wrap != nil {
		conn = wrap(cli)
	}
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, conn: conn, tun: dev, stall: newFlowTable(),
		strategy:    &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "polling", priority: 6},
		sessionCand: cand, hasSessionCand: true,
		connectedAt: time.Now().Add(-time.Hour), lastRx: time.Now()}
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	go v.readFromTun()
	go v.readFromServer()
	watched := make(chan struct{})
	go func() { v.watchStalls(); close(watched) }()
	t.Cleanup(func() {
		atomic.StoreInt32(&v.running, 0)
		select {
		case <-v.stopCh:
		default:
			close(v.stopCh)
		}
		<-watched // the clocks are put back after this, and the watcher reads them
		cli.Close()
		srv.Close()
		app.Close()
		dev.file.Close()
	})

	h := &stallHarness{v: v, m: m, exit: exit, app: app, out: out, addr: addrs[0]}
	go func() { // the application drains what comes down
		buf := make([]byte, 2048)
		for {
			if _, err := app.Read(buf); err != nil {
				return
			}
		}
	}()
	return h
}

// wait polls for a log line for up to d.
func (h *stallHarness) wait(line string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(h.out.String(), line) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return strings.Contains(h.out.String(), line)
}

// TestHealthySessionHasNoStall: the exit answers the flow; no suspicion, no
// keepalive sent for confirmation, no verdict, over several thresholds.
func TestHealthySessionHasNoStall(t *testing.T) {
	h := newStallHarness(t, nil)
	h.exit.answerData.Store(true)
	h.exit.echo.Store(true)
	pkts := fixtureFlows(t)
	for range 10 { // the application keeps asking, the exit keeps answering
		time.Sleep(100 * time.Millisecond)
		_, _ = h.app.Write(pkts[5].data)
	}
	if h.wait("Session suspect", 300*time.Millisecond) {
		t.Fatalf("a healthy session was suspected:\n%s", h.out)
	}
	if h.exit.gotData.Load() == 0 {
		t.Fatal("no data reached the exit - the test proves nothing")
	}
}

// TestFrozenSessionIsGivenUp is the detector end to end: the exit takes the
// data and answers neither it nor the keepalives. Within the threshold plus
// the two confirmations the session ends as degraded; the endpoint is
// charged like a dead session, and the next reconnect walks the pool.
func TestFrozenSessionIsGivenUp(t *testing.T) {
	h := newStallHarness(t, nil)
	if !h.wait("VPN disconnected: session degraded", 2*time.Second) {
		t.Fatalf("a frozen session was not given up:\n%s", h.out)
	}
	if !strings.Contains(h.out.String(), "keepalive echo 0/2") {
		t.Fatalf("the verdict did not come from two unanswered keepalives:\n%s", h.out)
	}
	if d := cooldownLeft(t, h.m, h.addr); d <= 0 {
		t.Fatal("the degraded session's endpoint was not charged")
	}
	if !h.m.PreflightArmed() {
		t.Fatal("the reconnect after a degraded session does not walk the pool through the gate")
	}
}

// TestDeadPeerBehindALiveTunnelIsNotDegraded: the stalled flow's own server
// is gone but the tunnel answers keepalives (h_deadpeer). Suspected,
// confirmed alive, no verdict.
func TestDeadPeerBehindALiveTunnelIsNotDegraded(t *testing.T) {
	h := newStallHarness(t, nil)
	h.exit.echo.Store(true)
	if !h.wait("Session alive", 2*time.Second) {
		t.Fatalf("the stalled flow was never confirmed alive:\n%s", h.out)
	}
	if h.wait("Session degraded", 500*time.Millisecond) {
		t.Fatalf("a live tunnel was given up for a dead peer:\n%s", h.out)
	}
	// Confirmed once: the flows waiting then are left alone until they are
	// answered, not re-confirmed with a keepalive every check.
	if n := strings.Count(h.out.String(), "Session suspect"); n != 1 {
		t.Fatalf("%d confirmations for one stall", n)
	}
}

// TestMadeUpKeepalivesAreNoEcho: HTTP Polling feeds zero-length frames of its
// own into the downlink. Counting those as echoes confirmed every frozen
// Polling session alive - the main case the detector exists for.
func TestMadeUpKeepalivesAreNoEcho(t *testing.T) {
	h := newStallHarness(t, func(c net.Conn) net.Conn { return pollingLike{c} })
	h.exit.feeder.Store(true)
	if !h.wait("VPN disconnected: session degraded", 2*time.Second) {
		t.Fatalf("a frozen Polling session was confirmed alive by its own feeder:\n%s", h.out)
	}
}

// TestOneVerdictLimitPerWindow: three verdicts in ten minutes, then ten
// minutes of log only.
func TestOneVerdictLimitPerWindow(t *testing.T) {
	var l verdictLimiter
	now := time.Now()
	allowed := func(at time.Time) bool { ok, _ := l.allow(at); return ok }
	for i := range stallVerdictMax {
		if !allowed(now.Add(time.Duration(i) * time.Minute)) {
			t.Fatalf("verdict %d refused", i+1)
		}
	}
	if ok, until := l.allow(now.Add(4 * time.Minute)); ok || !until.Equal(now.Add(14*time.Minute)) {
		t.Fatalf("a fourth verdict within the window: allowed=%v, quiet until %v", ok, until)
	}
	if allowed(now.Add(13 * time.Minute)) {
		t.Fatal("a verdict inside the quiet period was allowed")
	}
	if !allowed(now.Add(15 * time.Minute)) {
		t.Fatal("verdicts did not come back after the quiet period")
	}
}

// pendingFlow leaves the flow table with demand waiting since an hour ago.
func pendingFlow(t *testing.T, ft *flowTable) {
	t.Helper()
	pkts := fixtureFlows(t)
	then := time.Now().Add(-time.Hour)
	ft.down(pkts[2].data, then)
	ft.up(pkts[5].data, then.Add(time.Second))
	if ft.stalledFor(time.Now()) == 0 {
		t.Fatal("no pending flow - the test proves nothing")
	}
}

// TestEveryNewConnectionStartsWithNoFlows: connect, the port hop and the
// upgrade swap each start a session on a new connection. Demand left from the
// old one (an echo answered after a reconnect inside the same stall, as the
// stand's REALITY b_bc runs showed) must not be judged against the new.
func TestEveryNewConnectionStartsWithNoFlows(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		v := newCallsiteClient(newPipeManager(t))
		v.stall = newFlowTable()
		pendingFlow(t, v.stall)
		if err := v.connect(t.Context()); err != nil {
			t.Fatalf("connect: %v", err)
		}
		if s := v.stall.stalledFor(time.Now()); s != 0 {
			t.Fatalf("connect kept demand from the old session: %v", s)
		}
	})
	t.Run("port hop", func(t *testing.T) {
		m, _, _ := poolManager(t, 1)
		v := newCallsiteClient(m)
		v.stopCh = make(chan struct{})
		setLog(t, &stampedLog{})
		if err := v.connect(context.Background()); err != nil {
			t.Fatalf("connect: %v", err)
		}
		pendingFlow(t, v.stall)
		v.seamlessPortHop(1234)
		if s := v.stall.stalledFor(time.Now()); s != 0 {
			t.Fatalf("the port hop kept demand from the old session: %v", s)
		}
	})
	t.Run("upgrade swap", func(t *testing.T) {
		v, _, _, better := upgradeOnSelector(t)
		setLog(t, &stampedLog{})
		pendingFlow(t, v.stall)
		v.tryStrategyUpgrade([]strategy.Strategy{better})
		if v.strategy != better {
			t.Fatal("no swap - the test proves nothing")
		}
		if s := v.stall.stalledFor(time.Now()); s != 0 {
			t.Fatalf("the swap kept demand from the old session: %v", s)
		}
	})
}

// relayStallHarness runs the control socket's relay (Android) over a
// scripted exit, the same way.
type relayStallHarness struct {
	r        *tunRelay
	exit     *stallExit
	app      *os.File
	reasons  chan string
	degraded atomic.Int64
	log      *stampedLog
}

// newRelayStallHarness starts the relay; strat, when given, is the strategy
// its callbacks name for the session.
func newRelayStallHarness(t *testing.T, wrap func(net.Conn) net.Conn, strat ...strategy.Strategy) *relayStallHarness {
	t.Helper()
	shortStallClocks(t)
	out := &stampedLog{}
	setLog(t, out)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := &TUNDevice{file: os.NewFile(uintptr(fds[0]), "tun"), mtu: 1500, atomicMTU: 1500}
	app := os.NewFile(uintptr(fds[1]), "app")
	pkts := fixtureFlows(t)
	cli, srv := net.Pipe()
	exit := &stallExit{conn: srv, answer: pkts[8].data}
	go exit.serve()
	conn := cli
	if wrap != nil {
		conn = wrap(cli)
	}
	h := &relayStallHarness{exit: exit, app: app, reasons: make(chan string, 4), log: out}
	var sessionStrategy strategy.Strategy
	if len(strat) > 0 {
		sessionStrategy = strat[0]
	}
	stop := make(chan struct{})
	h.r = startTUNRelay(dev, conn, net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), stop, &RelayCallbacks{
		Strategy: sessionStrategy,
		OnError:  func(reason string) { h.reasons <- reason },
		OnSessionEnd: func(end RelaySessionEnd) {
			if end.Degraded {
				h.degraded.Add(1)
			}
		},
	})
	t.Cleanup(func() {
		close(stop)
		cli.Close()
		srv.Close()
		app.Close()
		dev.file.Close()
		<-h.r.done
	})
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, err := app.Read(buf); err != nil {
				return
			}
		}
	}()
	if err := exit.writeFrame(pkts[2].data); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := app.Write(pkts[5].data); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *relayStallHarness) reason(d time.Duration) string {
	select {
	case r := <-h.reasons:
		return r
	case <-time.After(d):
		return ""
	}
}

// TestRelayGivesUpAFrozenSession is the detector on the Android path: the
// control socket's relay carries its own hooks and watcher. Without them a
// phone never noticed.
func TestRelayGivesUpAFrozenSession(t *testing.T) {
	h := newRelayStallHarness(t, nil)
	if r := h.reason(2 * time.Second); !strings.HasPrefix(r, "session_degraded") {
		t.Fatalf("relay ended with %q, want a degraded session", r)
	}
	if h.degraded.Load() != 1 {
		t.Fatalf("OnSessionEnd reported %d degraded ends", h.degraded.Load())
	}
}

// TestRelayKeepsAHealthySession: answered flows, echoed keepalives.
func TestRelayKeepsAHealthySession(t *testing.T) {
	h := newRelayStallHarness(t, nil)
	h.exit.answerData.Store(true)
	h.exit.echo.Store(true)
	pkts := fixtureFlows(t)
	for range 10 {
		time.Sleep(100 * time.Millisecond)
		_, _ = h.app.Write(pkts[5].data)
	}
	if r := h.reason(300 * time.Millisecond); r != "" || h.degraded.Load() != 0 {
		t.Fatalf("a healthy relay ended: %q", r)
	}
}

// TestRelayMadeUpKeepalivesAreNoEcho: the Polling feeder on the Android path.
func TestRelayMadeUpKeepalivesAreNoEcho(t *testing.T) {
	h := newRelayStallHarness(t, func(c net.Conn) net.Conn { return pollingLike{c} })
	h.exit.feeder.Store(true)
	if r := h.reason(2 * time.Second); !strings.HasPrefix(r, "session_degraded") {
		t.Fatalf("relay ended with %q, want a degraded session", r)
	}
}

// TestRelayMadeUpKeepaliveStrategyWithoutItsCountIsNotJudged is P3-7 of the
// round-5 review, the Android half of r4 P3-7: the relay looked for the
// keepalive counter on the conn only. A Polling conn under a wrapper that
// hides its count fell back to the generic count - the feeder's made-up
// frames included - and every confirmation passed. Named by its strategy,
// the session is not judged instead.
func TestRelayMadeUpKeepaliveStrategyWithoutItsCountIsNotJudged(t *testing.T) {
	polling := &keepaliveMakingStrategy{rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "polling", priority: 6}}
	h := newRelayStallHarness(t, nil, polling)
	h.exit.feeder.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h.log.first("not judged: the strategy makes up keepalives"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := h.log.first("not judged: the strategy makes up keepalives"); !ok {
		t.Fatalf("no skip:\n%s", h.log)
	}
	if h.exit.gotEcho.Load() != 0 {
		t.Fatal("keepalives went out to confirm against a count that includes made-up frames")
	}
}

// TestRelayDeadPeerIsNotDegraded: h_deadpeer on the Android path.
func TestRelayDeadPeerIsNotDegraded(t *testing.T) {
	h := newRelayStallHarness(t, nil)
	h.exit.echo.Store(true)
	if r := h.reason(1500 * time.Millisecond); r != "" || h.degraded.Load() != 0 {
		t.Fatalf("a live relay was given up for a dead peer: %q", r)
	}
}

// TestPollingKeepaliveCountSurvivesTheHandshakeWrapper: the TUN handshake may
// hand the tunnel back wrapped in a replayConn; the Polling count under it
// must still be what the detector reads, or the feeder's frames count again.
func TestPollingKeepaliveCountSurvivesTheHandshakeWrapper(t *testing.T) {
	generic := func() uint64 { return 7 }
	if got := echoSourceFor(&replayConn{Conn: pollingLike{}}, nil, generic).count(); got != 0 {
		t.Fatalf("read %d echoes through the wrapper: the generic count, not the server's", got)
	}
}

// TestAConnThatLostCountIsNotJudged is P3-6 of the round-4 review: once the
// Polling tracker loses the framing it stops counting the server's
// keepalives, and every later confirmation failed - toward a verdict. Such a
// session is not judged at all.
func TestAConnThatLostCountIsNotJudged(t *testing.T) {
	h := newStallHarness(t, func(c net.Conn) net.Conn { return lostTrackConn{c} })
	if !h.wait("not judged: the conn has lost track", 2*time.Second) {
		t.Fatalf("no skip:\n%s", h.out)
	}
	time.Sleep(500 * time.Millisecond)
	if strings.Contains(h.out.String(), "Session degraded") || h.exit.gotEcho.Load() != 0 {
		t.Fatalf("a session without a usable echo count was judged:\n%s", h.out)
	}
}

// TestAMadeUpKeepaliveStrategyWithoutItsCountIsNotJudged is P3-7: a conn of
// a strategy that makes up keepalives, wrapped in something that hides its
// count, fell back to the generic count - which includes the made-up frames
// and passes every confirmation. It is not judged instead.
func TestAMadeUpKeepaliveStrategyWithoutItsCountIsNotJudged(t *testing.T) {
	h := newStallHarness(t, nil)
	h.v.mu.Lock()
	h.v.strategy = &keepaliveMakingStrategy{rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "polling", priority: 6}}
	h.v.mu.Unlock()
	if !h.wait("not judged: the strategy makes up keepalives", 2*time.Second) {
		t.Fatalf("no skip:\n%s", h.out)
	}
	if h.exit.gotEcho.Load() != 0 {
		t.Fatal("keepalives went out to confirm against a count that includes made-up frames")
	}
}

// TestAConfirmationCannotTouchTheNextSession is P2-5 of the round-4 review:
// the flow table was shared by every session, so a confirmation still running
// when a swap or hop replaced the session marked the new session's waiting
// flows as ignored when the old session's echo came in - and a new session
// that then froze was never judged. The table now belongs to its session.
func TestAConfirmationCannotTouchTheNextSession(t *testing.T) {
	h := newStallHarness(t, nil)
	h.exit.echo.Store(true)
	h.exit.echoDelay.Store(int64(100 * time.Millisecond))
	deadline := time.Now().Add(2 * time.Second)
	for h.exit.gotEcho.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no confirmation started:\n%s", h.out)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The swap lands while the old session waits for its echo.
	other, _ := net.Pipe()
	t.Cleanup(func() { other.Close() })
	next := newFlowTable()
	pendingFlow(t, next)
	h.v.mu.Lock()
	h.v.conn, h.v.stall = other, next
	h.v.mu.Unlock()
	time.Sleep(300 * time.Millisecond) // the echo arrives, the old confirmation ends
	if s := next.stalledFor(time.Now()); s == 0 {
		t.Fatal("the old session's confirmation marked the new session's flows as answered")
	}
}

// keepaliveRefusingConn fails every keepalive write and passes the rest.
type keepaliveRefusingConn struct{ net.Conn }

func (c keepaliveRefusingConn) Write(p []byte) (int, error) {
	if len(p) == 4 && p[0]|p[1]|p[2]|p[3] == 0 {
		return 0, errors.New("uplink stuck")
	}
	return c.Conn.Write(p)
}

// TestAKeepaliveThatCannotGoOutIsNoAnswer is P3-8 of the round-4 review: a
// confirmation whose keepalive could not be sent came back "alive" with 0
// sent, logged "a keepalive echoed (0 sent)" and was asked again at the next
// check. It is no answer: no verdict, nothing marked, and the next question
// after one threshold.
func TestAKeepaliveThatCannotGoOutIsNoAnswer(t *testing.T) {
	h := newStallHarness(t, func(c net.Conn) net.Conn { return keepaliveRefusingConn{c} })
	if !h.wait("could not confirm", 2*time.Second) {
		t.Fatalf("no failed confirmation:\n%s", h.out)
	}
	time.Sleep(200 * time.Millisecond) // under one threshold (300 ms)
	out := h.out.String()
	if strings.Contains(out, "Session alive") || strings.Contains(out, "Session degraded") {
		t.Fatalf("a keepalive that never went out gave an answer:\n%s", out)
	}
	if n := strings.Count(out, "Session suspect: a flow"); n != 1 {
		t.Fatalf("%d suspicions within one threshold of a failed confirmation", n)
	}
}

// TestAFlowAnsweredDuringTheConfirmationIsNoVerdict is P2-3 of the round-4
// review: a stalled flow that got its answer while the keepalives were out -
// its packet queued behind a downlink burst - still ended the session. The
// exit stays silent to keepalives and answers the flow once the confirmation
// has started.
func TestAFlowAnsweredDuringTheConfirmationIsNoVerdict(t *testing.T) {
	h := newStallHarness(t, nil)
	deadline := time.Now().Add(2 * time.Second)
	for h.exit.gotEcho.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no confirmation started:\n%s", h.out)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := h.exit.writeFrame(fixtureFlows(t)[8].data); err != nil {
		t.Fatal(err)
	}
	if !h.wait("got its answer during the confirmation", 2*time.Second) {
		t.Fatalf("no recheck of the flow:\n%s", h.out)
	}
	if strings.Contains(h.out.String(), "Session degraded") {
		t.Fatalf("a session whose flow was answered was given up:\n%s", h.out)
	}
}

// TestRelayFlowAnsweredDuringTheConfirmationIsNoVerdict: the same on the
// Android relay.
func TestRelayFlowAnsweredDuringTheConfirmationIsNoVerdict(t *testing.T) {
	h := newRelayStallHarness(t, nil)
	deadline := time.Now().Add(2 * time.Second)
	for h.exit.gotEcho.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no confirmation started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := h.exit.writeFrame(fixtureFlows(t)[8].data); err != nil {
		t.Fatal(err)
	}
	if r := h.reason(1500 * time.Millisecond); r != "" || h.degraded.Load() != 0 {
		t.Fatalf("a relay whose flow was answered was given up: %q", r)
	}
}

// quietLimiter is a limiter in its quiet period for d more.
func quietLimiter(d time.Duration) *verdictLimiter {
	return &verdictLimiter{quietUntil: time.Now().Add(d)}
}

// TestARefusedVerdictIsJudgedAgainAfterTheQuiet is P2-1 of the round-4
// review: a session whose verdict the limiter refused was never judged again
// - on the desktop it was marked judged, the Android relay's watcher
// returned - and a Polling session under a byte cap, which never ends on its
// own, stayed for good. It is judged again when the quiet period ends, and no
// keepalive goes out for it in between.
func TestARefusedVerdictIsJudgedAgainAfterTheQuiet(t *testing.T) {
	h := newStallHarness(t, nil)
	stallVerdictsNow.Store(quietLimiter(1500 * time.Millisecond))
	if !h.wait("not acting until", 2*time.Second) {
		t.Fatalf("no refused verdict:\n%s", h.out)
	}
	sent := h.exit.gotEcho.Load()
	time.Sleep(300 * time.Millisecond) // inside the quiet period
	if n := h.exit.gotEcho.Load() - sent; n != 0 {
		t.Fatalf("%d keepalives went out for a session that may not be judged yet", n)
	}
	if !h.wait("VPN disconnected: session degraded", 3*time.Second) {
		t.Fatalf("the session was not judged again after the quiet period:\n%s", h.out)
	}
}

// TestRelayRefusedVerdictIsJudgedAgainAfterTheQuiet: the same on the relay.
func TestRelayRefusedVerdictIsJudgedAgainAfterTheQuiet(t *testing.T) {
	out := &stampedLog{}
	h := newRelayStallHarness(t, nil)
	setLog(t, out)
	stallVerdictsNow.Store(quietLimiter(1500 * time.Millisecond))
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := out.first("not acting until"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no refused verdict:\n%s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sent := h.exit.gotEcho.Load()
	time.Sleep(300 * time.Millisecond) // inside the quiet period
	if n := h.exit.gotEcho.Load() - sent; n != 0 {
		t.Fatalf("%d keepalives went out for a session that may not be judged yet", n)
	}
	if r := h.reason(3 * time.Second); !strings.HasPrefix(r, "session_degraded") {
		t.Fatalf("relay ended with %q, want a verdict after the quiet period", r)
	}
}

// queueingConn is a tunnel conn whose Write only queues, as HTTP Polling's
// does: a write reaches the exit lag later, in order, and UplinkProgress
// says how far the queue has gone.
type queueingConn struct {
	net.Conn
	lag      time.Duration
	mu       sync.Mutex
	accepted uint64
	sent     atomic.Uint64
	queue    chan []byte
}

func newQueueingConn(c net.Conn, lag time.Duration) *queueingConn {
	q := &queueingConn{Conn: c, lag: lag, queue: make(chan []byte, 64)}
	go func() {
		for p := range q.queue {
			time.Sleep(q.lag)
			if _, err := q.Conn.Write(p); err != nil {
				return
			}
			q.sent.Add(uint64(len(p)))
		}
	}()
	return q
}

func (q *queueingConn) Write(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.accepted += uint64(len(p))
	q.queue <- append([]byte(nil), p...)
	return len(p), nil
}

func (q *queueingConn) UplinkProgress() (uint64, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.accepted, q.sent.Load()
}

// TestAQueuedKeepaliveIsTimedFromItsDelivery is P2-6 of the round-4 review:
// on Polling a keepalive Write only queues, and the echo window ran from the
// queueing. Behind an upload both keepalives could sit in the queue for the
// whole confirmation and a live tunnel was given up. Here every write reaches
// the exit 400 ms late (the windows are 150 ms) and the exit echoes at once;
// the peer behind the stalled flow is dead.
func TestAQueuedKeepaliveIsTimedFromItsDelivery(t *testing.T) {
	h := newStallHarness(t, func(c net.Conn) net.Conn { return newQueueingConn(c, 400*time.Millisecond) })
	h.exit.echo.Store(true)
	if !h.wait("Session alive", 3*time.Second) {
		t.Fatalf("the queued keepalive's echo was not waited for:\n%s", h.out)
	}
	if strings.Contains(h.out.String(), "Session degraded") {
		t.Fatalf("a live tunnel behind a queue was given up:\n%s", h.out)
	}
}

// TestControlRelaysNameTheSessionStrategy: every relay the control server
// starts carries the session's strategy, for the test above to matter on a
// phone.
func TestControlRelaysNameTheSessionStrategy(t *testing.T) {
	polling := &keepaliveMakingStrategy{rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "polling", priority: 6}}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := &TUNDevice{file: os.NewFile(uintptr(fds[0]), "tun"), mtu: 1500, atomicMTU: 1500}
	app := os.NewFile(uintptr(fds[1]), "app")
	cli, srv := net.Pipe()
	stop := make(chan struct{})
	cs := &ControlServer{config: &ControlConfig{SessionStrategyFn: func() strategy.Strategy { return polling }}}
	r := cs.startRelay(dev, cli, net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), stop, &RelayCallbacks{})
	t.Cleanup(func() {
		close(stop)
		cli.Close()
		srv.Close()
		app.Close()
		dev.file.Close()
		<-r.done
	})
	if r.callbacks.Strategy != polling {
		t.Fatalf("the relay carries strategy %v, want the session's", r.callbacks.Strategy)
	}
}

// TestDataDownIsStampedAndEchoesAreNot: Stop books a session as useful by
// its last data packet down (P3-4 of the round-6 review). A keepalive echo
// moves lastRx and nothing else; a data packet moves lastData.
func TestDataDownIsStampedAndEchoesAreNot(t *testing.T) {
	h := newQuietStallHarness(t, nil)
	if err := h.exit.writeFrame(nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	h.v.mu.Lock()
	data := h.v.lastData
	h.v.mu.Unlock()
	if !data.IsZero() {
		t.Fatal("a keepalive echo was stamped as data")
	}
	if err := h.exit.writeFrame(fixtureFlows(t)[8].data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.v.mu.Lock()
		data = h.v.lastData
		h.v.mu.Unlock()
		if !data.IsZero() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a data packet down was not stamped")
}
