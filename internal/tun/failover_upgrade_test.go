package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// rankedPipeStrategy is a pipeStrategy with its own identity and rank, and an
// optional failure, so a test can hold two of them side by side.
type rankedPipeStrategy struct {
	*pipeStrategy
	id       string
	priority int
	fail     error
	dials    atomic.Int64
}

func (s *rankedPipeStrategy) Name() string  { return s.id }
func (s *rankedPipeStrategy) ID() string    { return s.id }
func (s *rankedPipeStrategy) Priority() int { return s.priority }
func (s *rankedPipeStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	s.dials.Add(1)
	if s.fail != nil {
		return nil, s.fail
	}
	return s.pipeStrategy.Connect(ctx, target)
}

// newUpgradeClient is a client whose tunnel rides a fallback strategy, over a
// manager with one endpoint and a better strategy registered next to it. The
// tunnel's addresses are the ones the scripted exit hands out.
func newUpgradeClient(t *testing.T, better *rankedPipeStrategy) (*VPNClient, *rankedPipeStrategy, net.Conn) {
	t.Helper()
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: "203.0.113.10:443"}}, endpoint.V4Only); err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	fallback := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response()}, id: "polling", priority: 6}
	m.Register(fallback)
	m.Register(better)

	oldConn, srv := net.Pipe()
	t.Cleanup(func() { oldConn.Close(); srv.Close() })
	v := &VPNClient{
		running:     1,
		stopCh:      make(chan struct{}),
		manager:     m,
		serverAddr:  "203.0.113.10:443",
		localIP:     callsiteClientIP,
		tun:         &TUNDevice{mtu: 1280, remoteIP: callsiteServerIP},
		conn:        oldConn,
		strategy:    fallback,
		connectedAt: time.Now().Add(-10 * time.Minute),
		lastRx:      time.Now(),
	}
	return v, fallback, oldConn
}

// TestUpgradeMovesTheTunnelMakeBeforeBreak is D3 of the 2026-10-21 stand report
// at the tunnel's end: offered a strategy that ranks above the one carrying the
// tunnel, the client dials it, handshakes, swaps it in and only then closes the
// old conn. The read loop that was blocked on the old conn must not take its
// closing for a lost tunnel and reconnect on top of the new one.
func TestUpgradeMovesTheTunnelMakeBeforeBreak(t *testing.T) {
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "reality", priority: 5}
	v, _, oldConn := newUpgradeClient(t, better)

	out := &stampedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	reader := make(chan struct{})
	go func() {
		v.readFromServer()
		close(reader)
	}()
	t.Cleanup(func() {
		atomic.StoreInt32(&v.running, 0)
		v.mu.Lock()
		if v.conn != nil {
			v.conn.Close()
		}
		v.mu.Unlock()
		<-reader
	})
	time.Sleep(20 * time.Millisecond) // the reader is parked on the old conn

	v.tryStrategyUpgrade([]strategy.Strategy{better})

	v.mu.Lock()
	cur, conn := v.strategy, v.conn
	v.mu.Unlock()
	if cur == nil || cur.ID() != "reality" {
		t.Fatalf("tunnel strategy after the upgrade: %v, want reality; log:\n%s", cur, out)
	}
	if conn == oldConn {
		t.Fatal("the old conn is still installed")
	}
	if _, err := oldConn.Write([]byte{0}); !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) &&
		(err == nil || !strings.Contains(err.Error(), "closed")) {
		t.Fatalf("old conn left open after the swap (write err %v)", err)
	}

	time.Sleep(100 * time.Millisecond)
	if ln, ok := out.first("VPN disconnected"); ok {
		t.Fatalf("closing the replaced conn started a reconnect: %s", ln.text)
	}
}

// TestUpgradeIsOnlyUpward: a candidate that does not rank above the current
// strategy is not dialled.
func TestUpgradeIsOnlyUpward(t *testing.T) {
	worse := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "morph", priority: 10}
	v, _, oldConn := newUpgradeClient(t, worse)
	v.tryStrategyUpgrade([]strategy.Strategy{worse})
	if worse.dials.Load() != 0 || v.conn != oldConn {
		t.Fatal("an upgrade dialled a strategy ranked below the current one")
	}
}

// TestFailedUpgradeLeavesTheTunnelAlone: the dial fails, the tunnel stays where
// it was.
func TestFailedUpgradeLeavesTheTunnelAlone(t *testing.T) {
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response()}, id: "reality", priority: 5,
		fail: errors.New("tls: handshake reset")}
	v, fallback, oldConn := newUpgradeClient(t, better)
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if better.dials.Load() != 1 {
		t.Fatalf("upgrade dialled %d times, want 1", better.dials.Load())
	}
	if v.conn != oldConn || v.strategy != fallback {
		t.Fatal("a failed upgrade touched the tunnel")
	}
}

// TestUpgradeWithDifferentAddressesIsDropped: a new session that comes back
// with another tunnel address would break every flow in the tunnel if swapped
// in. The client keeps the old one.
func TestUpgradeWithDifferentAddressesIsDropped(t *testing.T) {
	resp := []byte{0x00}
	resp = append(resp, callsiteServerIP.To4()...)
	resp = append(resp, net.IPv4(10, 99, 0, 77).To4()...)
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: resp, gap: silent}, id: "reality", priority: 5}
	v, fallback, oldConn := newUpgradeClient(t, better)
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.conn != oldConn || v.strategy != fallback {
		t.Fatal("swapped in a session with a different tunnel address")
	}
}

// exitStrategy is a strategy whose exit is scripted per test: onHandshake runs
// on the exit's side of the pipe once the 8-byte TUN request is in, and gets
// to answer it however the test needs.
type exitStrategy struct {
	id          string
	priority    int
	t           *testing.T
	onHandshake func(srv net.Conn)
	beforeDial  func()
	onTarget    func(target string)
	handshakes  atomic.Int64
}

func (s *exitStrategy) Name() string                        { return s.id }
func (s *exitStrategy) ID() string                          { return s.id }
func (s *exitStrategy) Priority() int                       { return s.priority }
func (s *exitStrategy) Probe(context.Context, string) error { return nil }
func (s *exitStrategy) RequiresServer() bool                { return true }
func (s *exitStrategy) Description() string                 { return "scripted exit" }
func (s *exitStrategy) Connect(_ context.Context, target string) (net.Conn, error) {
	if s.onTarget != nil {
		s.onTarget(target)
	}
	if s.beforeDial != nil {
		s.beforeDial()
	}
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		s.handshakes.Add(1)
		s.onHandshake(srv)
	}()
	return cli, nil
}

// answer writes the bare v3 handshake response; then is what the exit does
// with the session afterwards.
func answer(then func(srv net.Conn)) func(net.Conn) {
	return func(srv net.Conn) {
		if _, err := srv.Write(bareV3Response()); err != nil {
			return
		}
		if then != nil {
			then(srv)
		}
	}
}

// runReader runs the client's read loop until the test ends.
func runReader(t *testing.T, v *VPNClient) {
	t.Helper()
	done := make(chan struct{})
	go func() { v.readFromServer(); close(done) }()
	t.Cleanup(func() {
		atomic.StoreInt32(&v.running, 0)
		v.mu.Lock()
		if v.conn != nil {
			v.conn.Close()
		}
		v.mu.Unlock()
		<-done
	})
}

// TestUpgradeIsConfirmedOnlyByAUsefulSession is P1-3 of the PR #126 review: an
// upgrade that dialled was booked as a success there and then. Now it is
// pending until the new session has carried traffic for sessionUsefulMin; a
// keepalive from the exit past that line confirms it.
func TestUpgradeIsConfirmedOnlyByAUsefulSession(t *testing.T) {
	keepalive := make(chan struct{})
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(func(srv net.Conn) {
		<-keepalive
		_, _ = srv.Write([]byte{0, 0, 0, 0})
		select {} // and then the session just lives
	})}
	v, _, _ := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)
	setLog(t, &stampedLog{})

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.strategy != better {
		t.Fatal("no swap - the test proves nothing")
	}
	if got := v.manager.GetLastConnectionInfo().StrategyID; got == "reality" {
		t.Fatal("the upgrade was booked as a success before its session carried anything")
	}

	// Past the strategy line but short of the dead-session line: a session
	// that died now would still count as dead young, so it is no proof yet.
	v.mu.Lock()
	v.connectedAt = time.Now().Add(-sessionUsefulMin - 5*time.Second)
	v.mu.Unlock()
	v.noteDownlink(true)
	if got := v.manager.GetLastConnectionInfo().StrategyID; got == "reality" {
		t.Fatal("confirmed between the 20 s and 40 s lines, where the same session would still count as dead")
	}

	v.mu.Lock()
	v.connectedAt = time.Now().Add(-deadSessionMax - time.Second) // the session has been up long enough
	v.mu.Unlock()
	runReader(t, v)
	close(keepalive)

	deadline := time.Now().Add(2 * time.Second)
	for v.manager.GetLastConnectionInfo().StrategyID != "reality" {
		if time.Now().After(deadline) {
			t.Fatal("downlink past sessionUsefulMin did not confirm the upgrade")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUpgradedSessionThatDiesFeedsTheBackoff: the missing test from the
// review - an upgrade whose session dies right after the swap is a failed
// upgrade, and the backoff hears about it.
func TestUpgradedSessionThatDiesFeedsTheBackoff(t *testing.T) {
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(func(srv net.Conn) {
		time.Sleep(50 * time.Millisecond)
		srv.Close() // the exit drops the new session at once
	})}
	v, _, _ := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.strategy != better {
		t.Fatal("no swap - the test proves nothing")
	}
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	done := make(chan struct{})
	go func() { v.readFromServer(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("the dropped session was never noticed; log:\n%s", out)
	}
	if n := v.manager.UpgradeFailures("reality"); n != 1 {
		t.Fatalf("upgrade failures = %d after the upgraded session died, want 1", n)
	}
}

// TestUpgradeHandshakeFailureFeedsTheBackoff: the other missing test - an
// exit that refuses the upgraded session's handshake is a failed upgrade.
func TestUpgradeHandshakeFailureFeedsTheBackoff(t *testing.T) {
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: func(srv net.Conn) {
		_, _ = srv.Write([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}) // pool exhausted
	}}
	v, fallback, oldConn := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)
	setLog(t, &stampedLog{})

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.conn != oldConn || v.strategy != fallback {
		t.Fatal("a refused handshake touched the tunnel")
	}
	if n := v.manager.UpgradeFailures("reality"); n != 1 {
		t.Fatalf("upgrade failures = %d after a refused handshake, want 1", n)
	}
}

// TestUpgradeDoesNotHandshakeOverASessionChange is P1-4 with the exit's
// behaviour modelled: a new session's handshake moves the client's address to
// it and evicts whatever held it. While a reconnect or a port hop holds
// sessionMu (it is between its own handshake and its commit), an upgrade must
// not handshake at all - or it evicts the session the client is about to keep.
func TestUpgradeDoesNotHandshakeOverASessionChange(t *testing.T) {
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(nil)}
	v, _, oldConn := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)
	setLog(t, &stampedLog{})

	v.sessionMu.Lock() // a reconnect mid-handshake
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	v.sessionMu.Unlock()

	time.Sleep(50 * time.Millisecond)
	if n := better.handshakes.Load(); n != 0 {
		t.Fatalf("the upgrade handshook %d time(s) over a session change in progress - the exit evicted the other session", n)
	}
	if v.conn != oldConn {
		t.Fatal("the tunnel conn changed")
	}
}

// TestUpgradeAfterStopInstallsNothing is the P2 "upgrade after Stop" item: a
// client stopped while the upgrade was dialling must not get a handshaken
// session installed on it.
func TestUpgradeAfterStopInstallsNothing(t *testing.T) {
	var v *VPNClient
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(nil)}
	better.beforeDial = func() { atomic.StoreInt32(&v.running, 0) } // Stop lands mid-dial
	v, _, oldConn := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)
	setLog(t, &stampedLog{})

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	time.Sleep(50 * time.Millisecond)
	if better.handshakes.Load() != 0 || v.conn != oldConn {
		t.Fatal("a stopped client got an upgraded session")
	}
}

// TestRejectedUpgradeIsTunnelLoss: once the new session has handshaken, the
// exit has moved the client's address to it and the old session is gone. If
// the client then drops the new one (here: the exit stopped reporting the IPv6
// side the tunnel runs), it has no tunnel left, and must reconnect instead of
// "staying put" on a dead conn until the read deadline.
func TestRejectedUpgradeIsTunnelLoss(t *testing.T) {
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(nil)}
	v, _, _ := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)
	v.serverCaps.DualStackEnabled = true // the bare response carries no capabilities

	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	v.tryStrategyUpgrade([]strategy.Strategy{better})

	if !strings.Contains(out.String(), "VPN disconnected: strategy upgrade") {
		t.Fatalf("a dropped upgrade after the handshake was not taken for tunnel loss; log:\n%s", out)
	}
	if n := v.manager.UpgradeFailures("reality"); n != 1 {
		t.Fatalf("upgrade failures = %d, want 1", n)
	}
}

// TestFailedUpgradeDialsOnlyOneCandidate is N7 of the second acceptance of PR
// #126: one offer from a reprobe dials one strategy. When it failed the loop
// went on to the next candidate at once, and a single offer put the handshakes
// of five transports on the wire within 3 ms.
func TestFailedUpgradeDialsOnlyOneCandidate(t *testing.T) {
	first := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response()}, id: "reality", priority: 4,
		fail: errors.New("tls: handshake reset")}
	v, fallback, oldConn := newUpgradeClient(t, first)
	second := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "stego", priority: 5}
	v.manager.Register(second)

	v.tryStrategyUpgrade([]strategy.Strategy{first, second})

	if first.dials.Load() != 1 {
		t.Fatalf("the best candidate was dialled %d times, want 1", first.dials.Load())
	}
	if n := second.dials.Load(); n != 0 {
		t.Fatalf("a failed upgrade went on to dial the next candidate (%d dials)", n)
	}
	if v.conn != oldConn || v.strategy != fallback {
		t.Fatal("a failed upgrade touched the tunnel")
	}
}

// TestAnUpgradeDoesNotGoBackOntoATransportTheRouteKilled is P2-B of the
// round-6 review at the tunnel's end: REALITY died the same way on a and on b,
// and the route rule set it aside on both. An upgrade offered on b must not
// dial it there.
func TestAnUpgradeDoesNotGoBackOntoATransportTheRouteKilled(t *testing.T) {
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "reality", priority: 5}
	v, _, oldConn := newUpgradeClient(t, better)
	m := v.manager
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: "203.0.113.10:443"}, {Name: "b", V4: "203.0.113.11:443", Order: 1}},
		endpoint.V4Only); err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	cands := map[string]endpoint.Candidate{}
	for _, st := range m.EndpointStates() {
		cands[st.Addr] = st.Candidate
	}
	for _, addr := range []string{"203.0.113.10:443", "203.0.113.11:443"} {
		m.SessionEnded(strategy.SessionEnd{Strategy: "reality", Endpoint: cands[addr], HasEndpoint: true, Degraded: true})
	}
	v.mu.Lock()
	v.sessionCand, v.hasSessionCand, v.serverAddr = cands["203.0.113.11:443"], true, "203.0.113.11:443"
	v.mu.Unlock()

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if n := better.dials.Load(); n != 0 || v.conn != oldConn {
		t.Fatalf("the upgrade dialled REALITY %d times on b, where the route set it aside", n)
	}
}
