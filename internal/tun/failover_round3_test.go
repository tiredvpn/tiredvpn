package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// upgradeOnSelector brings a tunnel up on the fallback "polling" through the
// client's own connect path - so the session's endpoint comes from the real
// selector - and then registers a better "reality" whose exit answers the
// handshake and then holds the session silent.
func upgradeOnSelector(t *testing.T) (*VPNClient, *strategy.Manager, []string, *exitStrategy) {
	t.Helper()
	m := strategy.NewManager()
	var eps []endpoint.Endpoint
	var addrs []string
	for i := range 2 {
		a := newNetcheckListener(t).addr
		addrs = append(addrs, a)
		eps = append(eps, endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: a, Order: i})
	}
	if err := m.SetEndpointSelection(endpoint.Config{Endpoints: eps, Family: endpoint.V4Only, FailureThreshold: 2,
		Cooldown: time.Minute, MaxCooldown: 30 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	m.Register(&rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "polling", priority: 6})
	v := newCallsiteClient(m)
	v.running = 1
	v.stopCh = make(chan struct{})
	if err := v.connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !v.hasSessionCand || v.sessionCand.Addr != addrs[0] {
		t.Fatalf("session endpoint %v (set=%v), want %s", v.sessionCand, v.hasSessionCand, addrs[0])
	}
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(func(srvConn net.Conn) { select {} })}
	m.Register(better)
	return v, m, addrs, better
}

func deadStreak(t *testing.T, m *strategy.Manager, addr string) int {
	t.Helper()
	for _, st := range m.EndpointStates() {
		if st.Addr == addr {
			return st.DeadStreak
		}
	}
	t.Fatalf("no candidate %s", addr)
	return 0
}

// TestFailedUpgradeDoesNotParkTheFallbacksServer is P1-A of the PR #126 round-2
// review. The client sat on Polling at srv-a, the upgrade swapped in REALITY,
// and REALITY froze a second later. That young silent death was booked as the
// endpoint's verdict: srv-a parked, a server hop, an outage - for a server that
// had just carried ten minutes of Polling. The strategy is to blame, and the
// failed upgrade already says so.
func TestFailedUpgradeDoesNotParkTheFallbacksServer(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = old })

	v, m, addrs, better := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.strategy != better {
		t.Fatal("no swap - the test proves nothing")
	}

	now := time.Now()
	v.mu.Lock()
	v.conn = &failingConn{err: silenceErr}
	v.connectedAt, v.lastRx = now.Add(-31*time.Second), now.Add(-30*time.Second)
	v.mu.Unlock()
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	done := make(chan struct{})
	go func() { v.readFromServer(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("read loop did not return; log:\n%s", out)
	}

	if left := cooldownLeft(t, m, addrs[0]); left > 0 {
		t.Fatalf("a failed upgrade parked the fallback's server for %v", left)
	}
	if n := m.UpgradeFailures("reality"); n != 1 {
		t.Fatalf("upgrade failures = %d, want 1", n)
	}
}

// TestUpgradeSwapClearsTheDeadStreak: the swap ends a useful fallback session,
// and that has to reach the endpoint like any useful session does. The swap
// used to book it without the endpoint, so each failed upgrade parked the
// server longer than the last: 1, 2, 4, 8 minutes.
func TestUpgradeSwapClearsTheDeadStreak(t *testing.T) {
	v, m, addrs, better := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	m.SessionEnded(strategy.SessionEnd{Strategy: "other", Endpoint: v.sessionCand, HasEndpoint: true, Dead: true})
	if deadStreak(t, m, addrs[0]) != 1 {
		t.Fatal("no dead streak to clear - the test proves nothing")
	}

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.strategy != better {
		t.Fatal("no swap")
	}
	if n := deadStreak(t, m, addrs[0]); n != 0 {
		t.Fatalf("the useful fallback session ended by the swap left the dead streak at %d", n)
	}
}

// TestUpgradeDialsTheSessionsEndpoint covers the call site of P3 from round 1:
// the upgrade must dial the endpoint the tunnel rides, not wherever the pin has
// moved since.
func TestUpgradeDialsTheSessionsEndpoint(t *testing.T) {
	v, m, addrs, better := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	var dialled string
	better.onTarget = func(target string) { dialled = target }
	m.PinAnswering(addrs[1])
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if dialled != addrs[0] {
		t.Fatalf("the upgrade dialled %q, want the session's endpoint %s", dialled, addrs[0])
	}
}

// TestFamilyRecoveredDuringPoolWaitIsPolled is P1-C of the round-2 review. The
// pool poll walks only the candidates marked as having a physical route, and
// that mark is refreshed by the family preflight - which ran only inside a
// connect cycle. Round 2 removed the wait's periodic exit to a connect, so a
// family whose route came back mid-wait stayed excluded: here IPv4 is
// blackholed, IPv6 has no route at first and gets it back 1.5 s in, and the
// client must reconnect over IPv6.
func TestFamilyRecoveredDuringPoolWaitIsPolled(t *testing.T) {
	setPoolWaitKnobs(t, true)
	reconnectConnectTimeout = time.Second

	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { ln6.Close() })
	go func() {
		for {
			c, err := ln6.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	v4 := silentTCPAddr(t)
	v6 := ln6.Addr().String()

	m := strategy.NewManager()
	if err := m.SetEndpointSelection(endpoint.Config{
		Endpoints: []endpoint.Endpoint{{Name: "a", V4: v4, V6: v6}},
		Family:    endpoint.PreferV6,
	}); err != nil {
		t.Fatal(err)
	}
	var v6Back atomic.Bool
	m.SetRouteReachable(func(addr string) (bool, bool) {
		if addr == v6 {
			return v6Back.Load(), true
		}
		return true, true
	})
	m.Register(&pipeStrategy{t: t, resp: bareV3Response(), gap: silent})
	m.SetConnectivityChecker(strategy.NewConnectivityChecker(v4, 300*time.Millisecond, true))

	out := &stampedLog{}
	setLog(t, out)
	v := newCallsiteClient(m)
	v.running = 1
	v.stopCh = make(chan struct{})
	done := make(chan struct{})
	go func() { v.handleDisconnect("server read", io.EOF); close(done) }()
	time.AfterFunc(1500*time.Millisecond, func() { v6Back.Store(true) })

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		atomic.StoreInt32(&v.running, 0)
		close(v.stopCh)
		<-done
		t.Fatalf("IPv6 came back mid-wait and the client never used it; log:\n%s", out)
	}
	if _, ok := out.first("VPN reconnected successfully"); !ok {
		t.Fatalf("no tunnel; log:\n%s", out)
	}
}

// TestLostUpgradeResponseIsTunnelLoss is P2-2 of the round-2 review. Once the
// request is out, the exit may already have registered the new session and
// moved the client's address to it - several handlers register before they
// answer. A response that never arrives therefore leaves the old session
// displaced, and keeping it meant downlink went nowhere until a read deadline.
// Only a status other than 0 says the exit registered nothing.
func TestLostUpgradeResponseIsTunnelLoss(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	better := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: func(net.Conn) { select {} }}
	v, _, _ := newUpgradeClient(t, &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t}, id: "unused", priority: 99})
	v.manager.Register(better)
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)

	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if !strings.Contains(out.String(), "VPN disconnected: strategy upgrade") {
		t.Fatalf("a lost handshake response left the client on a session the exit had displaced; log:\n%s", out)
	}
	if n := v.manager.UpgradeFailures("reality"); n != 1 {
		t.Fatalf("upgrade failures = %d, want 1", n)
	}
}

// TestPortHopJoinsTheSessionState is P2-3 of the round-2 review: the port hop
// swaps the session like an upgrade does, but left upgradePending and
// sessionCand from before, so an upgrade could be confirmed or failed by the
// hop's session, and a hop onto another endpoint booked its session's death
// against the previous one.
func TestPortHopJoinsTheSessionState(t *testing.T) {
	m, addrs, _ := poolManager(t, 2)
	v := newCallsiteClient(m)
	v.running = 1
	v.stopCh = make(chan struct{})
	setLog(t, &stampedLog{})
	if err := v.connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	v.mu.Lock()
	v.upgradePending = v.strategy
	v.mu.Unlock()
	m.PinAnswering(addrs[1])

	v.seamlessPortHop(1234)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.upgradePending != nil {
		t.Error("the hop's session inherited a pending upgrade")
	}
	if !v.hasSessionCand || v.sessionCand.Addr != addrs[1] {
		t.Errorf("after the hop the session endpoint is %v, want %s", v.sessionCand, addrs[1])
	}
}

// TestPortHopOnAStoppedClientInstallsNothing: a hop waiting on sessionMu
// behind an upgrade could handshake and publish after Stop.
func TestPortHopOnAStoppedClientInstallsNothing(t *testing.T) {
	m, _, _ := poolManager(t, 1)
	v := newCallsiteClient(m)
	v.running = 1
	v.stopCh = make(chan struct{})
	setLog(t, &stampedLog{})
	if err := v.connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	v.mu.Lock()
	v.conn = nil // what Stop leaves
	v.mu.Unlock()
	v.running = 0

	v.seamlessPortHop(1234)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.conn != nil {
		t.Fatal("a port hop published a session on a stopped client")
	}
}

// TestPortHopChecksRunningOnBothSides: before the handshake (so a stopped
// client registers nothing on the exit) and again before the commit (Stop may
// land during the handshake).
func TestPortHopChecksRunningOnBothSides(t *testing.T) {
	for _, stopDuring := range []bool{false, true} {
		m := strategy.NewManager()
		addr := newNetcheckListener(t).addr
		if err := m.SetEndpointSelection(endpoint.Config{Endpoints: []endpoint.Endpoint{{Name: "a", V4: addr}}, Family: endpoint.V4Only}); err != nil {
			t.Fatal(err)
		}
		var v *VPNClient
		exit := &exitStrategy{id: "reality", priority: 5, t: t, onHandshake: answer(nil)}
		if stopDuring {
			exit.onHandshake = func(srv net.Conn) {
				atomic.StoreInt32(&v.running, 0)
				answer(nil)(srv)
			}
		}
		m.Register(exit)
		v = newCallsiteClient(m)
		v.stopCh = make(chan struct{})
		setLog(t, &stampedLog{})
		v.running = 1
		if !stopDuring {
			v.running = 0
		}

		v.seamlessPortHop(1234)
		v.mu.Lock()
		conn := v.conn
		v.mu.Unlock()
		if conn != nil {
			t.Fatalf("stopDuring=%v: a stopped client got the hop's session", stopDuring)
		}
		if !stopDuring && exit.handshakes.Load() != 0 {
			t.Fatal("a stopped client handshook on the exit")
		}
	}
}

// TestNoGatewayMeansNoDeadSessionVerdict is the "D6 outside Linux/Android" P3
// of the round-2 review: without a physical gateway to ask, the local-network
// check fell back to public resolvers that route into the dead tunnel, so the
// verdict was a coin toss (and up to 6 s of waiting). With no gateway the
// answer is "cannot tell", and no server is charged on it.
func TestNoGatewayMeansNoDeadSessionVerdict(t *testing.T) {
	old := gatewayAddrs
	gatewayAddrs = func() []string { return nil }
	t.Cleanup(func() { gatewayAddrs = old })
	if localLinkUp() {
		t.Fatal("no gateway known, and the local link was declared up")
	}
}

// TestFailedUpgradeIsChargedOnce is the "double penalty" P3: a failed upgraded
// session was charged by UpgradeOutcome and again as a session that was not
// useful.
func TestFailedUpgradeIsChargedOnce(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = old })

	v, m, _, better := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.strategy != better {
		t.Fatal("no swap")
	}
	before := m.GetStats()["reality"].FailureCount
	v.mu.Lock()
	v.conn = &failingConn{err: io.EOF}
	v.mu.Unlock()
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	done := make(chan struct{})
	go func() { v.readFromServer(); close(done) }()
	<-done
	if got := m.GetStats()["reality"].FailureCount - before; got != 1 {
		t.Fatalf("a failed upgraded session was charged %d times, want once", got)
	}
}

// TestUpgradeSkipsACandidateTheScanRanksLower is P2-5 of the round-2 review:
// the upgrade ranked by priority and the Android penalty only. On Linux QUIC
// (4) always outranked REALITY (5), and the QUIC probe reports success on
// silence: with REALITY healthy and QUIC failing, the scan stays on REALITY
// while every reprobe offered QUIC.
func TestUpgradeSkipsACandidateTheScanRanksLower(t *testing.T) {
	v, m, _, _ := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	cur := v.strategy
	for range 5 {
		m.UpdateStrategyConfidence(cur.ID(), true)
	}
	// One priority point above the current strategy, failing: the scan puts
	// it behind, so must the upgrade.
	quic := &exitStrategy{id: "quic_salamander", priority: cur.Priority() - 1, t: t, onHandshake: answer(nil)}
	var dials atomic.Int64
	quic.onTarget = func(string) { dials.Add(1) }
	m.Register(quic)
	for range 4 {
		m.UpdateStrategyConfidence(quic.ID(), false)
	}

	v.tryStrategyUpgrade([]strategy.Strategy{quic})
	if dials.Load() != 0 {
		t.Fatal("the upgrade dialled a candidate the scan itself ranks below the current strategy")
	}
}

// TestUpgradeRechecksEligibilityAtTheDial: the offer is built at the reprobe
// and the dial comes up to four minutes later. A UDP strategy offered then
// must not be dialled once UDP is excluded.
func TestUpgradeRechecksEligibilityAtTheDial(t *testing.T) {
	v, m, _, _ := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	quic := &exitStrategy{id: "quic_salamander", priority: 4, t: t, onHandshake: answer(nil)}
	var dials atomic.Int64
	quic.onTarget = func(string) { dials.Add(1) }
	m.Register(quic)

	m.ResetForNetworkChange() // auto mode: QUIC sits out until the UDP verdict lands
	v.tryStrategyUpgrade([]strategy.Strategy{quic})
	if dials.Load() != 0 {
		t.Fatal("a UDP candidate was dialled while UDP is excluded")
	}
}

// stallingConn takes writes until their deadline and then fails them the way
// smux does, as a bufferbloated uplink would.
type stallingConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *stallingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *stallingConn) SetReadDeadline(time.Time) error { return nil }
func (c *stallingConn) Write([]byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	time.Sleep(time.Until(d) + 5*time.Millisecond)
	return 0, errors.New("timeout")
}
func (c *stallingConn) Close() error { return nil }

// TestStalledKeepaliveWriteIsNotServerSilence is a P3 of the round-2 review: a
// keepalive write that runs into its own 5 s deadline says the local uplink is
// stuck (bufferbloat), not that the server went quiet. Taking it for silence
// armed the pool gate and could park a young session's server. Only reads
// speak for the server.
func TestStalledKeepaliveWriteIsNotServerSilence(t *testing.T) {
	oldKA, oldW := keepaliveInterval, keepaliveWriteTimeout
	keepaliveInterval, keepaliveWriteTimeout = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { keepaliveInterval, keepaliveWriteTimeout = oldKA, oldW })

	m := strategy.NewManager()
	m.SetConnectivityChecker(strategy.NewConnectivityChecker("127.0.0.1:1", time.Second, true))
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, conn: &stallingConn{},
		connectedAt: time.Now().Add(-time.Minute), lastRx: time.Now().Add(-time.Minute)}
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	done := make(chan struct{})
	go func() { v.sendKeepalive(); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "VPN disconnected") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(v.stopCh)
	<-done
	if !strings.Contains(out.String(), "VPN disconnected") {
		t.Fatal("the stalled write never ended the session - the test proves nothing")
	}
	if m.PreflightArmed() {
		t.Fatal("a stalled keepalive write was taken for the server's silence")
	}
}

// TestOldExitIsNotUpgradedAgain is a P3 of the round-2 review: an exit older
// than the credential lease answers every upgrade with another address, so
// every reprobe cycle spent a dial and a handshake to learn the same thing.
// After the first such answer the client stops upgrading on that endpoint.
func TestOldExitIsNotUpgradedAgain(t *testing.T) {
	resp := []byte{0x00}
	resp = append(resp, callsiteServerIP.To4()...)
	resp = append(resp, net.IPv4(10, 99, 0, 77).To4()...)
	v, m, _, _ := upgradeOnSelector(t)
	setLog(t, &stampedLog{})
	old := &exitStrategy{id: "reality2", priority: 5, t: t, onHandshake: func(srv net.Conn) { _, _ = srv.Write(resp) }}
	var dials atomic.Int64
	old.onTarget = func(string) { dials.Add(1) }
	m.Register(old)

	v.tryStrategyUpgrade([]strategy.Strategy{old})
	for range 5 { // the reprobes keep finding it reachable
		m.UpdateStrategyConfidence(old.ID(), true)
	}
	v.tryStrategyUpgrade([]strategy.Strategy{old})
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d upgrade dials to an exit that answers with another address, want 1", n)
	}
}
