package tun

import (
	"context"
	"fmt"
	"io"
	"net"
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
	old := probeInternet
	probeInternet = func() bool { return true }
	t.Cleanup(func() { probeInternet = old })

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
