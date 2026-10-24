package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// poolManager is a manager over n listening loopback endpoints (so the family
// probe passes) with one in-memory strategy, failure threshold 2, cooldown 1m.
func poolManager(t *testing.T, n int) (*strategy.Manager, []string, *pipeStrategy) {
	t.Helper()
	m := strategy.NewManager()
	var eps []endpoint.Endpoint
	var addrs []string
	for i := range n {
		a := newNetcheckListener(t).addr
		addrs = append(addrs, a)
		eps = append(eps, endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: a, Order: i})
	}
	if err := m.SetEndpointSelection(endpoint.Config{Endpoints: eps, Family: endpoint.V4Only, FailureThreshold: 2,
		Cooldown: time.Minute, MaxCooldown: 30 * time.Minute}); err != nil {
		t.Fatalf("SetEndpointSelection: %v", err)
	}
	ps := &pipeStrategy{t: t, resp: bareV3Response()}
	m.Register(ps)
	return m, addrs, ps
}

// connectAndEnd brings a session up through the client's own connect path and
// ends it with readErr, as if it had connected at connectedAt and last heard
// from the server at lastRx. It returns the endpoint the session rode.
func connectAndEnd(t *testing.T, m *strategy.Manager, readErr error, connectedAt, lastRx time.Time) string {
	t.Helper()
	v := newCallsiteClient(m)
	v.running = 1
	v.stopCh = make(chan struct{})
	if err := v.connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	rode := m.GetServerAddr(context.Background())
	v.mu.Lock()
	v.conn = &failingConn{err: readErr}
	v.connectedAt, v.lastRx = connectedAt, lastRx
	v.mu.Unlock()

	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)
	done := make(chan struct{})
	go func() { v.readFromServer(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("read loop did not return; log:\n%s", out)
	}
	return rode
}

func setLog(t *testing.T, w io.Writer) {
	t.Helper()
	logSetOutput(w)
	t.Cleanup(func() { logSetOutput(os.Stderr) })
}

func cooldownLeft(t *testing.T, m *strategy.Manager, addr string) time.Duration {
	t.Helper()
	for _, st := range m.EndpointStates() {
		if st.Addr == addr {
			return time.Until(st.CooldownUntil)
		}
	}
	t.Fatalf("no candidate %s", addr)
	return 0
}

var silenceErr = &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}

// TestDeadSessionNotChargedWhenTheLinkIsDown is P1-6 of the PR #126 review: a
// session that died in silence right after connecting because the client's own
// link dropped parked the server it had just reached - D7's bug class, on the
// session path. The local network is asked first.
func TestDeadSessionNotChargedWhenTheLinkIsDown(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return false }
	t.Cleanup(func() { probeLocalLink = old })

	m, _, _ := poolManager(t, 2)
	now := time.Now()
	rode := connectAndEnd(t, m, silenceErr, now.Add(-31*time.Second), now.Add(-30*time.Second))
	if left := cooldownLeft(t, m, rode); left > 0 {
		t.Fatalf("the server was parked for %v for a session the client's own link killed", left)
	}
}

// TestDeadSessionsEscalateUntilAUsefulSession: every dead session followed a
// successful connect, which cleared the backoff, so each park was the base
// minute and a route-wide freeze walked the pool every half minute. The dead
// streak now grows the park until a useful session clears it.
func TestDeadSessionsEscalateUntilAUsefulSession(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = old })

	m, addrs, _ := poolManager(t, 1)
	now := time.Now()
	connectAndEnd(t, m, silenceErr, now.Add(-31*time.Second), now.Add(-30*time.Second))
	first := cooldownLeft(t, m, addrs[0])
	connectAndEnd(t, m, silenceErr, time.Now().Add(-31*time.Second), time.Now().Add(-30*time.Second))
	second := cooldownLeft(t, m, addrs[0])
	if first <= 0 || second <= first {
		t.Fatalf("parks %v then %v: the second dead session in a row did not park longer", first, second)
	}

	// A useful session ends the streak: the next dead one is back to the base.
	connectAndEnd(t, m, silenceErr, time.Now().Add(-10*time.Minute), time.Now().Add(-31*time.Second))
	connectAndEnd(t, m, silenceErr, time.Now().Add(-31*time.Second), time.Now().Add(-30*time.Second))
	if again := cooldownLeft(t, m, addrs[0]); again > 75*time.Second {
		t.Fatalf("after a useful session the next dead one parked for %v, want the base minute", again)
	}
}

// TestDeathOnTwoServersIsTheRoute: when a session dies the same way on a second
// server right after the first, the cause is the route, not the servers.
// Parking both would walk the client through the whole pool, listing it for an
// observer; the second server is left alone and the storm detector works on
// the strategies.
func TestDeathOnTwoServersIsTheRoute(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = old })

	m, addrs, _ := poolManager(t, 2)
	now := time.Now()
	a := connectAndEnd(t, m, silenceErr, now.Add(-31*time.Second), now.Add(-30*time.Second))
	if a != addrs[0] || cooldownLeft(t, m, a) <= 0 {
		t.Fatalf("first dead session on %s did not park it - the test proves nothing", a)
	}
	b := connectAndEnd(t, m, silenceErr, time.Now().Add(-31*time.Second), time.Now().Add(-30*time.Second))
	if b != addrs[1] {
		t.Fatalf("second session rode %s, want %s", b, addrs[1])
	}
	if left := cooldownLeft(t, m, b); left > 0 {
		t.Fatalf("the second server was parked for %v after the same death on the first one", left)
	}
}

// TestDeadSessionLineHasMargin is N3: HTTP Polling's dead sessions end 19.8-19.9
// s after connecting by the downlink clock (its keepalive feeder runs for the
// poll grace of 20 s), right on the old 20 s line - one of three slipped
// through as useful at 29.9 s. The endpoint verdict line is split from the
// strategy one and sits clear of the measured spread.
func TestDeadSessionLineHasMargin(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = old })

	polling := fmt.Errorf("http_polling: no successful poll within the health grace: %w", strategy.ErrServerSilent)
	for _, tc := range []struct {
		rxAlive time.Duration
		parked  bool
	}{
		{19830 * time.Millisecond, true},
		{19940 * time.Millisecond, true},
		{29860 * time.Millisecond, true},
		{2 * time.Minute, false},
	} {
		t.Run(tc.rxAlive.String(), func(t *testing.T) {
			m, _, _ := poolManager(t, 2)
			now := time.Now()
			rode := connectAndEnd(t, m, polling, now.Add(-tc.rxAlive-20*time.Second), now.Add(-20*time.Second))
			if parked := cooldownLeft(t, m, rode) > 0; parked != tc.parked {
				t.Fatalf("downlink alive %v: parked=%v, want %v", tc.rxAlive, parked, tc.parked)
			}
		})
	}
}

func logSetOutput(w io.Writer) { log.SetOutput(w) }

// TestUsefulSessionEndsTheRouteVerdict: the "same death on two servers is the
// route" rule holds only for deaths in a row. A useful session in between means
// the route carried traffic, and the next server to kill a session young is
// charged again.
func TestUsefulSessionEndsTheRouteVerdict(t *testing.T) {
	old := probeLocalLink
	probeLocalLink = func() bool { return true }
	t.Cleanup(func() { probeLocalLink = old })

	m, addrs, _ := poolManager(t, 2)
	now := time.Now()
	connectAndEnd(t, m, silenceErr, now.Add(-31*time.Second), now.Add(-30*time.Second)) // parks the first
	b := connectAndEnd(t, m, silenceErr, time.Now().Add(-10*time.Minute), time.Now().Add(-31*time.Second))
	if b != addrs[1] {
		t.Fatalf("useful session rode %s, want %s", b, addrs[1])
	}
	b = connectAndEnd(t, m, silenceErr, time.Now().Add(-31*time.Second), time.Now().Add(-30*time.Second))
	if b != addrs[1] || cooldownLeft(t, m, b) <= 0 {
		t.Fatalf("after a useful session on %s its dead session was not charged", b)
	}
}
