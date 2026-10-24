package strategy

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestAUsefulV6SessionKeepsV4sDeadSessionPark is P2-1 of the round-8
// review: a useful session on v6 cleared the dead streak of every address
// of the server (N14), and the pool poll took the cleared streak for "not
// parked for dead sessions": v4 answered TCP, as every one of its dying
// sessions had, and its park was lifted at once. Through SessionEnded and
// PinAnswering, the park still in force.
func TestAUsefulV6SessionKeepsV4sDeadSessionPark(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	sel := m.selector()
	c4, _ := sel.CandidateForAddr(a4.addr)
	c6, _ := sel.CandidateForAddr(a6.addr)

	m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c4, HasEndpoint: true, Dead: true})
	if !sel.ParkedForDeadSessions(c4) {
		t.Fatal("a dead session did not park v4 - the test proves nothing")
	}
	m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c6, HasEndpoint: true, Useful: true})

	if m.PinAnswering(a4.addr) {
		t.Fatal("the pool poll lifted v4's dead-session park after a useful session on v6")
	}
	if !sel.IsParked(c4) {
		t.Fatal("v4's dead-session park was lifted")
	}
	if got := m.GetServerAddr(context.Background()); got == a4.addr {
		t.Fatal("pinned v4, parked for dead sessions")
	}
	// The streak itself starts over (N14): the next dead session on v4,
	// once the park has run out, parks it for the base cooldown again.
	for _, st := range sel.Snapshot() {
		if st.Addr == a4.addr && st.DeadStreak != 0 {
			t.Fatalf("v4's dead streak is %d after the useful session, want 0 (N14)", st.DeadStreak)
		}
	}
}

// TestACarriedDeadSessionParkHoldsAgainstThePoolPoll: the park's reason
// travels with the carried health, as the streak did before.
func TestACarriedDeadSessionParkHoldsAgainstThePoolPoll(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	pool := [][2]string{{a6.addr, a4.addr}, {b6.addr, b4.addr}}
	m := dualStackPool(t, time.Second, nil, pool...)
	c4, _ := m.selector().CandidateForAddr(a4.addr)
	m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c4, HasEndpoint: true, Dead: true})

	next := dualStackPool(t, time.Second, nil, pool...)
	next.ImportEndpointHealth(m.EndpointHealth())
	if next.PinAnswering(a4.addr) {
		t.Fatal("the pool poll lifted a carried dead-session park")
	}
}

// TestAServerParkKeepsTheDeadSessionReasonOfItsAddresses: a dead session on
// v4, then one on v6 late in v4's park, parks the server past v4's own park.
// Until the server's park ends, v4 is still parked for dead sessions - it
// was, before the reason had its own field, through the streak.
func TestAServerParkKeepsTheDeadSessionReasonOfItsAddresses(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	clk := newEndpointClock()
	m := dualStackPool(t, time.Second, clk, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	sel := m.selector()
	c4, _ := sel.CandidateForAddr(a4.addr)
	c6, _ := sel.CandidateForAddr(a6.addr)

	m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c4, HasEndpoint: true, Dead: true})
	var ownEnd time.Time
	for _, st := range sel.Snapshot() {
		if st.Addr == a4.addr {
			ownEnd = st.CooldownUntil
		}
	}
	clk.Advance(ownEnd.Sub(clk.Now()) - 10*time.Second)
	m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c6, HasEndpoint: true, Dead: true})
	clk.Advance(20 * time.Second) // past v4's own park, inside the server's
	if !sel.IsParked(c4) {
		t.Fatal("the server's park did not cover v4 - the test proves nothing")
	}
	if m.PinAnswering(a4.addr) {
		t.Fatal("the pool poll lifted v4 inside the server's park for dead sessions")
	}
}

// TestALiftedDeadSessionParkLeavesNoReasonBehind: once the dead-session park
// is over - lifted because the poll heard only this server, or ended by a
// connect that worked - a later park for failed connects is one a TCP answer
// speaks against.
func TestALiftedDeadSessionParkLeavesNoReasonBehind(t *testing.T) {
	for _, lift := range []struct {
		name string
		do   func(m *Manager, c endpoint.Candidate)
	}{
		{"the poll heard only this server", func(m *Manager, c endpoint.Candidate) { m.PinParkedAnswering(c.Addr) }},
		{"a connect worked", func(m *Manager, c endpoint.Candidate) { m.selector().Report(c, true, time.Millisecond) }},
	} {
		t.Run(lift.name, func(t *testing.T) {
			a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
			b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
			m := dualStackPool(t, time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
			sel := m.selector()
			c4, _ := sel.CandidateForAddr(a4.addr)
			m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c4, HasEndpoint: true, Dead: true})
			lift.do(m, c4)
			sel.Report(c4, false, 0)
			sel.Report(c4, false, 0)
			if !sel.IsParked(c4) {
				t.Fatal("two failed connects did not park v4 - the test proves nothing")
			}
			if !m.PinAnswering(a4.addr) {
				t.Fatal("a park for failed connects was taken for one for dead sessions")
			}
		})
	}
}

// TestAMuteTransportIsNoUpgradeOnItsServer is P3-5 of the round-8 review:
// Confusion's session handshake went unanswered on a, Polling connected
// there - and its connect cleared the list that held Confusion, so the
// upgrade offer (and the next scan) went straight back to it. Its next miss
// tears the tunnel down: the request went out.
func TestAMuteTransportIsNoUpgradeOnItsServer(t *testing.T) {
	noUpgradeDelay(t)
	a, b := newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr)
	confusion := &greetingStrategy{id: "confusion", priority: 5}
	m.Register(confusion)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	ca, _ := m.selector().CandidateForAddr(a.addr)
	m.HandshakeUnanswered(confusion, ca, true)

	conn, s, cand, _, err := m.ConnectSession(context.Background(), "")
	if err != nil {
		t.Fatalf("ConnectSession: %v", err)
	}
	conn.Close()
	if s.ID() != "polling" || cand.Addr != a.addr {
		t.Fatalf("the session rode %s@%s, want polling on a", s.ID(), cand.Addr)
	}
	m.HandshakeAnswered(s, cand, true)
	if m.UpgradeEligible(confusion, a.addr) {
		t.Fatal("Confusion eligible for an upgrade on a, where its session handshake went unanswered")
	}
	offers := newUpgradeOffers()
	m.SetStrategyUpgradeCallback(offers.take)
	m.doPeriodicReprobe(context.Background())
	if got := offers.next(t); slices.Contains(got, "confusion") {
		t.Fatalf("the reprobe on a offered %v, Confusion included", got)
	}

	// Control: Confusion answered on a is a candidate again.
	m.HandshakeAnswered(confusion, ca, true)
	if !m.UpgradeEligible(confusion, a.addr) {
		t.Fatal("Confusion still set aside on a after it was answered there - the test proves nothing")
	}
}

// TestAMuteTransportCrossesACoreRestart: what is mute on a server goes
// with the route history to the next core.
func TestAMuteTransportCrossesACoreRestart(t *testing.T) {
	a, b := newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr)
	confusion := &greetingStrategy{id: "confusion", priority: 5}
	m.Register(confusion)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	ca, _ := m.selector().CandidateForAddr(a.addr)
	m.HandshakeUnanswered(confusion, ca, true)
	conn, _, _, _, err := m.ConnectSession(context.Background(), "")
	if err != nil {
		t.Fatalf("ConnectSession: %v", err)
	}
	conn.Close()

	next := newSilenceManager(t, time.Second, a.addr, b.addr)
	next.Register(confusion)
	next.Register(&greetingStrategy{id: "polling", priority: 6})
	next.AdoptRouteHistory(m.RouteHistory())
	if next.UpgradeEligible(confusion, a.addr) {
		t.Fatal("the next core forgot that Confusion is mute on a")
	}
}
