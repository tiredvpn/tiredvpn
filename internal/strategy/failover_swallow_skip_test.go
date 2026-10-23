package strategy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestSwallowedTransportsDoNotTakeTurns is P3-10 of the round-3 review of PR
// #126. The cycle after a swallowed handshake left out one transport, the last
// one swallowed: with REALITY and WS both swallowed, cycle 2 skipped REALITY
// and spent itself on WS, cycle 3 skipped WS and spent itself on REALITY, and
// Polling, which works there, was never reached.
func TestSwallowedTransportsDoNotTakeTurns(t *testing.T) {
	addr := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, addr)
	reality := &protectedGreeter{id: "reality", priority: 5, swallow: true}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "ws", priority: 6, swallow: true})
	m.Register(&protectedGreeter{id: "polling", priority: 7})
	markConnected(m, reality)

	for cycle := 1; cycle <= 3; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, s, err := m.Connect(ctx, "")
		cancel()
		if err == nil {
			conn.Close()
			if s.ID() != "polling" {
				t.Fatalf("cycle %d connected via %s", cycle, s.ID())
			}
			if skip := m.swallowSkip(addr); len(skip) != 0 {
				t.Fatalf("a connected cycle left the record behind: %v", skip)
			}
			return
		}
		t.Logf("cycle %d: %v", cycle, err)
	}
	t.Fatal("three cycles and Polling was never reached: the swallowed transports took turns")
}

// TestASwallowedTransportSittingOutIsNotGone: the other half of P3-10. A fast
// path whose dial heard nothing, with the only other transport sitting out its
// turn after a swallowed handshake, is one silent transport, not "the only
// transport there is" - the address must not get the silence verdict for it.
func TestASwallowedTransportSittingOutIsNotGone(t *testing.T) {
	addr := slowHelloListener(t, 0)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, addr, other.addr)
	reality := &protectedGreeter{id: "reality", priority: 5, stall: true}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "ws", priority: 6})
	markConnected(m, reality)
	m.noteSwallowed(addr, []string{"ws"})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := m.Connect(ctx, "")
	if errors.Is(err, errAddrSilent) {
		t.Fatalf("the address got the silence verdict while a transport sat out its turn: %v", err)
	}
	if st := endpointState(t, m, addr); st.CooldownUntil.After(time.Now()) {
		t.Fatalf("parked: %+v", st)
	}
}

// TestTheSkipListOutlivesAPark is P3-16 of the round-4 review: the skip list
// lasted three minutes, the park on the address can last longer (it
// doubles), and a client that came back to the server after the park had
// forgotten which transports it swallows - and spent its first cycle there
// on one of them again.
func TestTheSkipListOutlivesAPark(t *testing.T) {
	addr := slowHelloListener(t, 0)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, addr, other.addr)
	m.Register(&protectedGreeter{id: "reality", priority: 5})
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.noteSwallowed(addr, []string{"reality"})
	key := m.swallowKey(addr)
	m.mu.Lock()
	m.swallowed[key].last = time.Now().Add(-2 * swallowWindow)
	m.mu.Unlock()
	if len(m.swallowSkip(addr)) != 0 {
		t.Fatal("a stale record on an address that is not parked still skips - the test proves nothing")
	}
	cand, _ := m.selector().CandidateForAddr(addr)
	m.selector().ReportSilent(cand)
	if !m.swallowSkip(addr)["reality"] {
		t.Fatal("the skip list was forgotten while its address is still parked")
	}
}

// TestTheSkipListIsThereOnTheReturnAfterALongPark is P2-3 of the round-5
// review: the skip list was kept while the server was parked, but a park of
// more than three minutes (the third server verdict in a row) outlived it,
// and the first cycle back lost itself on the swallowed transport again.
// This drives the return itself: the park is over, the last cycle is five
// minutes old, and the cycle must go straight to the transport that works.
func TestTheSkipListIsThereOnTheReturnAfterALongPark(t *testing.T) {
	a, b := newHelloListener(t), "127.0.0.1:1"
	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{Cooldown: time.Minute}, a.addr, b)
	reality := &swallowAtGreeter{protectedGreeter{id: "reality", priority: 5}, map[string]bool{a.addr: true}}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "ws", priority: 6})
	markConnected(m, reality)
	if err := oneCycle(m); err == nil {
		t.Fatal("the first cycle connected - REALITY was not swallowed")
	}
	if !m.swallowSkip(a.addr)["reality"] {
		t.Fatal("no skip list after the swallowed cycle - the test proves nothing")
	}

	// Three server verdicts in a row: a 4-minute park.
	cand, _ := m.selector().CandidateForAddr(a.addr)
	for range 3 {
		m.selector().ReportSilent(cand)
	}
	park := endpointState(t, m, a.addr).CooldownUntil.Sub(clk.Now())
	if park <= swallowWindow {
		t.Fatalf("park %v is no longer than the skip window - the test proves nothing", park)
	}
	clk.Advance(park + 10*time.Second)
	key := m.swallowKey(a.addr)
	m.mu.Lock()
	m.swallowed[key].last = time.Now().Add(-park - 10*time.Second)
	m.mu.Unlock()

	markConnected(m, reality)
	conn, s, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("the cycle back after the park: %v", err)
	}
	conn.Close()
	if s.ID() != "ws" {
		t.Fatalf("connected through %s", s.ID())
	}
	if n := reality.dials.Load(); n != 1 {
		t.Fatalf("REALITY dialled %d times: the return tried the swallowed transport again", n)
	}

}

// TestTheSwallowRunCrossesACoreRestart: on Android the app restarts the core
// after a failed connect, and a run of two or three swallowed cycles could
// never build up across fresh managers (P1-4 of the round-5 review).
// RouteHistory hands the runs and their skip lists to the next manager, as a
// copy: the old one cannot change them afterwards.
func TestTheSwallowRunCrossesACoreRestart(t *testing.T) {
	addr := slowHelloListener(t, 0)
	other := newHelloListener(t)
	m1 := newSilenceManager(t, 2*time.Second, addr, other.addr)
	m1.Register(&protectedGreeter{id: "reality", priority: 5})
	m1.Register(&protectedGreeter{id: "polling", priority: 6})
	m1.noteSwallowed(addr, []string{"reality"})

	m2 := newSilenceManager(t, 2*time.Second, addr, other.addr)
	m2.Register(&protectedGreeter{id: "reality", priority: 5})
	m2.Register(&protectedGreeter{id: "polling", priority: 6})
	m2.Register(&protectedGreeter{id: "ws", priority: 7})
	m2.AdoptRouteHistory(m1.RouteHistory())
	if !m2.swallowSkip(addr)["reality"] {
		t.Fatal("the next manager does not know which transport the server swallows")
	}
	m1.noteSwallowed(addr, []string{"polling"})
	if m2.swallowSkip(addr)["polling"] {
		t.Fatal("the history is shared with the old manager, not copied")
	}
}

// TestRouteHistoryFollowsServersByAddress is P3-2 of the round-6 review: the
// route memory named servers by their index in the pool, and a pool
// reordered between two cores put a park on the wrong server. It is matched
// by address now.
func TestRouteHistoryFollowsServersByAddress(t *testing.T) {
	a, b := newHelloListener(t), newHelloListener(t)
	m1 := newSilenceManager(t, time.Second, a.addr, b.addr)
	m1.Register(&protectedGreeter{id: "reality", priority: 5})
	m1.Register(&protectedGreeter{id: "polling", priority: 6})
	m1.Register(&protectedGreeter{id: "ws", priority: 7})
	m1.noteSwallowed(a.addr, []string{"reality"})
	m1.mu.Lock()
	m1.routeParked = map[int]map[string]time.Time{0: {"polling": time.Now().Add(time.Minute)}}
	m1.lastDeath = deathMark{server: 0, class: deathDegraded, ids: []string{"polling"}, at: time.Now()}
	m1.mu.Unlock()

	m2 := newSilenceManager(t, time.Second, b.addr, a.addr) // the same two, reordered
	m2.Register(&protectedGreeter{id: "reality", priority: 5})
	m2.Register(&protectedGreeter{id: "polling", priority: 6})
	m2.Register(&protectedGreeter{id: "ws", priority: 7})
	m2.AdoptRouteHistory(m1.RouteHistory())
	if !m2.routeSkip(a.addr)["polling"] || len(m2.routeSkip(b.addr)) != 0 {
		t.Fatalf("route park after the reorder: a %v, b %v - want it on a only", m2.routeSkip(a.addr), m2.routeSkip(b.addr))
	}
	if !m2.swallowSkip(a.addr)["reality"] || len(m2.swallowSkip(b.addr)) != 0 {
		t.Fatalf("swallow skip after the reorder: a %v, b %v", m2.swallowSkip(a.addr), m2.swallowSkip(b.addr))
	}
	m2.mu.RLock()
	mark := m2.lastDeath
	m2.mu.RUnlock()
	if cand, _ := m2.selector().CandidateForAddr(a.addr); mark.server != cand.EndpointIdx {
		t.Fatalf("the route mark points at server %d, want a's %d", mark.server, cand.EndpointIdx)
	}
}

// TestASuccessOnOneFamilyKeepsTheOthersSkipList is P3-6 of the round-6
// review: a connect on v4 deleted the server's whole swallow record, v6's
// skip list with it, and the next return to v6 lost a cycle to the
// swallowed transport again.
func TestASuccessOnOneFamilyKeepsTheOthersSkipList(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 2*time.Second, nil, [2]string{a6.addr, a4.addr})
	m.Register(&protectedGreeter{id: "reality", priority: 5})
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.noteSwallowed(a6.addr, []string{"reality"})
	m.noteSwallowed(a4.addr, []string{"polling"})
	m.clearSwallowed(a4.addr)
	if !m.swallowSkip(a6.addr)["reality"] {
		t.Fatal("a success on v4 wiped v6's skip list")
	}
	if len(m.swallowSkip(a4.addr)) != 0 {
		t.Fatal("a success on v4 kept v4's own skip list")
	}
}

// TestStampsThatCrossACoreRestartAreWallClock is P3-6 of the round-7 review:
// the swallow records and the storm history travel in the Android carry,
// and a phone may sleep between two cores. Stamped on the monotonic clock,
// which stops during the sleep, a run or a storm from before a long doze
// still counted after waking. Both are stamped here through the real paths
// - a swallowed cycle, a session started as the tunnel starts one - and must
// carry no monotonic reading.
func TestStampsThatCrossACoreRestartAreWallClock(t *testing.T) {
	a, b := newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a.addr, b.addr)
	dead := map[string]bool{a.addr: true}
	reality := &swallowAtGreeter{protectedGreeter{id: "reality", priority: 5}, dead}
	m.Register(reality)
	m.Register(&swallowAtGreeter{protectedGreeter{id: "polling", priority: 6}, dead})
	markConnected(m, reality)
	connectCycles(t, m, 1, 500*time.Millisecond)
	m.mu.RLock()
	var stamps []time.Time
	for _, r := range m.swallowed {
		stamps = append(stamps, r.last)
	}
	m.mu.RUnlock()
	if len(stamps) == 0 {
		t.Fatal("no swallow record - the test proves nothing")
	}

	m2 := newSilenceManager(t, time.Second, b.addr)
	m2.Register(&protectedGreeter{id: "reality", priority: 5})
	conn, s, _, ok, err := m2.ConnectSession(context.Background(), "")
	if err != nil || !ok {
		t.Fatalf("ConnectSession: %v", err)
	}
	conn.Close()
	m2.RecordSessionStart(s.ID()) // as the tunnel does once the session is up
	d := m2.StormHistory()
	d.mu.Lock()
	stamps = append(stamps, d.startedAt)
	for _, at := range d.openedAt {
		stamps = append(stamps, at)
	}
	d.mu.Unlock()
	if len(stamps) < 3 {
		t.Fatalf("%d stamps - the session left no trace in the storm history", len(stamps))
	}
	for _, at := range stamps {
		if at != at.Round(0) {
			t.Fatalf("stamp %v carries a monotonic reading, which stops while the phone sleeps", at)
		}
	}
}
