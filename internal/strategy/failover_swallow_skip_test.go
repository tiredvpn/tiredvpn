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
