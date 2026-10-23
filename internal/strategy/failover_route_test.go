package strategy

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

// P2-7 of the round-4 review and P3-7 of round 3: a censor that kills one
// transport on every exit is the route, not the servers. The client used to
// walk the pool on it - or, for stall verdicts, never change the transport at
// all. Two same deaths on two different servers now park the transport, and
// the client tries another one on the second server; the third is not
// touched with the dead transport.

// TestARouteWideDeathChangesTheTransportAfterTwoServers: REALITY's sessions
// die the same way on every server of a three-server dual-stack pool. They
// die on a's two families (one server), then on b; the client then rides
// Stego on b, and c never sees REALITY - nor anything else.
func TestARouteWideDeathChangesTheTransportAfterTwoServers(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(SessionEnd) SessionEnd
	}{
		{"dead session", func(e SessionEnd) SessionEnd { e.Dead = true; return e }},
		{"degraded", func(e SessionEnd) SessionEnd { e.Degraded = true; return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var servers [3][2]*helloListener
			var addrs [3][2]string
			for i := range servers {
				servers[i] = [2]*helloListener{newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)}
				addrs[i] = [2]string{servers[i][0].addr, servers[i][1].addr}
			}
			clk := newEndpointClock()
			m := dualStackPool(t, time.Second, clk, addrs[0], addrs[1], addrs[2])
			realitySeen, stegoSeen := &targetLog{}, &targetLog{}
			m.Register(&greetingStrategy{id: "reality", priority: 5, seen: realitySeen})
			m.Register(&greetingStrategy{id: "stego", priority: 6, seen: stegoSeen})

			var rode []string
			for range 6 {
				conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
				if err != nil || !ok {
					t.Fatalf("ConnectSession: %v", err)
				}
				conn.Close()
				rode = append(rode, s.ID()+"@"+cand.Addr)
				if s.ID() != "reality" {
					break
				}
				clk.Advance(45 * time.Second)
				m.SessionEnded(tc.end(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true}))
				if len(rode) == 3 {
					// Set aside where it died - a and b - and nowhere else.
					for i, want := range []bool{true, true, false} {
						if got := m.routeSkip(addrs[i][0])["reality"]; got != want {
							t.Fatalf("server %d: REALITY set aside %v, want %v", i, got, want)
						}
					}
				}
			}
			want := []string{"reality@" + addrs[0][0], "reality@" + addrs[0][1], "reality@" + addrs[1][0], "stego@" + addrs[1][0]}
			if !slices.Equal(rode, want) {
				t.Fatalf("sessions rode %v, want %v", rode, want)
			}
			for _, l := range servers[2] {
				if n := l.accepts.Load(); n != 0 {
					t.Fatalf("the third server was dialled %d times", n)
				}
			}
			if slices.Contains(realitySeen.since(0), addrs[2][0]) || slices.Contains(realitySeen.since(0), addrs[2][1]) {
				t.Fatal("REALITY was tried on the third server")
			}
			if st := endpointState(t, m, addrs[1][0]); st.CooldownUntil.After(clk.Now()) {
				t.Fatalf("the second server was parked for the route's death: %+v", st)
			}
		})
	}
}

// TestDifferentDeathsAreNotTheRoute: a stall on one server and a dead
// session on the next are two servers' faults; the second is charged.
func TestDifferentDeathsAreNotTheRoute(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	ends := []func(SessionEnd) SessionEnd{
		func(e SessionEnd) SessionEnd { e.Degraded = true; return e },
		func(e SessionEnd) SessionEnd { e.Dead = true; return e },
	}
	var rode []string
	for _, end := range ends {
		conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
		if err != nil || !ok {
			t.Fatalf("ConnectSession: %v", err)
		}
		conn.Close()
		rode = append(rode, cand.Addr)
		m.SessionEnded(end(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true}))
	}
	if !slices.Equal(rode, []string{a.addr, b.addr}) {
		t.Fatalf("sessions rode %v", rode)
	}
	if st := endpointState(t, m, b.addr); !st.CooldownUntil.After(time.Now()) {
		t.Fatalf("a dead session after a stall elsewhere did not charge its server: %+v", st)
	}
}

// TestRouteWideSwallowingChangesTheTransportOnTheSecondServer: REALITY and
// Polling handshakes are swallowed on every server, WebSocket gets through.
// The swallow verdict on a parks a; the same verdict on b parks the two
// transports instead, and the next cycle connects WebSocket on b. c is never
// dialled.
func TestRouteWideSwallowingChangesTheTransportOnTheSecondServer(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, a.addr, b.addr, c.addr)
	reality := &protectedGreeter{id: "reality", priority: 5, swallow: true}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6, swallow: true})
	m.Register(&protectedGreeter{id: "ws", priority: 7})
	markConnected(m, reality)

	s, cycles := connectCycles(t, m, 6, time.Second)
	if s == nil || s.ID() != "ws" {
		t.Fatalf("after %d cycles: connected through %v, want ws", cycles, s)
	}
	if got := m.GetServerAddr(context.Background()); got != b.addr {
		t.Fatalf("connected on %s, want the second server %s", got, b.addr)
	}
	if n := c.accepts.Load(); n != 0 {
		t.Fatalf("the third server was dialled %d times", n)
	}
}

// TestRouteWideSilenceChangesTheTransportOnTheSecondServer: REALITY, Polling
// and Stego connect and then hear nothing for their whole connect timeout on
// every server - the silence verdict, three transports on the desktop - and
// WebSocket gets through. a is parked; on b the same silence parks the three
// transports, and the next cycle connects WebSocket there. c is never dialled.
func TestRouteWideSilenceChangesTheTransportOnTheSecondServer(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 500*time.Millisecond, a.addr, b.addr, c.addr)
	m.Register(&protectedGreeter{id: "reality", priority: 5, swallow: true})
	m.Register(&protectedGreeter{id: "polling", priority: 6, swallow: true})
	m.Register(&protectedGreeter{id: "stego", priority: 7, swallow: true})
	m.Register(&protectedGreeter{id: "ws", priority: 8})

	s, cycles := connectCycles(t, m, 3, 4*time.Second)
	if s == nil || s.ID() != "ws" {
		t.Fatalf("after %d cycles: connected through %v, want ws", cycles, s)
	}
	if got := m.GetServerAddr(context.Background()); got != b.addr {
		t.Fatalf("connected on %s, want the second server %s", got, b.addr)
	}
	if n := c.accepts.Load(); n != 0 {
		t.Fatalf("the third server was dialled %d times", n)
	}
}

// synBlockedGreeter is protectedGreeter on a network where the listed
// addresses are IP-blocked: the SYN goes out and nothing ever comes back, for
// every transport alike.
type synBlockedGreeter struct {
	protectedGreeter
	blocked map[string]bool
}

func (s *synBlockedGreeter) Connect(ctx context.Context, target string) (net.Conn, error) {
	if s.blocked[target] {
		stalled := protectedGreeter{id: s.id, priority: s.priority, stall: true}
		return stalled.Connect(ctx, target)
	}
	return s.protectedGreeter.Connect(ctx, target)
}

// TestAnIPBlockedServerIsNotTheRoute is P1-2 of the round-5 review: a and b
// never answer a SYN - an IP block, the TSPU's commonest action - and c is
// healthy. Every transport dials the same host:port, so a SYN nobody answers
// says nothing about the transports: the client must reach c on REALITY with
// nothing parked, not on the fourth transport after parking three.
func TestAnIPBlockedServerIsNotTheRoute(t *testing.T) {
	// a and b listen, so the family probe - a plain dial outside the
	// strategies - finds them up; only the strategies' SYNs are blocked.
	a, b, c := newHelloListener(t).addr, newHelloListener(t).addr, newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a, b, c.addr)
	blocked := map[string]bool{a: true, b: true}
	for i, id := range []string{"reality", "polling", "stego", "ws"} {
		s := &synBlockedGreeter{protectedGreeter: protectedGreeter{id: id, priority: 5 + i}, blocked: blocked}
		m.Register(s)
		if id == "reality" {
			markConnected(m, s) // the fast path's attempt counts like the scan's
		}
	}

	s, cycles := connectCycles(t, m, 3, 3*time.Second)
	if s == nil {
		t.Fatalf("not connected after %d cycles", cycles)
	}
	if got := m.GetServerAddr(context.Background()); got != c.addr {
		t.Fatalf("connected on %s, want %s", got, c.addr)
	}
	if s.ID() != "reality" {
		t.Fatalf("connected through %s: an IP block parked the transports that work", s.ID())
	}
	for _, addr := range []string{a, b, c.addr} {
		if skip := m.routeSkip(addr); len(skip) != 0 {
			t.Fatalf("%v set aside on %s for the route", skip, addr)
		}
	}
}

// TestAnOldDeathIsNotTheRoute: the route marker now outlives an Android core
// restart, so it carries a time. A death on another server more than
// routeDeathWindow ago is no evidence about the route now: the second death
// charges its server.
func TestAnOldDeathIsNotTheRoute(t *testing.T) {
	a, b := newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	candB, _ := m.selector().CandidateForAddr(b.addr)
	for _, tc := range []struct {
		age   time.Duration
		route bool
	}{
		{time.Minute, true},
		{routeDeathWindow + time.Minute, false},
	} {
		m.mu.Lock()
		m.lastDeath = deathMark{server: 0, class: deathDegraded, at: time.Now().Add(-tc.age)}
		m.mu.Unlock()
		if got := m.routeDeath(candB, deathDegraded, "test", []string{"reality"}); got != tc.route {
			t.Fatalf("a death on a %v ago: route=%v, want %v", tc.age, got, tc.route)
		}
	}
	m.mu.RLock()
	at := m.lastDeath.at
	m.mu.RUnlock()
	if at != at.Round(0) {
		t.Fatal("the route mark is stamped with a monotonic clock, which stops while a phone sleeps")
	}
}

// refuseAtGreeter is greetingStrategy refused at the listed addresses.
type refuseAtGreeter struct {
	greetingStrategy
	at map[string]bool
}

func (s *refuseAtGreeter) Connect(ctx context.Context, target string) (net.Conn, error) {
	if s.at[target] {
		if s.seen != nil {
			s.seen.add(target)
		}
		return nil, errors.New("connection refused by peer")
	}
	return s.greetingStrategy.Connect(ctx, target)
}

// TestARouteParkStaysWithTheServersItWasDecidedOn is P2-2 of the round-5
// review: the route verdict parked the transport on every server for five
// minutes and dropped it from the fast path, so when a and b died on REALITY
// and c was healthy, c was dialled on Polling. Now REALITY is set aside on a
// and b only. Here Polling is refused on b, so the next connect walks on to c,
// and c gets REALITY first, through the fast path.
func TestARouteParkStaysWithTheServersItWasDecidedOn(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	seen := &targetLog{}
	m.Register(&greetingStrategy{id: "reality", priority: 5, seen: seen})
	m.Register(&refuseAtGreeter{greetingStrategy{id: "polling", priority: 6}, map[string]bool{b.addr: true}})

	var rode []string
	for range 3 {
		conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
		if err != nil || !ok {
			t.Fatalf("ConnectSession: %v", err)
		}
		conn.Close()
		rode = append(rode, s.ID()+"@"+cand.Addr)
		if cand.Addr == c.addr {
			break
		}
		m.SessionEnded(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true, Degraded: true})
	}
	want := []string{"reality@" + a.addr, "reality@" + b.addr, "reality@" + c.addr}
	if !slices.Equal(rode, want) {
		t.Fatalf("sessions rode %v, want %v", rode, want)
	}
}

// TestARouteParkRunsOut: the transports a route verdict set aside come back
// on those servers after stormCooldown.
func TestARouteParkRunsOut(t *testing.T) {
	a, b := newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	m.mu.Lock()
	m.routeParked = map[int]map[string]time.Time{0: {"reality": time.Now().Add(time.Minute), "polling": time.Now().Add(-time.Second)}}
	m.mu.Unlock()
	skip := m.routeSkip(a.addr)
	if !skip["reality"] || skip["polling"] {
		t.Fatalf("set aside on a: %v, want reality only", skip)
	}
	if len(m.routeSkip(b.addr)) != 0 {
		t.Fatal("b has nothing set aside")
	}
}

// TestARouteParkHoldsAgainstAnUpgrade is P2-B of the round-6 review: the
// route verdict set REALITY aside on b, but the reprobe offered it back and
// the upgrade check admitted it - the tunnel went straight back onto the
// transport the route had killed there. Neither the offer nor the dial's
// check admits it on b; on c, where nothing died, both do.
func TestARouteParkHoldsAgainstAnUpgrade(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	reality := &greetingStrategy{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	m.mu.Lock()
	m.routeParked = map[int]map[string]time.Time{0: {"reality": time.Now().Add(time.Minute)}, 1: {"reality": time.Now().Add(time.Minute)}}
	m.mu.Unlock()

	if m.UpgradeEligible(reality, b.addr) {
		t.Fatal("REALITY eligible for an upgrade on b, where the route set it aside")
	}
	if !m.UpgradeEligible(reality, c.addr) {
		t.Fatal("REALITY not eligible on c, where nothing died")
	}

	noUpgradeDelay(t)
	offer := func(pin string) bool {
		cand, _ := m.selector().CandidateForAddr(pin)
		m.selector().Pin(cand)
		offers := newUpgradeOffers()
		m.SetStrategyUpgradeCallback(offers.take)
		m.offerUpgrade([]Result{{Strategy: reality, Success: true}})
		select {
		case <-offers.got:
			return true
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
	if offer(b.addr) {
		t.Fatal("the reprobe on b offered REALITY back")
	}
	if !offer(c.addr) {
		t.Fatal("the reprobe on c did not offer REALITY - the test proves nothing")
	}
}
