package strategy

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
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
// The transport changes, the pool is not walked: c is never dialled. Until
// round 15 each cycle tried one swallowed transport - the swallow verdict on
// a parked a, the same verdict on b set the two transports aside, and the
// next cycle connected WebSocket on b. Under swallow pressure (REALITY
// swallowed on a in the first cycle) the second cycle gives each transport
// its share, and WebSocket connects on a, which never had anything wrong
// with it.
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
	if got := m.GetServerAddr(context.Background()); got != a.addr || cycles != 2 {
		t.Fatalf("connected on %s in cycle %d, want the first server %s in the second", got, cycles, a.addr)
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
		m.lastDeath = deathMark{server: 0, class: deathDegraded, ids: []string{"reality"}, at: time.Now().Add(-tc.age)}
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

// refuseAtGreeter is greetingStrategy refused at the listed addresses, after
// the number of dials there given in after (0: from the first).
type refuseAtGreeter struct {
	greetingStrategy
	at    map[string]bool
	after int
	mu    sync.Mutex
	dials map[string]int
}

func (s *refuseAtGreeter) Connect(ctx context.Context, target string) (net.Conn, error) {
	s.mu.Lock()
	if s.dials == nil {
		s.dials = map[string]int{}
	}
	s.dials[target]++
	n := s.dials[target]
	s.mu.Unlock()
	if s.at[target] && n > s.after {
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
// and b only. Here b refuses everything after REALITY's session there, so the
// next connect walks on to c, and c gets REALITY first, through the fast path.
func TestARouteParkStaysWithTheServersItWasDecidedOn(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	m.Register(&refuseAtGreeter{greetingStrategy: greetingStrategy{id: "reality", priority: 5}, at: map[string]bool{b.addr: true}, after: 1})
	m.Register(&refuseAtGreeter{greetingStrategy: greetingStrategy{id: "polling", priority: 6}, at: map[string]bool{b.addr: true}})

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

// dieOnTheRoute drives sessions through ConnectSession and SessionEnded, each
// ending degraded, until want sessions have ridden; it returns where they
// rode as "strategy@addr".
func dieOnTheRoute(t *testing.T, m *Manager, want int) []string {
	t.Helper()
	var rode []string
	for range want {
		conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
		if err != nil || !ok {
			t.Fatalf("ConnectSession: %v", err)
		}
		conn.Close()
		rode = append(rode, s.ID()+"@"+cand.Addr)
		m.SessionEnded(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true, Degraded: true})
	}
	return rode
}

// TestARouteParkHoldsAgainstAnUpgrade is P2-B of the round-6 review: the
// route verdict set REALITY aside on b, but the reprobe offered it back and
// the upgrade check admitted it - the tunnel went straight back onto the
// transport the route had killed there. REALITY dies on a and on b, the
// client rides Polling on b, and the periodic reprobe there offers nothing;
// once the set-aside has run out, the same reprobe offers REALITY.
func TestARouteParkHoldsAgainstAnUpgrade(t *testing.T) {
	noUpgradeDelay(t)
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	reality := &greetingStrategy{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})

	if rode := dieOnTheRoute(t, m, 2); !slices.Equal(rode, []string{"reality@" + a.addr, "reality@" + b.addr}) {
		t.Fatalf("sessions rode %v - the route was not killed the way the test needs", rode)
	}
	conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
	if err != nil || !ok {
		t.Fatalf("ConnectSession: %v", err)
	}
	conn.Close()
	if s.ID() != "polling" || cand.Addr != b.addr {
		t.Fatalf("the session after the route verdict rode %s@%s, want polling on b", s.ID(), cand.Addr)
	}
	if m.UpgradeEligible(reality, b.addr) {
		t.Fatal("REALITY eligible for an upgrade on b, where the route set it aside")
	}
	if !m.UpgradeEligible(reality, c.addr) {
		t.Fatal("REALITY not eligible on c, where nothing died")
	}

	offers := newUpgradeOffers()
	m.SetStrategyUpgradeCallback(offers.take)
	m.doPeriodicReprobe(context.Background())
	if got := offers.next(t); slices.Contains(got, "reality") {
		t.Fatalf("the reprobe on b offered %v, REALITY included", got)
	}

	// Control: the same reprobe, once the set-aside has run out.
	m.mu.Lock()
	for _, ids := range m.routeParked {
		for id := range ids {
			ids[id] = time.Now().Add(-time.Second)
		}
	}
	m.mu.Unlock()
	m.doPeriodicReprobe(context.Background())
	if got := offers.next(t); !slices.Contains(got, "reality") {
		t.Fatalf("the reprobe on b offered %v once the set-aside ran out - the test proves nothing", got)
	}
}

// TestARescanWithOneTransportLeftChargesTheServer is P2-C of the round-6
// review: after the route verdict on b set three transports aside, the
// rescan had one left, and one timeout never reached the silence threshold
// of three - b was left uncharged, to be dialled again next cycle. A rescan
// whose transports all heard nothing is b's own second verdict, however few
// they were; the same Connect then goes on to c.
func TestARescanWithOneTransportLeftChargesTheServer(t *testing.T) {
	old := rescanPause
	var pauses atomic.Int32
	rescanPause = func() time.Duration { pauses.Add(1); return 10 * time.Millisecond }
	t.Cleanup(func() { rescanPause = old })
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a.addr, b.addr, c.addr)
	// The pre-flight gate runs, as on a client that has never connected.
	m.SetConnectivityChecker(NewConnectivityChecker(a.addr, time.Second, true))
	dead := map[string]bool{a.addr: true, b.addr: true}
	var counters []*targetCounter
	for i, id := range []string{"reality", "polling", "stego", "ws"} {
		c := &targetCounter{Strategy: &swallowAtGreeter{protectedGreeter{id: id, priority: 5 + i}, dead}}
		counters = append(counters, c)
		m.Register(c)
	}

	s, cycles := connectCycles(t, m, 2, 6*time.Second)
	if s == nil {
		t.Fatalf("not connected after %d cycles", cycles)
	}
	// Each transport was dialled once on b: the three in the first scan, the
	// fourth in the rescan, which leaves the three set aside a moment before
	// out - and b, charged by the rescan, was not dialled again in cycle 2.
	for _, c := range counters {
		if n := c.at(b.addr); n != 1 {
			t.Fatalf("%s dialled %d times on b", c.ID(), n)
		}
	}
	if got := m.GetServerAddr(context.Background()); got != c.addr {
		t.Fatalf("connected on %s, want c %s", got, c.addr)
	}
	if st := endpointState(t, m, b.addr); !st.CooldownUntil.After(time.Now()) {
		t.Fatalf("b was not charged for its second silence: %+v", st)
	}
	// P3-7: the rescan waits a moment first, so b does not see two volleys
	// back to back.
	if n := pauses.Load(); n != 1 {
		t.Fatalf("%d pauses drawn for one rescan", n)
	}
	// P3-7: one pre-flight connect on b, before the first scan; the rescan
	// dials the transport left and nothing else.
	dials := int64(0)
	for _, c := range counters {
		dials += int64(c.at(b.addr))
	}
	if extra := b.accepts.Load() - dials; extra != 1 {
		t.Fatalf("%d bare connects on b besides the %d dials, want the one pre-flight", extra, dials)
	}
}

// TestAnIPBlockedServerDoesNotMakeTheNextOneTheRoute is P2-D of the round-6
// review: a is IP-blocked (its SYNs go unanswered), b accepts and swallows
// everything, c is healthy. a's verdict names no transport and must not be
// the "previous death": b's silence is b's own, nothing is set aside, and
// the client reaches c.
func TestAnIPBlockedServerDoesNotMakeTheNextOneTheRoute(t *testing.T) {
	a, b, c := newHelloListener(t).addr, newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a, b.addr, c.addr)
	for i, id := range []string{"reality", "polling", "stego", "ws"} {
		m.Register(&blockedThenSwallowed{Strategy: &protectedGreeter{id: id, priority: 5 + i}, blocked: a, swallowed: b.addr})
	}

	s, cycles := connectCycles(t, m, 3, 6*time.Second)
	if s == nil {
		t.Fatalf("not connected after %d cycles", cycles)
	}
	if got := m.GetServerAddr(context.Background()); got != c.addr {
		t.Fatalf("connected on %s, want c %s", got, c.addr)
	}
	for _, addr := range []string{a, b.addr, c.addr} {
		if skip := m.routeSkip(addr); len(skip) != 0 {
			t.Fatalf("%v set aside on %s after an IP block and a swallow", skip, addr)
		}
	}
}

// blockedThenSwallowed wraps a strategy: SYN-blocked at blocked, swallowed
// at swallowed, the strategy's own behaviour elsewhere.
type blockedThenSwallowed struct {
	Strategy
	blocked, swallowed string
}

func (*blockedThenSwallowed) reportsTCPConnect() {}

func (s *blockedThenSwallowed) Connect(ctx context.Context, target string) (net.Conn, error) {
	switch target {
	case s.blocked:
		stalled := protectedGreeter{id: s.ID(), priority: s.Priority(), stall: true}
		return stalled.Connect(ctx, target)
	case s.swallowed:
		swallowed := protectedGreeter{id: s.ID(), priority: s.Priority(), swallow: true}
		return swallowed.Connect(ctx, target)
	}
	plain := protectedGreeter{id: s.ID(), priority: s.Priority()}
	return plain.Connect(ctx, target)
}

// TestASetAsideTransportIsTriedLastNotSkipped is P2-E of the round-6 review:
// the transports a route verdict set aside were left out while anything else
// was eligible. REALITY dies on a and on b, Polling is refused on both, and
// cycle after cycle failed on Polling - each one charging the servers - while
// REALITY, which connects, was never dialled. It goes last, and connects.
func TestASetAsideTransportIsTriedLastNotSkipped(t *testing.T) {
	a, b := newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	polling := &atomic.Int64{}
	m.Register(&greetingStrategy{id: "polling", priority: 6, refuse: true, tries: polling})

	if rode := dieOnTheRoute(t, m, 2); !slices.Equal(rode, []string{"reality@" + a.addr, "reality@" + b.addr}) {
		t.Fatalf("sessions rode %v - the route was not killed the way the test needs", rode)
	}
	before := polling.Load()
	conn, s, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("the first cycle after the route verdict failed: %v", err)
	}
	conn.Close()
	if s.ID() != "reality" {
		t.Fatalf("connected through %s", s.ID())
	}
	if polling.Load() == before {
		t.Fatal("Polling was not tried before REALITY - nothing was set aside")
	}
}

// TestDifferentTransportsDyingAreNotTheRoute: the same death is the same
// transport. REALITY stalling on a and Polling stalling on b are two servers'
// faults, and b is charged.
func TestDifferentTransportsDyingAreNotTheRoute(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	m.Register(&refuseAtGreeter{greetingStrategy: greetingStrategy{id: "reality", priority: 5}, at: map[string]bool{b.addr: true}})
	m.Register(&greetingStrategy{id: "polling", priority: 6})

	if rode := dieOnTheRoute(t, m, 2); !slices.Equal(rode, []string{"reality@" + a.addr, "polling@" + b.addr}) {
		t.Fatalf("sessions rode %v, want REALITY on a, then Polling on b", rode)
	}
	for _, addr := range []string{a.addr, b.addr} {
		if skip := m.routeSkip(addr); len(skip) != 0 {
			t.Fatalf("%v set aside on %s: two different transports were taken for the route", skip, addr)
		}
	}
	if st := endpointState(t, m, b.addr); !st.CooldownUntil.After(time.Now()) {
		t.Fatalf("b was not charged for its own death: %+v", st)
	}
}

// TestTheRouteMarkNamesTheTransports is the mark's own rule, unit by unit: a
// verdict with no transport does not move it, and the route needs a
// transport that died on both servers.
func TestTheRouteMarkNamesTheTransports(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, time.Second, a.addr, b.addr, c.addr)
	candA, _ := m.selector().CandidateForAddr(a.addr)
	candB, _ := m.selector().CandidateForAddr(b.addr)
	m.routeDeath(candB, deathSilent, "test", nil)
	m.mu.RLock()
	mark := m.lastDeath
	m.mu.RUnlock()
	if mark.server != -1 {
		t.Fatalf("a verdict with no transport moved the mark to %+v", mark)
	}
	if m.routeDeath(candA, deathDegraded, "test", []string{"reality"}) {
		t.Fatal("a first death was the route")
	}
	if m.routeDeath(candB, deathDegraded, "test", []string{"polling"}) {
		t.Fatal("Polling stalling on b after REALITY stalled on a was taken for the route")
	}
	if !m.routeDeath(candA, deathDegraded, "test", []string{"polling", "ws"}) {
		t.Fatal("Polling stalling on a after it stalled on b was not the route")
	}
	if skip := m.routeSkip(a.addr); !skip["polling"] || skip["ws"] {
		t.Fatalf("set aside on a: %v, want polling only - the transport that died on both", skip)
	}
}

// TestForcedModeDoesNotRescan is P3-1 of the round-6 review: in forced mode
// the route verdict still rescanned the server, and the one forced transport
// was dialled twice in a row on it. a and b answer nothing; the forced
// transport's silence on b, after the same on a, is the route - and with
// nothing else to try, the cycle moves on without dialling b again.
func TestForcedModeDoesNotRescan(t *testing.T) {
	old := rescanPause
	rescanPause = func() time.Duration { return 10 * time.Millisecond }
	t.Cleanup(func() { rescanPause = old })
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a.addr, b.addr, c.addr)
	reality := &targetCounter{Strategy: &swallowAtGreeter{protectedGreeter{id: "reality", priority: 5}, map[string]bool{a.addr: true, b.addr: true}}}
	m.Register(reality)
	if err := m.ForceStrategy("reality"); err != nil {
		t.Fatal(err)
	}
	markConnected(m, reality)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
	}
	if n := reality.at(a.addr); n != 1 {
		t.Fatalf("a dialled %d times - the test proves nothing", n)
	}
	if n := reality.at(b.addr); n != 1 {
		t.Fatalf("the forced transport was dialled %d times in a row on b", n)
	}
}

// targetCounter counts a strategy's dials per target.
type targetCounter struct {
	Strategy
	mu sync.Mutex
	n  map[string]int
}

func (*targetCounter) reportsTCPConnect() {}

func (s *targetCounter) Connect(ctx context.Context, target string) (net.Conn, error) {
	s.mu.Lock()
	if s.n == nil {
		s.n = map[string]int{}
	}
	s.n[target]++
	s.mu.Unlock()
	return s.Strategy.Connect(ctx, target)
}

func (s *targetCounter) at(target string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n[target]
}

// TestATransportSetAsideIsReachedWhenTheOthersTimeOut is P2-2 and P3-5 of
// the round-7 review. REALITY died on a and on b and was set aside there;
// it works again, while Polling, Stego and WS now complete TCP on a and b
// and answer nothing. The scan on b gave up after three timeouts, before
// the set-aside transports at the end of the list, and the rescan after the
// route verdict left out every transport set aside on b, REALITY included:
// "no available strategies". The scan reaches REALITY on b and connects.
func TestATransportSetAsideIsReachedWhenTheOthersTimeOut(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a.addr, b.addr, c.addr)
	reality := &targetCounter{Strategy: &protectedGreeter{id: "reality", priority: 5}}
	m.Register(reality)
	dead := map[string]bool{a.addr: true, b.addr: true}
	for i, id := range []string{"polling", "stego", "ws"} {
		m.Register(&swallowAtGreeter{protectedGreeter{id: id, priority: 6 + i}, dead})
	}
	if rode := dieOnTheRoute(t, m, 2); !slices.Equal(rode, []string{"reality@" + a.addr, "reality@" + b.addr}) {
		t.Fatalf("sessions rode %v - the route was not killed the way the test needs", rode)
	}

	s, cycles := connectCycles(t, m, 1, 3*time.Second)
	if s == nil {
		t.Fatalf("no connection in %d cycle", cycles)
	}
	if got := m.GetServerAddr(context.Background()); s.ID() != "reality" || got != b.addr {
		t.Fatalf("connected via %s on %s, want REALITY on b %s", s.ID(), got, b.addr)
	}
}

// TestASwallowedTransportSitsOutThoughTheRouteSetItAside: P3-5 of the
// round-7 review. A transport both set aside by the route and swallowed on
// this server went to the end of the list before the swallow check, and was
// dialled every cycle instead of sitting out its turn. The swallow record is
// planted by hand; the route verdict and the cycle are real.
func TestASwallowedTransportSitsOutThoughTheRouteSetItAside(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, a.addr, b.addr, c.addr)
	reality := &targetCounter{Strategy: &protectedGreeter{id: "reality", priority: 5}}
	m.Register(reality)
	m.Register(&refuseAtGreeter{greetingStrategy: greetingStrategy{id: "polling", priority: 6}, at: map[string]bool{b.addr: true}})
	if rode := dieOnTheRoute(t, m, 2); !slices.Equal(rode, []string{"reality@" + a.addr, "reality@" + b.addr}) {
		t.Fatalf("sessions rode %v - the route was not killed the way the test needs", rode)
	}
	m.noteSwallowed(b.addr, []string{"reality"})
	before := reality.at(b.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
	}
	if n := reality.at(b.addr) - before; n != 0 {
		t.Fatalf("REALITY, swallowed on b, was dialled there %d times", n)
	}
}

// TestAHealthyThirdServerGetsTheBestTransportAfterRouteWideSilence is R2 of
// the fix9 stand run: a and b went silent one after the other - every
// transport connected and heard nothing - and the route rule parked REALITY
// for every server, so the healthy c got HTTP Polling for 5 minutes. Since
// round 10 the set-aside holds on the two servers it was decided on: c gets
// REALITY.
func TestAHealthyThirdServerGetsTheBestTransportAfterRouteWideSilence(t *testing.T) {
	a, b, c := newHelloListener(t), newHelloListener(t), newHelloListener(t)
	m := newSilenceManager(t, 300*time.Millisecond, a.addr, b.addr, c.addr)
	dead := map[string]bool{a.addr: true, b.addr: true}
	for i, id := range []string{"reality", "polling", "stego", "ws"} {
		m.Register(&swallowAtGreeter{protectedGreeter{id: id, priority: 5 + i}, dead})
	}
	s, cycles := connectCycles(t, m, 4, 3*time.Second)
	if s == nil {
		t.Fatalf("not connected after %d cycles", cycles)
	}
	if got := m.GetServerAddr(context.Background()); got != c.addr || s.ID() != "reality" {
		t.Fatalf("connected via %s on %s, want REALITY on c %s", s.ID(), got, c.addr)
	}
}
