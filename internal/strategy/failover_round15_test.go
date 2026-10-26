package strategy

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestTwoSwallowingServersWithRunningOutParksReachTheThird is R1 of the
// fix13c stand (rt3-seq-sw-p1-1, -2): a and b swallow every handshake on
// both families, c is healthy, and the client did not reach c in 6.5
// minutes, both runs. It went a, b, a, b: each server's park ran out while
// the other was being tried, the route rule spared the second server of each
// pair, and the move off a parked server took the first available one in
// preference order - a again - never c. Through Connect, on the selector's
// clock advanced by the stand's cycle, so parks run out as they did there.
func TestTwoSwallowingServersWithRunningOutParksReachTheThird(t *testing.T) {
	a6, a4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	b6, b4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	c6, c4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	clk := newEndpointClock()
	m := dualStackPool(t, 150*time.Millisecond, clk,
		[2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr}, [2]string{c6.addr, c4.addr})
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.Register(&protectedGreeter{id: "stego", priority: 7})
	m.Register(&protectedGreeter{id: "seqovl", priority: 8})
	markConnected(m, reality)

	names := map[string]string{a6.addr: "a6", a4.addr: "a4", b6.addr: "b6", b4.addr: "b4", c6.addr: "c6", c4.addr: "c4"}
	var path []string
	// 26 cycles of 15 s plus backoff is the stand's 6.5 minutes.
	for cycle := 1; cycle <= 26; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		conn, _, err := m.Connect(ctx, "")
		cancel()
		addr := m.GetServerAddr(context.Background())
		path = append(path, names[addr])
		if err == nil {
			conn.Close()
			if addr != c6.addr && addr != c4.addr {
				t.Fatalf("connected on %s: %v", names[addr], path)
			}
			t.Logf("on c in cycle %d: %v", cycle, path)
			if cycle > 14 {
				t.Fatalf("on c only in cycle %d: %v", cycle, path)
			}
			// a, then b, then c, each family of a server tried once before
			// the next server (N9 of the final 1.11.9 acceptance), and no
			// server again once left.
			var servers []byte
			for _, p := range path {
				if len(servers) == 0 || servers[len(servers)-1] != p[0] {
					servers = append(servers, p[0])
				}
			}
			if string(servers) != "abc" || !slices.Contains(path, "a4") || !slices.Contains(path, "b4") {
				t.Fatalf("path %v, want a's two families, b's two, then c", path)
			}
			return
		}
		clk.Advance(15*time.Second + min(time.Duration(cycle)*4*time.Second, 30*time.Second))
	}
	t.Fatalf("not on c after 26 cycles: %v", path)
}

// quietDialer is a transport that does not report its TCP connect and whose
// handshake the route swallows: it dials and waits for an answer that never
// comes, like WebSocket Salamander or Traffic Morph behind a censor dropping
// large ClientHellos.
type quietDialer struct {
	id       string
	priority int
}

func (s *quietDialer) Name() string                        { return s.id }
func (s *quietDialer) ID() string                          { return s.id }
func (s *quietDialer) Priority() int                       { return s.priority }
func (s *quietDialer) RequiresServer() bool                { return true }
func (s *quietDialer) Description() string                 { return "dials, never answered" }
func (s *quietDialer) Probe(context.Context, string) error { return nil }
func (s *quietDialer) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	<-ctx.Done()
	conn.Close()
	return nil, ctx.Err()
}

// TestARouteCuttingLargeClientHellosLetsGenevaInSoon is the ClientHello cut
// of the fix13c stand (r9-rx_hs_ab): a and b drop every TLS record over
// 1500 B, so REALITY, Polling, Stego, Seqovl (which report their TCP
// connect), WebSocket and Morph (which do not) all connect and hear nothing;
// Geneva fragments its ClientHello and gets through. On fix13c Geneva never
// came up in 300 s: a reporting transport whose TCP connect was up kept the
// rest of its cycle, so each cycle tried one transport on one address, and
// the skip lists are per address. Scaled 1:10 - a 1.5 s cycle, a 3 s
// connect timeout - through Connect, the selector's clock advanced by the
// stand's backoff between cycles. Geneva needs 30 ms (300 ms real, a round
// trip and the server) to connect, which is what a cycle halved down the
// list did not leave it.
func TestARouteCuttingLargeClientHellosLetsGenevaInSoon(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	clk := newEndpointClock()
	m := dualStackPool(t, 3*time.Second, clk, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	reality := &protectedGreeter{id: "reality", priority: 5, swallow: true}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6, swallow: true})
	m.Register(&protectedGreeter{id: "stego", priority: 7, swallow: true})
	m.Register(&protectedGreeter{id: "seqovl", priority: 7, swallow: true})
	m.Register(&quietDialer{id: "ws", priority: 8})
	for i := range 4 {
		m.Register(&quietDialer{id: fmt.Sprintf("morph_%d", i), priority: 10})
	}
	m.Register(&slowAnswer{greetingStrategy: greetingStrategy{id: "geneva", priority: 12}, after: 30 * time.Millisecond})
	// What comes after Geneva in the real list: anti-probe and the five
	// Protocol Confusions, cut here too.
	for i := range 6 {
		m.Register(&quietDialer{id: fmt.Sprintf("after_%d", i), priority: 20 + i})
	}
	markConnected(m, reality)

	backoff := time.Second
	var elapsed time.Duration // stand time: 15 s a cycle plus its backoff
	for cycle := 1; cycle <= 12; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		conn, s, err := m.Connect(ctx, "")
		cancel()
		elapsed += 15 * time.Second
		if err == nil {
			conn.Close()
			if s.ID() != "geneva" {
				t.Fatalf("connected via %s", s.ID())
			}
			t.Logf("Geneva in cycle %d, %v of stand time", cycle, elapsed)
			// fix9 took 247 s; the stand's fault window is 300 s. The
			// first cycle has no evidence yet and runs out on REALITY;
			// the second is under pressure.
			if cycle > 2 {
				t.Fatalf("Geneva only in cycle %d, %v of stand time", cycle, elapsed)
			}
			return
		}
		t.Logf("cycle %d on %s: %v", cycle, m.GetServerAddr(context.Background()), err)
		clk.Advance(15*time.Second + backoff)
		elapsed += backoff
		backoff = min(2*backoff, 30*time.Second)
	}
	t.Fatalf("no Geneva after 12 cycles, %v of stand time", elapsed)
}

// slowAnswer is greetingStrategy whose handshake takes after past the
// server's greeting.
type slowAnswer struct {
	greetingStrategy
	after time.Duration
}

func (s *slowAnswer) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := s.greetingStrategy.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	select {
	case <-time.After(s.after):
		return conn, nil
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
}

// TestPressureFromAnotherServerHoldsTheFirstCycleOnTheNext: a takes every
// TCP connect and answers nothing, Geneva included, and gets its silence
// verdict; b cuts large ClientHellos as in the stand. The first cycle on b
// already runs under pressure - a's verdict is evidence about the route -
// so it gives Geneva its turn instead of running out on REALITY.
func TestPressureFromAnotherServerHoldsTheFirstCycleOnTheNext(t *testing.T) {
	a6, a4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 3*time.Second, newEndpointClock(), [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	reality := &protectedGreeter{id: "reality", priority: 5, swallow: true}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6, swallow: true})
	m.Register(&protectedGreeter{id: "stego", priority: 7, swallow: true})
	m.Register(&slowAnswer{greetingStrategy: greetingStrategy{id: "geneva", priority: 12}, after: 30 * time.Millisecond})
	markConnected(m, reality)

	firstOnB := 0
	for cycle := 1; cycle <= 8; cycle++ {
		onB := func() bool { return b6.accepts.Load()+b4.accepts.Load() > 0 }
		before := onB()
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		conn, s, err := m.Connect(ctx, "")
		cancel()
		if !before && onB() {
			firstOnB = cycle
		}
		if err == nil {
			conn.Close()
			if s.ID() != "geneva" || firstOnB == 0 {
				t.Fatalf("connected via %s, first on b in cycle %d", s.ID(), firstOnB)
			}
			if cycle != firstOnB {
				t.Fatalf("Geneva on b in cycle %d, the first cycle on b was %d", cycle, firstOnB)
			}
			return
		}
	}
	t.Fatal("no Geneva in 8 cycles")
}

// TestALoneTransportKeepsItsCycleUnderPressure: another server has just
// had its silence verdict, so b's cycle runs under pressure, and b answers
// the one transport there is slowly, in 60% of the cycle, on the fast path.
// An attempt is held to its share only when other transports come after
// it; a lone one keeps the rest, or it would never connect.
func TestALoneTransportKeepsItsCycleUnderPressure(t *testing.T) {
	a := newBlackholeListener(t)
	b := slowHelloListener(t, 900*time.Millisecond)
	m := newSilenceManager(t, 3*time.Second, a.addr, b)
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	markConnected(m, reality)
	cb, ok := m.selector().CandidateForAddr(b)
	if !ok {
		t.Fatal("no candidate for b")
	}
	m.selector().Pin(cb)
	m.mu.Lock()
	m.lastDeath = deathMark{server: 0, class: deathSwallowed, ids: []string{"reality"}, at: time.Now()}
	m.mu.Unlock()
	if !m.swallowPressure(b) {
		t.Fatal("no pressure on b - the test proves nothing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(context.Background()); s.ID() != "reality" || got != b {
		t.Fatalf("connected via %s on %s, want reality on b %s", s.ID(), got, b)
	}
}

// TestSwallowPressureSources: what puts a cycle under swallow pressure, one
// source at a time, and that forced mode, with one transport, never is.
func TestSwallowPressureSources(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	newPool := func() *Manager {
		m := dualStackPool(t, 3*time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
		m.Register(&greetingStrategy{id: "confusion", priority: 5})
		m.Register(&greetingStrategy{id: "geneva", priority: 6})
		return m
	}
	cand := func(m *Manager, addr string) endpoint.Candidate {
		c, ok := m.selector().CandidateForAddr(addr)
		if !ok {
			t.Fatalf("no candidate %s", addr)
		}
		return c
	}

	m := newPool()
	if m.swallowPressure(a4.addr) {
		t.Fatal("pressure with nothing behind it")
	}
	// A session handshake unanswered on a's v6 is evidence on a's v4.
	_ = m.HandshakeUnanswered(m.strategies[0], cand(m, a6.addr), true)
	if !m.swallowPressure(a4.addr) {
		t.Fatal("no pressure on a's v4 after a mute transport on its v6")
	}
	if m.swallowPressure(b4.addr) {
		t.Fatal("a's mute transport put b under pressure")
	}

	m = newPool()
	m.mu.Lock()
	m.lastDeath = deathMark{server: 0, class: deathSilent, ids: []string{"confusion"}, at: time.Now()}
	m.mu.Unlock()
	if !m.swallowPressure(b4.addr) || m.swallowPressure(a4.addr) {
		t.Fatal("a's silence verdict must put b under pressure, not a itself")
	}
	if err := m.ForceStrategy("confusion"); err != nil {
		t.Fatal(err)
	}
	if m.swallowPressure(b4.addr) {
		t.Fatal("pressure in forced mode")
	}
}

// TestASlowLastGoodTransportKeepsItsCycleUnderPressure: another server has
// just had its silence verdict, on Polling, so b's cycle runs under
// pressure. b is healthy, but slow: REALITY - the transport that worked
// last - is answered in 60% of the cycle (8-9 s of 15 on a bad mobile link
// or a server slow to reach its cover). Held to its share it was cut every
// cycle and the client failed over for nothing. A transport nothing has
// seen swallowed keeps its cycle on the fast path; the slicing is for the
// ones under suspicion.
func TestASlowLastGoodTransportKeepsItsCycleUnderPressure(t *testing.T) {
	a := newBlackholeListener(t)
	b := slowHelloListener(t, 900*time.Millisecond)
	m := newSilenceManager(t, 3*time.Second, a.addr, b)
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.Register(&protectedGreeter{id: "stego", priority: 7})
	markConnected(m, reality)
	cb, ok := m.selector().CandidateForAddr(b)
	if !ok {
		t.Fatal("no candidate for b")
	}
	m.selector().Pin(cb)
	m.mu.Lock()
	m.lastDeath = deathMark{server: 0, class: deathSwallowed, ids: []string{"polling"}, at: time.Now()}
	m.mu.Unlock()
	if !m.swallowPressure(b) {
		t.Fatal("no pressure on b - the test proves nothing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("a slow REALITY on a healthy b was cut under pressure: %v", err)
	}
	conn.Close()
	if s.ID() != "reality" {
		t.Fatalf("connected via %s, want reality", s.ID())
	}
}

// TestASuspectLastGoodTransportIsHeldUnderPressure is the other side: when
// the transport that worked last is the one the previous server's verdict
// named, the fast path gets its share like any other attempt, and the
// transports after it get theirs.
func TestASuspectLastGoodTransportIsHeldUnderPressure(t *testing.T) {
	a := newBlackholeListener(t)
	b := newBlackholeListener(t)
	m := newSilenceManager(t, 3*time.Second, a.addr, b.addr)
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	geneva := &slowAnswer{greetingStrategy: greetingStrategy{id: "geneva", priority: 12}, after: 30 * time.Millisecond}
	m.Register(geneva)
	markConnected(m, reality)
	cb, ok := m.selector().CandidateForAddr(b.addr)
	if !ok {
		t.Fatal("no candidate for b")
	}
	m.selector().Pin(cb)
	m.mu.Lock()
	m.lastDeath = deathMark{server: 0, class: deathSwallowed, ids: []string{"reality"}, at: time.Now()}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _ = m.Connect(ctx, "")
	// b swallows everything, Geneva included; what matters is that REALITY
	// gave the rest of the cycle up.
	if n := b.accepts.Load(); n < 2 {
		t.Fatalf("b accepted %d connections in %v: the suspect REALITY kept the whole cycle", n, time.Since(start).Round(time.Millisecond))
	}
}

// TestSwallowSuspectSources: a transport mute on one address of a server is
// a suspect on its other address; another transport is not.
func TestSwallowSuspectSources(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 3*time.Second, nil, [2]string{a6.addr, a4.addr})
	confusion := &greetingStrategy{id: "confusion", priority: 5}
	m.Register(confusion)
	m.Register(&greetingStrategy{id: "geneva", priority: 6})
	c6, ok := m.selector().CandidateForAddr(a6.addr)
	if !ok {
		t.Fatal("no candidate")
	}
	if m.swallowSuspect(a4.addr, "confusion") {
		t.Fatal("a suspect with nothing behind it")
	}
	_ = m.HandshakeUnanswered(confusion, c6, true)
	if !m.swallowSuspect(a4.addr, "confusion") {
		t.Fatal("a transport mute on a's v6 is no suspect on its v4")
	}
	if m.swallowSuspect(a4.addr, "geneva") {
		t.Fatal("Geneva became a suspect for Confusion's silence")
	}
}
