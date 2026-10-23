package strategy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// connectCycles runs up to n reconnect cycles of length cycle and returns the
// conn of the first one that connects, with how many cycles it took.
func connectCycles(t *testing.T, m *Manager, n int, cycle time.Duration) (Strategy, int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), cycle)
		conn, s, err := m.Connect(ctx, "")
		cancel()
		if err == nil {
			conn.Close()
			return s, i
		}
		t.Logf("cycle %d: %v", i, err)
	}
	return nil, n
}

// TestAServerThatSwallowsEveryHandshakeIsLeft is P1-1 of the round-3 review of
// PR #126. Server A completes every TCP connect and then answers nothing; B is
// healthy. Since round 3 a connected handshake keeps the rest of its cycle, so
// each cycle spent itself on one swallowed transport, ended as a bare deadline
// with no verdict, and the next cycle started on A again with the next
// transport: A was never charged and B was never dialled.
func TestAServerThatSwallowsEveryHandshakeIsLeft(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(id string, prio int) Strategy
	}{
		{"protected dials", func(id string, prio int) Strategy { return &protectedGreeter{id: id, priority: prio} }},
		// A transport that does not report its connect never counts as
		// swallowed (swallowEvidence); the reporting ones carry the verdict.
		{"mixed dials", func(id string, prio int) Strategy {
			if id == "ws" {
				return &greetingStrategy{id: id, priority: prio}
			}
			return &protectedGreeter{id: id, priority: prio}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swallower := newBlackholeListener(t)
			healthy := newHelloListener(t)
			m := newSilenceManager(t, 2*time.Second, swallower.addr, healthy.addr)
			reality := tc.make("reality", 5)
			m.Register(reality)
			m.Register(tc.make("polling", 6))
			m.Register(tc.make("ws", 7))
			markConnected(m, reality)

			s, cycles := connectCycles(t, m, 3, time.Second)
			if s == nil {
				t.Fatalf("still not connected after %d cycles; A: %+v", cycles, endpointState(t, m, swallower.addr))
			}
			if got := m.GetServerAddr(context.Background()); got != healthy.addr {
				t.Fatalf("connected through %s, want the healthy server %s", got, healthy.addr)
			}
			if healthy.accepts.Load() == 0 {
				t.Fatal("the healthy server was never dialled")
			}
		})
	}
}

// TestOneSwallowedTransportOnALiveServerParksNothing is the other side: a
// server where only REALITY is swallowed and Polling works is never charged,
// however many cycles it takes.
func TestOneSwallowedTransportOnALiveServerParksNothing(t *testing.T) {
	addr := slowHelloListener(t, 0)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, addr, other.addr)
	reality := &protectedGreeter{id: "reality", priority: 5, swallow: true}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 7})

	for range 4 {
		markConnected(m, reality)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if conn, _, err := m.Connect(ctx, ""); err == nil {
			conn.Close()
		}
		cancel()
		if st := endpointState(t, m, addr); st.CooldownUntil.After(time.Now()) {
			t.Fatalf("a server whose Polling works was parked: %+v", st)
		}
	}
	if got := m.GetServerAddr(context.Background()); got != addr {
		t.Fatalf("moved to %s", got)
	}
}

// TestAForcedTransportSwallowedCycleAfterCycleLeavesTheServer: with one
// transport there is nothing to rotate through, and a server that swallows it
// cycle after cycle is left after swallowCyclesMax of them.
func TestAForcedTransportSwallowedCycleAfterCycleLeavesTheServer(t *testing.T) {
	swallower := newBlackholeListener(t)
	healthy := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, swallower.addr, healthy.addr)
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	markConnected(m, reality)

	s, cycles := connectCycles(t, m, swallowCyclesMax+1, time.Second)
	if s == nil {
		t.Fatalf("still on the swallowing server after %d cycles", cycles)
	}
	if got := m.GetServerAddr(context.Background()); got != healthy.addr {
		t.Fatalf("connected through %s, want %s", got, healthy.addr)
	}
}

// Modes of a modalStrategy.
const (
	modeSwallow int32 = iota // TCP up, then nothing
	modeReject               // the server answers and turns the handshake down
)

// modalStrategy dials through protect.ProtectDialer like the real strategies
// and then behaves as its mode says; a test switches the mode between cycles.
type modalStrategy struct {
	id       string
	priority int
	mode     atomic.Int32
}

func (s *modalStrategy) Name() string                        { return s.id }
func (s *modalStrategy) ID() string                          { return s.id }
func (s *modalStrategy) Priority() int                       { return s.priority }
func (s *modalStrategy) RequiresServer() bool                { return true }
func (s *modalStrategy) Description() string                 { return "switchable" }
func (s *modalStrategy) Probe(context.Context, string) error { return nil }
func (*modalStrategy) reportsTCPConnect()                    {}

func (s *modalStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := (&protect.ProtectDialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if s.mode.Load() == modeReject {
		return nil, errors.New("handshake rejected")
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func oneCycle(m *Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, _, err := m.Connect(ctx, "")
	if err == nil {
		conn.Close()
	}
	return err
}

// TestACycleThatHeardAnAnswerEndsTheRun: a no-verdict cycle in which some
// transport got an answer - a rejection - is an address that talks, and the
// swallowed handshakes around it are a property of those transports.
func TestACycleThatHeardAnAnswerEndsTheRun(t *testing.T) {
	addr := slowHelloListener(t, 0)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, addr, other.addr)
	a := &modalStrategy{id: "a", priority: 5}
	b := &modalStrategy{id: "b", priority: 6}
	c := &modalStrategy{id: "c", priority: 7}
	b.mode.Store(modeReject)
	for _, s := range []Strategy{a, b, c} {
		m.Register(s)
	}
	markConnected(m, a)

	for cycle := 1; cycle <= 2; cycle++ {
		err := oneCycle(m)
		if errors.Is(err, errAddrSilent) {
			t.Fatalf("cycle %d: the silence verdict for an address that answered: %v", cycle, err)
		}
		if st := endpointState(t, m, addr); st.CooldownUntil.After(time.Now()) {
			t.Fatalf("cycle %d: parked: %+v", cycle, st)
		}
	}
}

// TestAVerdictEndsTheRun: a cycle that ends in a verdict on the address (every
// transport tried and answered no) ends the run of no-verdict cycles before
// it; a swallowed handshake after it starts a new one.
func TestAVerdictEndsTheRun(t *testing.T) {
	addr := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, addr)
	a := &modalStrategy{id: "a", priority: 5}
	b := &modalStrategy{id: "b", priority: 6}
	m.Register(a)
	m.Register(b)
	markConnected(m, a)

	if err := oneCycle(m); err == nil || errors.Is(err, errAddrSilent) {
		t.Fatalf("cycle 1 (a swallowed): %v", err)
	}
	b.mode.Store(modeReject)
	if err := oneCycle(m); !errors.Is(err, errStrategyScanFailed) || errors.Is(err, errAddrSilent) {
		t.Fatalf("cycle 2 (b rejected) gave %v, want an ordinary scan failure", err)
	}
	b.mode.Store(modeSwallow)
	if err := oneCycle(m); errors.Is(err, errAddrSilent) {
		t.Fatalf("cycle 3 counted cycle 1 across the verdict between them: %v", err)
	}
	if st := endpointState(t, m, addr); st.CooldownUntil.After(time.Now()) {
		t.Fatalf("parked: %+v", st)
	}
}

// TestAnUnansweredCycleSaysSo is side finding 2 of the degraded-session
// report. With one transport left (forced, or the rest held back) the fast
// path that heard nothing excluded itself and the cycle ended as "no
// available strategies" - read as a circuit-breaker problem, and the
// reconnect backoff doubled to 2 minutes. The cycle now ends with the fast
// path's own failure, marked as unanswered.
func TestAnUnansweredCycleSaysSo(t *testing.T) {
	swallower := newBlackholeListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, swallower.addr, other.addr)
	geneva := &closingStrategy{id: "geneva", priority: 5}
	m.Register(geneva)
	markConnected(m, geneva)

	err := oneCycle(m)
	if err == nil {
		t.Fatal("connected to a server that answers nothing")
	}
	if strings.Contains(err.Error(), "no available strategies") {
		t.Fatalf("the cycle hid the transport's failure: %v", err)
	}
	if !errors.Is(err, ErrCycleUnanswered) {
		t.Fatalf("err = %v, want it marked as unanswered", err)
	}
}

// quicBlackhole is a UDP transport whose datagrams vanish: it reports no
// dial and waits out its attempt.
type quicBlackhole struct{ priority int }

func (q *quicBlackhole) Name() string                        { return "quic_blackhole" }
func (q *quicBlackhole) ID() string                          { return "quic_blackhole" }
func (q *quicBlackhole) Priority() int                       { return q.priority }
func (q *quicBlackhole) RequiresServer() bool                { return true }
func (q *quicBlackhole) Description() string                 { return "UDP into a blackhole" }
func (q *quicBlackhole) Probe(context.Context, string) error { return nil }
func (q *quicBlackhole) Connect(ctx context.Context, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestOnlyRealSwallowsCountTowardTheVerdict is P2-4 of the round-4 review.
// Server A swallows REALITY and serves Polling, slowly (0.6 s); B is healthy;
// UDP is blackholed on the route. QUIC took half of cycle 2 and Polling was cut
// by what was left: both were counted as "heard nothing", A was parked and
// Polling went on its skip list. A UDP blackhole is the route's, and a
// handshake cut by the end of the cycle had no real time to answer: neither
// counts.
func TestOnlyRealSwallowsCountTowardTheVerdict(t *testing.T) {
	a := slowHelloListener(t, 600*time.Millisecond)
	b := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, a, b.addr)
	reality := &protectedGreeter{id: "reality", priority: 3, swallow: true}
	m.Register(reality)
	m.Register(&quicBlackhole{priority: 4})
	m.Register(&protectedGreeter{id: "polling", priority: 7})
	markConnected(m, reality)

	for cycle := 1; cycle <= 3; cycle++ {
		_ = oneCycle(m)
		if st := endpointState(t, m, a); st.CooldownUntil.After(time.Now()) {
			t.Fatalf("cycle %d: a server whose Polling works was parked", cycle)
		}
	}
	if m.swallowSkip(a)["polling"] {
		t.Fatal("Polling, cut by the end of the cycle, went on the skip list")
	}
}

// TestAUDPBlackholeIsTheRoutes: QUIC heard nothing for a whole cycle, but a
// datagram blackhole says the route, not the server. With REALITY swallowed
// the cycle before, counting it made two transports and parked the server.
func TestAUDPBlackholeIsTheRoutes(t *testing.T) {
	a := slowHelloListener(t, 0)
	b := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, a, b.addr)
	reality := &protectedGreeter{id: "reality", priority: 3, swallow: true}
	m.Register(reality)
	m.Register(&quicBlackhole{priority: 4})
	markConnected(m, reality)
	for cycle := 1; cycle <= 2; cycle++ {
		_ = oneCycle(m)
	}
	if st := endpointState(t, m, a); st.CooldownUntil.After(time.Now()) {
		t.Fatal("a UDP blackhole counted as the server swallowing handshakes")
	}
}

// slowConnectSwallower connects only after connectDelay, then hears nothing.
type slowConnectSwallower struct {
	id    string
	delay time.Duration
}

func (s *slowConnectSwallower) Name() string                        { return s.id }
func (s *slowConnectSwallower) ID() string                          { return s.id }
func (s *slowConnectSwallower) Priority() int                       { return 5 }
func (s *slowConnectSwallower) RequiresServer() bool                { return true }
func (s *slowConnectSwallower) Description() string                 { return "slow connect, then nothing" }
func (s *slowConnectSwallower) Probe(context.Context, string) error { return nil }
func (*slowConnectSwallower) reportsTCPConnect()                    {}
func (s *slowConnectSwallower) Connect(ctx context.Context, target string) (net.Conn, error) {
	d := &protect.ProtectDialer{Dialer: &net.Dialer{Control: func(string, string, syscall.RawConn) error {
		time.Sleep(s.delay)
		return nil
	}}}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestTheAllowanceRunsFromTheConnect: what counts is how long the handshake
// had after its TCP connect, not the attempt's whole run. A connect that took
// most of the cycle left a handshake no real time.
func TestTheAllowanceRunsFromTheConnect(t *testing.T) {
	a := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, a)
	m.Register(&slowConnectSwallower{id: "reality", delay: 500 * time.Millisecond})
	scan := &scanState{addr: a}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, _, err := m.connectScan(ctx, a, nil, scan); err == nil {
		conn.Close()
		t.Fatal("connected - the test proves nothing")
	}
	if scan.unheard == 0 {
		t.Fatal("the attempt was not seen as unanswered - the test proves nothing")
	}
	if len(scan.inconclusive) != 0 || len(m.swallowSkip(a)) != 0 {
		t.Fatalf("a handshake with half a second after its connect counted as swallowed: %v, skip %v", scan.inconclusive, m.swallowSkip(a))
	}
}

// TestAHandshakeCutByTheCycleIsNotSkipped: a handshake that had only the end
// of the cycle after its connect does not go on the address's skip list -
// the next cycle would leave out a transport that may well work there.
func TestAHandshakeCutByTheCycleIsNotSkipped(t *testing.T) {
	silent := newBlackholeListener(t)
	a := silent.addr
	m := newSilenceManager(t, 2*time.Second, a)
	geneva := &closingStrategy{id: "geneva", priority: 3}
	m.Register(geneva)
	m.Register(&protectedGreeter{id: "reality", priority: 5, swallow: true})
	m.Register(&protectedGreeter{id: "polling", priority: 7, swallow: true})
	markConnected(m, geneva) // the fast path takes half the cycle
	if err := oneCycle(m); err == nil {
		t.Fatal("connected - the test proves nothing")
	}
	if m.swallowSkip(a)["reality"] {
		t.Fatal("a handshake with half a cycle went on the skip list")
	}
}
