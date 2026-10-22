package strategy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
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
		{"plain dials", func(id string, prio int) Strategy { return &greetingStrategy{id: id, priority: prio} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swallower := newBlackholeListener(t)
			healthy := newHelloListener(t)
			m := newSilenceManager(t, 2*time.Second, swallower.addr, healthy.addr)
			reality := tc.make("reality", 5)
			m.Register(reality)
			m.Register(tc.make("ws", 6))
			m.Register(tc.make("polling", 7))
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
