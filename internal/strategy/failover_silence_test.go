package strategy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// newSilenceManager is a desktop-shaped manager over a pool of addresses: the
// selector the client builds, the desktop silence threshold, short timeouts.
// The first address is pinned and counts as the one the tunnel was riding.
func newSilenceManager(t *testing.T, connectTimeout time.Duration, addrs ...string) *Manager {
	t.Helper()
	eps := make([]endpoint.Endpoint, len(addrs))
	for i, a := range addrs {
		eps[i] = endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: a, Order: i}
	}
	sel, err := endpoint.NewTunedSelector(eps, endpoint.Tuning{FailureThreshold: 2, Cooldown: time.Minute}, endpoint.V4Only)
	if err != nil {
		t.Fatalf("NewTunedSelector: %v", err)
	}
	m := NewManager()
	m.endpoints = sel
	m.maxRetries = 1
	m.connectTimeout = connectTimeout
	m.probeTimeout = connectTimeout
	return m
}

// markConnected puts the manager where it is after a tunnel came up through s:
// the fast path armed, the pre-flight gate on its hot-path skip.
func markConnected(m *Manager, s Strategy) {
	m.mu.Lock()
	m.lastSuccessfulStrategy = s
	m.lastSuccessfulTime = time.Now()
	m.mu.Unlock()
}

// gateDialer stands in for the network under the pre-flight gate: the listed
// addresses swallow the SYN and the dial times out, the rest are dialled for
// real.
func gateDialer(silent ...string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		for _, s := range silent {
			if addr == s {
				select {
				case <-time.After(50 * time.Millisecond):
				case <-ctx.Done():
				}
				return nil, &net.OpError{Op: "dial", Net: network, Err: os.ErrDeadlineExceeded}
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

// TestSilentServerSendsTheFirstReconnectThroughTheGate is D1 of the 2026-10-21
// stand report. The tunnel to the first server died of silence; the second
// server is alive. The reconnect cycle has 15 seconds, one fast-path attempt at
// the silent address eats all of them, and the gate - which would have found the
// live server in one walk - was only allowed to run after two such cycles had
// failed. 72 seconds of outage for a dead server.
//
// The budget here is shorter than one attempt at the silent address, so the
// only way to come back connected in a single Connect is for the gate to run
// first and move the pin.
func TestSilentServerSendsTheFirstReconnectThroughTheGate(t *testing.T) {
	silent := newBlackholeListener(t)
	live := newHelloListener(t)

	m := newSilenceManager(t, time.Second, silent.addr, live.addr)
	s := &greetingStrategy{id: "s0", priority: 1}
	m.Register(s)

	checker := NewConnectivityChecker(silent.addr, 500*time.Millisecond, true)
	checker.auxTimeout = 50 * time.Millisecond
	checker.auxGrace = 50 * time.Millisecond
	checker.tcpDial = gateDialer(silent.addr)
	m.SetConnectivityChecker(checker)

	markConnected(m, s)
	m.NoteServerSilent()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("the first reconnect after a silent disconnect did not reach the live server: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(context.Background()); got != live.addr {
		t.Fatalf("pinned %s, want the live server %s", got, live.addr)
	}
	if m.PreflightArmed() {
		t.Fatal("the gate ran but the flag is still set: every later reconnect would pay for a gate walk")
	}
}

// TestHotReconnectStillSkipsTheGate is the other side: without a silence the
// hot path must not start paying for gate walks. A server that reset us is back
// in a moment and the real dial reaches it first.
func TestHotReconnectStillSkipsTheGate(t *testing.T) {
	live := newHelloListener(t)
	other := newHelloListener(t)

	m := newSilenceManager(t, time.Second, live.addr, other.addr)
	s := &greetingStrategy{id: "s0", priority: 1}
	m.Register(s)

	var gateDials int
	checker := NewConnectivityChecker(live.addr, 500*time.Millisecond, true)
	checker.auxTimeout = 50 * time.Millisecond
	checker.auxGrace = 50 * time.Millisecond
	checker.tcpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		gateDials++
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	m.SetConnectivityChecker(checker)
	markConnected(m, s)

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()
	if gateDials != 0 {
		t.Fatalf("the gate dialled %d times on a hot reconnect nobody armed", gateDials)
	}
}

// TestDeadlineOnASilentAddressParksIt: when the gate is not there to help (or
// passes because the port still completes a handshake), the cycle's own budget
// runs out on an address that answered nothing. That is the silence verdict
// reached the slow way. v1.11.8 returned a bare "context deadline exceeded",
// dialEndpoints broke out without a word to the selector, and the next cycle
// dialled the same address.
func TestDeadlineOnASilentAddressParksIt(t *testing.T) {
	// SYNs unanswered: the TCP connect itself never completes. (An address that
	// completes the handshake and then says nothing is not a verdict when the
	// cycle is short - see TestDesktopRetriesAreNotTwoSilentTransports.)
	silent := struct{ addr string }{silentTCPAddr(t)}
	live := newHelloListener(t)

	// A connect timeout longer than the caller's budget: what the reconnect
	// loop does with its 15 seconds against connectTimeout's 30.
	//
	// The strategy masks its timeout the way REALITY did on the device, so the
	// verdict has to come from the clock measured against the budget the
	// attempt really had, not from the error text.
	//
	// Two transports, both silent there: one silent transport is not a verdict
	// on the address (TestOneSwallowedTransportLeavesRoomForTheNext).
	m := newSilenceManager(t, 2*time.Second, silent.addr, live.addr)
	s := &maskedTimeoutStrategy{id: "s0", priority: 1}
	m.Register(s)
	m.Register(&maskedTimeoutStrategy{id: "s1", priority: 2})
	markConnected(m, s)
	// The tunnel was up on this address, so its family probe has run.
	for _, c := range m.selector().Candidates() {
		m.selector().ReportProbe(c, true, time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
		t.Fatal("Connect succeeded against a blackhole - the test proves nothing")
	} else if !errors.Is(err, errAddrSilent) {
		t.Fatalf("err = %v, want the silence verdict", err)
	}

	if st := endpointState(t, m, silent.addr); !st.CooldownUntil.After(time.Now()) {
		t.Fatal("the cycle ran out of time on an address that answered nothing, and the address was not parked")
	}
	if st := endpointState(t, m, live.addr); !st.CooldownUntil.IsZero() || st.ConsecutiveFailures != 0 {
		t.Fatalf("the live server was charged for a cycle that never had time to dial it: %+v", st)
	}

	// The verdict pays off on the very next cycle.
	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(context.Background()); got != live.addr {
		t.Fatalf("second cycle pinned %s, want %s", got, live.addr)
	}
}

// unreachableStrategy fails the way a dial to a dead host on the same segment
// fails: EHOSTUNREACH from neighbour discovery, wrapped like REALITY wraps it.
type unreachableStrategy struct {
	id       string
	priority int
}

func (s *unreachableStrategy) Name() string                        { return s.id }
func (s *unreachableStrategy) ID() string                          { return s.id }
func (s *unreachableStrategy) Priority() int                       { return s.priority }
func (s *unreachableStrategy) RequiresServer() bool                { return true }
func (s *unreachableStrategy) Description() string                 { return "test strategy behind a dead neighbour" }
func (s *unreachableStrategy) Probe(context.Context, string) error { return nil }
func (s *unreachableStrategy) Connect(_ context.Context, target string) (net.Conn, error) {
	return nil, fmt.Errorf("reality: server connection failed: %w",
		&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)})
}

// TestNoRouteToHostIsSilenceNotAnAnswer: in the stand's run #1 the fast path
// came back with "no route to host" and the scan counted that as the address
// answering, which kept it off the silence verdict. Nothing answered - the
// network could not deliver the packet - and every other transport aimed at
// that address meets the same wall.
func TestNoRouteToHostIsSilenceNotAnAnswer(t *testing.T) {
	m := newSilenceManager(t, time.Second, "192.0.2.1:995", "192.0.2.2:995")
	for i := range m.tcpFailuresBeforeQUIC + 1 {
		m.Register(&unreachableStrategy{id: fmt.Sprintf("s%d", i), priority: i + 1})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := m.ConnectExcluding(ctx, "192.0.2.1:995", nil)
	if !errors.Is(err, errAddrSilent) {
		t.Fatalf("err = %v, want the silence verdict for an address no transport could reach", err)
	}
}

// TestNetUnreachableIsNotSilence is a P2 of the PR #126 review. ENETUNREACH is
// the local stack saying it has no route at all - the client's network, not
// the server - and the selector already treats it as local (ProbeCurrent). The
// scan counted it as the address's silence, which parks the server at once.
// EHOSTUNREACH stays silence: the packet went out and nothing came back.
func TestNetUnreachableIsNotSilence(t *testing.T) {
	netUnreach := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
	hostUnreach := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
	if heardNothing(netUnreach, time.Millisecond, 15*time.Second) {
		t.Error("ENETUNREACH counted as the server's silence")
	}
	if !heardNothing(hostUnreach, time.Millisecond, 15*time.Second) {
		t.Error("EHOSTUNREACH no longer counts as silence")
	}
}

// swallowingStrategy connects and then hears nothing until its context ends -
// a transport whose handshake the censor swallows while the port answers.
type swallowingStrategy struct {
	id       string
	priority int
}

func (s *swallowingStrategy) Name() string                        { return s.id }
func (s *swallowingStrategy) ID() string                          { return s.id }
func (s *swallowingStrategy) Priority() int                       { return s.priority }
func (s *swallowingStrategy) RequiresServer() bool                { return true }
func (s *swallowingStrategy) Description() string                 { return "handshake swallowed" }
func (s *swallowingStrategy) Probe(context.Context, string) error { return nil }
func (s *swallowingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("reality: serverhello read failed: %w", ctx.Err())
}

// TestOneSwallowedTransportLeavesRoomForTheNext is a P2 of the PR #126 review.
// The reconnect gives a cycle 15 s and an attempt may take 30, so a fast path
// whose handshake is swallowed used the whole cycle; the deadline then read as
// the address's silence and parked the server - without Polling, which works
// there, ever being tried. The fast path now gets half the budget, and one
// silent transport is not a verdict on the address.
func TestOneSwallowedTransportLeavesRoomForTheNext(t *testing.T) {
	live := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, live.addr, other.addr)
	reality := &swallowingStrategy{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	markConnected(m, reality)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("a swallowed fast path took the whole cycle: %v", err)
	}
	conn.Close()
	if s.ID() != "polling" {
		t.Fatalf("connected via %s, want polling", s.ID())
	}
	if st := endpointState(t, m, live.addr); st.CooldownUntil.After(time.Now()) {
		t.Fatal("the server was parked for one swallowed transport")
	}
}

// TestScanLeavesRoomForTheNextTransport is the same rule without a fast path:
// a first strategy whose handshake is swallowed may not take the whole cycle
// while others are still to try.
func TestScanLeavesRoomForTheNextTransport(t *testing.T) {
	live := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, live.addr, other.addr)
	m.Register(&swallowingStrategy{id: "reality", priority: 5})
	m.Register(&greetingStrategy{id: "polling", priority: 6})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("a swallowed first strategy took the whole cycle: %v", err)
	}
	conn.Close()
	if s.ID() != "polling" {
		t.Fatalf("connected via %s, want polling", s.ID())
	}
}

// slowStrategy needs delay to complete its handshake against a live server.
type slowStrategy struct {
	id       string
	priority int
	delay    time.Duration
}

func (s *slowStrategy) Name() string                        { return s.id }
func (s *slowStrategy) ID() string                          { return s.id }
func (s *slowStrategy) Priority() int                       { return s.priority }
func (s *slowStrategy) RequiresServer() bool                { return true }
func (s *slowStrategy) Description() string                 { return "slow handshake" }
func (s *slowStrategy) Probe(context.Context, string) error { return nil }
func (s *slowStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, fmt.Errorf("slow handshake: %w", ctx.Err())
	}
	return (&greetingStrategy{id: s.id}).Connect(ctx, target)
}

// TestDesktopRetriesAreNotTwoSilentTransports is P1-D of the round-2 review:
// with the desktop default of two attempts per strategy, one swallowed REALITY
// counted as two silent transports, and its halved-budget attempts left too
// little for a Polling handshake of a couple of seconds - so a live server was
// parked without Polling ever getting through. Scaled 1:10: a 3 s connect
// timeout, a 1.5 s cycle, Polling needing 0.25 s.
func TestDesktopRetriesAreNotTwoSilentTransports(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra Strategy // a second swallowed transport ahead of Polling, or nil
	}{
		{"REALITY swallowed", nil},
		{"REALITY and WS swallowed", &swallowingStrategy{id: "ws", priority: 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live := newHelloListener(t)
			other := newHelloListener(t)
			m := newSilenceManager(t, 3*time.Second, live.addr, other.addr)
			m.maxRetries = 2 // the desktop default
			m.Register(&swallowingStrategy{id: "reality", priority: 4})
			if tc.extra != nil {
				m.Register(tc.extra)
			}
			m.Register(&slowStrategy{id: "polling", priority: 6, delay: 250 * time.Millisecond})

			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			conn, s, err := m.Connect(ctx, "")
			if err != nil {
				t.Fatalf("Polling never got through: %v", err)
			}
			conn.Close()
			if s.ID() != "polling" {
				t.Fatalf("connected via %s", s.ID())
			}
			if st := endpointState(t, m, live.addr); st.CooldownUntil.After(time.Now()) {
				t.Fatal("a live server was parked")
			}
		})
	}
}

// TestOnlyTransportLeftIsNotAllTransports covers the corner of the same item:
// a silent fast path with every other strategy skipped by its breaker is one
// silent transport, not "the only transport there is".
func TestOnlyTransportLeftIsNotAllTransports(t *testing.T) {
	silent := silentTCPAddr(t) // the fast path's dial itself times out: conclusive silence
	live := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, silent, live.addr)
	reality := &greetingStrategy{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	markConnected(m, reality)
	for _, c := range m.selector().Candidates() {
		m.selector().ReportProbe(c, true, time.Millisecond)
	}
	cb := m.circuitBreakers.Get("polling")
	cb.mu.Lock()
	cb.openCircuit()
	cb.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
	}
	if st := endpointState(t, m, silent); st.CooldownUntil.After(time.Now()) {
		t.Fatal("one silent transport with the rest circuit-broken parked the address as silent on every transport")
	}
}

// TestSwallowedHandshakesAreNoVerdictInAShortCycle: in a cycle shorter than
// connectTimeout every attempt but the last runs on a shortened budget, and a
// handshake still waiting when that budget ran out - TCP connected - heard
// nothing in less time than a server is given. Two of those, then a Polling
// too slow for what is left, must not park a server that answers TCP.
func TestSwallowedHandshakesAreNoVerdictInAShortCycle(t *testing.T) {
	live := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, 3*time.Second, live.addr, other.addr)
	m.maxRetries = 2
	m.Register(&swallowingDialStrategy{id: "reality", priority: 4})
	m.Register(&swallowingDialStrategy{id: "ws", priority: 5})
	m.Register(&slowStrategy{id: "polling", priority: 6, delay: 2 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
		t.Fatal("connected - the test proves nothing")
	}
	if st := endpointState(t, m, live.addr); st.CooldownUntil.After(time.Now()) {
		t.Fatal("cut-short handshakes on a TCP-answering server parked it")
	}
}

// swallowingDialStrategy completes the TCP connect and then hears nothing.
type swallowingDialStrategy struct {
	id       string
	priority int
}

func (s *swallowingDialStrategy) Name() string                        { return s.id }
func (s *swallowingDialStrategy) ID() string                          { return s.id }
func (s *swallowingDialStrategy) Priority() int                       { return s.priority }
func (s *swallowingDialStrategy) RequiresServer() bool                { return true }
func (s *swallowingDialStrategy) Description() string                 { return "TCP up, handshake swallowed" }
func (s *swallowingDialStrategy) Probe(context.Context, string) error { return nil }
func (s *swallowingDialStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	<-ctx.Done()
	return nil, fmt.Errorf("reality: serverhello read failed: %w", ctx.Err())
}

// silentTCPAddr is a loopback address whose SYNs go unanswered: a zero-backlog
// listener with its one queue slot taken and never accepted.
func silentTCPAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatalf("listen: %v", err)
	}
	sa, _ := syscall.Getsockname(fd)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))
	filler, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("filling the backlog: %v", err)
	}
	t.Cleanup(func() { filler.Close(); syscall.Close(fd) })
	return addr
}

// lateTimerCtx has a deadline whose timer never fires: Err stays nil and Done
// never closes. It is the moment a loaded runtime makes of every deadline - the
// netpoller already failed a dial bounded by it, the context's own timer has
// not run yet.
type lateTimerCtx struct {
	context.Context
	dl time.Time
}

func (c lateTimerCtx) Deadline() (time.Time, bool) { return c.dl, true }

// TestALateDeadlineTimerStillGivesTheVerdict is the cause behind
// TestDeadlineOnASilentAddressParksIt failing a few times in 50 runs next to
// a full test run: the last transport's dial came back with "i/o timeout" at
// the deadline, the scan asked ctx.Err(), the context's timer had not fired
// yet, and the cycle ended as "all strategies failed" - then went on to the
// live server with no time left. The deadline is read from the clock.
func TestALateDeadlineTimerStillGivesTheVerdict(t *testing.T) {
	silent := silentTCPAddr(t)
	live := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, silent, live.addr)
	s := &maskedTimeoutStrategy{id: "s0", priority: 1}
	m.Register(s)
	m.Register(&maskedTimeoutStrategy{id: "s1", priority: 2})
	markConnected(m, s)
	for _, c := range m.selector().Candidates() {
		m.selector().ReportProbe(c, true, time.Millisecond)
	}

	ctx := lateTimerCtx{Context: context.Background(), dl: time.Now().Add(300 * time.Millisecond)}
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
		t.Fatal("Connect succeeded against a blackhole - the test proves nothing")
	} else if !errors.Is(err, errAddrSilent) {
		t.Fatalf("err = %v, want the silence verdict", err)
	}
	if st := endpointState(t, m, silent); !st.CooldownUntil.After(time.Now()) {
		t.Fatal("the silent address was not parked")
	}
	if st := endpointState(t, m, live.addr); st.ConsecutiveFailures != 0 {
		t.Fatalf("the live server was charged for a cycle with no time left: %+v", st)
	}
}

// overrunStrategy ignores its context and fails after d: a transport stuck in
// a call that does not watch the deadline.
type overrunStrategy struct {
	id    string
	prio  int
	d     time.Duration
	tries atomic.Int64
}

func (s *overrunStrategy) Name() string                        { return s.id }
func (s *overrunStrategy) ID() string                          { return s.id }
func (s *overrunStrategy) Priority() int                       { return s.prio }
func (s *overrunStrategy) RequiresServer() bool                { return true }
func (s *overrunStrategy) Description() string                 { return "overruns its deadline" }
func (s *overrunStrategy) Probe(context.Context, string) error { return nil }
func (s *overrunStrategy) Connect(context.Context, string) (net.Conn, error) {
	s.tries.Add(1)
	time.Sleep(s.d)
	return nil, errors.New("stuck transport gave up")
}

// TestNoDialAfterTheDeadlineWithALateTimer: once the caller's deadline is
// behind it the scan dials nothing more, whether or not the context's timer
// has fired. A dial on a spent budget fails at once and charges the strategy
// for the caller's deadline.
func TestNoDialAfterTheDeadlineWithALateTimer(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, live.addr)
	m.Register(&overrunStrategy{id: "stuck", prio: 1, d: 200 * time.Millisecond})
	next := &overrunStrategy{id: "next", prio: 2}
	m.Register(next)

	ctx := lateTimerCtx{Context: context.Background(), dl: time.Now().Add(100 * time.Millisecond)}
	if conn, _, err := m.Connect(ctx, ""); err == nil {
		conn.Close()
		t.Fatal("connected")
	}
	if n := next.tries.Load(); n != 0 {
		t.Fatalf("dialled the next strategy %d times after the deadline had passed", n)
	}
}
