package strategy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
	silent := newBlackholeListener(t)
	live := newHelloListener(t)

	// A connect timeout longer than the caller's budget: what the reconnect
	// loop does with its 15 seconds against connectTimeout's 30.
	//
	// The strategy masks its timeout the way REALITY did on the device, so the
	// verdict has to come from the clock measured against the budget the
	// attempt really had, not from the error text.
	m := newSilenceManager(t, 2*time.Second, silent.addr, live.addr)
	s := &maskedTimeoutStrategy{id: "s0", priority: 1}
	m.Register(s)
	markConnected(m, s)

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
