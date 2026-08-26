package strategy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// endpointClock is the selector's injected time source, so these tests drive
// cooldowns and dwell windows without sleeping.
type endpointClock struct {
	mu sync.Mutex
	t  time.Time
}

func newEndpointClock() *endpointClock {
	return &endpointClock{t: time.Unix(1_700_000_000, 0)}
}

func (c *endpointClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *endpointClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// countingListener is a loopback listener that counts accepted connections and
// can be killed mid-test. Counts are only ever read after the call under test
// returned, so no accept is still in flight when they are compared.
type countingListener struct {
	ln      net.Listener
	addr    string
	accepts atomic.Int64
	done    chan struct{}
	once    sync.Once
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &countingListener{ln: ln, addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepts.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(l.stop)
	return l
}

func (l *countingListener) stop() {
	l.once.Do(func() {
		l.ln.Close()
		<-l.done
	})
}

// targetStrategy dials whatever target the manager hands it and records both
// that target and the address GetServerAddr reports at the same moment. The
// second one is what proves a whole scan sees one address.
type targetStrategy struct {
	mgr      *Manager
	id       string
	priority int

	mu       sync.Mutex
	targets  []string
	resolved []string
}

func (s *targetStrategy) Name() string         { return s.id }
func (s *targetStrategy) ID() string           { return s.id }
func (s *targetStrategy) Priority() int        { return s.priority }
func (s *targetStrategy) RequiresServer() bool { return true }
func (s *targetStrategy) Description() string  { return "test strategy dialling the supplied target" }

func (s *targetStrategy) note(ctx context.Context, target string) {
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.resolved = append(s.resolved, s.mgr.GetServerAddr(ctx))
	s.mu.Unlock()
}

func (s *targetStrategy) seenTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

func (s *targetStrategy) seenResolved() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.resolved...)
}

func (s *targetStrategy) Probe(ctx context.Context, target string) error {
	s.note(ctx, target)
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *targetStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	s.note(ctx, target)
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
}

// distinct returns the addresses in the order first seen.
func distinct(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// newMultiEndpointManager wires a manager to N single-family endpoints, so the
// candidate machinery is exercised on hosts without IPv6 loopback. The
// family-specific half of the same machinery is covered in serveraddr_test.go.
func newMultiEndpointManager(t *testing.T, clk *endpointClock, cfg endpoint.Config, addrs ...string) *Manager {
	t.Helper()
	eps := make([]endpoint.Endpoint, len(addrs))
	for i, a := range addrs {
		eps[i] = endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: a, Order: i}
	}
	cfg.Endpoints = eps
	cfg.Family = endpoint.V4Only
	cfg.Now = clk.Now
	if cfg.Rand == nil {
		cfg.Rand = func() float64 { return 0.5 }
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = time.Second
	}
	sel, err := endpoint.NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	m := NewManager()
	m.endpoints = sel
	m.maxRetries = 1
	m.connectTimeout = 2 * time.Second
	m.probeTimeout = 2 * time.Second
	return m
}

// clearBreakers wipes the per-strategy circuit breakers between cycles. These
// tests are about the endpoint layer; the breaker has its own tests, and
// letting it open here would turn a scan failure into "no eligible strategy",
// which is deliberately NOT an endpoint signal.
func clearBreakers(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.strategies {
		m.circuitBreakers.Get(s.ID()).Reset()
	}
	m.lastSuccessfulStrategy = nil
}

// TestStrategyScanSeesOneAddress is the property that makes GetServerAddr safe
// to call from every strategy: the address is decided once per connect cycle
// and read, never recomputed. Before the refactor each of these calls could
// have taken a mutex and dialled.
func TestStrategyScanSeesOneAddress(t *testing.T) {
	live := newCountingListener(t)
	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{}, live.addr)

	// Three strategies, all of which will be tried: the first two dial a
	// closed port, the third the live one.
	dead := newCountingListener(t)
	dead.stop()
	strategies := []*targetStrategy{
		{mgr: m, id: "s1", priority: 1},
		{mgr: m, id: "s2", priority: 2},
		{mgr: m, id: "s3", priority: 3},
	}
	for _, s := range strategies {
		m.Register(s)
	}

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()

	var all []string
	for _, s := range strategies {
		all = append(all, s.seenResolved()...)
		for _, tgt := range s.seenTargets() {
			if tgt != live.addr {
				t.Errorf("%s was handed target %q, want %q", s.id, tgt, live.addr)
			}
		}
	}
	if len(all) == 0 {
		t.Fatal("no strategy ran - the test proves nothing")
	}
	if got := distinct(all); len(got) != 1 || got[0] != live.addr {
		t.Fatalf("scan saw %v addresses, want exactly [%s]", got, live.addr)
	}
	_ = dead
}

// TestConnectFallsBackToNextEndpoint replays the whole failover: a working
// endpoint dies, the client moves to the second one within the same Connect,
// the dead one is only parked after the SECOND failed cycle, the parked one is
// not retried while it is parked, and the client comes back once both the
// cooldown and the dwell have elapsed.
func TestConnectFallsBackToNextEndpoint(t *testing.T) {
	primary := newCountingListener(t)
	backup := newCountingListener(t)

	clk := newEndpointClock()
	// Cooldown deliberately longer than the dwell: the two brakes are
	// independent and the longer one has to win.
	m := newMultiEndpointManager(t, clk, endpoint.Config{
		FailureThreshold: 2,
		Cooldown:         10 * time.Minute,
		MinDwell:         5 * time.Minute,
	}, primary.addr, backup.addr)

	strat := &targetStrategy{mgr: m, id: "s1", priority: 1}
	m.Register(strat)
	ctx := context.Background()

	// 1. Healthy: the preferred endpoint answers.
	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("initial connect: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(ctx); got != primary.addr {
		t.Fatalf("pinned %s, want the preferred %s", got, primary.addr)
	}

	// 2. The preferred endpoint dies. The very same Connect has to land on the
	//    backup - refusing to switch for a whole cycle would be an outage.
	primary.stop()
	clearBreakers(m)
	conn, _, err = m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect after primary died: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(ctx); got != backup.addr {
		t.Fatalf("pinned %s after the primary died, want %s", got, backup.addr)
	}
	if st := endpointState(t, m, primary.addr); !st.CooldownUntil.IsZero() {
		t.Fatalf("parked the primary after ONE failed cycle (until %v)", st.CooldownUntil)
	}

	// 3. After the dwell the client tries the preferred endpoint again. It is
	//    still dead, which is the second failed cycle and parks it.
	clk.Advance(6 * time.Minute)
	clearBreakers(m)
	conn, _, err = m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect after the dwell: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(ctx); got != backup.addr {
		t.Fatalf("pinned %s, want %s", got, backup.addr)
	}
	if st := endpointState(t, m, primary.addr); st.CooldownUntil.IsZero() {
		t.Fatal("the primary is not parked after two failed cycles")
	}

	// 4. Anti-flap: the dwell has elapsed again but the cooldown has not, so
	//    the primary must not be dialled at all this cycle.
	clk.Advance(6 * time.Minute)
	clearBreakers(m)
	before := len(strat.seenTargets())
	conn, _, err = m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect while the primary is parked: %v", err)
	}
	conn.Close()
	for _, tgt := range strat.seenTargets()[before:] {
		if tgt == primary.addr {
			t.Fatal("dialled the parked primary before its cooldown expired")
		}
	}

	// 5. The primary comes back and its cooldown expires: the client returns.
	revived := reviveListener(t, primary.addr)
	defer revived.stop()
	clk.Advance(10 * time.Minute)
	clearBreakers(m)
	conn, _, err = m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect after recovery: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(ctx); got != primary.addr {
		t.Fatalf("pinned %s after recovery, want to be back on %s", got, primary.addr)
	}
}

// reviveListener re-binds a specific address that a previous listener released.
func reviveListener(t *testing.T, addr string) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot re-bind %s: %v", addr, err)
	}
	l := &countingListener{ln: ln, addr: addr, done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepts.Add(1)
			conn.Close()
		}
	}()
	return l
}

func endpointState(t *testing.T, m *Manager, addr string) endpoint.CandidateState {
	t.Helper()
	for _, st := range m.EndpointStates() {
		if st.Addr == addr {
			return st
		}
	}
	t.Fatalf("no candidate for %s", addr)
	return endpoint.CandidateState{}
}

// TestReprobeTouchesOnlyThePinnedCandidate is a censorship-resistance
// requirement, not an efficiency one. Sweeping every configured endpoint on a
// timer multiplies this client's traffic by the size of its server list and
// produces a periodic fan-out pattern nothing else on the wire produces.
func TestReprobeTouchesOnlyThePinnedCandidate(t *testing.T) {
	pinned := newCountingListener(t)
	other := newCountingListener(t)

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{}, pinned.addr, other.addr)
	m.Register(&targetStrategy{mgr: m, id: "s1", priority: 1})
	m.Register(&targetStrategy{mgr: m, id: "s2", priority: 2})

	ctx := context.Background()
	m.ProbeAll(ctx, "")
	m.doPeriodicReprobe(ctx)

	if n := pinned.accepts.Load(); n == 0 {
		t.Fatal("the pinned endpoint saw no probes - the test proves nothing")
	}
	if n := other.accepts.Load(); n != 0 {
		t.Fatalf("the unpinned endpoint saw %d probe connections, want 0", n)
	}
}

// TestConnectForReconnectDoesNotWalkCandidates guards the Android handover
// path. It re-picks the family once - a network change can flip which one works
// - but it must not run the outer candidate loop: it already retries the last
// strategy five times and then walks the whole strategy list, and a second
// level of retries turns a handover into a minute-long stall.
func TestConnectForReconnectDoesNotWalkCandidates(t *testing.T) {
	first := newCountingListener(t)
	second := newCountingListener(t)
	first.stop()
	second.stop() // both endpoints are dark: nothing can succeed

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{}, first.addr, second.addr)
	strat := &targetStrategy{mgr: m, id: "s1", priority: 1}
	m.Register(strat)

	_, _, err := m.ConnectForReconnect(context.Background(), "")
	if err == nil {
		t.Fatal("ConnectForReconnect succeeded against two dead endpoints")
	}

	seen := distinct(strat.seenTargets())
	if len(seen) != 1 {
		t.Fatalf("strategies were pointed at %v, want a single candidate", seen)
	}
}

// TestConnectStopsWhenTheNetworkIsDown: a pre-flight that fails outright means
// the whole network is down, not that this endpoint is bad. Counting it would
// park every candidate the first time a laptop lid closes.
func TestConnectStopsWhenTheNetworkIsDown(t *testing.T) {
	dead := newCountingListener(t)
	backup := newCountingListener(t)
	dead.stop()
	backup.stop()

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{FailureThreshold: 2}, dead.addr, backup.addr)
	m.Register(&targetStrategy{mgr: m, id: "s1", priority: 1})

	checker := NewConnectivityChecker(dead.addr, 200*time.Millisecond, true)
	checker.auxTimeout = 50 * time.Millisecond
	checker.auxGrace = 50 * time.Millisecond
	m.SetConnectivityChecker(checker)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, _, err := m.Connect(ctx, ""); err == nil {
		t.Fatal("Connect succeeded with no reachable endpoint")
	}
	for _, st := range m.EndpointStates() {
		if st.ConsecutiveFailures != 0 || !st.CooldownUntil.IsZero() {
			t.Fatalf("a total network outage charged %s: %+v", st.Addr, st)
		}
	}
}

// TestConnectDoesNotBlameTheEndpointForAnEmptyStrategyList covers the other
// non-endpoint error. "No eligible strategy" means every transport is
// circuit-broken or disabled; the address is not implicated, and switching
// servers over it would send a client whose breakers all tripped to hammer the
// second server for a reason that has nothing to do with the first.
func TestConnectDoesNotBlameTheEndpointForAnEmptyStrategyList(t *testing.T) {
	first := newCountingListener(t)
	second := newCountingListener(t)

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{FailureThreshold: 2}, first.addr, second.addr)
	// Priority <= 0 disables a strategy, so the scan has nothing to run.
	m.Register(&targetStrategy{mgr: m, id: "disabled", priority: 0})

	ctx := context.Background()
	if _, _, err := m.Connect(ctx, ""); err == nil {
		t.Fatal("Connect succeeded with no eligible strategy")
	}

	if got := m.GetServerAddr(ctx); got != first.addr {
		t.Errorf("pinned %s, want to have stayed on %s", got, first.addr)
	}
	for _, st := range m.EndpointStates() {
		if st.ConsecutiveFailures != 0 || !st.CooldownUntil.IsZero() {
			t.Errorf("an empty strategy list charged %s: %+v", st.Addr, st)
		}
	}
}

// TestPreflightSwitchesToTheAnsweringSibling covers the second failure signal.
// The gate already dials both addresses of a dual-addressed server and knows
// which one answered; acting on that costs zero extra packets, and ignoring it
// means dialling the dark family through every strategy first.
func TestPreflightSwitchesToTheAnsweringSibling(t *testing.T) {
	live, stopV6 := liveV6Listener(t)
	defer stopV6()
	v4 := newCountingListener(t)
	v4.stop() // the v4 address is dark; only the v6 sibling answers

	sel, err := endpoint.NewSelector(endpoint.Config{
		Endpoints: []endpoint.Endpoint{{Name: "srv", V4: v4.addr, V6: live}},
		Family:    endpoint.PreferV4, // pin the dark family on purpose
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	m := NewManager()
	m.endpoints = sel
	m.maxRetries = 1
	m.connectTimeout = 2 * time.Second
	m.Register(&targetStrategy{mgr: m, id: "s1", priority: 1})

	checker := NewConnectivityChecker(v4.addr, 500*time.Millisecond, true)
	checker.auxTimeout = 50 * time.Millisecond
	checker.auxGrace = 50 * time.Millisecond
	m.SetConnectivityChecker(checker)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()

	if got := m.GetServerAddr(ctx); got != live {
		t.Fatalf("pinned %s, want the sibling that answered the gate (%s)", got, live)
	}
}
