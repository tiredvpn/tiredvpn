package strategy

import (
	"context"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestConnectWalksAPoolOfThree checks the failover walk on a real pool rather
// than the two-element degenerate case: two dead servers ahead of a live one
// must not leave the client offline.
//
// The walk that gets there has two kinds of step, and only one of them is
// budgeted. The reachability probe skips a candidate for the cost of one TCP
// dial; a full strategy scan is what maxEndpointAttempts caps, because
// handleDisconnect gives the whole reconnect 15 seconds and a scan can eat most
// of it. So the assertion is on the scans, not on how far the pin travelled.
func TestConnectWalksAPoolOfThree(t *testing.T) {
	dead1 := newCountingListener(t)
	dead2 := newCountingListener(t)
	live := newCountingListener(t)
	dead1.stop()
	dead2.stop()

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{
		FailureThreshold: 2,
		Cooldown:         10 * time.Minute,
		MinDwell:         5 * time.Minute,
	}, dead1.addr, dead2.addr, live.addr)

	strat := &targetStrategy{mgr: m, id: "s1", priority: 1}
	m.Register(strat)
	ctx := context.Background()

	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("Connect over a pool with two dead servers ahead of a live one: %v", err)
	}
	conn.Close()

	if got := m.GetServerAddr(ctx); got != live.addr {
		t.Fatalf("pinned %s, want the only live endpoint %s", got, live.addr)
	}
	if scanned := distinct(strat.seenTargets()); len(scanned) > maxEndpointAttempts {
		t.Fatalf("one Connect ran full scans against %v, want at most %d", scanned, maxEndpointAttempts)
	}
}

// TestConnectBudgetsScansOverADeadPool is the other half: when nothing answers,
// a single Connect must still come back inside its 15-second budget rather than
// walking the whole list. The bound is on strategy scans, which is the
// expensive step.
func TestConnectBudgetsScansOverADeadPool(t *testing.T) {
	var addrs []string
	for range 4 {
		l := newCountingListener(t)
		l.stop()
		addrs = append(addrs, l.addr)
	}

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{FailureThreshold: 2}, addrs...)
	strat := &targetStrategy{mgr: m, id: "s1", priority: 1}
	m.Register(strat)

	if _, _, err := m.Connect(context.Background(), ""); err == nil {
		t.Fatal("Connect succeeded with every endpoint dark")
	}
	scanned := distinct(strat.seenTargets())
	if len(scanned) == 0 {
		t.Fatal("no strategy scan ran - the test proves nothing")
	}
	if len(scanned) > maxEndpointAttempts {
		t.Fatalf("one Connect ran full scans against %v, want at most %d", scanned, maxEndpointAttempts)
	}
}

// TestPoolReprobesTouchOnlyThePinnedCandidate is the censorship-resistance
// requirement stated over a real pool. A background sweep of N servers on a
// timer multiplies this client's connection count by N and draws a periodic
// fan-out that nothing else on the wire draws. Both the periodic reprobe and
// the emergency one must therefore stay on the pinned candidate.
func TestPoolReprobesTouchOnlyThePinnedCandidate(t *testing.T) {
	pinned := newCountingListener(t)
	other1 := newCountingListener(t)
	other2 := newCountingListener(t)

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{}, pinned.addr, other1.addr, other2.addr)
	m.Register(&targetStrategy{mgr: m, id: "s1", priority: 1})
	m.Register(&targetStrategy{mgr: m, id: "s2", priority: 2})

	ctx := context.Background()
	m.ProbeAll(ctx, "")
	m.doPeriodicReprobe(ctx)

	// Ask for the wrong endpoint on purpose. This is the guard that covers all
	// three reprobe entry points at once: the periodic one, the emergency one
	// and any future caller all reach the network through ProbeAll, and
	// ProbeAll answers with the pinned candidate whatever it was handed. The
	// emergency reprobe cannot be driven directly here - its first probe is a
	// 30-second tick away - so this is what stands in for it.
	m.ProbeAll(ctx, other1.addr)

	if n := pinned.accepts.Load(); n == 0 {
		t.Fatal("the pinned endpoint saw no probes - the test proves nothing")
	}
	for i, l := range []*countingListener{other1, other2} {
		if n := l.accepts.Load(); n != 0 {
			t.Fatalf("unpinned endpoint %d saw %d probe connections, want 0", i+1, n)
		}
	}
}

// TestPoolSteadyStateAddsNoDials: with everything healthy the pool must cost
// exactly what a single-server client costs. Any per-cycle sweep would show up
// here as accepts on the endpoints nobody is using.
func TestPoolSteadyStateAddsNoDials(t *testing.T) {
	pinned := newCountingListener(t)
	other1 := newCountingListener(t)
	other2 := newCountingListener(t)

	clk := newEndpointClock()
	m := newMultiEndpointManager(t, clk, endpoint.Config{}, pinned.addr, other1.addr, other2.addr)
	m.Register(&targetStrategy{mgr: m, id: "s1", priority: 1})

	ctx := context.Background()
	for range 5 {
		conn, _, err := m.Connect(ctx, "")
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		conn.Close()
		clk.Advance(time.Minute)
	}

	if n := pinned.accepts.Load(); n == 0 {
		t.Fatal("the pinned endpoint saw no connections - the test proves nothing")
	}
	for i, l := range []*countingListener{other1, other2} {
		if n := l.accepts.Load(); n != 0 {
			t.Errorf("healthy pool dialled unused endpoint %d %d time(s), want 0", i+1, n)
		}
	}
}

// TestPoolWeightedSelectionIsSticky is the same property as the selector-level
// test, asserted where it is observable: the manager must keep dialling one
// address across reconnects rather than spreading across the pool.
func TestPoolWeightedSelectionIsSticky(t *testing.T) {
	a := newCountingListener(t)
	b := newCountingListener(t)
	c := newCountingListener(t)

	clk := newEndpointClock()
	draws := 0
	m := newMultiEndpointManager(t, clk, endpoint.Config{
		Selection: endpoint.SelectWeighted,
		Rand: func() float64 {
			draws++
			return float64(draws%7) / 7.0
		},
	}, a.addr, b.addr, c.addr)
	m.Register(&targetStrategy{mgr: m, id: "s1", priority: 1})

	ctx := context.Background()
	first := m.GetServerAddr(ctx)
	if first == "" {
		t.Fatal("no endpoint pinned")
	}
	for i := range 5 {
		conn, _, err := m.Connect(ctx, "")
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		conn.Close()
		clk.Advance(time.Hour) // well past MinDwell
		if got := m.GetServerAddr(ctx); got != first {
			t.Fatalf("cycle %d moved from %s to %s with nothing failing", i, first, got)
		}
	}
}

// TestConnectivityCheckerAccessor: the reconnect loop in internal/tun asks the
// manager for this gate instead of hand-rolling its own probe. A nil manager
// gate has to be reported as nil so the caller can fall back rather than panic.
func TestConnectivityCheckerAccessor(t *testing.T) {
	m := NewManager()
	if got := m.ConnectivityChecker(); got != nil {
		t.Fatalf("fresh manager reported a checker: %v", got)
	}
	checker := NewConnectivityChecker("127.0.0.1:1", time.Second, true)
	m.SetConnectivityChecker(checker)
	if got := m.ConnectivityChecker(); got != checker {
		t.Fatalf("ConnectivityChecker = %v, want the one that was set", got)
	}
}

// TestDerivedSalamanderPortFallsBackToTheEndpointList: a client configured only
// through [[servers]] leaves ServerAddr empty, and the old derivation then
// silently landed on 443 - a port the exit is not listening on.
func TestDerivedSalamanderPortFallsBackToTheEndpointList(t *testing.T) {
	cases := []struct {
		name string
		cfg  DefaultManagerConfig
		want int
	}{
		{"from ServerAddr", DefaultManagerConfig{ServerAddr: "1.2.3.4:995"}, 995},
		{"from the first endpoint", DefaultManagerConfig{
			Endpoints: []endpoint.Endpoint{{V4: "1.2.3.4:8443"}},
		}, 8443},
		{"from the first endpoint's v6 address", DefaultManagerConfig{
			Endpoints: []endpoint.Endpoint{{V6: "[2001:db8::1]:9000"}},
		}, 9000},
		{"ServerAddr wins over the list", DefaultManagerConfig{
			ServerAddr: "1.2.3.4:995",
			Endpoints:  []endpoint.Endpoint{{V4: "5.6.7.8:8443"}},
		}, 995},
		{"nothing usable", DefaultManagerConfig{}, 443},
		{"unparseable address", DefaultManagerConfig{ServerAddr: "not-an-address"}, 443},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := derivedSalamanderPort(c.cfg); got != c.want {
				t.Errorf("derivedSalamanderPort = %d, want %d", got, c.want)
			}
		})
	}
}

// TestEndpointListAloneRegistersStrategies: checking ServerAddr alone would
// register nothing at all for a pure server-list client, and the failure would
// surface as "no strategies available" - a message that points nowhere near the
// config that caused it.
func TestEndpointListAloneRegistersStrategies(t *testing.T) {
	m := NewDefaultManager(DefaultManagerConfig{
		Secret:    []byte("0123456789abcdef0123456789abcdef"),
		Endpoints: []endpoint.Endpoint{{Name: "a", V4: "1.2.3.4:995"}},
	})
	if len(m.strategies) == 0 {
		t.Fatal("a config with only [[servers]] registered no strategies")
	}
	if got := m.GetServerAddr(context.Background()); got != "1.2.3.4:995" {
		t.Fatalf("pinned %q, want the single configured endpoint", got)
	}
}
