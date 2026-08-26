package endpoint

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeClock is the injected time source. Every cooldown and dwell decision in
// this package reads it, so a test drives minutes of policy in microseconds and
// never sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// scriptedDialer answers from a fixed table and counts every call, so a test
// asserts how many times the selector went to the network rather than only what
// it concluded.
type scriptedDialer struct {
	mu      sync.Mutex
	ok      map[string]bool
	calls   []string
	network []string
}

func newScriptedDialer(reachable ...string) *scriptedDialer {
	d := &scriptedDialer{ok: map[string]bool{}}
	for _, a := range reachable {
		d.ok[a] = true
	}
	return d
}

func (d *scriptedDialer) dial(_ context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, addr)
	d.network = append(d.network, network)
	ok := d.ok[addr]
	d.mu.Unlock()
	if !ok {
		return nil, errors.New("scripted: unreachable")
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func (d *scriptedDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (d *scriptedDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

const (
	v6Addr = "[2001:db8::1]:443"
	v4Addr = "203.0.113.1:443"
)

func dualEndpoint() []Endpoint {
	return []Endpoint{{Name: "srv", V6: v6Addr, V4: v4Addr}}
}

func newTestSelector(t *testing.T, cfg Config) (*Selector, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	if cfg.Endpoints == nil {
		cfg.Endpoints = dualEndpoint()
	}
	cfg.Now = clk.Now
	if cfg.Rand == nil {
		cfg.Rand = func() float64 { return 0.5 } // no jitter unless a test asks for it
	}
	s, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	return s, clk
}

// stateOf returns one candidate's snapshot by address.
func stateOf(t *testing.T, s *Selector, addr string) CandidateState {
	t.Helper()
	for _, st := range s.Snapshot() {
		if st.Addr == addr {
			return st
		}
	}
	t.Fatalf("no candidate for %s", addr)
	return CandidateState{}
}

// TestFamilyPolicyFromLegacy pins the flag mapping. The last row is the one
// that matters: -prefer-ipv6=false today returns IPv4 and never probes IPv6, so
// it maps to v4_only. Mapping it to prefer_v4 would quietly hand those clients
// a fallback they never had.
func TestFamilyPolicyFromLegacy(t *testing.T) {
	for _, tc := range []struct {
		preferV6, fallbackV4 bool
		want                 FamilyPolicy
		wantCands            []string
	}{
		{true, true, PreferV6, []string{v6Addr, v4Addr}},
		{true, false, V6Only, []string{v6Addr}},
		{false, true, V4Only, []string{v4Addr}},
		{false, false, V4Only, []string{v4Addr}},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			got := FamilyPolicyFromLegacy(tc.preferV6, tc.fallbackV4)
			if got != tc.want {
				t.Fatalf("FamilyPolicyFromLegacy(%v,%v) = %s, want %s",
					tc.preferV6, tc.fallbackV4, got, tc.want)
			}
			s, _ := newTestSelector(t, Config{Family: got})
			var addrs []string
			for _, c := range s.Candidates() {
				addrs = append(addrs, c.Addr)
			}
			if len(addrs) != len(tc.wantCands) {
				t.Fatalf("candidates = %v, want %v", addrs, tc.wantCands)
			}
			for i := range addrs {
				if addrs[i] != tc.wantCands[i] {
					t.Fatalf("candidates = %v, want %v", addrs, tc.wantCands)
				}
			}
		})
	}
}

// TestParseFamilyPolicy covers the configuration spelling, including the empty
// string that a TOML file without the key produces.
func TestParseFamilyPolicy(t *testing.T) {
	for in, want := range map[string]FamilyPolicy{
		"":          PreferV6,
		"prefer_v6": PreferV6,
		"PREFER_V4": PreferV4,
		" v6_only ": V6Only,
		"v4_only":   V4Only,
	} {
		got, err := ParseFamilyPolicy(in)
		if err != nil {
			t.Errorf("ParseFamilyPolicy(%q) = %v", in, err)
		}
		if got != want {
			t.Errorf("ParseFamilyPolicy(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseFamilyPolicy("ipv7"); err == nil {
		t.Error("ParseFamilyPolicy(ipv7) = nil error, want a rejection")
	}
}

// TestCandidateOrderIsEndpointMajor pins the fallback order: both families of
// the first server before the second server is touched. Falling back within a
// server is cheaper - same secret, same bypass route, same latency profile - so
// it has to come first.
func TestCandidateOrderIsEndpointMajor(t *testing.T) {
	s, _ := newTestSelector(t, Config{
		Endpoints: []Endpoint{
			{Name: "second", V4: "198.51.100.2:443", V6: "[2001:db8::2]:443", Order: 5},
			{Name: "first", V4: "198.51.100.1:443", V6: "[2001:db8::1]:443", Order: 1},
			{Name: "v4only", V4: "198.51.100.3:443", Order: 9},
		},
		Family: PreferV6,
	})
	want := []string{
		"[2001:db8::1]:443", "198.51.100.1:443",
		"[2001:db8::2]:443", "198.51.100.2:443",
		"198.51.100.3:443",
	}
	got := s.Candidates()
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Addr != want[i] {
			t.Fatalf("candidate %d = %s, want %s", i, got[i].Addr, want[i])
		}
	}
	// Siblings must stay inside one endpoint: the connectivity gate uses them
	// as "the same server on its other family", not "some other server".
	if sib := s.Siblings(got[0]); len(sib) != 1 || sib[0] != "198.51.100.1:443" {
		t.Fatalf("Siblings = %v, want the same endpoint's v4 address", sib)
	}
	if sib := s.Siblings(got[4]); len(sib) != 0 {
		t.Fatalf("Siblings of a single-family endpoint = %v, want none", sib)
	}
}

// TestFailureThresholdCountsCycles is the anti-flap rule: one failed connect
// cycle is not evidence. A single lost handshake would otherwise park the
// preferred endpoint for a minute.
func TestFailureThresholdCountsCycles(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: PreferV6, FailureThreshold: 2})
	cur, _ := s.Current()

	s.Report(cur, false, 0)
	if st := stateOf(t, s, v6Addr); !st.CooldownUntil.IsZero() {
		t.Fatalf("parked after one failed cycle (until %v), want no cooldown", st.CooldownUntil)
	}
	if _, ok := s.Reconsider(clk.Now()); !ok {
		t.Fatal("Reconsider lost the pin")
	}
	if cand, _ := s.Current(); cand.Addr != v6Addr {
		t.Fatalf("moved off %s after one failure, now on %s", v6Addr, cand.Addr)
	}

	s.Report(cur, false, 0)
	if st := stateOf(t, s, v6Addr); st.CooldownUntil.IsZero() {
		t.Fatal("not parked after two failed cycles")
	}
}

// TestNoFlapOnAlternatingOutcomes: a link that works every other attempt must
// never park. The streak is consecutive by definition, and a success is the
// only thing that clears it.
func TestNoFlapOnAlternatingOutcomes(t *testing.T) {
	s, _ := newTestSelector(t, Config{Family: PreferV6, FailureThreshold: 2})
	cur, _ := s.Current()

	for range 20 {
		s.Report(cur, false, 0)
		s.Report(cur, true, 10*time.Millisecond)
		if st := stateOf(t, s, v6Addr); !st.CooldownUntil.IsZero() {
			t.Fatal("alternating success/failure parked the candidate")
		}
	}
	if cand, _ := s.Current(); cand.Addr != v6Addr {
		t.Fatalf("pinned %s, want to still be on %s", cand.Addr, v6Addr)
	}
}

// TestCooldownBackoffAndJitter pins the growth (1m -> 30m, doubling) and the
// +/-20% spread. Losing the growth hammers a dead endpoint every minute for
// hours; losing the jitter makes every client that lost the same server come
// back at the same instant.
func TestCooldownBackoffAndJitter(t *testing.T) {
	t.Run("doubles and clamps", func(t *testing.T) {
		s, clk := newTestSelector(t, Config{
			Family: PreferV6, FailureThreshold: 1,
			Cooldown: time.Minute, MaxCooldown: 30 * time.Minute,
			Rand: func() float64 { return 0.5 }, // factor 1.0, isolates the growth
		})
		cur, _ := s.Current()
		want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
		for i, w := range want {
			s.Report(cur, false, 0)
			got := stateOf(t, s, v6Addr).CooldownUntil.Sub(clk.Now())
			if got != w*time.Minute {
				t.Fatalf("cooldown %d = %v, want %v", i, got, w*time.Minute)
			}
		}
	})

	t.Run("jitter spans the configured band", func(t *testing.T) {
		for _, tc := range []struct {
			r    float64
			want time.Duration
		}{
			{0.0, 48 * time.Second}, // 1m * 0.8
			{0.5, 60 * time.Second}, // 1m * 1.0
			{1.0, 72 * time.Second}, // 1m * 1.2
		} {
			s, clk := newTestSelector(t, Config{
				Family: PreferV6, FailureThreshold: 1,
				Cooldown: time.Minute, JitterFrac: 0.2,
				Rand: func() float64 { return tc.r },
			})
			cur, _ := s.Current()
			s.Report(cur, false, 0)
			if got := stateOf(t, s, v6Addr).CooldownUntil.Sub(clk.Now()); got != tc.want {
				t.Errorf("rand=%v: cooldown = %v, want %v", tc.r, got, tc.want)
			}
		}
	})

	t.Run("a success wipes the accumulated backoff", func(t *testing.T) {
		s, clk := newTestSelector(t, Config{
			Family: PreferV6, FailureThreshold: 1, Cooldown: time.Minute,
		})
		cur, _ := s.Current()
		s.Report(cur, false, 0)
		s.Report(cur, false, 0) // backoff now 2m
		s.Report(cur, true, time.Millisecond)
		s.Report(cur, false, 0)
		if got := stateOf(t, s, v6Addr).CooldownUntil.Sub(clk.Now()); got != time.Minute {
			t.Fatalf("cooldown after a success = %v, want the base %v", got, time.Minute)
		}
	})
}

// TestNextConvergesWhenAllParked: the failover loop must always produce a
// target. Leaving the client with nothing because every candidate is serving a
// cooldown is strictly worse than dialling the least-bad one, which is the same
// call the storm detector makes when every strategy is parked.
func TestNextConvergesWhenAllParked(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: PreferV6, FailureThreshold: 1})
	cands := s.Candidates()

	s.Report(cands[0], false, 0)
	s.Report(cands[1], false, 0)
	s.Report(cands[1], false, 0) // v4 is the worse of the two
	for _, c := range cands {
		if stateOf(t, s, c.Addr).CooldownUntil.IsZero() {
			t.Fatalf("%s is not parked, the test is not exercising the branch", c.Addr)
		}
	}

	next, ok := s.Next(clk.Now())
	if !ok {
		t.Fatal("Next = false with every candidate parked - the failover loop dead-ends")
	}
	if next.Addr != v4Addr {
		t.Fatalf("Next = %s, want the only alternative %s", next.Addr, v4Addr)
	}
	if !stateOf(t, s, v4Addr).CooldownUntil.IsZero() {
		t.Error("Next returned a candidate whose cooldown it did not clear")
	}
}

// TestNextRefusesToLoopOnASingleCandidate guards the v6_only / v4_only case:
// there is nowhere to go, and pretending otherwise would make Connect burn its
// second attempt on the address that just failed.
func TestNextRefusesToLoopOnASingleCandidate(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: V6Only})
	if next, ok := s.Next(clk.Now()); ok {
		t.Fatalf("Next = %s with one candidate, want false", next.Addr)
	}
}

// TestMinDwellGatesTheReturn: coming back to the preferred endpoint has to wait
// out MinDwell, and it happens on a reconnect boundary - Reconsider - so the
// check rides a dial that was going to happen anyway.
func TestMinDwellGatesTheReturn(t *testing.T) {
	s, clk := newTestSelector(t, Config{
		Family: PreferV6, FailureThreshold: 2,
		Cooldown: time.Minute, MinDwell: 5 * time.Minute,
	})
	cands := s.Candidates()

	s.Pin(cands[1])
	if cur, _ := s.Current(); cur.Addr != v4Addr {
		t.Fatalf("Pin did not take: on %s", cur.Addr)
	}

	clk.Advance(4 * time.Minute)
	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v4Addr {
		t.Fatalf("promoted to %s after 4m, want to dwell on %s for 5m", cur.Addr, v4Addr)
	}

	clk.Advance(2 * time.Minute)
	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v6Addr {
		t.Fatalf("still on %s after the dwell elapsed, want %s", cur.Addr, v6Addr)
	}
}

// TestMinDwellDoesNotPromoteIntoACooldown: the dwell and the cooldown are two
// independent brakes and the longer one wins. With a 10m cooldown and a 5m
// dwell, the client must not bounce back onto a parked endpoint at 5m.
func TestMinDwellDoesNotPromoteIntoACooldown(t *testing.T) {
	s, clk := newTestSelector(t, Config{
		Family: PreferV6, FailureThreshold: 1,
		Cooldown: 10 * time.Minute, MinDwell: 5 * time.Minute,
	})
	cands := s.Candidates()

	s.Report(cands[0], false, 0) // parks v6 for 10m
	s.Pin(cands[1])

	clk.Advance(6 * time.Minute)
	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v4Addr {
		t.Fatalf("promoted back to a parked %s at 6m", cur.Addr)
	}

	clk.Advance(5 * time.Minute)
	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v6Addr {
		t.Fatalf("still on %s once the cooldown expired, want %s", cur.Addr, v6Addr)
	}
}

// TestReconsiderMovesOffAParkedPin covers the other direction: whatever parked
// the pinned candidate, the next cycle must not dial it again.
func TestReconsiderMovesOffAParkedPin(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: PreferV6, FailureThreshold: 1})
	cands := s.Candidates()
	s.Report(cands[0], false, 0)

	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v4Addr {
		t.Fatalf("Reconsider stayed on the parked %s", cur.Addr)
	}
}

// TestReportProbeDoesNotClearTheFailureStreak pins the asymmetry between a
// reachability probe and a real connect. A censor that completes the TCP
// handshake and kills the session afterwards is the case this whole mechanism
// exists for; treating "the port answers" as "the endpoint works" would pin the
// client to a dead endpoint forever.
func TestReportProbeDoesNotClearTheFailureStreak(t *testing.T) {
	s, _ := newTestSelector(t, Config{Family: PreferV6, FailureThreshold: 2})
	cur, _ := s.Current()

	s.Report(cur, false, 0)
	s.ReportProbe(cur, true, 5*time.Millisecond)
	if got := stateOf(t, s, v6Addr).ConsecutiveFailures; got != 1 {
		t.Fatalf("failure streak = %d after a probe success, want the connect failure to stand", got)
	}

	// The next real failure must still reach the threshold.
	s.Report(cur, false, 0)
	if stateOf(t, s, v6Addr).CooldownUntil.IsZero() {
		t.Fatal("a probe success let the candidate escape the threshold")
	}

	// A real success, by contrast, clears everything.
	s.Report(cur, true, time.Millisecond)
	st := stateOf(t, s, v6Addr)
	if st.ConsecutiveFailures != 0 || !st.CooldownUntil.IsZero() {
		t.Fatalf("connect success left %+v", st)
	}
}

// TestProbeCurrentFallsBackOnce reproduces the old one-shot IPv6 check: one
// dial, pinned to the family it picks, and no repeat on later cycles. Repeating
// it would put a 3s timeout back on the hot reconnect path.
func TestProbeCurrentFallsBackOnce(t *testing.T) {
	d := newScriptedDialer(v4Addr) // v6 is dark
	s, _ := newTestSelector(t, Config{Family: PreferV6, Dial: d.dial})

	cand, kept := s.ProbeCurrent(context.Background())
	if kept {
		t.Error("ProbeCurrent reported the pin survived an unreachable address")
	}
	if cand.Addr != v4Addr {
		t.Fatalf("ProbeCurrent = %s, want the fallback %s", cand.Addr, v4Addr)
	}
	if cur, _ := s.Current(); cur.Addr != v4Addr {
		t.Fatalf("pinned %s, want %s", cur.Addr, v4Addr)
	}
	if got := d.dialed(); len(got) != 1 || got[0] != v6Addr {
		t.Fatalf("dialled %v, want exactly one probe of %s", got, v6Addr)
	}

	// v4 is the last candidate: probing it would spend a dial on a verdict
	// nothing can act on.
	for range 5 {
		s.ProbeCurrent(context.Background())
	}
	if n := d.count(); n != 1 {
		t.Fatalf("dialled %d times over six cycles, want 1", n)
	}
}

// TestProbeCurrentPinsTheFamily: the probe must dial the family it is deciding
// about. A plain "tcp" dial against a dual-stack host lets the resolver pick,
// so a "v6 is up" verdict could be produced by an IPv4 connection.
func TestProbeCurrentPinsTheFamily(t *testing.T) {
	d := newScriptedDialer(v6Addr)
	s, _ := newTestSelector(t, Config{Family: PreferV6, Dial: d.dial})

	if cand, kept := s.ProbeCurrent(context.Background()); !kept || cand.Addr != v6Addr {
		t.Fatalf("ProbeCurrent = %s (kept=%v), want %s", cand.Addr, kept, v6Addr)
	}
	d.mu.Lock()
	network := d.network[0]
	d.mu.Unlock()
	if network != "tcp6" {
		t.Fatalf("probe network = %q, want tcp6", network)
	}
}

// TestResetHealthRepinsThePreferred is the network-change contract: every
// cached verdict describes a network that no longer exists, including the pin.
func TestResetHealthRepinsThePreferred(t *testing.T) {
	d := newScriptedDialer(v4Addr)
	s, _ := newTestSelector(t, Config{Family: PreferV6, Dial: d.dial})

	s.ProbeCurrent(context.Background())
	if cur, _ := s.Current(); cur.Addr != v4Addr {
		t.Fatalf("setup: pinned %s, want %s", cur.Addr, v4Addr)
	}

	s.ResetHealth()
	if cur, _ := s.Current(); cur.Addr != v6Addr {
		t.Fatalf("after reset pinned %s, want the preferred %s", cur.Addr, v6Addr)
	}
	st := stateOf(t, s, v6Addr)
	if st.Probed || st.ConsecutiveFailures != 0 {
		t.Fatalf("reset left state behind: %+v", st)
	}

	// And the probe runs again rather than reusing the old verdict.
	s.ProbeCurrent(context.Background())
	if n := d.count(); n != 2 {
		t.Fatalf("dialled %d times, want a second probe after the reset", n)
	}
}

// TestNewSelectorRejectsEmptyConfigurations: a selector with nothing to dial
// must fail loudly at construction rather than hand out empty addresses to
// fifteen call sites.
func TestNewSelectorRejectsEmptyConfigurations(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no endpoints":        {Family: PreferV6},
		"no address":          {Endpoints: []Endpoint{{Name: "empty"}}, Family: PreferV6},
		"policy excludes all": {Endpoints: []Endpoint{{Name: "v4", V4: v4Addr}}, Family: V6Only},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSelector(cfg); !errors.Is(err, ErrNoCandidates) {
				t.Fatalf("NewSelector = %v, want ErrNoCandidates", err)
			}
		})
	}
}

// TestPinKeepsTheDwellClock: re-pinning the candidate that is already current
// must not restart the dwell, or a client that reconnects every few minutes
// never reaches MinDwell and never returns to its preferred endpoint.
func TestPinKeepsTheDwellClock(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: PreferV6, MinDwell: 5 * time.Minute})
	cands := s.Candidates()
	s.Pin(cands[1])

	for range 10 {
		clk.Advance(30 * time.Second)
		s.Pin(cands[1]) // same candidate, every reconnect
	}

	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v6Addr {
		t.Fatalf("pinned %s after 5m of re-pinning, want the promotion to %s", cur.Addr, v6Addr)
	}
}
