package endpoint

import (
	"sync/atomic"
	"testing"
	"time"
)

func threeEndpoints() []Endpoint {
	return []Endpoint{
		{Name: "a", V4: "10.0.0.1:995", Weight: 1, Order: 0},
		{Name: "b", V4: "10.0.0.2:995", Weight: 1, Order: 1},
		{Name: "c", V4: "10.0.0.3:995", Weight: 1, Order: 2},
	}
}

func TestParseSelectionPolicy(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    SelectionPolicy
		wantErr bool
	}{
		{"", SelectPriority, false},
		{"priority", SelectPriority, false},
		{"  Latency ", SelectLatency, false},
		{"WEIGHTED", SelectWeighted, false},
		{"round-robin", SelectPriority, true},
	} {
		got, err := ParseSelectionPolicy(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseSelectionPolicy(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
		}
		if got != c.want {
			t.Errorf("ParseSelectionPolicy(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestTuningFamilyOr(t *testing.T) {
	if got := (Tuning{}).FamilyOr(V4Only); got != V4Only {
		t.Errorf("unset family = %v, want the legacy fallback V4Only", got)
	}
	explicit := PreferV4
	if got := (Tuning{Family: &explicit}).FamilyOr(V4Only); got != PreferV4 {
		t.Errorf("explicit family = %v, want PreferV4", got)
	}
}

// TestWeightedIsSticky is the observable-trace requirement, not a performance
// one. Re-drawing the endpoint on every dial would walk a client across its
// whole server list for no reason - a pattern that is trivially distinguishable
// from a client that simply talks to its server.
func TestWeightedIsSticky(t *testing.T) {
	var draws atomic.Int64
	// A Rand that changes its answer every call: if anything re-drew, the order
	// would move.
	seq := []float64{0.1, 0.9, 0.5, 0.05, 0.95, 0.3, 0.7}
	rnd := func() float64 {
		i := draws.Add(1) - 1
		return seq[int(i)%len(seq)]
	}

	s, err := NewSelector(Config{
		Endpoints: threeEndpoints(),
		Family:    V4Only,
		Selection: SelectWeighted,
		Rand:      rnd,
		Now:       func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	drawsAfterBuild := draws.Load()
	if drawsAfterBuild == 0 {
		t.Fatal("weighted selection consumed no randomness - the test proves nothing")
	}

	first, _ := s.Current()
	now := s.Now()
	for i := range 50 {
		got, ok := s.Reconsider(now)
		if !ok {
			t.Fatal("Reconsider returned no candidate")
		}
		if got != first {
			t.Fatalf("reconsider %d moved from %v to %v with nothing failing", i, first, got)
		}
		now = now.Add(time.Hour) // well past MinDwell
	}
	if got := draws.Load(); got != drawsAfterBuild {
		t.Errorf("the order was re-drawn %d time(s) after construction, want 0", got-drawsAfterBuild)
	}
}

// TestWeightedHonoursWeights checks the draw is actually weighted, using a
// fixed Rand so the outcome is a fact about the algorithm and not about luck.
func TestWeightedHonoursWeights(t *testing.T) {
	eps := []Endpoint{
		{Name: "small", V4: "10.0.0.1:995", Weight: 1, Order: 0},
		{Name: "big", V4: "10.0.0.2:995", Weight: 99, Order: 1},
	}

	// 0.5 of the total 100 lands inside "small"'s first unit only if weights are
	// ignored; weighted, 0.5*100 = 50 falls in "big"'s share.
	order := endpointOrder(eps, SelectWeighted, func() float64 { return 0.5 })
	if len(order) != 2 || order[0] != 1 {
		t.Fatalf("endpointOrder = %v, want the heavy endpoint (index 1) first", order)
	}
	// The tail must still contain everything exactly once.
	if order[1] != 0 {
		t.Fatalf("endpointOrder = %v, want the light endpoint second", order)
	}

	// A draw at the very bottom of the range picks the light endpoint, proving
	// the light one is reachable at all rather than sorted out.
	if got := endpointOrder(eps, SelectWeighted, func() float64 { return 0.0 }); got[0] != 0 {
		t.Fatalf("endpointOrder with rnd=0 = %v, want the light endpoint first", got)
	}
}

// TestWeightedZeroWeightStillDrawn: a missing weight means "not stated", not
// "never use". An endpoint that must never be dialled is left out of the list.
func TestWeightedZeroWeightStillDrawn(t *testing.T) {
	eps := []Endpoint{
		{Name: "unweighted", V4: "10.0.0.1:995", Order: 0},
		{Name: "also", V4: "10.0.0.2:995", Order: 1},
	}
	order := endpointOrder(eps, SelectWeighted, func() float64 { return 0.6 })
	if len(order) != 2 {
		t.Fatalf("endpointOrder = %v, want both endpoints", order)
	}
	if order[0] != 1 {
		t.Fatalf("endpointOrder = %v: equal weights and rnd=0.6 should pick the second", order)
	}
}

// TestPriorityFollowsOrderField pins that the default policy is the configured
// order, whatever the slice order is.
func TestPriorityFollowsOrderField(t *testing.T) {
	eps := []Endpoint{
		{Name: "third", V4: "10.0.0.3:995", Order: 30},
		{Name: "first", V4: "10.0.0.1:995", Order: 10},
		{Name: "second", V4: "10.0.0.2:995", Order: 20},
	}
	s, err := NewSelector(Config{Endpoints: eps, Family: V4Only})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	want := []string{"10.0.0.1:995", "10.0.0.2:995", "10.0.0.3:995"}
	for i, c := range s.Candidates() {
		if c.Addr != want[i] {
			t.Fatalf("candidate %d = %s, want %s", i, c.Addr, want[i])
		}
	}
}

// TestLatencyPrefersTheFastestEndpoint drives the latency policy through real
// Report calls, then checks the promotion happens on a reconnect boundary after
// the dwell - not mid-session.
func TestLatencyPrefersTheFastestEndpoint(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	s, err := NewSelector(Config{
		Endpoints: threeEndpoints(),
		Family:    V4Only,
		Selection: SelectLatency,
		MinDwell:  5 * time.Minute,
		Now:       clock,
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	cands := s.Candidates()
	// The configured-first endpoint is the slow one.
	s.Report(cands[0], true, 300*time.Millisecond)
	s.Report(cands[2], true, 20*time.Millisecond)

	// Same instant: the dwell has not elapsed, so nothing may move. Guarding
	// this separately matters - a policy that re-ranks eagerly would flip the
	// pin on every call and undo the anti-flap brake the cooldown provides.
	if got, _ := s.Reconsider(now); got != cands[0] {
		t.Fatalf("promoted to %v before the dwell elapsed", got)
	}

	now = now.Add(6 * time.Minute)
	got, _ := s.Reconsider(now)
	if got != cands[2] {
		t.Fatalf("Reconsider = %v, want the fastest endpoint %v", got, cands[2])
	}
}

// TestLatencyDoesNotReorderFamiliesWithinOneEndpoint: the family policy is a
// separate decision the operator already made, and a censor that throttles one
// family makes it the slow one on purpose. Letting a millisecond comparison
// override prefer_v6 would hand the censor the switch.
func TestLatencyDoesNotReorderFamiliesWithinOneEndpoint(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := NewSelector(Config{
		Endpoints: []Endpoint{{
			Name: "dual", V4: "10.0.0.1:995", V6: "[2001:db8::1]:995",
		}},
		Family:    PreferV6,
		Selection: SelectLatency,
		MinDwell:  time.Minute,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	cands := s.Candidates()
	if cands[0].Family != FamilyV6 {
		t.Fatalf("candidate order = %v, want the v6 address first under prefer_v6", cands)
	}
	// v4 measured much faster than v6.
	s.Report(cands[0], true, 500*time.Millisecond)
	s.Report(cands[1], true, 5*time.Millisecond)

	now = now.Add(time.Hour)
	if got, _ := s.Reconsider(now); got != cands[0] {
		t.Fatalf("Reconsider = %v, want to have stayed on the preferred family %v", got, cands[0])
	}
}

// TestLatencyRanksMeasuredAboveUnmeasured: "no measurement" must not read as
// "instant", or every reconnect would go to a server nobody has ever timed.
func TestLatencyRanksMeasuredAboveUnmeasured(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := NewSelector(Config{
		Endpoints: threeEndpoints(),
		Family:    V4Only,
		Selection: SelectLatency,
		MinDwell:  time.Minute,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	cands := s.Candidates()
	// Only the last endpoint is measured, and slowly. It still outranks the two
	// unknowns.
	s.Report(cands[2], true, 900*time.Millisecond)

	now = now.Add(time.Hour)
	if got, _ := s.Reconsider(now); got != cands[2] {
		t.Fatalf("Reconsider = %v, want the only measured endpoint %v", got, cands[2])
	}
}

// TestLatencyNextWalksTheRankedOrder checks the failover step uses the same
// ranking as the promotion step. Two orders would let Next hand back a
// candidate Reconsider immediately moves away from.
func TestLatencyNextWalksTheRankedOrder(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := NewSelector(Config{
		Endpoints: threeEndpoints(),
		Family:    V4Only,
		Selection: SelectLatency,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	cands := s.Candidates()
	s.Report(cands[0], true, 400*time.Millisecond) // pinned, slowest
	s.Report(cands[1], true, 300*time.Millisecond)
	s.Report(cands[2], true, 10*time.Millisecond) // fastest

	// Pinned is cands[0], which ranks last now. The next one in rank order
	// after it wraps around to the fastest.
	got, ok := s.Next(now)
	if !ok {
		t.Fatal("Next returned nothing with three healthy candidates")
	}
	if got != cands[2] {
		t.Fatalf("Next = %v, want the fastest candidate %v", got, cands[2])
	}
}

// TestSelectionPolicyDefaultIsUnchanged: the zero Config must behave exactly
// like the single-endpoint client always did.
func TestSelectionPolicyDefaultIsUnchanged(t *testing.T) {
	s, err := NewSelector(Config{Endpoints: threeEndpoints(), Family: V4Only})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	if s.cfg.Selection != SelectPriority {
		t.Fatalf("default selection = %v, want priority", s.cfg.Selection)
	}
	cur, _ := s.Current()
	if cur.Addr != "10.0.0.1:995" {
		t.Fatalf("pinned %s, want the first configured endpoint", cur.Addr)
	}
}

func TestNewTunedSelector(t *testing.T) {
	family := V4Only
	s, err := NewTunedSelector(threeEndpoints(), Tuning{
		Family:           &family,
		Selection:        SelectPriority,
		FailureThreshold: 7,
		Cooldown:         42 * time.Second,
		MinDwell:         13 * time.Minute,
	}, PreferV6)
	if err != nil {
		t.Fatalf("NewTunedSelector: %v", err)
	}
	if s.cfg.FailureThreshold != 7 || s.cfg.Cooldown != 42*time.Second || s.cfg.MinDwell != 13*time.Minute {
		t.Fatalf("tuning not carried through: %+v", s.cfg)
	}
	if len(s.Candidates()) != 3 {
		t.Fatalf("got %d candidates, want 3 (V4Only over three v4 endpoints)", len(s.Candidates()))
	}
}
