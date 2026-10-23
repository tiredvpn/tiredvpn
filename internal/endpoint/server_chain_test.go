package endpoint

import (
	"testing"
	"time"
)

// N9 of the final 1.11.9 acceptance: a verdict parked the address, not the
// server. With two dual-stack servers the client went v6, v4, v6 of the first
// one and never reached the second: each address was parked on its own for
// the base cooldown, which ran out while the other family was being tried.

const (
	aV6 = "[2001:db8::a]:995"
	aV4 = "198.51.100.10:995"
	bV6 = "[2001:db8::b]:995"
	bV4 = "198.51.100.11:995"
)

// twoDualStackServers is a prefer_v6 pool of two dual-stack servers, with the
// shortest jitter the policy allows (0.8 of the cooldown) - the case in which
// a base cooldown ran out soonest.
func twoDualStackServers(t *testing.T) (*Selector, *fakeClock) {
	t.Helper()
	return newTestSelector(t, Config{
		Endpoints: []Endpoint{
			{Name: "a", V6: aV6, V4: aV4, Order: 0},
			{Name: "b", V6: bV6, V4: bV4, Order: 1},
		},
		Family: PreferV6,
		Rand:   func() float64 { return 0 },
	})
}

func candFor(t *testing.T, s *Selector, addr string) Candidate {
	t.Helper()
	c, ok := s.CandidateForAddr(addr)
	if !ok {
		t.Fatalf("no candidate %s", addr)
	}
	return c
}

func reconsidered(s *Selector, clk *fakeClock) string {
	c, _ := s.Reconsider(clk.Now())
	return c.Addr
}

// verdictKinds are the selector's two ways in for a verdict: silence (and
// swallowed handshakes) and a session that died - a dead one or a stalled one.
var verdictKinds = []struct {
	name   string
	report func(s *Selector, c Candidate) bool
}{
	{"silence", func(s *Selector, c Candidate) bool { return s.ReportSilent(c) }},
	{"dead session", func(s *Selector, c Candidate) bool { return s.ReportDeadSession(c) }},
}

// TestAVerdictTriesTheOtherFamilyOnceThenTheNextServer: after a verdict on
// a's v6 the client tries a's v4 - once; v6 stays parked for as long as that
// takes (a session dying there lived up to a minute on the stand), and a
// verdict on v4 parks the whole of a and sends the client to b.
func TestAVerdictTriesTheOtherFamilyOnceThenTheNextServer(t *testing.T) {
	for _, kind := range verdictKinds {
		t.Run(kind.name, func(t *testing.T) {
			s, clk := twoDualStackServers(t)
			if got := reconsidered(s, clk); got != aV6 {
				t.Fatalf("starts on %s, want %s", got, aV6)
			}
			if kind.report(s, candFor(t, s, aV6)) {
				t.Fatal("one family's verdict parked the whole server")
			}
			if got := reconsidered(s, clk); got != aV4 {
				t.Fatalf("after a verdict on a v6: %s, want a's other family %s", got, aV4)
			}

			// A connect cycle there and a session that dies under load.
			clk.Advance(100 * time.Second)
			if got := reconsidered(s, clk); got != aV4 {
				t.Fatalf("100 s into the try on v4 the client is back on %s", got)
			}
			if !kind.report(s, candFor(t, s, aV4)) {
				t.Fatal("verdicts on both families did not park the server")
			}
			if got := reconsidered(s, clk); got != bV6 {
				t.Fatalf("after verdicts on both of a's families: %s, want %s", got, bV6)
			}
			for _, addr := range []string{aV6, aV4} {
				if until := stateOf(t, s, addr).CooldownUntil; !until.After(clk.Now().Add(40 * time.Second)) {
					t.Fatalf("%s is parked only until %v", addr, until)
				}
			}
		})
	}
}

// TestAServerVerdictGrows: each verdict on the whole server parks it longer,
// and a useful session there brings the park back to the base. Read on v6,
// which a swallow run names without a verdict of its own, so the park it gets
// is the server's.
func TestAServerVerdictGrows(t *testing.T) {
	s, clk := twoDualStackServers(t)
	serverPark := func() time.Duration {
		s.ReportSilent(candFor(t, s, aV4), aV6)
		park := stateOf(t, s, aV6).CooldownUntil.Sub(clk.Now())
		clk.Advance(park + time.Second) // back right after the park
		return park
	}
	parks := []time.Duration{serverPark(), serverPark(), serverPark()}
	if parks[0] >= parks[1] || parks[1] >= parks[2] {
		t.Fatalf("server parks %v do not grow", parks)
	}
	s.ReportSessionUseful(candFor(t, s, aV4))
	if got := serverPark(); got != parks[0] {
		t.Fatalf("after a useful session the server is parked for %v, want the base %v", got, parks[0])
	}
}

// TestAServerBackoffDecays is P3-4 of the round-5 review: the backoff only
// ever grew. A server that stays quiet after a park for as long as that park
// lasted starts the next one from the base again.
func TestAServerBackoffDecays(t *testing.T) {
	s, clk := twoDualStackServers(t)
	verdict := func() time.Duration {
		s.ReportSilent(candFor(t, s, aV4), aV6)
		return stateOf(t, s, aV6).CooldownUntil.Sub(clk.Now())
	}
	base := verdict()
	clk.Advance(base + time.Second)
	grown := verdict()
	if grown <= base {
		t.Fatalf("a verdict right after the park parked for %v, the first for %v - the test proves nothing", grown, base)
	}
	clk.Advance(2*grown + time.Second) // the park, then as long again in quiet
	if got := verdict(); got != base {
		t.Fatalf("after a quiet park-length the server is parked for %v, want the base %v", got, base)
	}
}

// TestTheFirstFamilyStaysParkedWhileTheOtherIsTried: a's v6 must not come
// back while v4 is being tried - here v4 fails its connects a minute and a
// half in, past v6's base park, and the client must go to b, not to v6.
func TestTheFirstFamilyStaysParkedWhileTheOtherIsTried(t *testing.T) {
	for _, kind := range verdictKinds {
		t.Run(kind.name, func(t *testing.T) {
			s, clk := twoDualStackServers(t)
			kind.report(s, candFor(t, s, aV6))
			if got := reconsidered(s, clk); got != aV4 {
				t.Fatalf("on %s, want %s", got, aV4)
			}
			clk.Advance(90 * time.Second)
			s.Report(candFor(t, s, aV4), false, 0)
			s.Report(candFor(t, s, aV4), false, 0)
			if got := reconsidered(s, clk); got != bV6 {
				t.Fatalf("v4 parked 90 s after v6's verdict: on %s, want %s", got, bV6)
			}
		})
	}
}

// TestTheServerParkSurvivesACoreRestart: the Android app rebuilds the client
// after every dead connection; a server's grown park must reach the next
// selector.
func TestTheServerParkSurvivesACoreRestart(t *testing.T) {
	s, clk := twoDualStackServers(t)
	s.ReportSilent(candFor(t, s, aV4), aV6)
	first := stateOf(t, s, aV6).CooldownUntil.Sub(clk.Now())
	recs := s.ExportHealth()

	next, nclk := twoDualStackServers(t)
	next.ImportHealth(recs)
	nclk.Advance(first + time.Second)
	next.ReportSilent(candFor(t, next, aV4), aV6)
	if got := stateOf(t, next, aV6).CooldownUntil.Sub(nclk.Now()); got <= first {
		t.Fatalf("after the restart the server is parked for %v, no longer than the first %v", got, first)
	}
}

// TestASingleFamilyServerIsLeftOnItsFirstVerdict: with v4_only there is no
// other family to try.
func TestASingleFamilyServerIsLeftOnItsFirstVerdict(t *testing.T) {
	s, clk := newTestSelector(t, Config{
		Endpoints: []Endpoint{{Name: "a", V6: aV6, V4: aV4}, {Name: "b", V6: bV6, V4: bV4, Order: 1}},
		Family:    V4Only,
	})
	if !s.ReportSilent(candFor(t, s, aV4)) {
		t.Fatal("the only address's verdict did not park the server")
	}
	if got := reconsidered(s, clk); got != bV4 {
		t.Fatalf("on %s, want %s", got, bV4)
	}
}

// TestAnUnroutableFamilyIsNotWaitedFor: a family without a physical route is
// no try, so the routable one's verdict parks the server.
func TestAnUnroutableFamilyIsNotWaitedFor(t *testing.T) {
	s, clk := twoDualStackServers(t)
	s.SetReachable(aV4, false)
	s.SetReachable(bV4, false)
	if !s.ReportDeadSession(candFor(t, s, aV6)) {
		t.Fatal("the routable family's verdict did not park the server")
	}
	if got := reconsidered(s, clk); got != bV6 {
		t.Fatalf("on %s, want %s", got, bV6)
	}
}

// TestASilenceNamingBothFamiliesParksTheServer: a run of swallowed cycles
// that covered both families is one verdict on the server.
func TestASilenceNamingBothFamiliesParksTheServer(t *testing.T) {
	s, clk := twoDualStackServers(t)
	if !s.ReportSilent(candFor(t, s, aV4), aV6) {
		t.Fatal("silence on both families did not park the server")
	}
	if got := reconsidered(s, clk); got != bV6 {
		t.Fatalf("on %s, want %s", got, bV6)
	}
	// Only addresses of the same server count.
	s2, _ := twoDualStackServers(t)
	if s2.ReportSilent(candFor(t, s2, aV6), bV6) {
		t.Fatal("another server's address completed a's chain")
	}
}
