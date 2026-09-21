package endpoint

import (
	"testing"
	"time"
)

// twoDualEndpoints builds two dual-addressed servers, so the candidate list is
// four (endpoint, family) pairs: ep0v6, ep0v4, ep1v6, ep1v4 under PreferV6.
func twoDualEndpoints() []Endpoint {
	return []Endpoint{
		{Name: "a", V6: "[2001:db8::1]:443", V4: "203.0.113.1:443"},
		{Name: "b", V6: "[2001:db8::2]:443", V4: "203.0.113.2:443"},
	}
}

// TestReconsiderMovesOffUnreachablePinned is the core of "if IPv6 is gone, it is
// gone": with the preferred family marked unreachable, a fresh connect cycle
// must move off it to the reachable family instead of staying pinned and
// dialling into a family the host cannot reach.
//
// Discriminator: before the reachability skip, Reconsider only moved off a
// candidate that was in a time-based cooldown. An unreachable-but-not-parked
// pin stayed put, which is the stall this fixes - so the pre-fix code returns
// v6Addr here and fails the test.
//
// Positive control (rule 2): the SAME selector, with v6 left reachable, stays
// on the preferred v6 - so the test can tell "moved because unreachable" from
// "moved for any reason".
func TestReconsiderMovesOffUnreachablePinned(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: PreferV6})

	// Positive control first, on an untouched selector: preferred family stays.
	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v6Addr {
		t.Fatalf("control: pinned %s, want the preferred %s", cur.Addr, v6Addr)
	}

	if !s.SetReachable(v6Addr, false) {
		t.Fatal("SetReachable(v6,false) reported no change on a reachable candidate")
	}
	if cur, _ := s.Reconsider(clk.Now()); cur.Addr != v4Addr {
		t.Fatalf("with v6 unreachable, Reconsider pinned %s, want the reachable %s", cur.Addr, v4Addr)
	}

	// And once the route is back, the preferred family is re-admitted.
	if !s.SetReachable(v6Addr, true) {
		t.Fatal("SetReachable(v6,true) reported no change after marking it unreachable")
	}
}

// TestNextSkipsUnreachable: the failover walk must step over an unreachable
// candidate to the next reachable one, not hand it back.
//
// Discriminator: the pre-fix Next returned the first candidate after the pin
// that was not in cooldown - ep0v4 - even with no physical route. The fixed
// walk skips it and returns ep1v6.
func TestNextSkipsUnreachable(t *testing.T) {
	s, clk := newTestSelector(t, Config{Family: PreferV6, Endpoints: twoDualEndpoints()})
	cands := s.Candidates() // ep0v6, ep0v4, ep1v6, ep1v4
	ep0v4 := cands[1].Addr
	ep1v6 := cands[2].Addr

	s.SetReachable(ep0v4, false)

	got, ok := s.Next(clk.Now()) // pinned is ep0v6 (idx 0)
	if !ok {
		t.Fatal("Next found nothing to fall back to")
	}
	if got.Addr == ep0v4 {
		t.Fatalf("Next returned the unreachable %s", ep0v4)
	}
	if got.Addr != ep1v6 {
		t.Fatalf("Next returned %s, want the next reachable %s", got.Addr, ep1v6)
	}
}

// TestUnreachableIsNotUnparked: when every reachable fallback is parked, Next
// un-parks the least-bad one - but it must never un-park an unreachable
// candidate, because un-parking gives it no route.
//
// The unreachable candidate ep0v4 is given the cleanest health (zero failures),
// so the pre-fix betterFallback picks it first: that is exactly the trap. Every
// reachable fallback is parked, so a correct walk still returns one of them
// (un-parked as a last resort) rather than the routeless ep0v4.
func TestUnreachableIsNotUnparked(t *testing.T) {
	s, clk := newTestSelector(t, Config{
		Family: PreferV6, FailureThreshold: 1, Cooldown: time.Minute, Endpoints: twoDualEndpoints(),
	})
	cands := s.Candidates() // ep0v6, ep0v4, ep1v6, ep1v4
	ep0v4 := cands[1]
	ep1v6 := cands[2]
	ep1v4 := cands[3]

	// Park both of endpoint b's addresses; ep0v4 stays clean but is unroutable.
	s.Report(ep1v6, false, 0)
	s.Report(ep1v4, false, 0)
	s.SetReachable(ep0v4.Addr, false)

	got, ok := s.Next(clk.Now()) // pinned ep0v6
	if !ok {
		t.Fatal("Next found nothing to fall back to")
	}
	if got.Addr == ep0v4.Addr {
		t.Fatalf("Next un-parked the unreachable %s; must pick a reachable fallback", ep0v4.Addr)
	}
	if got.Addr != ep1v6.Addr && got.Addr != ep1v4.Addr {
		t.Fatalf("Next returned %s, want a reachable (parked) endpoint-b address", got.Addr)
	}
}

// TestGateAddrsExcludeUnreachable: the connectivity gate should not be handed an
// address whose family has no route - it would only spend a TCP timeout on a
// dial that cannot leave the host.
func TestGateAddrsExcludeUnreachable(t *testing.T) {
	s, _ := newTestSelector(t, Config{Family: PreferV6, Endpoints: twoDualEndpoints()})
	cands := s.Candidates()
	ep0v6 := cands[0]
	ep1v6 := cands[2].Addr

	full := s.GateAddrs(ep0v6)
	if !contains(full, ep1v6) {
		t.Fatalf("control: GateAddrs %v should list %s before it is excluded", full, ep1v6)
	}

	s.SetReachable(ep1v6, false)
	got := s.GateAddrs(ep0v6)
	if contains(got, ep1v6) {
		t.Fatalf("GateAddrs %v still lists the unreachable %s", got, ep1v6)
	}
}

// TestResetHealthClearsUnreachable: a network change may bring a family up, so
// ResetHealth must forget the route verdict and let the next preflight re-mark.
func TestResetHealthClearsUnreachable(t *testing.T) {
	s, _ := newTestSelector(t, Config{Family: PreferV6})
	s.SetReachable(v6Addr, false)
	if s.Reachable(v6Addr) {
		t.Fatal("v6 should read unreachable after SetReachable(false)")
	}
	s.ResetHealth()
	if !s.Reachable(v6Addr) {
		t.Fatal("ResetHealth must clear the unreachable verdict")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
