package endpoint

import "testing"

// TestAForcedUnparkLeavesNoDeadSessionReason: Next un-parks the least-bad
// candidate when every other one is parked. A park for failed connects after
// that is not one for dead sessions (P2-1 of the round-8 review keyed the
// pool poll's check on the reason for the park).
func TestAForcedUnparkLeavesNoDeadSessionReason(t *testing.T) {
	s, clk := newTestSelector(t, Config{
		Endpoints:        []Endpoint{{Name: "a", V4: "203.0.113.1:443"}, {Name: "b", V4: "203.0.113.2:443", Order: 1}},
		Family:           V4Only,
		FailureThreshold: 2,
	})
	a, b := candFor(t, s, "203.0.113.1:443"), candFor(t, s, "203.0.113.2:443")
	s.ReportDeadSession(a)
	s.Report(b, false, 0)
	s.Report(b, false, 0)
	s.Pin(b)
	got, ok := s.Next(clk.Now())
	if !ok || got.Addr != a.Addr || s.IsParked(a) {
		t.Fatalf("Next gave %v %v, parked %v - want a, un-parked; the test proves nothing", got, ok, s.IsParked(a))
	}
	s.Report(a, false, 0)
	s.Report(a, false, 0)
	if !s.IsParked(a) {
		t.Fatal("two failed connects did not park a")
	}
	if s.ParkedForDeadSessions(a) {
		t.Fatal("a park for failed connects was taken for one for dead sessions")
	}
}
