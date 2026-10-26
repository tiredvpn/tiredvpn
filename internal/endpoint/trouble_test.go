package endpoint

import (
	"testing"
	"time"
)

// TestMovingOffAParkedServerSkipsOneThatFailedRecently: b is pinned and
// parked, a - preferred - failed before it and its park has run out, c has
// never failed. Within recentTroubleWindow of a's failure the move goes to
// c; once the window is over, a's failure no longer counts and the move goes
// to a, the first in preference order (R1 of the fix13c stand). So it does
// when a has connected since its failure.
func TestMovingOffAParkedServerSkipsOneThatFailedRecently(t *testing.T) {
	for _, tc := range []struct {
		name  string
		since time.Duration // from a's failure to the move
		// connected says a connected after its failure.
		connected bool
		want      string
	}{
		{"a failed 3 minutes ago", 3 * time.Minute, false, "c"},
		{"a failed past the window", recentTroubleWindow + time.Minute, false, "a"},
		{"a connected since", 3 * time.Minute, true, "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addrs := map[string]string{"a": "203.0.113.1:443", "b": "203.0.113.2:443", "c": "203.0.113.3:443"}
			s, clk := newTestSelector(t, Config{
				Endpoints: []Endpoint{
					{Name: "a", V4: addrs["a"]}, {Name: "b", V4: addrs["b"], Order: 1}, {Name: "c", V4: addrs["c"], Order: 2},
				},
				Family:           V4Only,
				FailureThreshold: 2,
			})
			a, b := candFor(t, s, addrs["a"]), candFor(t, s, addrs["b"])
			s.ReportSilent(a)
			s.Pin(b)
			clk.Advance(tc.since)
			if s.IsParked(a) {
				t.Fatal("a is still parked - the test proves nothing")
			}
			if tc.connected {
				s.Report(a, true, 10*time.Millisecond)
				s.Pin(b)
			}
			s.ReportSilent(b)
			got, ok := s.Reconsider(clk.Now())
			if !ok || got.Addr != addrs[tc.want] {
				t.Fatalf("moved off b to %v, want %s %s", got, tc.want, addrs[tc.want])
			}
		})
	}
}
