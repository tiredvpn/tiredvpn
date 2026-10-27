package endpoint

import (
	"testing"
	"time"
)

// TestAFailedHandshakePutsBackWhatItsConnectCleared is P3-3 of the round-14
// review: a successful connect clears the failure streak and every park, and
// a session handshake that then fails puts them back. The dead-session park
// was not put back, and a failure booked between the connect and the
// handshake's replaced the streak instead of adding to it.
func TestAFailedHandshakePutsBackWhatItsConnectCleared(t *testing.T) {
	s, _ := newTestSelector(t, Config{
		Endpoints:        []Endpoint{{Name: "a", V4: "203.0.113.1:443"}, {Name: "b", V4: "203.0.113.2:443", Order: 1}},
		Family:           V4Only,
		FailureThreshold: 3,
	})
	a := candFor(t, s, "203.0.113.1:443")

	s.ReportDeadSession(a)
	if !s.ParkedForDeadSessions(a) {
		t.Fatal("no dead-session park - the test proves nothing")
	}
	s.Report(a, true, 0)
	if s.ParkedForDeadSessions(a) {
		t.Fatal("the connect did not lift the park - the test proves nothing")
	}
	s.ReportHandshakeFailed(a)
	if !s.ParkedForDeadSessions(a) {
		t.Fatal("the failed handshake did not put back the dead-session park its connect lifted")
	}

	// A streak of 1, a connect, a failure in between, the handshake's
	// failure: 3, the threshold, parks a.
	b := candFor(t, s, "203.0.113.2:443")
	s.Report(b, false, 0)
	s.Report(b, true, 0)
	s.Report(b, false, 0)
	s.ReportHandshakeFailed(b)
	if !s.IsParked(b) {
		t.Fatal("1 + 1 + 1 failures did not reach the threshold of 3: the failure in between replaced the streak")
	}
}

// TestARestoredParkOutlastsTheHandshakeFailuresOwnCooldown is finding 1 of
// the round-15 review: with the default threshold of 2, the restored streak
// plus the handshake's failure reach it, and recording that failure set a
// cooldown of its own - two minutes here - over the restored ten, so the
// dead-session park ended with the shorter one.
func TestARestoredParkOutlastsTheHandshakeFailuresOwnCooldown(t *testing.T) {
	s, clk := newTestSelector(t, Config{
		Endpoints:        []Endpoint{{Name: "a", V4: "203.0.113.1:443"}, {Name: "b", V4: "203.0.113.2:443", Order: 1}},
		Family:           V4Only,
		FailureThreshold: 2,
		Cooldown:         time.Minute,
		MaxCooldown:      30 * time.Minute,
	})
	a := candFor(t, s, "203.0.113.1:443")
	s.mu.Lock()
	h := &s.health[s.byAddr[a.Addr]]
	h.consecutiveFailures, h.backoff = 1, time.Minute
	h.cooldownUntil = clk.Now().Add(10 * time.Minute)
	h.deadParkUntil = h.cooldownUntil
	s.mu.Unlock()
	if !s.ParkedForDeadSessions(a) {
		t.Fatal("no dead-session park - the test proves nothing")
	}
	s.Report(a, true, 0)
	s.ReportHandshakeFailed(a)
	clk.Advance(5 * time.Minute)
	if !s.ParkedForDeadSessions(a) {
		t.Fatal("5 min into a restored 10 min park it is over: the handshake failure's own cooldown cut it short")
	}
}
