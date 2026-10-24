package strategy

import (
	"context"
	"testing"
	"time"
)

// TestAFailedUpgradeInAStormDoesNotParkTheServer is P2-2 of the round-3 review
// of PR #126. The storm detector is keyed on the strategy, so short REALITY
// sessions from before the switch to Polling stay in its history; the failed
// upgrade back to REALITY completed the storm, and the storm branch parked the
// server Polling was carrying traffic on. The failed upgrade is the strategy's
// failure: the strategy is parked, the server is not.
func TestAFailedUpgradeInAStormDoesNotParkTheServer(t *testing.T) {
	live := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr, other.addr)
	m.stormDetector = NewStormDetector(StormConfig{Grace: -1, MinSessions: 3})
	m.Register(&greetingStrategy{id: "reality", priority: 5})

	conn, _, cand, ok, err := m.ConnectSession(context.Background(), "")
	if err != nil || !ok {
		t.Fatalf("ConnectSession: %v", err)
	}
	conn.Close()

	// Two REALITY sessions torn down young, each an ordinary short session.
	for range 2 {
		m.RecordSessionStart("reality")
		if m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: cand, HasEndpoint: true}) {
			t.Fatal("a storm before the upgrade - the test proves nothing")
		}
	}
	// Polling carried the tunnel and the swap ended it usefully: the route
	// marker is reset, the endpoint's streak cleared.
	m.SessionEnded(SessionEnd{Strategy: "polling", Endpoint: cand, HasEndpoint: true, Useful: true})

	// The upgrade to REALITY dies young.
	m.RecordSessionStart("reality")
	if !m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: cand, HasEndpoint: true, UpgradeFailed: true}) {
		t.Fatal("no storm on the failed upgrade - the test proves nothing")
	}
	if !m.stormDetector.IsParked("reality") {
		t.Fatal("the storming strategy was not parked")
	}
	if st := endpointState(t, m, live.addr); st.CooldownUntil.After(time.Now()) {
		t.Fatalf("a failed upgrade parked the server the fallback was carrying traffic on: %+v", st)
	}
}
