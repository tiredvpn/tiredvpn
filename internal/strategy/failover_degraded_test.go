package strategy

import (
	"context"
	"testing"
	"time"
)

// TestPollingCountsOnlyTheServersKeepalives: HTTP Polling splices keepalive
// frames of its own into the downlink; a keepalive echo has to be judged by
// the frames the server sent. Two server keepalives arrive in poll bodies,
// the feeder splices more on the boundaries between them, and the count is
// the server's two.
func TestPollingCountsOnlyTheServersKeepalives(t *testing.T) {
	hs := append([]byte{0}, make([]byte, 9)...) // v4 flags-only handshake response
	keepalive := []byte{0, 0, 0, 0}
	bodies := [][]byte{hs, keepalive, tunFrame(60, 0xb2), keepalive}
	c := newScriptedPollingConn(t, bodies)
	fc := useFakeClock(c)
	if _, err := c.Write([]byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, 0x04}); err != nil {
		t.Fatal(err)
	}
	_, spliced := runPollScript(t, c, fc, len(bodies))
	if len(spliced) == 0 {
		t.Fatal("the feeder spliced nothing - the test proves nothing")
	}
	counter, ok := ServerKeepaliveCounterOf(&StrategyConn{Conn: c})
	if !ok {
		t.Fatal("the polling conn is not found under its wrapper")
	}
	if n := counter.ServerKeepalives(); n != 2 {
		t.Fatalf("counted %d server keepalives, want 2 (the feeder spliced %d)", n, len(spliced))
	}
}

// TestDegradedSessionChargesItsEndpoint: the stall detector's verdict is
// booked like a dead session whatever the session's age - a session under a
// per-flow byte cap lives for hours - and a long session that ended degraded
// is not useful, so it clears nothing.
func TestDegradedSessionChargesItsEndpoint(t *testing.T) {
	frozen := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, time.Second, frozen.addr, other.addr)
	m.Register(&greetingStrategy{id: "polling", priority: 5})
	conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
	if err != nil || !ok {
		t.Fatalf("ConnectSession: %v", err)
	}
	conn.Close()

	m.SessionEnded(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true, Degraded: true})
	if st := endpointState(t, m, frozen.addr); !st.CooldownUntil.After(time.Now()) || st.DeadStreak != 1 {
		t.Fatalf("a degraded session did not park its endpoint: %+v", st)
	}
	// Even marked useful by its age, a degraded end clears nothing.
	m.SessionEnded(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true, Useful: true, Degraded: true})
	if st := endpointState(t, m, frozen.addr); st.DeadStreak == 0 {
		t.Fatal("a degraded session cleared the endpoint's dead streak")
	}
}

// TestPollingReportsItsUplinkProgress: a Write only queues; a poll that took
// the bytes to the server moves "sent" up to them. The stall detector times
// a keepalive's echo from there (P2-6 of the round-4 review).
func TestPollingReportsItsUplinkProgress(t *testing.T) {
	c := newScriptedPollingConn(t, [][]byte{{}})
	if _, err := c.Write([]byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, 0x04}); err != nil {
		t.Fatal(err)
	}
	q, ok := UplinkQueueOf(&StrategyConn{Conn: c})
	if !ok {
		t.Fatal("the polling conn's queue is not found under its wrapper")
	}
	if accepted, sent := q.UplinkProgress(); accepted != 8 || sent != 0 {
		t.Fatalf("after a write: accepted %d, sent %d; want 8 and 0", accepted, sent)
	}
	if ok, _ := c.poll(); !ok {
		t.Fatal("poll failed")
	}
	if accepted, sent := q.UplinkProgress(); accepted != 8 || sent != 8 {
		t.Fatalf("after the poll: accepted %d, sent %d; want 8 and 8", accepted, sent)
	}
}
