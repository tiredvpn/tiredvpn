package strategy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestDeadSessionParksTheEndpoint is D6 of the 2026-10-21 stand report. Every
// connect to the frozen server succeeded and every success cleared its failure
// streak, so the endpoint layer never learned that no session survived: ten
// choices of the same address in six minutes, the other server never dialled.
func TestDeadSessionParksTheEndpoint(t *testing.T) {
	frozen := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, time.Second, frozen.addr, other.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()

	m.ReportDeadSession()
	if st := endpointState(t, m, frozen.addr); !st.CooldownUntil.After(time.Now()) {
		t.Fatal("a dead session did not park its endpoint")
	}

	conn, _, err = m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect after the dead session: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(context.Background()); got != other.addr {
		t.Fatalf("pinned %s after a dead session, want %s", got, other.addr)
	}
}

// TestStormChargesTheEndpoint: a storm is three dead sessions of one strategy;
// the endpoint they were on takes an ordinary failure for it, so the pool joins
// the strategy list in working around a freeze.
func TestStormChargesTheEndpoint(t *testing.T) {
	live := newHelloListener(t)
	other := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr, other.addr)
	m.stormDetector = NewStormDetector(StormConfig{Grace: -1, MinSessions: 1})
	m.Register(&greetingStrategy{id: "reality", priority: 5})

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()

	m.RecordSessionStart("reality")
	if !m.SessionEnded("reality", false) {
		t.Fatal("no storm declared - the test proves nothing")
	}
	if st := endpointState(t, m, live.addr); st.ConsecutiveFailures != 1 {
		t.Fatalf("storm left the endpoint with %d failures, want 1", st.ConsecutiveFailures)
	}

	// No storm, no charge.
	m2 := newSilenceManager(t, time.Second, live.addr, other.addr)
	m2.Register(&greetingStrategy{id: "reality", priority: 5})
	conn, _, err = m2.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()
	m2.SessionEnded("reality", false)
	if st := endpointState(t, m2, live.addr); st.ConsecutiveFailures != 0 {
		t.Fatalf("one dead session without a storm charged the endpoint %d failures", st.ConsecutiveFailures)
	}
}

// TestPollingDeathReadsAsSilence: HTTP Polling ends a dead session with its own
// error, not a read deadline, and the TUN client must still see a server that
// went quiet - in stand run #7b every Polling session died this way. It must
// stay a non-timeout for the SOCKS relay (see errPollingDead).
func TestPollingDeathReadsAsSilence(t *testing.T) {
	if !errors.Is(errPollingDead, ErrServerSilent) {
		t.Fatal("errPollingDead does not match ErrServerSilent")
	}
	if ne, ok := errors.AsType[net.Error](errPollingDead); ok && ne.Timeout() {
		t.Fatal("errPollingDead became a timeout; the SOCKS relay would keep a dead exit open")
	}
}
