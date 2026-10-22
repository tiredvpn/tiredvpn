package strategy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
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

	conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
	if err != nil || !ok || cand.Addr != frozen.addr {
		t.Fatalf("ConnectSession: %v (cand %v, ok %v)", err, cand, ok)
	}
	conn.Close()

	m.SessionEnded(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true, Dead: true})
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

// TestStormMovesTheClient is P1-7 of the PR #126 review. A storm used to charge
// its endpoint one ordinary failure, under the threshold of two, and the next
// connect - on another strategy, same server - cleared it, so storm after storm
// walked the strategy list on one server and never moved the client. A storm
// now parks the endpoint, and the following connect lands elsewhere; a later
// storm there is the route and parks nothing.
func TestStormMovesTheClient(t *testing.T) {
	first := newHelloListener(t)
	second := newHelloListener(t)
	m := newSilenceManager(t, time.Second, first.addr, second.addr)
	m.stormDetector = NewStormDetector(StormConfig{Grace: -1, MinSessions: 1})
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	m.Register(&greetingStrategy{id: "polling", priority: 6})

	storm := func() endpoint.Candidate {
		t.Helper()
		conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
		if err != nil || !ok {
			t.Fatalf("ConnectSession: %v", err)
		}
		conn.Close()
		m.RecordSessionStart(s.ID())
		if !m.SessionEnded(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true}) {
			t.Fatal("no storm declared - the test proves nothing")
		}
		return cand
	}

	if c := storm(); c.Addr != first.addr {
		t.Fatalf("first session rode %s", c.Addr)
	}
	if st := endpointState(t, m, first.addr); !st.CooldownUntil.After(time.Now()) {
		t.Fatal("a storm did not park its endpoint")
	}
	if c := storm(); c.Addr != second.addr {
		t.Fatalf("after a storm on %s the next session still rode %s", first.addr, c.Addr)
	}
	if st := endpointState(t, m, second.addr); st.CooldownUntil.After(time.Now()) {
		t.Fatal("the same storm on a second server right after the first parked it too")
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

// TestFamilyProbeRepinIsLogged: in the stand's run #2 the log said "switching
// to 192.168.110.11:995/v4" and the client then turned up on another server
// without a line at Info saying so. The probe's move has to be in the log.
func TestFamilyProbeRepinIsLogged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()
	live := newHelloListener(t)

	var out bytes.Buffer
	var mu sync.Mutex
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return out.Write(p)
	}))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	m := newSilenceManager(t, time.Second, dead, live.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(out.String(), "did not answer the family probe, switching to "+live.addr) {
		t.Fatalf("the probe moved the pin without a line in the log:\n%s", out.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
