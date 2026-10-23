package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// targetPipeStrategy plays the reconnect exit over a pipe and records the
// address each dial was aimed at.
type targetPipeStrategy struct {
	t       *testing.T
	mu      sync.Mutex
	targets []string
}

func (s *targetPipeStrategy) Name() string                        { return "polling" }
func (s *targetPipeStrategy) ID() string                          { return "polling" }
func (s *targetPipeStrategy) Priority() int                       { return 1 }
func (s *targetPipeStrategy) Probe(context.Context, string) error { return nil }
func (s *targetPipeStrategy) RequiresServer() bool                { return true }
func (s *targetPipeStrategy) Description() string                 { return "pipe exit" }
func (s *targetPipeStrategy) Connect(_ context.Context, target string) (net.Conn, error) {
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	playReconnectExit(srv)
	return cli, nil
}

func (s *targetPipeStrategy) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 {
		return ""
	}
	return s.targets[len(s.targets)-1]
}

var androidPool = []string{"203.0.113.10:995", "203.0.113.20:995"}

func androidPoolManager(t *testing.T) (*strategy.Manager, *targetPipeStrategy) {
	t.Helper()
	m := strategy.NewManager()
	var eps []endpoint.Endpoint
	for i, a := range androidPool {
		eps = append(eps, endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: a, Order: i})
	}
	if err := m.SetEndpointSelection(endpoint.Config{Endpoints: eps, Family: endpoint.V4Only, FailureThreshold: 2,
		Cooldown: time.Minute, MaxCooldown: 30 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	s := &targetPipeStrategy{t: t}
	m.Register(s)
	return m, s
}

// TestAndroidDegradedVerdictMovesTheClient is P1-2 of the round-4 review:
// the relay's degraded verdict charged the server, and the auto-reconnect
// right after reset every endpoint's health, put the pin back on the first
// server and dialled the same transport there - a verdict that moved nothing.
// The whole chain runs here: connect on A, the relay's session end with the
// verdict, the relay's own reconnect.
func TestAndroidDegradedVerdictMovesTheClient(t *testing.T) {
	m, s := androidPoolManager(t)
	sess := &androidSession{mgr: m, linkUp: func() bool { return true }}
	ccfg := androidControlConfig(&Config{ServerAddr: androidPool[0], TunMTU: 1280}, m, false, sess)

	if _, _, conn, err := ccfg.ConnectFn(t.Context()); err != nil {
		t.Fatalf("connect: %v", err)
	} else {
		conn.Close()
	}
	if got := s.last(); got != androidPool[0] {
		t.Fatalf("first session on %s", got)
	}
	ccfg.SessionEndedFn(tun.RelaySessionEnd{Lifetime: 2 * time.Minute, Degraded: true, Stall: 30 * time.Second})

	res, err := ccfg.ReconnectFn(t.Context(), reconnClientIP, 1280, false)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	res.Conn.Close()
	if got := s.last(); got != androidPool[1] {
		t.Fatalf("after a degraded verdict on %s the reconnect dialled %s", androidPool[0], got)
	}
}

// TestAndroidVerdictSurvivesACoreRestart: the app answers a dead connection
// by restarting the whole core, and every core built a fresh manager that had
// forgotten the park. carryFrom/carryInto hand it to the next core.
func TestAndroidVerdictSurvivesACoreRestart(t *testing.T) {
	m1, _ := androidPoolManager(t)
	sess := &androidSession{mgr: m1, linkUp: func() bool { return true }}
	ccfg := androidControlConfig(&Config{ServerAddr: androidPool[0], TunMTU: 1280}, m1, false, sess)
	if _, _, conn, err := ccfg.ConnectFn(t.Context()); err != nil {
		t.Fatalf("connect: %v", err)
	} else {
		conn.Close()
	}
	ccfg.SessionEndedFn(tun.RelaySessionEnd{Lifetime: 2 * time.Minute, Degraded: true})
	carryFrom(m1)
	t.Cleanup(func() { androidCarry.health, androidCarry.storm = nil, nil })

	m2, s2 := androidPoolManager(t)
	carryInto(m2)
	ccfg2 := androidControlConfig(&Config{ServerAddr: androidPool[0], TunMTU: 1280}, m2, false, &androidSession{mgr: m2})
	if _, _, conn, err := ccfg2.ConnectFn(t.Context()); err != nil {
		t.Fatalf("connect on the new core: %v", err)
	} else {
		conn.Close()
	}
	if got := s2.last(); got != androidPool[1] {
		t.Fatalf("the restarted core dialled %s, the server parked a moment before", got)
	}
}

// TestAndroidSessionsFeedTheStormDetector: no Android path called
// RecordSessionStart, so every SessionClosed found nothing open and the storm
// detector could never fire there.
func TestAndroidSessionsFeedTheStormDetector(t *testing.T) {
	m, s := androidPoolManager(t)
	sess := &androidSession{mgr: m, linkUp: func() bool { return true }}
	ccfg := androidControlConfig(&Config{ServerAddr: androidPool[0], TunMTU: 1280}, m, false, sess)
	if _, _, conn, err := ccfg.ConnectFn(t.Context()); err != nil {
		t.Fatalf("connect: %v", err)
	} else {
		conn.Close()
	}
	if _, ok := m.SessionOpenedAt(s.ID()); !ok {
		t.Fatal("an Android session start was not recorded")
	}
	ccfg.SessionEndedFn(tun.RelaySessionEnd{Lifetime: 3 * time.Second, Reason: "server_read: EOF"})
	if _, ok := m.SessionOpenedAt(s.ID()); ok {
		t.Fatal("the session end was not booked")
	}
	res, err := ccfg.ReconnectFn(t.Context(), reconnClientIP, 1280, false)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	res.Conn.Close()
	if _, ok := m.SessionOpenedAt(s.ID()); !ok {
		t.Fatal("a session started by a reconnect was not recorded")
	}
}
