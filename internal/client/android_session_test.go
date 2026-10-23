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

// androidPool is two loopback servers that accept and hang up: the family
// probe the endpoint walk makes must get an answer, or it moves the pin on
// its own after its timeout (the scripted exit itself is a pipe).
var androidPool []string

func androidPoolManager(t *testing.T) (*strategy.Manager, *targetPipeStrategy) {
	t.Helper()
	if androidPool == nil {
		for range 2 {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					c.Close()
				}
			}()
			androidPool = append(androidPool, ln.Addr().String())
		}
	}
	m := strategy.NewManager()
	// Configured as buildManager configures it: a selector shared by every
	// core of the process.
	cfg := &Config{Selection: SelectionSpec{FailureThreshold: 2, Cooldown: time.Minute, MaxCooldown: 30 * time.Minute}}
	for i, a := range androidPool {
		cfg.Servers = append(cfg.Servers, ServerSpec{Name: fmt.Sprintf("ep%d", i), Addr: a})
	}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	selCfg, err := selectorConfig(cfg, eps)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetEndpointSelection(selCfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors) // the next test starts clean
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
	if got := ccfg.SessionStrategyFn(); got != s {
		t.Fatalf("the relay would be told the session rides %v", got)
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
// forgotten the park. carryFrom, and the next core's first dial
// (takeCarry), hand it over.
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
	carryFrom(m1, sess)
	t.Cleanup(clearCarry)

	m2, s2 := androidPoolManager(t)
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

func clearCarry() {
	androidCarry.mu.Lock()
	defer androidCarry.mu.Unlock()
	clearCarryLocked()
}

// namedPipeStrategy is targetPipeStrategy under a name of its own, logging
// "id@target" for every dial into a shared log.
type namedPipeStrategy struct {
	t    *testing.T
	id   string
	prio int
	log  *[]string
	mu   *sync.Mutex
	hang bool
}

func (s *namedPipeStrategy) Name() string                        { return s.id }
func (s *namedPipeStrategy) ID() string                          { return s.id }
func (s *namedPipeStrategy) Priority() int                       { return s.prio }
func (s *namedPipeStrategy) Probe(context.Context, string) error { return nil }
func (s *namedPipeStrategy) RequiresServer() bool                { return true }
func (s *namedPipeStrategy) Description() string                 { return "pipe exit" }
func (s *namedPipeStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	if s.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s.mu.Lock()
	*s.log = append(*s.log, s.id+"@"+target)
	s.mu.Unlock()
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	playReconnectExit(srv)
	return cli, nil
}

// fourExitPool is a single-family pool of four loopback servers that accept
// and hang up (the family probe needs an answer).
func fourExitPool(t *testing.T) []string {
	t.Helper()
	var addrs []string
	for range 4 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs
}

// coreOn builds one core: a fresh manager over pool with reality and ws,
// logging dials into log.
func coreOn(t *testing.T, pool []string, log *[]string, mu *sync.Mutex) *strategy.Manager {
	t.Helper()
	m := strategy.NewManager()
	// The selector is configured the way buildManager configures it
	// (ResolveEndpoints, selectorConfig): shared by every core of the
	// process. Without it the tests missed that parks outlived a stop (P2-F
	// of the round-6 review). Only the transports are the test's own.
	cfg := &Config{Selection: SelectionSpec{FailureThreshold: 2, Cooldown: time.Minute, MaxCooldown: 30 * time.Minute}}
	for i, a := range pool {
		cfg.Servers = append(cfg.Servers, ServerSpec{Name: fmt.Sprintf("ep%d", i), Addr: a})
	}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	selCfg, err := selectorConfig(cfg, eps)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetEndpointSelection(selCfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors) // the next test starts clean
	m.Register(&namedPipeStrategy{t: t, id: "reality", prio: 1, log: log, mu: mu, hang: hangingDial})
	m.Register(&namedPipeStrategy{t: t, id: "ws", prio: 2, log: log, mu: mu, hang: hangingDial})
	return m
}

// hangingDial, while set, makes every dial hang until its context ends - a
// connect that is still running when the next command comes.
var hangingDial bool
