package strategy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// N9 of the final 1.11.9 acceptance, through the manager: a verdict on one
// family of a dual-stack server is followed by one try of its other family,
// and then by the next server - not by v6, v4, v6 of the same one.

// dualStackPool is a prefer_v6 manager over servers given as {v6, v4} pairs.
// With a clock, the selector runs on it, with the shortest jitter the policy
// allows (0.8 of a cooldown) - the case in which a park runs out soonest.
func dualStackPool(t *testing.T, connectTimeout time.Duration, clk *endpointClock, servers ...[2]string) *Manager {
	t.Helper()
	eps := make([]endpoint.Endpoint, len(servers))
	for i, s := range servers {
		eps[i] = endpoint.Endpoint{Name: fmt.Sprintf("srv%d", i), V6: s[0], V4: s[1], Order: i}
	}
	cfg := endpoint.Config{Endpoints: eps, Family: endpoint.PreferV6, FailureThreshold: 2, Cooldown: time.Minute}
	if clk != nil {
		cfg.Now = clk.Now
		cfg.Rand = func() float64 { return 0 }
	}
	sel, err := endpoint.NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	m := NewManager()
	m.endpoints = sel
	m.maxRetries = 1
	m.connectTimeout = connectTimeout
	m.probeTimeout = connectTimeout
	return m
}

// TestASwallowingDualStackServerIsLeftWithinThreeCycles is P1-1 of the
// acceptance with prefer_v6: server a completes every TCP connect on both
// families and answers nothing. The run of swallowed cycles counts both
// families, so b is dialled by the third cycle (the stand needed five: two on
// a's v6, two on its v4).
func TestASwallowingDualStackServerIsLeftWithinThreeCycles(t *testing.T) {
	a6, a4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 2*time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.Register(&protectedGreeter{id: "ws", priority: 7})
	markConnected(m, reality)

	s, cycles := connectCycles(t, m, 3, time.Second)
	if s == nil {
		t.Fatalf("not connected after %d cycles; a v6 %+v, a v4 %+v", cycles,
			endpointState(t, m, a6.addr), endpointState(t, m, a4.addr))
	}
	if got := m.GetServerAddr(context.Background()); got != b6.addr {
		t.Fatalf("connected through %s, want b's v6 %s", got, b6.addr)
	}
	if a4.accepts.Load() == 0 {
		t.Fatal("a's v4 was never tried - the other family got no chance")
	}
}

// TestDeadSessionsWalkTheOtherFamilyOnceThenTheNextServer: sessions that die
// on a's v6 and then on its v4 park all of a; the next connect goes to b. The
// stand saw v6, v4, v6 of a (A4 b_bc40k): each session lived about a minute
// under load, longer than the base park of the address before it. The stall
// detector's verdicts (A1, A2) land the same way.
func TestDeadSessionsWalkTheOtherFamilyOnceThenTheNextServer(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(SessionEnd) SessionEnd
	}{
		{"dead session", func(e SessionEnd) SessionEnd { e.Dead = true; return e }},
		{"degraded", func(e SessionEnd) SessionEnd { e.Degraded = true; return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
			b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
			clk := newEndpointClock()
			m := dualStackPool(t, time.Second, clk, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
			m.Register(&greetingStrategy{id: "polling", priority: 5})

			var path []string
			for range 3 {
				conn, s, cand, ok, err := m.ConnectSession(context.Background(), "")
				if err != nil || !ok {
					t.Fatalf("ConnectSession: %v", err)
				}
				conn.Close()
				path = append(path, cand.Addr)
				clk.Advance(55 * time.Second) // the session's life on the stand
				m.SessionEnded(tc.end(SessionEnd{Strategy: s.ID(), Endpoint: cand, HasEndpoint: true}))
			}
			want := []string{a6.addr, a4.addr, b6.addr}
			for i := range want {
				if path[i] != want[i] {
					t.Fatalf("sessions ran on %v, want %v (a v6, a v4, b v6)", path, want)
				}
			}
		})
	}
}
