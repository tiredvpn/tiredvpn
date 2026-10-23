package strategy

import (
	"context"
	"fmt"
	"net"
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

// TestASwallowingDualStackServerIsLeft is P1-1 of the acceptance with
// prefer_v6: server a completes every TCP connect on both families and
// answers nothing. The run of swallowed cycles counts both families, so b is
// dialled by the fourth cycle (the stand needed five, and the bound was three
// before the skip lists went back to one per address: REALITY swallowed on v6
// is tried on v4 before the run can say anything about the server - see
// TestATransportSwallowedOnOneFamilyIsTriedOnTheOther).
func TestASwallowingDualStackServerIsLeft(t *testing.T) {
	a6, a4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 2*time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.Register(&protectedGreeter{id: "ws", priority: 7})
	markConnected(m, reality)

	s, cycles := connectCycles(t, m, 4, time.Second)
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

// swallowAtGreeter is protectedGreeter whose handshake is swallowed at the
// listed addresses only.
type swallowAtGreeter struct {
	protectedGreeter
	at map[string]bool
}

func (s *swallowAtGreeter) Connect(ctx context.Context, target string) (net.Conn, error) {
	if s.at[target] {
		s.dials.Add(1)
		swallowed := protectedGreeter{id: s.id, priority: s.priority, swallow: true}
		return swallowed.Connect(ctx, target)
	}
	return s.protectedGreeter.Connect(ctx, target)
}

// TestATransportSwallowedOnOneFamilyIsTriedOnTheOther is P1-3 of the round-5
// review: on a, REALITY is swallowed on v6 and works on v4; Polling is
// swallowed on both; b is down. The skip list had moved to the server with
// the run, so REALITY was never tried on v4 and a was parked whole. The run
// is the server's, the skip list the address's: the second cycle tries
// REALITY on a's v4, and it connects.
func TestATransportSwallowedOnOneFamilyIsTriedOnTheOther(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 2*time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{"[::1]:1", "127.0.0.1:1"})
	reality := &swallowAtGreeter{protectedGreeter{id: "reality", priority: 5}, map[string]bool{a6.addr: true}}
	m.Register(reality)
	m.Register(&swallowAtGreeter{protectedGreeter{id: "polling", priority: 6}, map[string]bool{a6.addr: true, a4.addr: true}})
	markConnected(m, reality)

	s, cycles := connectCycles(t, m, 3, time.Second)
	if s == nil || s.ID() != "reality" || m.GetServerAddr(context.Background()) != a4.addr {
		t.Fatalf("after %d cycles: %v on %s, want reality on a's v4 %s", cycles, s, m.GetServerAddr(context.Background()), a4.addr)
	}
	if cycles > 2 {
		t.Fatalf("connected on cycle %d, want the second", cycles)
	}
	// P3-6 of the round-6 review: the success on v4 clears v4's list only.
	// REALITY is still swallowed on v6, and the next return there skips it.
	if !m.swallowSkip(a6.addr)["reality"] {
		t.Fatal("the success on a's v4 wiped the skip list of its v6")
	}
}

// TestOneTransportSwallowedOnBothFamiliesParksNothing: on a, REALITY is
// swallowed on both families and Polling works. Two cycles of REALITY on two
// families are one transport, not the server's verdict; the third cycle
// connects Polling on a.
func TestOneTransportSwallowedOnBothFamiliesParksNothing(t *testing.T) {
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, 2*time.Second, nil, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	reality := &swallowAtGreeter{protectedGreeter{id: "reality", priority: 5}, map[string]bool{a6.addr: true, a4.addr: true}}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	markConnected(m, reality)

	s, cycles := connectCycles(t, m, 3, time.Second)
	if s == nil || s.ID() != "polling" {
		t.Fatalf("after %d cycles connected through %v, want polling", cycles, s)
	}
	if got := m.GetServerAddr(context.Background()); got != a6.addr && got != a4.addr {
		t.Fatalf("connected on %s: a was left for one swallowed transport", got)
	}
	if b6.accepts.Load()+b4.accepts.Load() != 0 {
		t.Fatal("b was dialled")
	}
}
