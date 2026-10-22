package strategy

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestAQueuedREALITYHandshakeIsNotSilence is P2-3 of the round-3 review of PR
// #126. REALITY waits at its own per-SNI handshake gate before it dials. When
// the wait outlasted the attempt's dial limit the cut landed before any SYN,
// and it was read as "no TCP connect": silence. With REALITY the only
// transport that silence was the address's verdict, and a healthy server was
// parked for a queue on the client. Run through the real strategy and the
// real gate, with every lane taken, on the fast path (cut at the dial limit)
// and in the scan (the last transport, which waits to the end of the cycle),
// for as many cycles as a run of swallowed handshakes needs.
func TestAQueuedREALITYHandshakeIsNotSilence(t *testing.T) {
	for _, fastPath := range []bool{true, false} {
		name := "scan"
		if fastPath {
			name = "fast path"
		}
		t.Run(name, func(t *testing.T) {
			live := newHelloListener(t)
			other := newHelloListener(t)
			m := newSilenceManager(t, 2*time.Second, live.addr, other.addr)
			r := NewREALITYStrategy(m, []byte("gate-wait-secret"))
			r.gate = newHandshakeGateWith(1, time.Hour, 0)
			for _, dest := range r.destPool {
				sni, _, err := net.SplitHostPort(dest)
				if err != nil {
					sni = dest
				}
				r.gate.laneFor(sni).slots <- struct{}{}
			}
			m.Register(r)
			for _, c := range m.selector().Candidates() {
				m.selector().ReportProbe(c, true, time.Millisecond) // no family probe dial
			}

			for cycle := 1; cycle <= swallowCyclesMax; cycle++ {
				if fastPath {
					markConnected(m, r)
				}
				err := oneCycle(m)
				if err == nil {
					t.Fatal("connected through a full gate - the test proves nothing")
				}
				if errors.Is(err, errAddrSilent) {
					t.Fatalf("cycle %d: a wait at the local handshake gate gave the address its silence verdict: %v", cycle, err)
				}
				if st := endpointState(t, m, live.addr); st.CooldownUntil.After(time.Now()) {
					t.Fatalf("cycle %d: parked for a local queue: %+v", cycle, st)
				}
			}
			if n := live.accepts.Load(); n != 0 {
				t.Fatalf("the server saw %d connects - the gate did not hold the dial", n)
			}
		})
	}
}

// TestAQueuedFastPathGivesTheCycleToTheOthers: a fast path still queued at
// its gate when its dial limit came is not dialled again in the same cycle -
// the queue is no shorter there - and the next transport connects first time.
func TestAQueuedFastPathGivesTheCycleToTheOthers(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, live.addr)
	r := NewREALITYStrategy(m, []byte("gate-wait-secret"))
	r.gate = newHandshakeGateWith(1, time.Hour, 0)
	for _, dest := range r.destPool {
		sni, _, err := net.SplitHostPort(dest)
		if err != nil {
			sni = dest
		}
		r.gate.laneFor(sni).slots <- struct{}{}
	}
	m.Register(r)
	m.Register(&greetingStrategy{id: "polling", priority: 200})
	markConnected(m, r)

	if err := oneCycle(m); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if info := m.GetLastConnectionInfo(); info.StrategyID != "polling" || info.Attempts != 1 {
		t.Fatalf("connected via %s after %d scan attempts, want polling on the first", info.StrategyID, info.Attempts)
	}
}
