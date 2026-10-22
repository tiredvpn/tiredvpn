package strategy

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestMorphProbeSaysItDoesNotKnow covers D5 and its P3 follow-up from the PR
// #126 review. A reprobe during an outage reported "5/21 strategies
// available": the four Traffic Morph profiles and State Table Exhaustion
// answered their probe without touching the network, and ProbeAll raised their
// confidence to 0.92 while every honest probe failed. The first fix had them
// dial - five extra bare connects in every reprobe burst. Their probe now says
// "unknown": no dial, not available, and confidence left where it was.
func TestMorphProbeSaysItDoesNotKnow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()
	live := newHelloListener(t)

	for _, addr := range []string{dead, live.addr} {
		m := newSilenceManager(t, time.Second, addr)
		m.Register(NewTrafficMorphStrategy(m, YandexVideoProfile, nil, []byte("secret")))
		m.Register(NewStateExhaustionStrategy(m, []byte("secret")))
		before := map[string]float64{}
		for id, r := range m.GetStats() {
			before[id] = r.Confidence
		}

		for _, r := range m.ProbeAll(context.Background(), addr) {
			if r.Success {
				t.Errorf("%s probe against %s reported available", r.Strategy.Name(), addr)
			}
		}
		for id, r := range m.GetStats() {
			if r.Confidence != before[id] {
				t.Errorf("%s: a probe that knows nothing moved confidence %.2f -> %.2f", id, before[id], r.Confidence)
			}
		}
	}
	if n := live.accepts.Load(); n != 0 {
		t.Errorf("the probes dialled the server %d times", n)
	}
}
