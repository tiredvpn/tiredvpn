package strategy

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestMorphProbeAsksTheNetwork is D5 of the 2026-10-21 stand report. A reprobe
// ran while nothing reached the pool and reported "5/21 strategies available":
// the four Traffic Morph profiles and State Table Exhaustion, none of which left
// the host - their Probe returned nil without a dial. ProbeAll fed that into confidence, Morph rose to 0.92,
// and both outage runs came back on Traffic Morph instead of REALITY.
//
// Through ProbeAll, the path the reprobe takes, against a dead address and a
// live one: a probe that cannot tell them apart is not a probe.
func TestMorphProbeAsksTheNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()
	live := newHelloListener(t)

	for _, tc := range []struct {
		addr string
		want bool
	}{{dead, false}, {live.addr, true}} {
		m := newSilenceManager(t, time.Second, tc.addr)
		m.Register(NewTrafficMorphStrategy(m, YandexVideoProfile, nil, []byte("secret")))
		m.Register(NewStateExhaustionStrategy(m, []byte("secret")))

		results := m.ProbeAll(context.Background(), tc.addr)
		if len(results) != 2 {
			t.Fatalf("%d results, want 2", len(results))
		}
		for _, r := range results {
			if r.Success != tc.want {
				t.Errorf("%s probe against %s: success=%v, want %v (err %v)", r.Strategy.Name(), tc.addr, r.Success, tc.want, r.Error)
			}
		}
	}
}
