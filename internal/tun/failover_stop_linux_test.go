package tun

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestAUsefulSessionTheUserStopsClearsTheServerBackoff is P3-4 of the
// round-5 review: only SessionEnded reported a useful session, and Stop never
// called it, so a server whose tunnel carried traffic for an hour until the
// user turned it off kept the backoff its earlier verdicts had grown.
func TestAUsefulSessionTheUserStopsClearsTheServerBackoff(t *testing.T) {
	m, addrs, ps := poolManager(t, 2)
	backoff := func() time.Duration {
		for _, r := range m.EndpointHealth() {
			if r.Addr == addrs[0] {
				return r.ServerBackoff
			}
		}
		t.Fatal("no health record for the first server")
		return 0
	}
	cand, ok := m.CurrentCandidate()
	if !ok || cand.Addr != addrs[0] {
		t.Fatalf("pinned %v", cand)
	}
	for range 2 {
		m.SessionEnded(strategy.SessionEnd{Strategy: ps.ID(), Endpoint: cand, HasEndpoint: true, Dead: true})
	}
	if backoff() == 0 {
		t.Fatal("two dead sessions grew no server backoff - the test proves nothing")
	}

	stop := func(lastData time.Time) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		cli, srv := net.Pipe()
		defer srv.Close()
		now := time.Now()
		v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, strategy: ps,
			conn: cli, connectedAt: now.Add(-time.Hour), lastRx: now, lastData: lastData,
			sessionCand: cand, hasSessionCand: true, tun: &TUNDevice{file: r, hostOwnedLink: true}}
		v.Stop()
	}

	// P3-4 of the round-6 review: an hour of keepalive echoes and no data is
	// a tunnel alive but useless, and stopping it clears nothing.
	stop(time.Time{})
	if backoff() == 0 {
		t.Fatal("stopping a session that echoed keepalives and carried no data cleared the server backoff")
	}
	stop(time.Now())
	if got := backoff(); got != 0 {
		t.Fatalf("after the user stopped an hour-long session the server backoff is %v", got)
	}
}
