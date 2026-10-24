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

// TestStopBooksASessionByWhatCameDown is P3-4 of the round-6 review through
// the tunnel's own loops: the exit's frames come down readFromServer, and
// the user's Stop books the session. Keepalive echoes alone are a tunnel
// alive but useless, and stopping it leaves the server's backoff as it was;
// a data packet down makes the session useful, and the backoff is cleared.
func TestStopBooksASessionByWhatCameDown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		data   bool
		wantBk bool // the backoff is still there after Stop
	}{{"echoes only", false, true}, {"data down", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newQuietStallHarness(t, nil)
			backoff := func() time.Duration {
				for _, r := range h.m.EndpointHealth() {
					if r.Addr == h.addr {
						return r.ServerBackoff
					}
				}
				t.Fatal("no health record for the session's server")
				return 0
			}
			for range 2 {
				h.m.SessionEnded(strategy.SessionEnd{Strategy: "polling", Endpoint: h.v.sessionCand, HasEndpoint: true, Dead: true})
			}
			if backoff() == 0 {
				t.Fatal("two dead sessions grew no server backoff - the test proves nothing")
			}

			h.v.mu.Lock()
			rx := h.v.lastRx
			h.v.mu.Unlock()
			for range 3 {
				if err := h.exit.writeFrame(nil); err != nil { // keepalive echoes
					t.Fatal(err)
				}
			}
			if tc.data {
				if err := h.exit.writeFrame(fixtureFlows(t)[8].data); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				h.v.mu.Lock()
				moved := h.v.lastRx.After(rx)
				h.v.mu.Unlock()
				if moved {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("nothing the exit sent reached the client")
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond) // the data packet, if any, is behind the echoes

			h.v.tun.hostOwnedLink = true // the host owns the link: Stop leaves the routes alone
			h.v.Stop()
			if got := backoff(); (got != 0) != tc.wantBk {
				t.Fatalf("after Stop the server backoff is %v", got)
			}
		})
	}
}
