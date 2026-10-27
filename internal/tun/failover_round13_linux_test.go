package tun

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestAnAndroidConnectRefusalCountsAsAnAnswer is P3-4 on the Android
// core's first connect: a refusal there did not end the server's run of
// unanswered handshakes either.
func TestAnAndroidConnectRefusalCountsAsAnAnswer(t *testing.T) {
	var mu sync.Mutex
	var outcomes []HandshakeOutcome
	h := newCtlHarnessWith(t, &ControlConfig{MTU: 1280, HandshakeOutcomeFn: func(outcome HandshakeOutcome, err error) error {
		mu.Lock()
		outcomes = append(outcomes, outcome)
		mu.Unlock()
		return err
	}})
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		_, _ = srv.Write([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})
	}()
	h.cs.mu.Lock()
	h.cs.serverConn = nil
	h.cs.assignedIP = nil
	h.cs.serverIP = nil
	h.cs.waitingForFd = false
	h.cs.config.ConnectFn = func(context.Context) (net.IP, net.IP, net.Conn, error) {
		return net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), cli, nil
	}
	h.cs.mu.Unlock()

	select {
	case resp := <-h.sendAsync(`{"command":"connect"}`+"\n", -1):
		if resp.Status != "error" {
			t.Fatalf("a refused connect answered %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connect never answered")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 1 || outcomes[0] != HandshakeAnsweredOutcome {
		t.Fatalf("handshake outcomes %v, want one answered", outcomes)
	}
}

// TestTheStallProbeAndTheMTUProbeStampTheUplink is P3-9 of the round-8
// review: the stall detector's confirming keepalives and the auto-MTU
// probe go up the tunnel without moving lastTx, so the uplink keepalive
// could follow one of them at once.
func TestTheStallProbeAndTheMTUProbeStampTheUplink(t *testing.T) {
	t.Run("stall probe", func(t *testing.T) {
		h := newStallHarness(t, nil)
		if !h.wait("confirming with keepalives", 2*time.Second) {
			t.Fatalf("no confirmation - the test proves nothing:\n%s", h.out)
		}
		before := h.v.lastTx.Load()
		if !h.wait("keepalive echo 0/2", 2*time.Second) {
			t.Fatalf("the confirmation sent no keepalives - the test proves nothing:\n%s", h.out)
		}
		if h.v.lastTx.Load() == before {
			t.Fatal("the confirming keepalives did not stamp the uplink")
		}
	})
	t.Run("MTU probe", func(t *testing.T) {
		h := newQuietStallHarness(t, nil)
		before := h.v.lastTx.Load()
		time.Sleep(time.Millisecond)
		if err := h.v.sendProbeFrame([]byte{0x01}); err != nil {
			t.Fatalf("probe frame: %v", err)
		}
		if h.v.lastTx.Load() == before {
			t.Fatal("the MTU probe did not stamp the uplink")
		}
	})
}

// TestTheUplinkKeepaliveLooksAgainWithTheConnInHand is the other half of
// P3-9: the keepalive decided before it took v.mu and wrote without looking
// at the stamp again, so a frame that went up meanwhile was followed by a
// keepalive at once - a pair. Here a frame goes up just as the conn is
// taken: no keepalive goes, and the timer waits out the rest of the period.
func TestTheUplinkKeepaliveLooksAgainWithTheConnInHand(t *testing.T) {
	h := newQuietStallHarness(t, nil)
	const period = 200 * time.Millisecond
	restore := SetUplinkKeepaliveDraw(func() time.Duration { return period })
	t.Cleanup(func() { SetUplinkKeepaliveDraw(restore) })
	var once sync.Once
	stamped := make(chan struct{})
	taken := func() { once.Do(func() { h.v.lastTx.Store(monoNow()); close(stamped) }) }
	uplinkConnTaken.Store(&taken)
	t.Cleanup(func() { uplinkConnTaken.Store(nil) })
	resets := make(chan time.Duration, 16)
	f := func(_, _, silent time.Duration) {
		select {
		case resets <- silent:
		default:
		}
	}
	uplinkTimerReset.Store(&f)
	t.Cleanup(func() { uplinkTimerReset.Store(nil) })
	go h.v.keepUplinkAlive()

	select {
	case <-stamped:
	case <-time.After(2 * time.Second):
		t.Fatal("the keepalive never took the conn - the test proves nothing")
	}
	if silent := <-resets; silent == 0 {
		t.Fatal("a keepalive went right behind a frame that went up as the conn was taken")
	}
}

// TestANumericNetworkIDKeepsTheCommand is P3-2 of the round-8 review:
// Kotlin's put("network_id", network.networkHandle) writes a JSON number,
// and the number made the whole command undecodable - dropped, unanswered.
func TestANumericNetworkIDKeepsTheCommand(t *testing.T) {
	var mu sync.Mutex
	var named []string
	h := newCtlHarnessWith(t, &ControlConfig{MTU: 1280, NetworkFn: func(id string) {
		mu.Lock()
		named = append(named, id)
		mu.Unlock()
	}})
	for _, tc := range []struct{ cmd, want string }{
		{`{"command":"status","network_id":432902426637}`, "432902426637"},
		{`{"command":"status","network_id":"101"}`, "101"},
		{`{"command":"status","network_id":true}`, ""},
	} {
		select {
		case resp := <-h.sendAsync(tc.cmd+"\n", -1):
			if resp.Status == "" || resp.Status == "error" || resp.Status == "read-failed" {
				t.Fatalf("%s answered %+v", tc.cmd, resp)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s was not answered", tc.cmd)
		}
		mu.Lock()
		last := ""
		if len(named) > 0 {
			last = named[len(named)-1]
		}
		if tc.want != "" && last != tc.want {
			t.Fatalf("%s: the network named is %q, want %q", tc.cmd, last, tc.want)
		}
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(named) != 2 {
		t.Fatalf("networks named %q, want the two valid ones only", named)
	}
}

// TestAnAndroidConnectResetAfterTheRequestIsAFailure is the control
// server's half of the P2 of the round-14 review: a handshake the exit
// resets after reading the request is reported as failed, not dropped.
func TestAnAndroidConnectResetAfterTheRequestIsAFailure(t *testing.T) {
	var mu sync.Mutex
	var outcomes []HandshakeOutcome
	h := newCtlHarnessWith(t, &ControlConfig{MTU: 1280, HandshakeOutcomeFn: func(outcome HandshakeOutcome, err error) error {
		mu.Lock()
		outcomes = append(outcomes, outcome)
		mu.Unlock()
		return err
	}})
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		_, _ = io.ReadFull(srv, make([]byte, 8))
		srv.Close()
	}()
	h.cs.mu.Lock()
	h.cs.serverConn = nil
	h.cs.assignedIP = nil
	h.cs.serverIP = nil
	h.cs.waitingForFd = false
	h.cs.config.ConnectFn = func(context.Context) (net.IP, net.IP, net.Conn, error) {
		return net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), cli, nil
	}
	h.cs.mu.Unlock()

	select {
	case resp := <-h.sendAsync(`{"command":"connect"}`+"\n", -1):
		if resp.Status != "error" {
			t.Fatalf("a reset connect answered %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connect never answered")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 1 || outcomes[0] != HandshakeFailedOutcome {
		t.Fatalf("handshake outcomes %v, want one failed", outcomes)
	}
}
