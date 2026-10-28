package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// An HTTP/2 TUN session whose sink is gone is over: on an exit another
// session took its address over, on a relay the exit ended the upstream
// leg. Its frame loop never looked, echoed the client's keepalives with no
// downlink, and the client sat on a dead tunnel for good (P1-1, P2-1 of
// the round-11 review; finding 1 of the round-12 one, through a relay).
// The session ends on the client's next frame, with nothing echoed, or, if
// the client sends nothing, after the backstop. Not at once: the client
// may be moving to the session that displaced this one, and an end of
// stream that beats the new session's answer throws that away (finding 4
// of the round-12 review).

// setH2TUNEndBackstop sets backstopH2TUNEnd's delay for the test.
func setH2TUNEndBackstop(t *testing.T, d time.Duration) {
	t.Helper()
	old := h2TUNEndBackstopNs.Swap(int64(d))
	t.Cleanup(func() { h2TUNEndBackstopNs.Store(old) })
}

// setH2TUNEndGrace sets how long a session takes frames after its sink
// went, for the test.
func setH2TUNEndGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := h2TUNEndGraceNs.Swap(int64(d))
	t.Cleanup(func() { h2TUNEndGraceNs.Store(old) })
}

// clientKeepalives sets both of the client's keepalives - on the server's
// silence and on its own uplink's - to every for the test.
func clientKeepalives(t *testing.T, every time.Duration) {
	t.Helper()
	oldTick := tun.SetKeepaliveInterval(every)
	oldDraw := tun.SetUplinkKeepaliveDraw(func() time.Duration { return every })
	t.Cleanup(func() {
		tun.SetKeepaliveInterval(oldTick)
		tun.SetUplinkKeepaliveDraw(oldDraw)
	})
}

func h2Maker(secret []byte) func(*strategy.Manager) strategy.Strategy {
	return func(m *strategy.Manager) strategy.Strategy { return strategy.NewHTTP2StegoStrategy(m, secret, "") }
}

// waitAbove waits up to within for n to pass before, and reports whether it
// did.
func waitAbove(n *atomic.Int64, before int64, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for n.Load() == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	return n.Load() != before
}

// TestADisplacedH2TUNSessionEndsOnItsNextFrame: two HTTP/2 Stego clients
// straight to the exit on one key and one address. The first one's session
// is displaced; it must still be up a second later - past the 200 ms grace,
// where round 17 closed it - and end at its client's next frame, without
// that frame's packet reaching the exit's TUN. The backstop is out of the
// way, and the client sends nothing on its own.
func TestADisplacedH2TUNSessionEndsOnItsNextFrame(t *testing.T) {
	clientKeepalives(t, time.Hour)
	setH2TUNEndBackstop(t, time.Hour)
	setH2TUNEndGrace(t, 500*time.Millisecond)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ask := net.IPv4(10, 8, 7, 66)
	first, app := clientAskingViaApp(t, exit.addr, ask, h2Maker(secret))
	if !first.LocalIP().Equal(ask) {
		t.Fatalf("the first client got %s", first.LocalIP())
	}
	before := exit.ended.Load()
	second := clientAskingVia(t, exit.addr, ask, h2Maker(secret))
	if !second.LocalIP().Equal(ask) {
		t.Fatalf("the second client got %s, want the same lease %s", second.LocalIP(), ask)
	}
	if waitAbove(&exit.ended, before, time.Second) {
		t.Fatal("the displaced session was closed before its client sent a frame - a client moving to the new session would lose it")
	}
	got := exit.app.got.Load()
	pkt := ipv4Packet(ask, net.IPv4(10, 8, 7, 9))
	if _, err := unix.Write(app, pkt); err != nil {
		t.Fatal(err)
	}
	if !waitAbove(&exit.ended, before, 3*time.Second) {
		t.Fatal("the displaced session is still running 3 s after its client's frame")
	}
	if n := exit.app.got.Load(); n != got {
		t.Fatalf("the displaced session wrote %d packets to the exit's TUN", n-got)
	}
}

// TestADisplacedH2TUNSessionEndsByTheBackstop: the same, with a client that
// sends nothing; the backstop ends it.
func TestADisplacedH2TUNSessionEndsByTheBackstop(t *testing.T) {
	clientKeepalives(t, time.Hour)
	setH2TUNEndBackstop(t, 300*time.Millisecond)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ask := net.IPv4(10, 8, 7, 67)
	clientAskingVia(t, exit.addr, ask, h2Maker(secret))
	before := exit.ended.Load()
	clientAskingVia(t, exit.addr, ask, h2Maker(secret))
	if !waitAbove(&exit.ended, before, 3*time.Second) {
		t.Fatal("the displaced session is still running 3 s after its address was taken over")
	}
}

// TestARelayedH2TUNSessionEndsWithItsUpstreamLeg is finding 1 of the
// round-12 review: an HTTP/2 Stego client through a relay, and the exit
// drops the relay's upstream leg. The relay went on echoing the client's
// keepalives and its read deadline never fired. It has to end the
// client's session, on the next frame or by the backstop.
func TestARelayedH2TUNSessionEndsWithItsUpstreamLeg(t *testing.T) {
	for _, tc := range []struct {
		name                string
		keepalive, backstop time.Duration
	}{
		{"on the next frame", 200 * time.Millisecond, time.Hour},
		{"by the backstop", time.Hour, 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientKeepalives(t, tc.keepalive)
			setH2TUNEndBackstop(t, tc.backstop)
			setH2TUNEndGrace(t, 0)
			secret := []byte("relay-leg-secret-0123456789abcdef")
			exit := newLegExit(t, secret)
			relay, ended := legRelayCounted(t, secret, exit)
			c := clientAskingVia(t, relay, net.IPv4(10, 8, 7, 68), h2Maker(secret))
			if c.LocalIP() == nil {
				t.Fatal("no tunnel address")
			}
			before := ended.Load()
			exit.dropAll()
			if !waitAbove(ended, before, 3*time.Second) {
				t.Fatal("the relay still runs the client's session 3 s after the exit dropped its leg")
			}
		})
	}
}

// TestADisplacedH2TUNSessionTakesFramesThroughItsGrace is finding 2 of the
// round-13 review: a client moving its tunnel - an upgrade is not held back
// while traffic flows - keeps sending on the old session until the new one
// answers. Round 18 ended the old session at its first frame after the
// takeover, 200 ms in, and that end could reach the client first and throw
// the new session away. Frames every 100 ms: the displaced session takes
// them through its grace and ends at the first one after it.
func TestADisplacedH2TUNSessionTakesFramesThroughItsGrace(t *testing.T) {
	clientKeepalives(t, 100*time.Millisecond)
	setH2TUNEndBackstop(t, time.Hour)
	setH2TUNEndGrace(t, 1500*time.Millisecond)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ask := net.IPv4(10, 8, 7, 69)
	clientAskingVia(t, exit.addr, ask, h2Maker(secret))
	before := exit.ended.Load()
	clientAskingVia(t, exit.addr, ask, h2Maker(secret))
	if waitAbove(&exit.ended, before, time.Second) {
		t.Fatal("the displaced session ended within its grace, on a frame of a client that may be moving")
	}
	if !waitAbove(&exit.ended, before, 3*time.Second) {
		t.Fatal("the displaced session is still running past its grace")
	}
}

// TestAnEndedH2TUNSessionLeavesNoBackstop is finding 6 of the round-13
// review: on every session end the backstop's timer stayed behind for 15 s,
// holding the ended session and closing its conn a second time. A session
// that ends stops it.
func TestAnEndedH2TUNSessionLeavesNoBackstop(t *testing.T) {
	setH2TUNEndBackstop(t, time.Hour)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	before := exit.ended.Load()
	c := clientAskingVia(t, exit.addr, net.IPv4(10, 8, 7, 70), h2Maker(secret))
	c.Stop()
	if !waitAbove(&exit.ended, before, 3*time.Second) {
		t.Fatal("the session did not end - the test proves nothing")
	}
	deadline := time.Now().Add(2 * time.Second)
	for h2TUNBackstopsArmed.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := h2TUNBackstopsArmed.Load(); n != 0 {
		t.Fatalf("%d backstops still armed after the session ended", n)
	}
}
