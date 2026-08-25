package strategy

import (
	"context"
	"net"
	"testing"
)

// liveV6Listener starts an IPv6 loopback listener and returns its address plus
// a stop func that waits for the accept loop to drain. Skips the whole test
// when the host has no IPv6 loopback.
//
// Tests below never count accepts: an accept is observed after the dial already
// returned, so a counter races the code under test. Instead they change the
// world (kill the listener) between calls, which makes a stale cached verdict
// and a fresh probe produce different answers.
func liveV6Listener(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable on this host: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	var once bool
	return ln.Addr().String(), func() {
		if once {
			return
		}
		once = true
		ln.Close()
		<-done
	}
}

// deadV6Addr binds an IPv6 loopback port and releases it, yielding an address
// that refuses connections fast (no firewall timeout involved).
func deadV6Addr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable on this host: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestGetServerAddrSelection pins the transport-family choice. This is the
// decision that used to be bypassed: the probe dialled IPv6 while the
// connectivity gate and the periodic reprobe were built straight from
// cfg.ServerAddr, so a host with a censored IPv4 never brought the tunnel up
// even though its v6 path was clean.
func TestGetServerAddrSelection(t *testing.T) {
	const v4 = "127.0.0.1:443"

	t.Run("no v6 configured falls through to v4", func(t *testing.T) {
		m := &Manager{serverAddrV4: v4, preferIPv6: true, fallbackToV4: true}
		// Without a v6 address there is nothing to probe; returning anything
		// but v4 here would dial an empty host.
		if got := m.GetServerAddr(context.Background()); got != v4 {
			t.Fatalf("GetServerAddr = %q, want %q", got, v4)
		}
		if m.ipv6CheckedOnce {
			t.Error("connectivity probe ran with no v6 address configured")
		}
	})

	t.Run("preferIPv6 false keeps v4 even with v6 configured", func(t *testing.T) {
		// Fallback is off, so if the short-circuit were missing the failed probe
		// against the dead v6 address would surface v6 here instead of v4.
		m := &Manager{serverAddrV4: v4, serverAddrV6: deadV6Addr(t), preferIPv6: false, fallbackToV4: false}
		if got := m.GetServerAddr(context.Background()); got != v4 {
			t.Fatalf("GetServerAddr = %q, want %q", got, v4)
		}
		// -prefer-ipv6=false is a "keep this client off IPv6" knob: it must not
		// even cost a probe dial.
		if m.ipv6CheckedOnce {
			t.Error("probed IPv6 despite preferIPv6=false")
		}
	})

	t.Run("v6 reachable wins", func(t *testing.T) {
		live, stop := liveV6Listener(t)
		defer stop()

		m := &Manager{serverAddrV4: v4, serverAddrV6: live, preferIPv6: true, fallbackToV4: true}
		if got := m.GetServerAddr(context.Background()); got != live {
			t.Fatalf("GetServerAddr = %q, want the v6 address %q", got, live)
		}
		if !m.ipv6Available {
			t.Error("reachable v6 was not recorded as available")
		}
	})

	t.Run("v6 unreachable with fallback lands on v4", func(t *testing.T) {
		m := &Manager{serverAddrV4: v4, serverAddrV6: deadV6Addr(t), preferIPv6: true, fallbackToV4: true}
		if got := m.GetServerAddr(context.Background()); got != v4 {
			t.Fatalf("GetServerAddr = %q, want the v4 fallback %q", got, v4)
		}
	})

	t.Run("v6 unreachable without fallback still returns v6", func(t *testing.T) {
		dead := deadV6Addr(t)
		m := &Manager{serverAddrV4: v4, serverAddrV6: dead, preferIPv6: true, fallbackToV4: false}
		// -fallback-v4=false is an explicit "never touch IPv4" knob; silently
		// dropping to v4 here would defeat it and leak onto the blocked family.
		if got := m.GetServerAddr(context.Background()); got != dead {
			t.Fatalf("GetServerAddr = %q, want %q (fallback disabled)", got, dead)
		}
	})
}

// TestGetServerAddrProbeCaching proves the verdict is computed once. Every
// Connect and every reprobe calls GetServerAddr; re-probing on each call would
// add a dial (and up to a 3s timeout) to the hot reconnect path.
func TestGetServerAddrProbeCaching(t *testing.T) {
	live, stop := liveV6Listener(t)
	defer stop()

	m := &Manager{serverAddrV4: "127.0.0.1:443", serverAddrV6: live, preferIPv6: true, fallbackToV4: true}
	ctx := context.Background()

	if got := m.GetServerAddr(ctx); got != live {
		t.Fatalf("GetServerAddr = %q, want %q", got, live)
	}

	// Tear the v6 endpoint down. A cached verdict keeps answering v6; a
	// re-probe would fail and fall back to v4, which is what makes this
	// observable without racing an accept counter.
	stop()

	for i := range 4 {
		if got := m.GetServerAddr(ctx); got != live {
			t.Fatalf("call %d: GetServerAddr = %q, want the cached %q (probe must not repeat)", i, got, live)
		}
	}
}

// TestResetIPv6CheckReprobes covers the network-change path (WiFi -> LTE):
// after ResetIPv6Check the cached verdict must be discarded, otherwise a client
// that lost IPv6 keeps dialling a dead family until restart.
func TestResetIPv6CheckReprobes(t *testing.T) {
	live, stop := liveV6Listener(t)
	defer stop()

	const v4 = "127.0.0.1:443"
	m := &Manager{serverAddrV4: v4, serverAddrV6: live, preferIPv6: true, fallbackToV4: true}
	ctx := context.Background()

	if got := m.GetServerAddr(ctx); got != live {
		t.Fatalf("GetServerAddr = %q, want %q", got, live)
	}

	// Network changed: the v6 endpoint is gone.
	stop()

	m.ResetIPv6Check()
	if m.ipv6CheckedOnce {
		t.Fatal("ResetIPv6Check left the checked-once flag set")
	}
	if got := m.GetServerAddr(ctx); got != v4 {
		t.Fatalf("GetServerAddr = %q after reset, want the v4 fallback %q", got, v4)
	}
	if m.ipv6Available {
		t.Error("re-probe did not clear the stale availability flag")
	}
}

// TestCheckIPv6ConnectivityNoAddr guards the early return: an unconfigured v6
// address must report "unavailable" instead of dialling an empty host.
func TestCheckIPv6ConnectivityNoAddr(t *testing.T) {
	m := &Manager{}
	if m.checkIPv6Connectivity(context.Background()) {
		t.Fatal("checkIPv6Connectivity = true with no v6 address configured")
	}
}
