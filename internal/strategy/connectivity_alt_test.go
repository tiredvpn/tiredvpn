package strategy

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingLoopback starts an IPv4 loopback listener that counts accepted
// connections, so a test can assert which addresses the TCP gate actually
// dialled rather than only which verdict it returned.
func countingLoopback(t *testing.T) (addr string, accepts *atomic.Int64, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			n.Add(1)
			conn.Close()
		}
	}()
	return ln.Addr().String(), &n, func() {
		ln.Close()
		<-done
	}
}

// TestCheckTCPAnyProbeOrder pins that the primary address is tried first and
// that a working primary costs no dial to the alternate. The alt address exists
// for the censored-family case; probing it unconditionally would double every
// pre-flight check on the hot reconnect path.
//
// The alt counter is only ever read after checkTCPAny returned, so a non-zero
// value means the loop really did dial it — there is no accept still in flight.
func TestCheckTCPAnyProbeOrder(t *testing.T) {
	primary, _, stopPrimary := countingLoopback(t)
	defer stopPrimary()
	alt, altHits, stopAlt := countingLoopback(t)
	defer stopAlt()

	c := NewConnectivityChecker(primary, 2*time.Second, true)
	c.SetAltAddr(alt)

	if got := c.addrsToTry(); len(got) != 2 || got[0] != primary || got[1] != alt {
		t.Fatalf("addrsToTry = %v, want [%s %s] (primary first)", got, primary, alt)
	}
	if err := c.checkTCPAny(context.Background()); err != nil {
		t.Fatalf("checkTCPAny = %v, want nil", err)
	}
	if n := altHits.Load(); n != 0 {
		t.Errorf("alt dialled %d times, want 0 when the primary answers", n)
	}
}

// TestCheckTCPAnyReturnsLastError verifies the reported error comes from the
// last address tried. The gate's error surfaces in the "waiting for network"
// log, and blaming the primary when the alternate was the final failure sends
// diagnosis down the wrong family.
func TestCheckTCPAnyReturnsLastError(t *testing.T) {
	deadPrimary := freeLoopbackAddr(t)
	deadAlt := freeLoopbackAddr(t)
	if deadPrimary == deadAlt {
		t.Skip("kernel handed out the same free port twice")
	}

	c := NewConnectivityChecker(deadPrimary, 500*time.Millisecond, true)
	c.SetAltAddr(deadAlt)

	err := c.checkTCPAny(context.Background())
	if err == nil {
		t.Fatal("checkTCPAny = nil, want an error when neither address answers")
	}
	if !strings.Contains(err.Error(), deadAlt) {
		t.Errorf("error = %v, want the last-tried address %s", err, deadAlt)
	}
}

// TestCheckInheritsAltAddr proves the alt-address gate reaches the public entry
// points, not just checkTCPAny. Check and checkTCPOnly are what the connect and
// reconnect paths call; if either bypassed the alternate, a client with a
// blocked IPv4 would still sit in "waiting for network".
func TestCheckInheritsAltAddr(t *testing.T) {
	live, _, stop := countingLoopback(t)
	defer stop()
	dead := freeLoopbackAddr(t)

	t.Run("Check", func(t *testing.T) {
		c := NewConnectivityChecker(dead, 2*time.Second, true) // androidMode: skip the ICMP probe
		c.auxTimeout = 100 * time.Millisecond
		c.auxGrace = 100 * time.Millisecond
		c.SetAltAddr(live)

		res := c.Check(context.Background())
		if !res.TCP {
			t.Fatalf("Check reported no TCP, got %+v", res)
		}
		if !res.HasBasicConnectivity() {
			t.Error("HasBasicConnectivity = false with TCP up")
		}
		if got := c.LastResult(); !got.TCP {
			t.Error("LastResult did not cache the successful verdict")
		}
	})

	t.Run("checkTCPOnly", func(t *testing.T) {
		c := NewConnectivityChecker(dead, 2*time.Second, true)
		c.SetAltAddr(live)

		res := c.checkTCPOnly(context.Background())
		if !res.TCP {
			t.Fatalf("checkTCPOnly reported no TCP, got %+v", res)
		}
		if res.Error != nil {
			t.Errorf("Error = %v, want nil on success", res.Error)
		}
	})

	t.Run("WaitForConnectivity", func(t *testing.T) {
		c := NewConnectivityChecker(dead, 2*time.Second, true)
		c.SetAltAddr(live)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		res := c.WaitForConnectivity(ctx, defaultProbeInterval)
		if !res.TCP {
			t.Fatalf("WaitForConnectivity blocked on the dead primary, got %+v", res)
		}
	})
}

// TestCheckInvalidServerAddr covers the parse guard: a malformed -server value
// must fail the check outright instead of being dialled.
func TestCheckInvalidServerAddr(t *testing.T) {
	c := NewConnectivityChecker("not-a-host-port", time.Second, true)
	res := c.Check(context.Background())
	if res.TCP {
		t.Fatal("Check = TCP up for an unparseable address")
	}
	if res.Error == nil {
		t.Fatal("Check reported no error for an unparseable address")
	}
}

// TestNextProbeBackoff covers the retry pacing WaitForConnectivity uses. Losing
// the growth turns a truly-down network into a 4-dials-per-second hammer;
// losing the ceiling turns a sub-second server reset into a multi-second freeze.
func TestNextProbeBackoff(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  time.Duration
		want time.Duration
	}{
		{"first step doubles", defaultProbeInterval, 500 * time.Millisecond},
		{"clamps to the ceiling", 2 * time.Second, maxProbeInterval},
		{"saturated stays put", maxProbeInterval, maxProbeInterval},
		{"caller interval above the ceiling is not pulled down", 10 * time.Second, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextProbeBackoff(tc.cur); got != tc.want {
				t.Errorf("nextProbeBackoff(%v) = %v, want %v", tc.cur, got, tc.want)
			}
		})
	}

	// Repeated application must converge on the ceiling, never overshoot it.
	b := defaultProbeInterval
	for range 20 {
		b = nextProbeBackoff(b)
	}
	if b != maxProbeInterval {
		t.Errorf("backoff converged to %v, want %v", b, maxProbeInterval)
	}
}

// TestConnectivityCheckerDefaults documents the constructor's zero-timeout
// substitution and the accessor the client logs from.
func TestConnectivityCheckerDefaults(t *testing.T) {
	c := NewConnectivityChecker("127.0.0.1:443", 0, false)
	if c.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want the 3s default when 0 is passed", c.timeout)
	}
	if c.ServerAddr() != "127.0.0.1:443" {
		t.Errorf("ServerAddr = %q, want 127.0.0.1:443", c.ServerAddr())
	}
	if got := c.addrsToTry(); len(got) != 1 {
		t.Errorf("addrsToTry = %v, want just the primary before SetAltAddr", got)
	}
}
