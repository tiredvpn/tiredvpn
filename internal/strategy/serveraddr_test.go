package strategy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
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

// setTestEndpoint points a manager at a single IPv4 address. It is the
// replacement for the old `mgr.serverAddrV4 = addr` one-liner, and it must stay
// equivalent: v4_only with one candidate is exactly what the old field meant.
func setTestEndpoint(m *Manager, addr string) {
	sel, err := endpoint.NewSelector(endpoint.Config{
		Endpoints: []endpoint.Endpoint{{Name: "test", V4: addr}},
		Family:    endpoint.V4Only,
	})
	if err != nil {
		panic(err)
	}
	m.endpoints = sel
}

// countingDialer wraps a real dialer and counts calls, so a test can assert how
// many times the selector went to the network rather than only what it decided.
type countingDialer struct {
	calls atomic.Int64
}

func (d *countingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	dl := &net.Dialer{Timeout: 2 * time.Second}
	return dl.DialContext(ctx, network, addr)
}

// newFamilyManager builds a manager whose selector describes one dual-addressed
// server under the legacy flag pair, with a counting dialer for the family
// probe.
func newFamilyManager(t *testing.T, v4, v6 string, preferIPv6, fallbackToV4 bool) (*Manager, *countingDialer) {
	t.Helper()
	d := &countingDialer{}
	sel, err := endpoint.NewSelector(endpoint.Config{
		Endpoints:    []endpoint.Endpoint{{Name: "test", V4: v4, V6: v6}},
		Family:       endpoint.FamilyPolicyFromLegacy(preferIPv6, fallbackToV4),
		Dial:         d.dial,
		ProbeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	m := NewManager()
	m.endpoints = sel
	return m, d
}

// TestGetServerAddrSelection pins the transport-family choice. This is the
// decision that used to be bypassed: the probe dialled IPv6 while the
// connectivity gate and the periodic reprobe were built straight from
// cfg.ServerAddr, so a host with a censored IPv4 never brought the tunnel up
// even though its v6 path was clean.
//
// The verdict now comes from the explicit probe step Connect runs, not from
// GetServerAddr - but the answers it produces are the same ones the old
// implementation produced, which is what this test holds fixed.
func TestGetServerAddrSelection(t *testing.T) {
	const v4 = "127.0.0.1:443"
	ctx := context.Background()

	t.Run("no v6 configured falls through to v4", func(t *testing.T) {
		m, d := newFamilyManager(t, v4, "", true, true)
		// Without a v6 address there is nothing to probe; returning anything
		// but v4 here would dial an empty host.
		m.ProbeEndpointFamily(ctx)
		if got := m.GetServerAddr(ctx); got != v4 {
			t.Fatalf("GetServerAddr = %q, want %q", got, v4)
		}
		if n := d.calls.Load(); n != 0 {
			t.Errorf("connectivity probe dialled %d times with no v6 address configured", n)
		}
	})

	t.Run("preferIPv6 false keeps v4 even with v6 configured", func(t *testing.T) {
		m, d := newFamilyManager(t, v4, deadV6Addr(t), false, false)
		m.ProbeEndpointFamily(ctx)
		if got := m.GetServerAddr(ctx); got != v4 {
			t.Fatalf("GetServerAddr = %q, want %q", got, v4)
		}
		// -prefer-ipv6=false is a "keep this client off IPv6" knob: it must not
		// even cost a probe dial, and v6 must not be reachable as a fallback.
		if n := d.calls.Load(); n != 0 {
			t.Errorf("probed %d times despite preferIPv6=false", n)
		}
		if cands := m.selector().Candidates(); len(cands) != 1 || cands[0].Addr != v4 {
			t.Errorf("candidates = %v, want the v4 address alone", cands)
		}
	})

	t.Run("v6 reachable wins", func(t *testing.T) {
		live, stop := liveV6Listener(t)
		defer stop()

		m, d := newFamilyManager(t, v4, live, true, true)
		m.ProbeEndpointFamily(ctx)
		if got := m.GetServerAddr(ctx); got != live {
			t.Fatalf("GetServerAddr = %q, want the v6 address %q", got, live)
		}
		if n := d.calls.Load(); n != 1 {
			t.Errorf("probe dialled %d times, want exactly 1", n)
		}
	})

	t.Run("v6 unreachable with fallback lands on v4", func(t *testing.T) {
		m, _ := newFamilyManager(t, v4, deadV6Addr(t), true, true)
		m.ProbeEndpointFamily(ctx)
		if got := m.GetServerAddr(ctx); got != v4 {
			t.Fatalf("GetServerAddr = %q, want the v4 fallback %q", got, v4)
		}
	})

	t.Run("v6 unreachable without fallback still returns v6", func(t *testing.T) {
		dead := deadV6Addr(t)
		m, _ := newFamilyManager(t, v4, dead, true, false)
		// -fallback-v4=false is an explicit "never touch IPv4" knob; silently
		// dropping to v4 here would defeat it and leak onto the blocked family.
		m.ProbeEndpointFamily(ctx)
		if got := m.GetServerAddr(ctx); got != dead {
			t.Fatalf("GetServerAddr = %q, want %q (fallback disabled)", got, dead)
		}
	})
}

// TestGetServerAddrNeverDials is the property the refactor exists for.
// GetServerAddr is on the path of every strategy in a scan; it used to hold a
// mutex across a 3s DialContext. A single dial from here would put that back.
func TestGetServerAddrNeverDials(t *testing.T) {
	live, stop := liveV6Listener(t)
	defer stop()

	m, d := newFamilyManager(t, "127.0.0.1:443", live, true, true)
	ctx := context.Background()

	for range 20 {
		if got := m.GetServerAddr(ctx); got != live {
			t.Fatalf("GetServerAddr = %q, want %q", got, live)
		}
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("GetServerAddr dialled %d times, want 0", n)
	}
}

// TestFamilyProbeRunsOnce proves the verdict is computed once. Every connect
// cycle calls the probe step; re-dialling on each one would add up to a 3s
// timeout to the hot reconnect path.
func TestFamilyProbeRunsOnce(t *testing.T) {
	live, stop := liveV6Listener(t)
	defer stop()

	m, d := newFamilyManager(t, "127.0.0.1:443", live, true, true)
	ctx := context.Background()

	m.ProbeEndpointFamily(ctx)
	if got := m.GetServerAddr(ctx); got != live {
		t.Fatalf("GetServerAddr = %q, want %q", got, live)
	}

	// Tear the v6 endpoint down. A cached verdict keeps answering v6; a
	// re-probe would fail and fall back to v4, which is what makes this
	// observable without racing an accept counter.
	stop()

	for i := range 4 {
		m.ProbeEndpointFamily(ctx)
		if got := m.GetServerAddr(ctx); got != live {
			t.Fatalf("call %d: GetServerAddr = %q, want the cached %q (probe must not repeat)", i, got, live)
		}
	}
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("probe dialled %d times across 5 cycles, want 1", n)
	}
}

// TestResetHealthReprobes covers the network-change path (WiFi -> LTE): after a
// reset the cached verdict must be discarded, otherwise a client that lost IPv6
// keeps dialling a dead family until restart.
func TestResetHealthReprobes(t *testing.T) {
	for name, reset := range map[string]func(*Manager){
		"ResetHealth":    (*Manager).ResetHealth,
		"ResetIPv6Check": (*Manager).ResetIPv6Check, // deprecated alias, Android calls it
	} {
		t.Run(name, func(t *testing.T) {
			live, stop := liveV6Listener(t)
			defer stop()

			const v4 = "127.0.0.1:443"
			m, _ := newFamilyManager(t, v4, live, true, true)
			ctx := context.Background()

			m.ProbeEndpointFamily(ctx)
			if got := m.GetServerAddr(ctx); got != live {
				t.Fatalf("GetServerAddr = %q, want %q", got, live)
			}

			// Network changed: the v6 endpoint is gone.
			stop()

			reset(m)
			m.ProbeEndpointFamily(ctx)
			if got := m.GetServerAddr(ctx); got != v4 {
				t.Fatalf("GetServerAddr = %q after reset, want the v4 fallback %q", got, v4)
			}
		})
	}
}

// TestResetForNetworkChangeResetsEndpoints is the desktop half of the bug: the
// Android control socket called ResetIPv6Check by hand, ResetForNetworkChange
// did not, so a family verdict outlived every network change everywhere else.
func TestResetForNetworkChangeResetsEndpoints(t *testing.T) {
	live, stop := liveV6Listener(t)
	defer stop()

	const v4 = "127.0.0.1:443"
	m, _ := newFamilyManager(t, v4, live, true, true)
	ctx := context.Background()

	stop() // v6 is down at this point
	m.ProbeEndpointFamily(ctx)
	if got := m.GetServerAddr(ctx); got != v4 {
		t.Fatalf("GetServerAddr = %q, want the v4 fallback %q", got, v4)
	}

	m.ResetForNetworkChange()
	if got := m.GetServerAddr(ctx); got != live {
		t.Fatalf("GetServerAddr = %q after network change, want the preferred v6 %q", got, live)
	}
}

// TestGetServerAddrWithoutSelector guards the degenerate manager: NewManager
// has no endpoints, and roughly fifteen call sites dereference this result.
func TestGetServerAddrWithoutSelector(t *testing.T) {
	m := NewManager()
	if got := m.GetServerAddr(context.Background()); got != "" {
		t.Fatalf("GetServerAddr = %q with no selector, want empty", got)
	}
	if states := m.EndpointStates(); states != nil {
		t.Fatalf("EndpointStates = %v with no selector, want nil", states)
	}
	m.ResetHealth() // must not panic
}
