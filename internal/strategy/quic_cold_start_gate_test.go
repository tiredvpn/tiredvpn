package strategy

import (
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// udpGateServer is a loopback stand-in for a server's port: TCP accepts and
// holds connections, and with silentUDP a UDP socket on the same port reads
// and never answers - what the Salamander listener does with the gate's probe.
// Without it the port is UDP-closed and the kernel answers the probe with a
// port unreachable.
func udpGateServer(t *testing.T, silentUDP bool) string {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		addr := ln.Addr().String()
		var pc net.PacketConn
		if silentUDP {
			if pc, err = net.ListenPacket("udp", addr); err != nil {
				ln.Close()
				continue // UDP twin of this port is taken; pick another
			}
			go func() {
				buf := make([]byte, 2048)
				for {
					if _, _, err := pc.ReadFrom(buf); err != nil {
						return
					}
				}
			}()
		}
		var (
			heldMu sync.Mutex
			held   []net.Conn
		)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				heldMu.Lock()
				held = append(held, c)
				heldMu.Unlock()
			}
		}()
		t.Cleanup(func() {
			ln.Close()
			if pc != nil {
				pc.Close()
			}
			heldMu.Lock()
			defer heldMu.Unlock()
			for _, c := range held {
				c.Close()
			}
		})
		return addr
	}
	t.Fatal("no loopback port with a free UDP twin")
	return ""
}

// udpGateForcedQUICManager is a cold manager forced onto a single UDP-based
// strategy, with the production connectivity checker (its real auxGrace and
// probe timings, which is where the bug lived) pointed at addr.
func udpGateForcedQUICManager(t *testing.T, addr string) *Manager {
	t.Helper()
	m := NewManager()
	m.Register(&mockStrategy{id: "quic_salamander", name: "QUIC Salamander", priority: 4, serverAddr: addr})
	m.Register(&mockStrategy{id: "confusion_0", priority: 10, serverAddr: addr})
	if err := m.ForceStrategy("quic_salamander"); err != nil {
		t.Fatalf("force: %v", err)
	}
	m.SetConnectivityChecker(NewConnectivityChecker(addr, 2*time.Second, false))
	return m
}

// TestUDPGateColdStartForcedQUICConnects drives the whole first connect - the
// pre-flight gate, its verdict, the strategy filter - against a server whose
// UDP port swallows the probe. The probe's only "UDP works" answer is its own
// read timeout (500ms), longer than the 300ms Check waits, so on a cold start
// the gate used to read the zero value of an empty cache as "UDP blocked",
// exclude every QUIC strategy and leave a forced quic_salamander client with
// "no available strategies".
func TestUDPGateColdStartForcedQUICConnects(t *testing.T) {
	addr := udpGateServer(t, true)
	m := udpGateForcedQUICManager(t, addr)

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("cold-start connect with a silent UDP port: %v", err)
	}
	defer conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("connected via %s, want quic_salamander", strat.ID())
	}
	m.mu.RLock()
	excluded := m.excludeUDPStrategies
	m.mu.RUnlock()
	if excluded {
		t.Fatal("UDP strategies excluded on a cold start without a UDP verdict")
	}
}

// TestUDPGateColdStartAutoDefersQUIC is the auto-mode half. The probe cannot
// tell a silent drop from a working path, so a pending verdict says nothing,
// and dialling QUIC into a dropped path costs ~10s ahead of every TCP
// strategy. Auto mode therefore starts without QUIC, as it did before, and the
// TCP strategy is the one dialled.
func TestUDPGateColdStartAutoDefersQUIC(t *testing.T) {
	addr := udpGateServer(t, true)
	m := NewManager()
	m.Register(&mockStrategy{id: "quic_salamander", name: "QUIC Salamander", priority: 4, serverAddr: addr})
	m.Register(&mockStrategy{id: "confusion_0", priority: 10, serverAddr: addr})
	m.SetConnectivityChecker(NewConnectivityChecker(addr, 2*time.Second, false))

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("auto-mode cold start: %v", err)
	}
	defer conn.Close()
	if strat.ID() != "confusion_0" {
		t.Fatalf("auto mode dialled %s before the UDP verdict was in, want confusion_0", strat.ID())
	}
}

// TestUDPGateColdStartRefusedUDPStillExcludes is the other half: a fix that
// simply stopped gating would pass the test above. Here the port answers the
// probe with a port unreachable at once, a real verdict inside the grace, and
// the forced QUIC client must still be refused.
func TestUDPGateColdStartRefusedUDPStillExcludes(t *testing.T) {
	addr := udpGateServer(t, false)
	m := udpGateForcedQUICManager(t, addr)

	conn, _, err := m.Connect(t.Context(), addr)
	if err == nil {
		conn.Close()
		t.Fatal("connected over QUIC although the UDP probe was refused")
	}
	if !strings.Contains(err.Error(), "no available strategies") {
		t.Fatalf("want the UDP gate to empty the list, got: %v", err)
	}
}

// TestUDPGateLateVerdictIsKnown follows the verdict that lands after Check has
// returned: it must reach the cache as a known one, survive the TCP-only retry
// path, and be what the next timed-out Check reports.
func TestUDPGateLateVerdictIsKnown(t *testing.T) {
	addr := udpGateServer(t, true)
	c := NewConnectivityChecker(addr, 2*time.Second, false)

	first := c.Check(t.Context())
	if !first.TCP {
		t.Fatalf("TCP gate failed: %+v", first)
	}
	if first.UDPKnown {
		t.Fatalf("cold Check claims a UDP verdict before the probe finished: %+v", first)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !c.LastResult().UDPKnown {
		if time.Now().After(deadline) {
			t.Fatal("late UDP verdict never reached the cache")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !c.LastResult().UDP {
		t.Fatalf("silent UDP port cached as blocked: %+v", c.LastResult())
	}

	if r := c.checkTCPOnly(t.Context()); !r.UDPKnown || !r.UDP {
		t.Fatalf("TCP-only path dropped the known UDP verdict: %+v", r)
	}

	c.auxGrace = time.Millisecond // force the fallback branch
	if r := c.Check(t.Context()); !r.UDPKnown || !r.UDP {
		t.Fatalf("timed-out Check did not reuse the cached verdict: %+v", r)
	}
}

// TestQUICRegistrationMatchesServerDialect pins which QUIC variant a client
// registers. The server's listener speaks Salamander unless it runs with
// -quic-sni-reassembly, the counterpart of the client's -quic-sni-frag, so
// exactly one variant can ever reach it.
func TestQUICRegistrationMatchesServerDialect(t *testing.T) {
	ids := func(sniFrag bool) []string {
		m := NewManager()
		registerQUICStrategies(m, DefaultManagerConfig{
			ServerAddr:         "192.0.2.1:443",
			Secret:             []byte("s"),
			QUICEnabled:        true,
			QUICSNIFragEnabled: sniFrag,
		}, true, true)
		var out []string
		for _, s := range m.strategies {
			out = append(out, s.ID())
		}
		return out
	}
	if got := ids(false); !slices.Equal(got, []string{"quic_salamander"}) {
		t.Fatalf("default mode registers %v, want only quic_salamander", got)
	}
	if got := ids(true); !slices.Equal(got, []string{"quic"}) {
		t.Fatalf("SNI-frag mode registers %v, want only quic", got)
	}
}

// TestQUICPlainForceExplains covers -strategy quic where only Salamander is
// registered: the prefix match would quietly hand over quic_salamander, so it
// must refuse with the reason instead. Without -quic at all the generic
// "no strategy matching" answer stays.
func TestQUICPlainForceExplains(t *testing.T) {
	salamanderOnly := func() *Manager {
		m := NewManager()
		m.Register(&mockStrategy{id: "quic_salamander", priority: 4})
		m.Register(&mockStrategy{id: "confusion_0", priority: 10})
		return m
	}

	err := salamanderOnly().ForceStrategy("quic")
	if err == nil || !strings.Contains(err.Error(), "-quic-sni-frag") {
		t.Fatalf("forcing plain quic with only Salamander registered: %v", err)
	}
	if err := salamanderOnly().ForceStrategy("quic_salamander"); err != nil {
		t.Fatalf("forcing quic_salamander: %v", err)
	}

	m := NewManager()
	m.Register(&mockStrategy{id: "confusion_0", priority: 10})
	if err := m.ForceStrategy("quic"); err == nil || strings.Contains(err.Error(), "-quic-sni-frag") {
		t.Fatalf("without any QUIC strategy want the generic error, got: %v", err)
	}

	m = NewManager()
	m.Register(&mockStrategy{id: "quic", priority: 5})
	m.Register(&mockStrategy{id: "quic_salamander", priority: 4})
	if err := m.ForceStrategy("quic"); err != nil {
		t.Fatalf("plain quic registered, force must succeed: %v", err)
	}
}

// TestUDPGateRefreshAppliesLandedVerdict: a cold start in auto mode defers
// QUIC until the probe lands. The landed verdict used to wait for the next
// pre-flight, which a connected client only runs after two failed connects,
// so one cold start kept QUIC out of every later scan. The next scan must
// pick it up.
func TestUDPGateRefreshAppliesLandedVerdict(t *testing.T) {
	addr := udpGateServer(t, true)
	m := NewManager()
	m.Register(&mockStrategy{id: "quic_salamander", name: "QUIC Salamander", priority: 4, serverAddr: addr})
	m.Register(&mockStrategy{id: "confusion_0", priority: 10, serverAddr: addr})
	c := NewConnectivityChecker(addr, 2*time.Second, false)
	m.SetConnectivityChecker(c)

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("cold start: %v", err)
	}
	conn.Close()
	if strat.ID() != "confusion_0" {
		t.Fatalf("cold start dialled %s, want confusion_0 (QUIC deferred)", strat.ID())
	}

	deadline := time.Now().Add(3 * time.Second)
	for !c.LastResult().UDPKnown {
		if time.Now().After(deadline) {
			t.Fatal("UDP verdict never landed")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A full scan without the TCP strategy: only QUIC is left, so the scan
	// connects if and only if the landed verdict re-admitted it.
	conn, strat, err = m.ConnectExcluding(t.Context(), addr, []string{"confusion_0"})
	if err != nil {
		t.Fatalf("scan after the verdict landed: %v", err)
	}
	conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("scan dialled %s, want quic_salamander", strat.ID())
	}
}
