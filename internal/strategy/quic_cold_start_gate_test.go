package strategy

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
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

// udpGateFlappingServer reserves a loopback port and brings TCP and a silent
// UDP socket up on it only when up() is called - a server that becomes
// reachable once the client's link does.
func udpGateFlappingServer(t *testing.T) (addr string, up func()) {
	t.Helper()
	addr = freeLoopbackAddr(t)
	return addr, func() {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("listen tcp %s: %v", addr, err)
			return
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			ln.Close()
			t.Errorf("listen udp %s: %v", addr, err)
			return
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
		go func() {
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		t.Cleanup(func() {
			ln.Close()
			pc.Close()
			heldMu.Lock()
			defer heldMu.Unlock()
			for _, c := range held {
				c.Close()
			}
		})
	}
}

// udpGateNetUnreachable is what a UDP dial returns with no route at all.
func udpGateNetUnreachable(context.Context, string, string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
}

// TestUDPGateLinkDownAtStartForcedQUICConnects is the review's E7: a forced
// QUIC client started while the link is down. The UDP probe met "network is
// unreachable", that counted as a finished probe saying "blocked", the TCP
// wait carried it, and when the link came up the client exited with "no
// available strategies". A failed TCP gate now voids the verdict, so the
// client connects once the server is back.
func TestUDPGateLinkDownAtStartForcedQUICConnects(t *testing.T) {
	addr, up := udpGateFlappingServer(t)
	m := udpGateForcedQUICManager(t, addr)
	m.connectivityChecker.udpDial = udpGateNetUnreachable

	go func() {
		time.Sleep(600 * time.Millisecond)
		m.connectivityChecker.mu.Lock()
		m.connectivityChecker.udpDial = nil
		m.connectivityChecker.mu.Unlock()
		up()
	}()

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("connect after the link came up: %v", err)
	}
	conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("connected via %s, want quic_salamander", strat.ID())
	}
}

// TestUDPGateRefusalWhileTCPDownIsVoid: a refusal the probe heard while the
// TCP gate failed is a verdict about a network the client is not using yet.
// It must not survive into the connect that follows recovery.
func TestUDPGateRefusalWhileTCPDownIsVoid(t *testing.T) {
	addr, up := udpGateFlappingServer(t) // UDP closed until up(): ICMP refused
	m := udpGateForcedQUICManager(t, addr)
	go func() {
		time.Sleep(600 * time.Millisecond)
		up()
	}()

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("connect after recovery: %v", err)
	}
	conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("connected via %s, want quic_salamander", strat.ID())
	}
}

// TestUDPGateLocalErrorIsNoVerdict: with TCP up, a UDP probe that dies on a
// local error ("network is unreachable" - say the family's route is gone)
// heard nothing about the server and must not exclude a forced QUIC client.
func TestUDPGateLocalErrorIsNoVerdict(t *testing.T) {
	addr := udpGateServer(t, true)
	m := udpGateForcedQUICManager(t, addr)
	m.connectivityChecker.udpDial = udpGateNetUnreachable

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("connect with a locally failing UDP probe: %v", err)
	}
	conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("connected via %s, want quic_salamander", strat.ID())
	}
}

// TestUDPGateNetworkChangeVoidsVerdict: ResetForNetworkChange used to keep the
// UDP verdict and the QUIC exclusion of the network the client just left. It
// now voids both, re-probes in the background, and the next scan in auto mode
// acts on the fresh verdict.
func TestUDPGateNetworkChangeVoidsVerdict(t *testing.T) {
	addr := udpGateServer(t, true)
	m := NewManager()
	m.Register(&mockStrategy{id: "quic_salamander", name: "QUIC Salamander", priority: 4, serverAddr: addr})
	m.Register(&mockStrategy{id: "confusion_0", priority: 10, serverAddr: addr})
	c := NewConnectivityChecker(addr, 2*time.Second, false)
	m.SetConnectivityChecker(c)

	// The old network refused UDP, and the gate acted on it.
	c.storeUDPVerdict(c.udpProbeAddr(addr), time.Now(), udpGateVerdict{known: true})
	m.applyUDPGate(false)

	m.ResetForNetworkChange()
	if r := c.LastResult(); r.UDPKnown && !r.UDP {
		t.Fatal("the old network's refusal survived the network change")
	}

	deadline := time.Now().Add(3 * time.Second)
	for !c.LastResult().UDPKnown {
		if time.Now().After(deadline) {
			t.Fatal("no fresh UDP verdict after the network change")
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, strat, err := m.ConnectExcluding(t.Context(), addr, []string{"confusion_0"})
	if err != nil {
		t.Fatalf("scan after the network change: %v", err)
	}
	conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("scan dialled %s, want quic_salamander", strat.ID())
	}
}

// TestUDPGateLateProbeCannotReviveVoidedVerdict: a Check whose UDP probe
// outlives the grace finishes in the background. If the network changes in
// between, the late verdict is about the old network and must not land on
// top of the invalidation.
func TestUDPGateLateProbeCannotReviveVoidedVerdict(t *testing.T) {
	addr := udpGateServer(t, true)
	c := NewConnectivityChecker(addr, 2*time.Second, false)
	if r := c.Check(t.Context()); !r.TCP || r.UDPKnown {
		t.Fatalf("want TCP up and the UDP verdict still in flight: %+v", r)
	}
	c.invalidateUDPVerdict() // what ResetForNetworkChange does
	time.Sleep(c.auxTimeout)
	if c.LastResult().UDPKnown {
		t.Fatal("a probe sent before the invalidation landed after it")
	}
}

// TestUDPGateVerdictIsPerAddress: the gate moves between servers and families
// (SetAddrs per candidate). A verdict about one address is no verdict about
// another, so a Check that times out on a new address reports unknown.
func TestUDPGateVerdictIsPerAddress(t *testing.T) {
	a := udpGateServer(t, true)
	b := udpGateServer(t, true)
	c := NewConnectivityChecker(a, 2*time.Second, false)
	c.storeUDPVerdict(a, time.Now(), udpGateVerdict{known: true})

	c.SetAddrs(b)
	if r := c.Check(t.Context()); r.UDPKnown {
		t.Fatalf("Check on %s reported %s's verdict: %+v", b, a, r)
	}
}

// TestUDPGateRecoveryReprobes: after an outage the TCP wait returns without a
// full Check, and the outage voided the verdict. Auto mode would then keep
// QUIC deferred with nothing to lift it until the next pre-flight; recovery
// must take a fresh verdict in the background.
func TestUDPGateRecoveryReprobes(t *testing.T) {
	addr, up := udpGateFlappingServer(t)
	m := NewManager()
	m.Register(&mockStrategy{id: "quic_salamander", name: "QUIC Salamander", priority: 4, serverAddr: addr})
	m.Register(&mockStrategy{id: "confusion_0", priority: 10, serverAddr: addr})
	c := NewConnectivityChecker(addr, 2*time.Second, false)
	m.SetConnectivityChecker(c)
	go func() {
		time.Sleep(600 * time.Millisecond)
		up()
	}()

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("connect after recovery: %v", err)
	}
	conn.Close()
	if strat.ID() != "confusion_0" {
		t.Fatalf("auto mode dialled %s with no UDP verdict, want confusion_0", strat.ID())
	}
	deadline := time.Now().Add(3 * time.Second)
	for !c.LastResult().UDPKnown {
		if time.Now().After(deadline) {
			t.Fatal("no UDP verdict after recovery")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestUDPGateCheckWithTCPDownLeavesNoVerdict: the reconnect loop asks Check
// alone whether the network is back (tun.checkNetworkConnectivity). With TCP
// down, a refusal the UDP probe heard is about a network the client cannot
// use, and must not be cached as the verdict.
func TestUDPGateCheckWithTCPDownLeavesNoVerdict(t *testing.T) {
	addr, _ := udpGateFlappingServer(t) // nothing listening: TCP and UDP refused
	c := NewConnectivityChecker(addr, 2*time.Second, false)
	if r := c.Check(t.Context()); r.TCP || r.UDPKnown {
		t.Fatalf("Check with TCP down: %+v", r)
	}
	time.Sleep(c.auxTimeout)
	if c.LastResult().UDPKnown {
		t.Fatal("a UDP verdict taken with TCP down was cached")
	}
}

// udpGateReadErrConn is a UDP socket whose reads fail with err: an ICMP host
// unreachable or prohibited from a router on the way, say.
type udpGateReadErrConn struct {
	net.Conn
	err error
}

func (c udpGateReadErrConn) Read([]byte) (int, error) { return 0, c.err }

// TestUDPGateHostUnreachableIsNoVerdict: only silence and a port unreachable
// are verdicts. A "no route to host" on the read is the network on the way
// talking about itself, and used to exclude QUIC as "UDP blocked".
func TestUDPGateHostUnreachableIsNoVerdict(t *testing.T) {
	addr := udpGateServer(t, true)
	m := udpGateForcedQUICManager(t, addr)
	m.connectivityChecker.udpDial = func(ctx context.Context, network, a string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, a)
		if err != nil {
			return nil, err
		}
		return udpGateReadErrConn{Conn: conn, err: &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.EHOSTUNREACH)}}, nil
	}

	conn, strat, err := m.Connect(t.Context(), addr)
	if err != nil {
		t.Fatalf("connect with a host-unreachable UDP probe: %v", err)
	}
	conn.Close()
	if strat.ID() != "quic_salamander" {
		t.Fatalf("connected via %s, want quic_salamander", strat.ID())
	}
}
