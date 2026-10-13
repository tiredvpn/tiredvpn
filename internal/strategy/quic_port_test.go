package strategy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// quicPortListener is a loopback UDP socket that counts the datagrams it gets.
type quicPortListener struct {
	pc   net.PacketConn
	got  chan int
	addr string
}

func newQUICPortListener(t *testing.T) *quicPortListener {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	l := &quicPortListener{pc: pc, got: make(chan int, 64), addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			l.got <- n
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return l
}

func (l *quicPortListener) received() int { return len(l.got) }

// quicRegisteredStrategy returns the single QUIC strategy a config registers.
func quicRegisteredStrategy(t *testing.T, m *Manager) *QUICStrategy {
	t.Helper()
	for _, s := range m.strategies {
		if q, ok := s.(*QUICStrategy); ok {
			return q
		}
	}
	t.Fatal("no QUIC strategy registered")
	return nil
}

// TestQUICDialPortIsTheServerPort drives Connect for both variants with the
// pinned endpoint on one port, the -server port on another and -quic-port on
// a third. QUIC must go to the -server port, the one the server's QUIC
// listener shares with -listen. Plain QUIC used to dial the pinned address
// as is, Salamander the derived port: one client, two different answers.
func TestQUICDialPortIsTheServerPort(t *testing.T) {
	for _, sniFrag := range []bool{false, true} {
		server := newQUICPortListener(t) // -server, where the QUIC listener is
		pinned := newQUICPortListener(t) // the endpoint the selector pins
		m := NewDefaultManager(DefaultManagerConfig{
			ServerAddr:         server.addr,
			Endpoints:          []endpoint.Endpoint{{Name: "a", V4: pinned.addr}},
			Secret:             []byte("0123456789abcdef0123456789abcdef"),
			QUICEnabled:        true,
			QUICPort:           8443,
			QUICSNIFragEnabled: sniFrag,
		})
		q := quicRegisteredStrategy(t, m)
		if got := m.GetServerAddr(t.Context()); got != pinned.addr {
			t.Fatalf("pinned %s, want %s", got, pinned.addr)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		if conn, err := q.Connect(ctx, pinned.addr); err == nil {
			conn.Close()
		}
		cancel()
		time.Sleep(50 * time.Millisecond)

		if server.received() == 0 || pinned.received() != 0 {
			t.Errorf("%s: datagrams to the -server port %d, to the pinned endpoint's port %d; want all on the -server port",
				q.ID(), server.received(), pinned.received())
		}
	}
}

// quicProbeVerdict runs the manager's ProbeAll - the call site that feeds
// probe results into confidence - for a forced quic_salamander client whose
// -server port is serverAddr and whose pinned endpoint is pinnedAddr.
func quicProbeVerdict(t *testing.T, serverAddr, pinnedAddr string) Result {
	t.Helper()
	m := NewDefaultManager(DefaultManagerConfig{
		ServerAddr:  serverAddr,
		Endpoints:   []endpoint.Endpoint{{Name: "a", V4: pinnedAddr}},
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		QUICEnabled: true,
	})
	if err := m.ForceStrategy("quic_salamander"); err != nil {
		t.Fatalf("force: %v", err)
	}
	res := m.ProbeAll(t.Context(), pinnedAddr)
	if len(res) != 1 {
		t.Fatalf("want one probe result, got %d", len(res))
	}
	return res[0]
}

// quicClosedUDPAddr returns a loopback address with nothing on its UDP port,
// so a datagram to it draws an ICMP port unreachable.
func quicClosedUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// TestQUICProbeReportsRefusal: the probe's only meaningful answer is an ICMP
// unreachable, and Probe swallowed it, so a closed QUIC port probed as
// available. It must fail there and pass where the port is open and silent.
func TestQUICProbeReportsRefusal(t *testing.T) {
	closed := quicClosedUDPAddr(t)
	if r := quicProbeVerdict(t, closed, closed); r.Success {
		t.Fatal("probe of a closed UDP port reported success")
	}

	open := newQUICPortListener(t)
	if r := quicProbeVerdict(t, open.addr, open.addr); !r.Success {
		t.Fatalf("probe of an open, silent UDP port failed: %v", r.Error)
	}
}

// TestQUICProbeTargetsTheQUICPort: with the pinned endpoint's port closed and
// the -server port open, the probe must look where Connect will dial, not at
// the pinned TCP address.
func TestQUICProbeTargetsTheQUICPort(t *testing.T) {
	server := newQUICPortListener(t)
	pinned := quicClosedUDPAddr(t)
	if r := quicProbeVerdict(t, server.addr, pinned); !r.Success {
		t.Fatalf("probe went to the pinned port instead of the QUIC port: %v", r.Error)
	}
	time.Sleep(50 * time.Millisecond)
	if server.received() == 0 {
		t.Fatal("no probe datagram reached the QUIC port")
	}
}

// quicGateVerdict wires a checker into a QUIC-enabled manager the way the
// client does (SetConnectivityChecker after registration), runs the gate
// against the pinned endpoint and waits for the UDP verdict.
func quicGateVerdict(t *testing.T, quicAddr, pinnedAddr string) bool {
	t.Helper()
	m := NewDefaultManager(DefaultManagerConfig{
		ServerAddr:  quicAddr,
		Endpoints:   []endpoint.Endpoint{{Name: "a", V4: pinnedAddr}},
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		QUICEnabled: true,
	})
	c := NewConnectivityChecker(pinnedAddr, 2*time.Second, false)
	m.SetConnectivityChecker(c)

	if r := c.Check(t.Context()); !r.TCP {
		t.Fatalf("TCP gate failed on %s: %+v", pinnedAddr, r)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !c.LastResult().UDPKnown {
		if time.Now().After(deadline) {
			t.Fatal("UDP verdict never landed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c.LastResult().UDP
}

// TestUDPGateProbesTheQUICPort: the gate's UDP verdict decides whether QUIC
// is tried, so it has to be about the port QUIC dials. It probed the pinned
// TCP port instead, which answered for an unrelated socket. Checked both
// ways: QUIC port open while the TCP port's UDP twin is closed, and the
// reverse.
func TestUDPGateProbesTheQUICPort(t *testing.T) {
	// pinned: TCP open (the gate needs it), UDP twin closed.
	pinnedClosed := udpGateServer(t, false)
	quicOpen := newQUICPortListener(t)
	if !quicGateVerdict(t, quicOpen.addr, pinnedClosed) {
		t.Error("open QUIC port judged blocked: the probe went to the TCP port's closed UDP twin")
	}

	// pinned: TCP open, UDP twin open and silent; QUIC port closed.
	pinnedOpen := udpGateServer(t, true)
	quicClosed := quicClosedUDPAddr(t)
	if quicGateVerdict(t, quicClosed, pinnedOpen) {
		t.Error("closed QUIC port judged working: the probe went to the TCP port's open UDP twin")
	}
}

// quicSilentDialTime runs a real QUIC Salamander Connect against a UDP port
// that swallows everything - a silent drop - and reports how long it took to
// give up.
func quicSilentDialTime(t *testing.T, forced bool) time.Duration {
	t.Helper()
	silent := newQUICPortListener(t)
	m := NewDefaultManager(DefaultManagerConfig{
		ServerAddr:  silent.addr,
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		QUICEnabled: true,
	})
	if forced {
		if err := m.ForceStrategy("quic_salamander"); err != nil {
			t.Fatalf("force: %v", err)
		}
	}
	q := quicRegisteredStrategy(t, m)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	start := time.Now()
	if conn, err := q.Connect(ctx, silent.addr); err == nil {
		conn.Close()
		t.Fatal("QUIC connected to a port that never answers")
	}
	return time.Since(start)
}

// TestQUICAutoDialGivesUpOnSilence: in auto mode a QUIC dial into a silent
// drop sat in quic-go's default handshake timeout for ~10s, ahead of every
// TCP strategy. Auto mode must give up within twice its idle budget.
func TestQUICAutoDialGivesUpOnSilence(t *testing.T) {
	limit := 2*quicAutoHandshakeIdleFloor + 500*time.Millisecond
	if took := quicSilentDialTime(t, false); took > limit {
		t.Fatalf("auto-mode QUIC dial into silence took %v, want under %v", took, limit)
	}
}

// TestQUICForcedDialKeepsDefaultTimeout: forced mode has nothing to fall back
// to, so it keeps quic-go's default patience.
func TestQUICForcedDialKeepsDefaultTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out quic-go's default handshake timeout")
	}
	if took := quicSilentDialTime(t, true); took < 4*time.Second {
		t.Fatalf("forced QUIC dial gave up after %v, want the default handshake timeout", took)
	}
}

// TestQUICClientConfigHandshakeIdle pins the dial budget without waiting it
// out, so it runs under -short in CI: forced keeps quic-go's default (0 in
// the config), auto scales with the RTT the TCP gate measured, between the
// floor and the ceiling. A flat 1s lost QUIC at 1s RTT on every dial.
func TestQUICClientConfigHandshakeIdle(t *testing.T) {
	quicWith := func(t *testing.T, forced bool, rtt time.Duration, checker bool) *QUICStrategy {
		t.Helper()
		m := NewDefaultManager(DefaultManagerConfig{
			ServerAddr:  "192.0.2.1:995",
			Secret:      []byte("0123456789abcdef0123456789abcdef"),
			QUICEnabled: true,
		})
		if checker {
			c := NewConnectivityChecker("192.0.2.1:995", time.Second, false)
			c.cacheResult(ConnectivityResult{TCP: true, Latency: rtt})
			m.SetConnectivityChecker(c)
		}
		if forced {
			if err := m.ForceStrategy("quic_salamander"); err != nil {
				t.Fatalf("force: %v", err)
			}
		}
		return quicRegisteredStrategy(t, m)
	}

	if got := quicWith(t, true, time.Second, true).quicClientConfig().HandshakeIdleTimeout; got != 0 {
		t.Errorf("forced: HandshakeIdleTimeout %v, want 0 (quic-go default)", got)
	}
	cases := []struct {
		name    string
		rtt     time.Duration
		checker bool
		want    time.Duration
	}{
		{"no gate, no RTT", 0, false, quicAutoHandshakeIdleFloor},
		{"fast path keeps the floor", 50 * time.Millisecond, true, quicAutoHandshakeIdleFloor},
		{"1s RTT gets three", time.Second, true, 3 * time.Second},
		{"slow path capped", 4 * time.Second, true, quicAutoHandshakeIdleCeil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := quicWith(t, false, c.rtt, c.checker).quicClientConfig().HandshakeIdleTimeout; got != c.want {
				t.Errorf("auto at RTT %v: HandshakeIdleTimeout %v, want %v", c.rtt, got, c.want)
			}
		})
	}
}
