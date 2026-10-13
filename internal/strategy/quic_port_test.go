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
