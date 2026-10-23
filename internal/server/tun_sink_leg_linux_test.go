package server

import (
	"encoding/binary"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// P1-A and P2-A of the round-6 review: the relay's keepalive was drawn at
// 60-150 s and sent from inside UpdateActivity, while the exit's HTTP/2 stego
// loop closes a raw conn after 60 s without a frame. Every idle leg through a
// relay died after a minute, on the client's 10 s grid. These run the real
// legs - dialRelayTUN on the relay, handleConnection and runH2FrameLoop on
// the exit - with every clock scaled down 50 times, the draw included.

const legScale = 50

// scaleLegClocks divides the leg's three clocks by legScale for the test.
func scaleLegClocks(t *testing.T) {
	t.Helper()
	oldRead, oldIdle, oldDraw := h2FrameReadTimeout, relayTUNIdleTimeout, relayKeepaliveAfter
	h2FrameReadTimeout /= legScale
	relayTUNIdleTimeout /= legScale
	relayKeepaliveAfter = func() time.Duration { return oldDraw() / legScale }
	t.Cleanup(func() {
		h2FrameReadTimeout, relayTUNIdleTimeout, relayKeepaliveAfter = oldRead, oldIdle, oldDraw
	})
}

// legExit is a TUN exit on loopback: the real dispatcher over a TUN made of a
// seqpacket socket pair.
type legExit struct {
	addr   string
	srvCtx *serverContext
	app    *tunApp
	ended  atomic.Int64 // connections handleConnection has returned from
}

func newLegExit(t *testing.T, secret []byte) *legExit {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := tun.CreateTUNFromFd(fds[0], "leg0", 1500)
	if err != nil {
		t.Fatal(err)
	}
	app := newTunApp(fds[1])
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.7.0/24", ServerIP: "10.8.7.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	shared := newTestSharedTUN(t)
	shared.tunDev = dev
	shared.mtu = 1500
	cfg := &Config{Secret: secret}
	srvCtx := &serverContext{cfg: cfg, tlsConfig: buildTLSProfile(cfg, selfSignedCertForTest(t)), ipPool: pool, sharedTUN: shared}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &legExit{addr: ln.Addr().String(), srvCtx: srvCtx, app: app}
	var wg sync.WaitGroup
	go func() {
		var id uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id++
			wg.Add(1)
			go func(c net.Conn, id uint64) {
				defer wg.Done()
				handleConnection(c, srvCtx, id)
				e.ended.Add(1)
			}(c, id)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		app.close()
		dev.Close()
	})
	return e
}

// tunApp drains the exit's TUN so packets written to it never block.
type tunApp struct{ fd int }

func newTunApp(fd int) *tunApp {
	a := &tunApp{fd: fd}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, err := unix.Read(fd, buf); err != nil {
				return
			}
		}
	}()
	return a
}

func (a *tunApp) close() { unix.Close(a.fd) }

// legTraffic is what the downstream side of the test does on the leg.
type legTraffic int

const (
	legIdle legTraffic = iota
	legUpload
	legDownload
)

// TestARelayLegOutlivesTheExitsReadDeadline: an idle leg, one that only
// uploads and one that only downloads each stay up for more than three of
// the exit's read deadlines, while the downstream client shows a sign of life
// every 10 s (scaled) as its keepalive would.
func TestARelayLegOutlivesTheExitsReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind legTraffic
	}{{"idle", legIdle}, {"upload only", legUpload}, {"download only", legDownload}} {
		t.Run(tc.name, func(t *testing.T) {
			scaleLegClocks(t)
			secret := []byte("relay-leg-secret-0123456789abcdef")
			exit := newLegExit(t, secret)
			relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(exit.addr, secret)}
			var down atomic.Int64
			sink, _, clientIP, err := dialRelayTUN(relayCtx, testLogger(t), dialTUNHandshake(), "origin",
				func([]byte) error { down.Add(1); return nil })
			if err != nil {
				t.Fatalf("dialRelayTUN: %v", err)
			}
			defer sink.Close()

			pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
			up := ipv4Packet(clientIP, net.IPv4(10, 8, 7, 9))
			deadline := time.Now().Add(4 * h2FrameReadTimeout)
			clientTick := time.NewTicker(10 * time.Second / legScale)
			defer clientTick.Stop()
			trafficTick := time.NewTicker(h2FrameReadTimeout / 5)
			defer trafficTick.Stop()
			for time.Now().Before(deadline) {
				select {
				case <-sink.Done():
					t.Fatalf("the leg closed after %v (exit read deadline %v)",
						4*h2FrameReadTimeout-time.Until(deadline), h2FrameReadTimeout)
				case <-clientTick.C:
					sink.UpdateActivity()
				case <-trafficTick.C:
					switch tc.kind {
					case legUpload:
						_ = sink.WritePacket(up)
					case legDownload:
						exitWriterFor(t, exit, clientIP).SendPacket(pkt) //nolint:errcheck
					}
				}
			}
			if tc.kind == legDownload && down.Load() == 0 {
				t.Fatal("nothing came down - the download leg proves nothing")
			}
			if n := exit.ended.Load(); n != 0 {
				t.Fatalf("the exit ended %d connections", n)
			}
		})
	}
}

// exitWriterFor returns the exit's writer for the relay's tunnel address.
func exitWriterFor(t *testing.T, e *legExit, clientIP net.IP) *ClientWriter {
	t.Helper()
	st := e.srvCtx.sharedTUN
	st.clientsMu.RLock()
	defer st.clientsMu.RUnlock()
	w := st.clients[clientIP.String()]
	if w == nil {
		t.Fatalf("no client %s registered on the exit", clientIP)
	}
	return w
}

// ipv4Packet is a minimal IPv4/UDP packet from src to dst.
func ipv4Packet(src, dst net.IP) []byte {
	p := make([]byte, 28)
	p[0], p[9] = 0x45, 17
	binary.BigEndian.PutUint16(p[2:], 28)
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	return p
}

// TestTheRelayKeepaliveIsOffTheClientsGrid is P2-A: keepalives went out only
// from UpdateActivity, so whatever the draw, the gaps on the wire were whole
// multiples of the client's 10 s keepalive. With the downstream client on a
// 100 ms grid here, the gaps between keepalives must not sit on it.
func TestTheRelayKeepaliveIsOffTheClientsGrid(t *testing.T) {
	old := relayKeepaliveAfter
	relayKeepaliveAfter = func() time.Duration { return old() / 100 } // 200-450 ms
	t.Cleanup(func() { relayKeepaliveAfter = old })
	sink, upstream := newTestRelaySink(t)
	sink.startKeepalive()

	var mu sync.Mutex
	var at []time.Time
	go func() {
		buf := make([]byte, 4)
		for {
			if _, err := readFullConn(upstream, buf); err != nil {
				return
			}
			mu.Lock()
			at = append(at, time.Now())
			mu.Unlock()
		}
	}()
	grid := time.NewTicker(100 * time.Millisecond)
	defer grid.Stop()
	stop := time.After(8 * time.Second)
loop:
	for {
		select {
		case <-grid.C:
			sink.UpdateActivity()
		case <-stop:
			break loop
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(at) < 12 {
		t.Fatalf("%d keepalives in 8 s - the test proves nothing", len(at))
	}
	onGrid := 0
	for i := 1; i < len(at); i++ {
		gap := at[i].Sub(at[i-1]).Seconds() * 10 // in grid ticks
		if math.Abs(gap-math.Round(gap)) < 0.08 {
			onGrid++
		}
	}
	// A continuous draw puts about 16% of gaps within 8 ms of a tick.
	if frac := float64(onGrid) / float64(len(at)-1); frac > 0.5 {
		t.Fatalf("%.0f%% of %d gaps sit on the client's 100 ms grid", 100*frac, len(at)-1)
	}
}

// TestRelayKeepalivePauseShape checks the drawn quiet period (verification
// rule 3): inside 20-45 s, well under the exit's 60 s, spread out rather than
// on a grid, and a hump - about two thirds of the draws at 24-34 s, where a
// flat draw puts two fifths - with the lowest tenth of the range thin.
func TestRelayKeepalivePauseShape(t *testing.T) {
	const n = 4000
	seen := map[time.Duration]bool{}
	var sum time.Duration
	low, mid := 0, 0
	for range n {
		d := relayKeepaliveAfter()
		if d < 20*time.Second || d >= 45*time.Second || d >= h2FrameReadTimeout-10*time.Second {
			t.Fatalf("drew %v, outside [20 s, 45 s)", d)
		}
		seen[d.Round(50*time.Millisecond)] = true
		sum += d
		if d < 22500*time.Millisecond {
			low++
		}
		if d >= 24*time.Second && d < 34*time.Second {
			mid++
		}
	}
	if len(seen) < n/10 {
		t.Fatalf("only %d distinct values in %d draws: a grid", len(seen), n)
	}
	if mean := sum / n; mean < 28*time.Second || mean > 32*time.Second {
		t.Fatalf("mean %v, want about 30 s", mean)
	}
	if mid < n*55/100 {
		t.Fatalf("%d of %d draws in 24-34 s: flat, not a hump", mid, n)
	}
	if low > n/10 {
		t.Fatalf("%d of %d draws in the lowest tenth: a pile-up at the floor", low, n)
	}
}

// TestARelayLegWithoutAClientGetsNoKeepalive: the keepalive keeps a leg
// alive for its downstream client. Once that client has shown nothing for
// relayClientActiveWindow, the relay stops, and the leg may close.
func TestARelayLegWithoutAClientGetsNoKeepalive(t *testing.T) {
	old := relayKeepaliveAfter
	relayKeepaliveAfter = func() time.Duration { return 100 * time.Millisecond }
	t.Cleanup(func() { relayKeepaliveAfter = old })
	sink, upstream := newTestRelaySink(t)
	sink.startKeepalive()
	sink.lastActivity.Store(time.Now().Add(-relayClientActiveWindow - time.Second).UnixNano())

	got := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 4)
		if _, err := readFullConn(upstream, buf); err == nil {
			got <- struct{}{}
		}
	}()
	select {
	case <-got:
		t.Fatal("a keepalive went up for a client gone a minute")
	case <-time.After(600 * time.Millisecond):
	}
	sink.UpdateActivity()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("no keepalive once the client was back")
	}
}

// TestABusyRelayLegGetsNoKeepalive: traffic both ways is all the two read
// deadlines need, and a keepalive on a busy leg would only add a frame.
func TestABusyRelayLegGetsNoKeepalive(t *testing.T) {
	old := relayKeepaliveAfter
	relayKeepaliveAfter = func() time.Duration { return 200 * time.Millisecond }
	t.Cleanup(func() { relayKeepaliveAfter = old })
	sink, upstream := newTestRelaySink(t)
	go sink.pump(func([]byte) error { return nil })
	sink.startKeepalive()

	var keepalives atomic.Int64
	go func() {
		hdr := make([]byte, 4)
		for {
			if _, err := readFullConn(upstream, hdr); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr)
			if n == 0 {
				keepalives.Add(1)
				continue
			}
			if _, err := readFullConn(upstream, make([]byte, n)); err != nil {
				return
			}
		}
	}()
	pkt := ipv4Packet(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	down := append(binary.BigEndian.AppendUint32(nil, uint32(len(pkt))), pkt...)
	for range 30 {
		sink.UpdateActivity()
		go func() { _ = sink.WritePacket(pkt) }()
		_, _ = upstream.Write(down)
		time.Sleep(40 * time.Millisecond)
	}
	if n := keepalives.Load(); n != 0 {
		t.Fatalf("%d keepalives on a leg busy both ways", n)
	}
}
