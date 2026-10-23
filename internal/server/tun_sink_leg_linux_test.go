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
// the exit - with every clock scaled down 25 times, the draw included.

const legScale = 25

// scaleLegClocks divides the leg's clocks by legScale for the test: the
// exit's read deadline, the relay's, the keepalive draw and how long the
// relay keeps a leg for a silent client.
func scaleLegClocks(t *testing.T) {
	t.Helper()
	oldRead, oldIdle, oldWindow := h2FrameReadTimeoutNs.Load(), relayTUNIdleTimeoutNs.Load(), relayClientActiveWindowNs.Load()
	h2FrameReadTimeoutNs.Store(oldRead / legScale)
	relayTUNIdleTimeoutNs.Store(oldIdle / legScale)
	relayClientActiveWindowNs.Store(oldWindow / legScale)
	setKeepaliveDraw(t, func(d time.Duration) time.Duration { return d / legScale })
	t.Cleanup(func() {
		h2FrameReadTimeoutNs.Store(oldRead)
		relayTUNIdleTimeoutNs.Store(oldIdle)
		relayClientActiveWindowNs.Store(oldWindow)
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
// uploads and one that only downloads each stay up for three of
// the exit's read deadlines, while the downstream client shows a sign of life
// every 10 s (scaled) as its keepalive would.
func TestARelayLegOutlivesTheExitsReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind legTraffic
	}{{"idle", legIdle}, {"upload only", legUpload}, {"download only", legDownload}} {
		t.Run(tc.name, func(t *testing.T) {
			scaleLegClocks(t)
			exit, sink, clientIP, down := dialLeg(t)

			pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
			up := ipv4Packet(clientIP, net.IPv4(10, 8, 7, 9))
			deadline := time.Now().Add(3 * h2FrameReadTimeout())
			clientTick := time.NewTicker(10 * time.Second / legScale)
			defer clientTick.Stop()
			trafficTick := time.NewTicker(h2FrameReadTimeout() / 5)
			defer trafficTick.Stop()
			for time.Now().Before(deadline) {
				select {
				case <-sink.Done():
					t.Fatalf("the leg closed after %v (exit read deadline %v)",
						3*h2FrameReadTimeout()-time.Until(deadline), h2FrameReadTimeout())
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

// dialLeg starts an exit and dials a relay leg to it with dialRelayTUN; down
// counts the packets the leg delivered to the downstream side.
func dialLeg(t *testing.T) (exit *legExit, sink *relayTUNSink, clientIP net.IP, down *atomic.Int64) {
	t.Helper()
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit = newLegExit(t, secret)
	relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(exit.addr, secret)}
	down = &atomic.Int64{}
	sink, _, clientIP, err := dialRelayTUN(relayCtx, testLogger(t), dialTUNHandshake(), "origin",
		func([]byte) error { down.Add(1); return nil })
	if err != nil {
		t.Fatalf("dialRelayTUN: %v", err)
	}
	t.Cleanup(sink.Close)
	return exit, sink, clientIP, down
}

// keepaliveLog records when the relay sent each keepalive up, for the test.
func keepaliveLog(t *testing.T) func() []time.Time {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	f := func() {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
	}
	relayKeepaliveSent.Store(&f)
	t.Cleanup(func() { relayKeepaliveSent.Store(nil) })
	return func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), at...)
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
// multiples of the client's 10 s keepalive. On a real leg, with the
// downstream client on a 100 ms grid here, the gaps between keepalives must
// not sit on it.
func TestTheRelayKeepaliveIsOffTheClientsGrid(t *testing.T) {
	setKeepaliveDraw(t, func(d time.Duration) time.Duration { return d / 100 }) // 200-450 ms
	sent := keepaliveLog(t)
	_, sink, _, _ := dialLeg(t)

	grid := time.NewTicker(100 * time.Millisecond)
	defer grid.Stop()
	stop := time.After(8 * time.Second)
loop:
	for {
		select {
		case <-grid.C:
			sink.UpdateActivity()
		case <-sink.Done():
			t.Fatal("the leg closed")
		case <-stop:
			break loop
		}
	}
	at := sent()
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
		if d < 20*time.Second || d >= 45*time.Second || d >= h2FrameReadTimeout()-10*time.Second {
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
// relayClientActiveWindow, the relay stops sending, and the exit closes the
// leg on its read deadline. On a real leg, clocks scaled: the client shows
// one sign of life and then nothing.
func TestARelayLegWithoutAClientGetsNoKeepalive(t *testing.T) {
	scaleLegClocks(t)
	sent := keepaliveLog(t)
	_, sink, _, _ := dialLeg(t)
	sink.UpdateActivity()
	gone := time.Now().Add(relayClientActiveWindow())

	select {
	case <-sink.Done():
	case <-time.After(relayClientActiveWindow() + 3*h2FrameReadTimeout()):
		t.Fatal("the leg of a client gone for good is still up")
	}
	if len(sent()) == 0 {
		t.Fatal("no keepalive while the client was there - the test proves nothing")
	}
	for _, at := range sent() {
		if at.After(gone.Add(h2FrameReadTimeout() / 10)) {
			t.Fatalf("a keepalive went up %v after the client was gone", at.Sub(gone))
		}
	}
}

// TestABusyRelayLegGetsNoKeepalive: traffic both ways is all the two read
// deadlines need, and a keepalive on a busy leg would only add a frame. A
// real leg carries a packet each way every 40 ms against a 200 ms quiet
// period.
func TestABusyRelayLegGetsNoKeepalive(t *testing.T) {
	setKeepaliveDraw(t, func(time.Duration) time.Duration { return 200 * time.Millisecond })
	sent := keepaliveLog(t)
	exit, sink, clientIP, down := dialLeg(t)
	w := exitWriterFor(t, exit, clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	up := ipv4Packet(clientIP, net.IPv4(10, 8, 7, 9))
	for range 30 {
		sink.UpdateActivity()
		_ = sink.WritePacket(up)
		_ = w.SendPacket(pkt)
		time.Sleep(40 * time.Millisecond)
	}
	if down.Load() < 20 {
		t.Fatalf("%d packets came down - the leg was not busy both ways", down.Load())
	}
	if n := len(sent()); n != 0 {
		t.Fatalf("%d keepalives on a leg busy both ways", n)
	}

	// Control: the same leg gone quiet one way gets its keepalive.
	for range 10 {
		sink.UpdateActivity()
		_ = sink.WritePacket(up)
		time.Sleep(40 * time.Millisecond)
	}
	if len(sent()) == 0 {
		t.Fatal("no keepalive once nothing came down - the test proves nothing")
	}
}

// setKeepaliveDraw replaces the keepalive draw for the test with f applied
// to the real one.
func setKeepaliveDraw(t *testing.T, f func(time.Duration) time.Duration) {
	t.Helper()
	old := relayKeepaliveDraw.Load()
	draw := func() time.Duration { return f((*old)()) }
	relayKeepaliveDraw.Store(&draw)
	t.Cleanup(func() { relayKeepaliveDraw.Store(old) })
}
