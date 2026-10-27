package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/log"
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
// exit's read deadline, the relay's, the relay's write deadline, the
// keepalive draw and how long the relay keeps a leg for a silent client.
func scaleLegClocks(t *testing.T) {
	t.Helper()
	oldRead, oldIdle, oldWindow := h2FrameReadTimeoutNs.Load(), relayTUNIdleTimeoutNs.Load(), relayClientActiveWindowNs.Load()
	oldWrite := relayWriteTimeoutNs.Load()
	oldTUN := tunClientReadTimeoutNs.Load()
	tunClientReadTimeoutNs.Store(oldTUN / legScale)
	h2FrameReadTimeoutNs.Store(oldRead / legScale)
	relayTUNIdleTimeoutNs.Store(oldIdle / legScale)
	relayClientActiveWindowNs.Store(oldWindow / legScale)
	relayWriteTimeoutNs.Store(oldWrite / legScale)
	setKeepaliveDraw(t, func(d time.Duration) time.Duration { return d / legScale })
	t.Cleanup(func() {
		h2FrameReadTimeoutNs.Store(oldRead)
		relayTUNIdleTimeoutNs.Store(oldIdle)
		relayClientActiveWindowNs.Store(oldWindow)
		relayWriteTimeoutNs.Store(oldWrite)
		tunClientReadTimeoutNs.Store(oldTUN)
	})
}

// legExit is a TUN exit on loopback: the real dispatcher over a TUN made of a
// seqpacket socket pair.
type legExit struct {
	addr   string
	srvCtx *serverContext
	app    *tunApp
	ended  atomic.Int64 // connections handleConnection has returned from
	mu     sync.Mutex
	conns  []net.Conn // every connection accepted, for dropAll
}

// dropAll closes every connection the exit accepted, as an exit restart
// does to the legs that reach it.
func (e *legExit) dropAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.conns {
		c.Close()
	}
	e.conns = nil
}

func newLegExit(t *testing.T, secret []byte) *legExit {
	t.Helper()
	return newLegExitWith(t, secret, nil)
}

// newLegExitWith is newLegExit with tweak applied to its config.
func newLegExitWith(t *testing.T, secret []byte, tweak func(*Config)) *legExit {
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
	bindPoolToTUN(pool, shared)
	cfg := &Config{Secret: secret}
	if tweak != nil {
		tweak(cfg)
	}
	srvCtx := &serverContext{cfg: cfg, tlsConfig: buildTLSProfile(cfg, selfSignedCertForTest(t)), ipPool: pool, sharedTUN: shared,
		donorDialer: testDonorFor(t, cfg)}

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
			e.mu.Lock()
			e.conns = append(e.conns, c)
			e.mu.Unlock()
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

// tunApp drains the exit's TUN so packets written to it never block; got
// counts the packets that came out of it.
type tunApp struct {
	fd  int
	got atomic.Int64
}

func newTunApp(fd int) *tunApp {
	a := &tunApp{fd: fd}
	go func() {
		buf := make([]byte, 2048)
		for {
			// The end of the stream is a 0-byte read, not an error. Read
			// on past it, the loop took the next test's socket, which got
			// the same descriptor number, and stole its packets.
			if n, err := unix.Read(fd, buf); err != nil || n == 0 {
				return
			}
			a.got.Add(1)
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

// legDeadlines is how many of the exit's read deadlines a leg must outlive.
// The keepalive draw tops out at 45 s and the relay's own deadline is three
// of the exit's; five cover both with room.
const legDeadlines = 5

// TestARelayLegOutlivesTheExitsReadDeadline: an idle leg, one that only
// uploads and one that only downloads each stay up for legDeadlines of the
// exit's read deadlines, while the downstream client shows a sign of life
// every 10 s (scaled) as its keepalive would.
func TestARelayLegOutlivesTheExitsReadDeadline(t *testing.T) {
	scaleLegClocks(t)
	for _, tc := range []struct {
		name string
		kind legTraffic
	}{{"idle", legIdle}, {"upload only", legUpload}, {"download only", legDownload}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runLeg(t, tc.kind)
		})
	}
}

// TestASteadyOneWayDownloadKeepsTheLeg is P2-1 of the round-7 review: a leg
// with a steady download and nothing going up died, of two causes.
//
// Bulk (1400-byte datagrams every 5 ms): the relay's write deadline was set
// for each keepalive and never cleared, and the stego conn's WINDOW_UPDATE
// flush from the read path (every 256 KB down) landed after it. The write
// failed, tls.Conn made that permanent, and the exit closed the leg on its
// read deadline. Bites when the quiet period is longer than the write
// deadline: at 45 s, every time.
//
// Sparse (28-byte datagrams every 20 ms, no flush within the run): the
// keepalive timer, armed on the downlink's stamp, ticked a few ms before the
// keepalive was due and waited a whole quiet period more - up to two of
// them without a frame for the exit.
//
// -short runs the 45 s draw only.
func TestASteadyOneWayDownloadKeepsTheLeg(t *testing.T) {
	draws := []time.Duration{45 * time.Second}
	if !testing.Short() {
		draws = append(draws, 20*time.Second, 30*time.Second)
	}
	scaleLegClocks(t)
	for _, flow := range []struct {
		name  string
		size  int
		every time.Duration
	}{{"bulk", 1400, 5 * time.Millisecond}, {"sparse", 28, 20 * time.Millisecond}} {
		for _, q := range draws {
			t.Run(flow.name+"/"+q.String(), func(t *testing.T) {
				setKeepaliveDraw(t, func(time.Duration) time.Duration { return q / legScale })
				steadyDownload(t, flow.size, flow.every)
			})
		}
	}
}

// steadyDownload runs a leg for legDeadlines exit deadlines with a datagram
// of size bytes coming down every interval and nothing going up but the
// relay's keepalives.
func steadyDownload(t *testing.T, size int, every time.Duration) {
	t.Helper()
	sentAt, sentLog := keepaliveRecord(t)
	// lateness is how far past its quiet period the latest keepalive went
	// up: the margin the exit's read deadline has left is the deadline less
	// the quiet period less this - 600 ms at 1:25 with the 45 s draw. The
	// timer's 100 ms floor is in it by design; under -race at load 41-50
	// the worst of 56 runs was 179 ms. A failure here names the lateness
	// and how long nothing had gone up, so a late timer can be told from a
	// keepalive that skipped a period.
	lateness := func() (worst time.Duration, n int) {
		for _, k := range sentLog() {
			worst = max(worst, k.sinceUp-k.quiet)
			n++
		}
		return worst, n
	}
	t.Cleanup(func() {
		worst, n := lateness()
		t.Logf("%d keepalives up, the latest %v past its quiet period", n, worst.Round(time.Millisecond))
	})
	exit, sink, clientIP, down := dialLeg(t)
	w := exitWriterFor(t, exit, clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	pkt = append(pkt, make([]byte, size-len(pkt))...)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	span := legDeadlines * h2FrameReadTimeout()
	start := time.Now()
	deadline := start.Add(span)
	clientTick := time.NewTicker(10 * time.Second / legScale)
	defer clientTick.Stop()
	stream := time.NewTicker(every)
	defer stream.Stop()
	sent := int64(0)
	for time.Now().Before(deadline) {
		select {
		case <-sink.Done():
			worst, n := lateness()
			quietUp := time.Since(start)
			if at := sentAt(); len(at) > 0 {
				quietUp = time.Since(at[len(at)-1])
			}
			t.Fatalf("the leg closed after %v (exit read deadline %v): %s; %d keepalives up, the latest %v past its quiet period, none for the last %v",
				span-time.Until(deadline), h2FrameReadTimeout(), closeReason(sink), n, worst.Round(time.Millisecond), quietUp.Round(time.Millisecond))
		case <-clientTick.C:
			sink.UpdateActivity()
		case <-stream.C:
			if w.SendPacket(pkt) == nil {
				sent++
			}
		}
	}
	if got := down.Load(); got < sent*9/10 {
		t.Fatalf("%d of %d packets came down", got, sent)
	}
}

// TestARelayLegClosesCleanly is P3-1 of the round-7 review: Close cut the
// write deadline whether or not a write was stuck, GOAWAY then failed and
// spent a TLS record number, and the exit read "bad record MAC" instead of a
// clean close. GOAWAY was also written outside the stego conn's lock while
// the read path wrote WINDOW_UPDATE under it; the leg closes here in the
// middle of a download, which -race watches.
func TestARelayLegClosesCleanly(t *testing.T) {
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	exit, sink, clientIP, down := dialLeg(t)
	w := exitWriterFor(t, exit, clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	pkt = append(pkt, make([]byte, 1372)...)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	stop := make(chan struct{})
	streamed := make(chan struct{})
	go func() {
		defer close(streamed)
		for {
			select {
			case <-stop:
				return
			default:
				_ = w.SendPacket(pkt)
				time.Sleep(time.Millisecond)
			}
		}
	}()
	for down.Load() < 400 { // past the first WINDOW_UPDATE flush
		time.Sleep(5 * time.Millisecond)
	}
	sink.Close()
	close(stop)
	<-streamed
	deadline := time.Now().Add(5 * time.Second)
	for exit.ended.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exit.ended.Load() == 0 {
		t.Fatal("the exit did not end the session")
	}
	if strings.Contains(out.String(), "bad record MAC") {
		t.Fatalf("the exit read a broken TLS record at the close:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "H2 TUN session ended: the peer closed it") {
		t.Fatalf("the exit did not see a clean close:\n%s", out.String())
	}
}

// TestARelayLegClosesCleanlyDuringAnUpload is P3-3 of the round-8 review:
// Close cut the deadline whenever the write lock was taken, and on a busy
// upload it is taken by a healthy write nearly always. The write was torn
// and the exit read a broken stream. Close has to wait for it.
func TestARelayLegClosesCleanlyDuringAnUpload(t *testing.T) {
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for i := range 5 {
		exit, sink, clientIP, _ := dialLeg(t)
		up := ipv4Packet(clientIP, net.IPv4(10, 8, 7, 9))
		up = append(up, make([]byte, 1372)...)
		binary.BigEndian.PutUint16(up[2:], uint16(len(up)))
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				for sink.WritePacket(up) == nil {
				}
			})
		}
		for exit.app.got.Load() < 200 {
			time.Sleep(time.Millisecond)
		}
		sink.Close()
		wg.Wait()
		deadline := time.Now().Add(5 * time.Second)
		for exit.ended.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		logs := out.String()
		if strings.Contains(logs, "bad record MAC") || strings.Contains(logs, "mid-frame") {
			t.Fatalf("close %d: the exit read a broken stream:\n%s", i, logs)
		}
		if n := strings.Count(logs, "H2 TUN session ended: the peer closed it"); n != i+1 {
			t.Fatalf("close %d: the exit saw %d clean closes:\n%s", i, n, logs)
		}
	}
}

// TestARelayLegClosesWhileAWriteIsStuck: P3-1 of the round-7 review saw
// Close wait 30 s behind a stuck write. Here the exit stops reading, writes
// back up, and Close has to return at once: the stuck write is cut, and the
// TLS close, whose close_notify waits up to 5 s on a peer that reads
// nothing, finishes in the background.
func TestARelayLegClosesWhileAWriteIsStuck(t *testing.T) {
	proxy := &stallProxy{}
	_, sink, clientIP, _ := dialLegVia(t, proxy)
	up := ipv4Packet(clientIP, net.IPv4(10, 8, 7, 9))
	up = append(up, make([]byte, 1372)...)
	binary.BigEndian.PutUint16(up[2:], uint16(len(up)))
	proxy.stalled.Store(true)
	var last atomic.Int64 // monoNow of the last write that came back
	last.Store(monoNow())
	for range 3 {
		go func() {
			for sink.WritePacket(up) == nil {
				last.Store(monoNow())
			}
		}()
	}
	// Stuck: no write has come back for half a second.
	deadline := time.Now().Add(20 * time.Second)
	for monoSince(last.Load()) < 500*time.Millisecond {
		if time.Now().After(deadline) {
			t.Fatal("the writes never blocked - the test cannot tell a stuck one")
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	sink.Close()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Close took %v with a write stuck and others queued", took)
	}
}

// TestRelayLegsUnderLoad is the same legs, many at once, with every CPU kept
// busy: the one unexplained drop of a download-only leg happened while other
// test processes loaded the machine. Not in -short.
func TestRelayLegsUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("a minute of CPU load")
	}
	scaleLegClocks(t)
	stop := make(chan struct{})
	var burners sync.WaitGroup
	for range runtime.NumCPU() {
		burners.Go(func() {
			x := 0
			for {
				select {
				case <-stop:
					return
				default:
					for i := range 100000 {
						x += i
					}
				}
			}
		})
	}
	t.Cleanup(func() { close(stop); burners.Wait() })
	kinds := []legTraffic{legIdle, legUpload}
	for range 10 {
		kinds = append(kinds, legDownload)
	}
	for i, kind := range kinds {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			runLeg(t, kind)
		})
	}
}

// runLeg dials one leg and drives it for legDeadlines of the exit's read
// deadlines: the downstream client's sign of life every 10 s (scaled), and a
// packet up or down every fifth of the deadline, as kind says.
func runLeg(t *testing.T, kind legTraffic) {
	t.Helper()
	exit, sink, clientIP, down := dialLeg(t)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	up := ipv4Packet(clientIP, net.IPv4(10, 8, 7, 9))
	span := legDeadlines * h2FrameReadTimeout()
	deadline := time.Now().Add(span)
	clientTick := time.NewTicker(10 * time.Second / legScale)
	defer clientTick.Stop()
	trafficTick := time.NewTicker(h2FrameReadTimeout() / 5)
	defer trafficTick.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-sink.Done():
			t.Fatalf("the leg closed after %v (exit read deadline %v): %s",
				span-time.Until(deadline), h2FrameReadTimeout(), closeReason(sink))
		case <-clientTick.C:
			sink.UpdateActivity()
		case <-trafficTick.C:
			switch kind {
			case legUpload:
				_ = sink.WritePacket(up)
			case legDownload:
				exitWriterFor(t, exit, clientIP).SendPacket(pkt) //nolint:errcheck
			}
		}
	}
	if kind == legDownload && down.Load() == 0 {
		t.Fatal("nothing came down - the download leg proves nothing")
	}
	if n := exit.ended.Load(); n != 0 {
		t.Fatalf("the exit ended %d connections", n)
	}
}

// closeReason is what the relay recorded as the end of a closed leg.
func closeReason(s *relayTUNSink) string {
	if w := s.why.Load(); w != nil {
		return *w
	}
	return "no reason recorded"
}

// dialLeg starts an exit and dials a relay leg to it with dialRelayTUN; down
// counts the packets the leg delivered to the downstream side.
func dialLeg(t *testing.T) (exit *legExit, sink *relayTUNSink, clientIP net.IP, down *atomic.Int64) {
	t.Helper()
	return dialLegVia(t, nil)
}

// dialLegVia is dialLeg with the leg running through proxy, when not nil.
func dialLegVia(t *testing.T, proxy *stallProxy) (exit *legExit, sink *relayTUNSink, clientIP net.IP, down *atomic.Int64) {
	t.Helper()
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit = newLegExit(t, secret)
	addr := exit.addr
	if proxy != nil {
		addr = proxy.start(t, exit.addr)
	}
	relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(addr, secret)}
	down = &atomic.Int64{}
	sink, _, clientIP, err := dialRelayTUN(relayCtx, testLogger(t), dialTUNHandshake(), "origin", "", nil,
		func([]byte) error { down.Add(1); return nil })
	if err != nil {
		t.Fatalf("dialRelayTUN: %v", err)
	}
	t.Cleanup(sink.Close)
	return exit, sink, clientIP, down
}

// stallProxy forwards a leg to the exit and, once stalled, stops reading
// what the relay sends: the relay's writes then back up and block, as on a
// leg whose path went dead.
type stallProxy struct{ stalled atomic.Bool }

func (p *stallProxy) start(t *testing.T, exitAddr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e, err := net.Dial("tcp", exitAddr)
			if err != nil {
				c.Close()
				return
			}
			t.Cleanup(func() { c.Close(); e.Close() })
			go func() { _, _ = io.Copy(c, e) }()
			go func() {
				buf := make([]byte, 32*1024)
				for {
					for p.stalled.Load() {
						time.Sleep(5 * time.Millisecond)
					}
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := e.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// keepaliveLog records when the relay sent each keepalive up, for the test.
func keepaliveLog(t *testing.T) func() []time.Time {
	t.Helper()
	at, _ := keepaliveRecord(t)
	return at
}

// sentKeepalive is one keepalive as the relay saw its leg when it sent it.
type sentKeepalive struct{ sinceUp, sinceDown, quiet time.Duration }

// keepaliveRecord is keepaliveLog with the state of the leg at each send.
func keepaliveRecord(t *testing.T) (func() []time.Time, func() []sentKeepalive) {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	var sent []sentKeepalive
	f := func(up, down, quiet time.Duration) {
		mu.Lock()
		at = append(at, time.Now())
		sent = append(sent, sentKeepalive{up, down, quiet})
		mu.Unlock()
	}
	relayKeepaliveSent.Store(&f)
	t.Cleanup(func() { relayKeepaliveSent.Store(nil) })
	return func() []time.Time {
			mu.Lock()
			defer mu.Unlock()
			return append([]time.Time(nil), at...)
		}, func() []sentKeepalive {
			mu.Lock()
			defer mu.Unlock()
			return append([]sentKeepalive(nil), sent...)
		}
}

// exitWriterFor returns the exit's writer for the relay's tunnel address.
//
// The raw TUN loop answers the handshake before it registers the client, so
// a client may be up before the exit has it: under load that took longer
// than the test's next line. It waits up to 5 s.
func exitWriterFor(t *testing.T, e *legExit, clientIP net.IP) *ClientWriter {
	t.Helper()
	st := e.srvCtx.sharedTUN
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		st.clientsMu.RLock()
		w := st.clients[clientIP.String()]
		st.clientsMu.RUnlock()
		if w != nil {
			return w
		}
		if time.Now().After(deadline) {
			t.Fatalf("no client %s registered on the exit", clientIP)
		}
	}
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
// period. Whether a keepalive goes out at all depends on scheduling - a
// stall under -race load is a quiet leg, and earns one - so the test checks
// each keepalive instead: one direction had to be silent for the period
// drawn when it went.
func TestABusyRelayLegGetsNoKeepalive(t *testing.T) {
	setKeepaliveDraw(t, func(time.Duration) time.Duration { return 200 * time.Millisecond })
	_, sent := keepaliveRecord(t)
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
	busy := len(sent())

	// Control: the same leg gone quiet one way gets its keepalive.
	for range 25 {
		sink.UpdateActivity()
		_ = sink.WritePacket(up)
		time.Sleep(40 * time.Millisecond)
	}
	all := sent()
	if len(all) == busy {
		t.Fatal("no keepalive once nothing came down - the test proves nothing")
	}
	for i, k := range all {
		if max(k.sinceUp, k.sinceDown) < k.quiet {
			t.Fatalf("keepalive %d went with the leg silent %v up and %v down, against a %v period", i+1, k.sinceUp, k.sinceDown, k.quiet)
		}
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
