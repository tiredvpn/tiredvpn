package server

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestAOneWayDownloadToAClientKeepsTheSession is P3-13 of the round-7
// review, through the real client and the real exit: a VPNClient over an
// HTTP/2 Stego conn into handleConnection and runH2FrameLoop, its TUN a
// seqpacket pair, clocks scaled 1:25. A datagram comes down every 20 ms and
// nothing goes up. The client sent a keepalive only when the server had been
// silent, the server never was, and the exit closed the session on its read
// deadline about 68 s in - the WINDOW_UPDATE flushes that might have fed the
// deadline come only every 256 KB, and this flow is far below that.
//
// Two rates: 50 datagrams a second, and the 1 a second of P3-11 of the
// round-8 review, at which the old client died at exactly the exit's read
// deadline on real clocks. Scaled 1:25, one a second is one every 40 ms.
func TestAOneWayDownloadToAClientKeepsTheSession(t *testing.T) {
	longTest(t)
	for _, every := range []time.Duration{20 * time.Millisecond, time.Second / legScale} {
		t.Run(every.String(), func(t *testing.T) { oneWayDownload(t, every) })
	}
}

// TestAOneWayLowRateDownloadOnRealClocks is the 1-a-second case of P3-11
// on real clocks, the exit's 60 s read deadline and the 20-45 s draw
// unscaled, for 2.5 deadlines. Not in -short.
func TestAOneWayLowRateDownloadOnRealClocks(t *testing.T) {
	if testing.Short() {
		t.Skip("two and a half minutes on real clocks")
	}
	oneWayDownloadFor(t, time.Second, 5*h2FrameReadTimeout()/2)
}

func oneWayDownload(t *testing.T, every time.Duration) {
	scaleLegClocks(t)
	restore := tun.SetUplinkKeepaliveDraw(func() time.Duration {
		return strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) / legScale
	})
	t.Cleanup(func() { tun.SetUplinkKeepaliveDraw(restore) })
	oneWayDownloadFor(t, every, legDeadlines*h2FrameReadTimeout())
}

// oneWayDownloadFor streams a datagram down to a real client every every
// for span, with nothing going up, on whatever clocks the caller set.
func oneWayDownloadFor(t *testing.T, every, span time.Duration) {

	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "exit", V4: exit.addr}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(strategy.NewHTTP2StegoStrategy(m, secret, "api.googleapis.com"))

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := newTunApp(fds[1])
	t.Cleanup(app.close)
	client, err := tun.NewVPNClient(tun.VPNConfig{TunFd: fds[0], TunName: "oneway0", MTU: 1500,
		LocalIP: net.IPv4(10, 8, 7, 50), RemoteIP: net.IPv4(10, 8, 7, 1), ServerAddr: exit.addr, Manager: m,
		IPv6Policy: tun.IPv6PolicyOff, NoStrategyUpgrade: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(client.Stop)

	clientIP := client.LocalIP()
	w := exitWriterFor(t, exit, clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	var sent atomic.Int64
	stream := time.NewTicker(every)
	defer stream.Stop()
	for deadline := time.Now().Add(span); time.Now().Before(deadline); {
		<-stream.C
		if w.SendPacket(pkt) == nil {
			sent.Add(1)
		}
		if n := exit.ended.Load(); n != 0 {
			t.Fatalf("the exit ended the client's session after %v (read deadline %v)",
				span-time.Until(deadline), h2FrameReadTimeout())
		}
	}
	if _, down, _, _ := client.Stats(); down < sent.Load()*9/10 {
		t.Fatalf("%d of %d packets came down", down, sent.Load())
	}
}
