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
func TestAOneWayDownloadToAClientKeepsTheSession(t *testing.T) {
	scaleLegClocks(t)
	restore := tun.SetUplinkKeepaliveDraw(func() time.Duration {
		return strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) / legScale
	})
	t.Cleanup(func() { tun.SetUplinkKeepaliveDraw(restore) })

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
	span := legDeadlines * h2FrameReadTimeout()
	stream := time.NewTicker(20 * time.Millisecond)
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
