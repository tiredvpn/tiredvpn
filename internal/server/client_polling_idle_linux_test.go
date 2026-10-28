package server

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestAnIdlePollingSessionGetsNoUplinkKeepalive is P2-4 of the round-8
// review, through a real client on HTTP Polling into a real exit, idle both
// ways, the draw scaled 1:25. The feeder's own keepalive frames keep the
// server-silence keepalive quiet, so the uplink keepalive fired every 20-45
// s, and each one woke the idle poll loop out of its backoff. Polling's
// polls reach the exit on their own: it gets none.
func TestAnIdlePollingSessionGetsNoUplinkKeepalive(t *testing.T) {
	longTest(t)
	forgetNewPollingSessions(t)
	scaleLegClocks(t)
	restore := tun.SetUplinkKeepaliveDraw(func() time.Duration {
		return strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) / legScale
	})
	t.Cleanup(func() { tun.SetUplinkKeepaliveDraw(restore) })
	out := captureLog(t)
	var sent atomic.Int64
	tun.SetUplinkKeepaliveSent(func() { sent.Add(1) })
	t.Cleanup(func() { tun.SetUplinkKeepaliveSent(nil) })

	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "exit", V4: exit.addr}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(strategy.NewHTTPPollingStrategy(m, secret))

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := newTunApp(fds[1])
	t.Cleanup(app.close)
	client, err := tun.NewVPNClient(tun.VPNConfig{TunFd: fds[0], TunName: "pollidle0", MTU: 1500,
		LocalIP: net.IPv4(10, 8, 7, 51), RemoteIP: net.IPv4(10, 8, 7, 1), ServerAddr: exit.addr, Manager: m,
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
	if !strings.Contains(out.String(), "HTTP Polling") {
		t.Fatalf("the client is not on HTTP Polling - the test proves nothing:\n%s", out.String())
	}

	// Five of the longest draws: the old client sent at least four.
	time.Sleep(5 * 45 * time.Second / legScale)
	if n := sent.Load(); n != 0 {
		t.Fatalf("%d uplink keepalives on an idle Polling session", n)
	}
}
