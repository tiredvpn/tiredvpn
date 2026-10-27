package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// legRelay is a relay on loopback: the real dispatcher with -upstream set
// to exit, terminating no client itself.
func legRelay(t *testing.T, secret []byte, exit *legExit) string {
	t.Helper()
	addr, _ := legRelayCounted(t, secret, exit)
	return addr
}

// legRelayCounted is legRelay, with a count of the client connections the
// relay has ended.
func legRelayCounted(t *testing.T, secret []byte, exit *legExit) (string, *atomic.Int64) {
	t.Helper()
	ended := new(atomic.Int64)
	cfg := &Config{Secret: secret}
	srvCtx := &serverContext{cfg: cfg, tlsConfig: buildTLSProfile(cfg, selfSignedCertForTest(t)),
		upstreamDialer: NewUpstreamDialer(exit.addr, secret)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var id uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id++
			go func(c net.Conn, id uint64) {
				handleConnection(c, srvCtx, id)
				ended.Add(1)
			}(c, id)
		}
	}()
	return ln.Addr().String(), ended
}

// clientVia starts a desktop client that reaches the exit through the relay
// at relay, on the strategy make makes, and returns it with the app end of
// its TUN. Without uplinkKeepalive it behaves like 1.11.8: a keepalive only
// when the server has been silent, none for its own uplink.
func clientVia(t *testing.T, relay string, uplinkKeepalive bool, make func(*strategy.Manager) strategy.Strategy) *tun.VPNClient {
	t.Helper()
	client, _ := startClientVia(t, relay, uplinkKeepalive, make)
	return client
}

// clientWithApp is clientVia, with the 1.11.9 uplink keepalive, and the
// app's end of the client's TUN, to write packets up through.
func clientWithApp(t *testing.T, relay string, make func(*strategy.Manager) strategy.Strategy) (*tun.VPNClient, int) {
	t.Helper()
	return startClientVia(t, relay, true, make)
}

func startClientVia(t *testing.T, relay string, uplinkKeepalive bool, make func(*strategy.Manager) strategy.Strategy) (*tun.VPNClient, int) {
	t.Helper()
	if !uplinkKeepalive {
		restore := tun.SetUplinkKeepaliveDraw(func() time.Duration { return time.Hour })
		t.Cleanup(func() { tun.SetUplinkKeepaliveDraw(restore) })
	}
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "relay", V4: relay}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(make(m))
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := newTunApp(fds[1])
	t.Cleanup(app.close)
	client, err := tun.NewVPNClient(tun.VPNConfig{TunFd: fds[0], TunName: "sparse0", MTU: 1500,
		LocalIP: net.IPv4(10, 8, 7, 60), RemoteIP: net.IPv4(10, 8, 7, 1), ServerAddr: relay, Manager: m,
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
	return client, fds[1]
}
