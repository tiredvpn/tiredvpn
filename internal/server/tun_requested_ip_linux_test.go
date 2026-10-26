package server

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestAGrantedRequestedAddressIsUnregisteredAtTheEnd: a client asks an exit
// for the address it holds and gets it, sends some packets, and leaves. The
// exit has to let go of that address. The pool handed back the requested
// address as given - a slice of the handshake frame's payload, the HTTP/2
// framer's read buffer - and the session kept it: the next frames
// overwrote it, and at the end the exit unregistered some other address
// ("143.18.120.236" in one run) and kept serving the real one, a dead
// writer on it, until another session took it over. Found by the
// shared-secret lease test under -race.
func TestAGrantedRequestedAddressIsUnregisteredAtTheEnd(t *testing.T) {
	scaleLegClocks(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ask := net.IPv4(10, 8, 7, 61)

	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "exit", V4: exit.addr}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(strategy.NewHTTP2StegoStrategy(m, secret, ""))
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := newTunApp(fds[1])
	t.Cleanup(app.close)
	client, err := tun.NewVPNClient(tun.VPNConfig{TunFd: fds[0], TunName: "ask0", MTU: 1500,
		LocalIP: ask, RemoteIP: net.IPv4(10, 8, 7, 1), ServerAddr: exit.addr, Manager: m,
		IPv6Policy: tun.IPv6PolicyOff, NoStrategyUpgrade: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	if got := client.LocalIP(); !got.Equal(ask) {
		t.Fatalf("the exit gave %s, asked for %s", got, ask)
	}
	// Packets up: each one is a frame through the buffer the address was
	// read from.
	for range 20 {
		pkt := ipv4Packet(ask, net.IPv4(10, 8, 7, 9))
		pkt[3] = byte(len(pkt))
		if _, err := unix.Write(fds[1], pkt); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for exit.app.got.Load() < 20 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exit.app.got.Load() < 20 {
		t.Fatalf("%d of 20 packets reached the exit - the test proves nothing", exit.app.got.Load())
	}
	client.Stop()
	for exit.srvCtx.sharedTUN.Serving(ask) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exit.srvCtx.sharedTUN.Serving(ask) {
		t.Fatalf("the session for %s ended and the exit still serves it", ask)
	}
}
