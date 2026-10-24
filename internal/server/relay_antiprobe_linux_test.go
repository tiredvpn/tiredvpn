package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestAnAntiProbeSessionThroughARelayOutlivesItsKnock: the knock check read
// each knock packet under a 2 s deadline and left the last one set. On an
// exit the TUN loop sets a deadline of its own per read, but the relay's
// bridge reads without one, so every anti-probe session through a relay
// ended 2 s after its knock ("the client to the upstream: ... i/o
// timeout"), whatever the traffic. Real clocks; a packet goes up 3 s in.
func TestAnAntiProbeSessionThroughARelayOutlivesItsKnock(t *testing.T) {
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)
	client, app := clientWithApp(t, relay, func(m *strategy.Manager) strategy.Strategy {
		return strategy.NewAntiProbeStrategy(m, secret)
	})
	time.Sleep(3 * time.Second)
	if n := exit.ended.Load(); n != 0 {
		t.Fatalf("the exit's leg ended %d times in 3 s", n)
	}
	pkt := ipv4Packet(client.LocalIP(), net.IPv4(10, 8, 7, 9))
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	before := exit.app.got.Load()
	if _, err := unix.Write(app, pkt); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for exit.app.got.Load() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exit.app.got.Load() == before {
		t.Fatal("the packet sent up 3 s in never reached the exit")
	}
	if n := exit.ended.Load(); n != 0 {
		t.Fatalf("the exit's leg ended %d times", n)
	}
}
