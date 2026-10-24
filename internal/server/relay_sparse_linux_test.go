package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// The fix12-slow stand run: the exit sends the client 28 B every 5 s and
// nothing goes up. That is more often than every 9 s, so a desktop client
// older than 1.11.9 sends no keepalive, and a sparse download feeds no
// WINDOW_UPDATE. On the TUN bridge the relay sent nothing either - it had
// no keepalive - and the exit closed the leg after exactly 60 s without a
// frame, twelve times in 15 minutes. These run the stand's shape, scaled
// 1:25 (a datagram every 200 ms, the exit's deadline 2.4 s), for five of
// the exit's deadlines, through every relay path into a real exit: the
// sink, the bridge, and a proxy relay over UpstreamDialer.Dial.

// sparseEvery is the stand's 5 s between two datagrams down, scaled.
const sparseEvery = 5 * time.Second / legScale

// sparseDownload sends the client a 28-byte datagram every sparseEvery for
// five of the exit's read deadlines and fails the test if the exit ends the
// client's session meanwhile. It returns how many were sent.
func sparseDownload(t *testing.T, exit *legExit, clientIP net.IP) int64 {
	t.Helper()
	w := exitWriterFor(t, exit, clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	span := legDeadlines * h2FrameReadTimeout()
	var sent int64
	tick := time.NewTicker(sparseEvery)
	defer tick.Stop()
	for range span / sparseEvery {
		<-tick.C
		if w.SendPacket(pkt) == nil {
			sent++
		}
		if n := exit.ended.Load(); n != 0 {
			t.Fatalf("the exit ended the leg after %d datagrams, %v in (read deadline %v)",
				sent, time.Duration(sent)*sparseEvery, h2FrameReadTimeout())
		}
	}
	return sent
}

// TestAnOldClientOnASparseDownloadKeepsItsSinkLeg: the same client over
// Traffic Morph, which the relay terminates itself and forwards through a
// relayTUNSink. Its keepalive was there, but stopped once the client had
// been silent for a minute (relayClientActiveWindow), while Morph's own
// read deadline on the client gives it 120 s: the leg died in between.
// Over HTTP/2 Stego the two are the same 60 s, and a client that sends
// nothing loses its session to the relay's own deadline, as it would
// straight to an exit; no relay keepalive can hold that one.
func TestAnOldClientOnASparseDownloadKeepsItsSinkLeg(t *testing.T) {
	scaleLegClocks(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)
	client := clientVia(t, relay, false, func(m *strategy.Manager) strategy.Strategy {
		return strategy.NewTrafficMorphStrategy(m, nil, nil, secret)
	})
	sent := sparseDownload(t, exit, client.LocalIP())
	waitDown(t, client, sent)
}

// waitDown waits for the datagrams sent down to reach the client.
func waitDown(t *testing.T, client *tun.VPNClient, sent int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, down, _, _ := client.Stats(); down >= sent*9/10 {
			return
		}
		if time.Now().After(deadline) {
			_, down, _, _ := client.Stats()
			t.Fatalf("%d of %d datagrams came down", down, sent)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
