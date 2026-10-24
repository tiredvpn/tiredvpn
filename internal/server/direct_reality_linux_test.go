package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestADirectREALITYClientKeepsItsSessionOnASparseDownload is the MSK field
// run, 1.11.8 on both ends: a REALITY TUN session straight to an exit, a
// sparse one-way UDP download and nothing up, died every 2.5 min - the exit's
// TUN loop gives a client 120 s without a frame, and the client noticed the
// silence 30 s later. Round 12b's uplink keepalive is transport-blind
// (VPNClient.keepUplinkAlive), so it has to cover REALITY as it covers HTTP/2
// Stego. The stand's shape, scaled 1:25, for three of the exit's 120 s
// deadlines, the uplink keepalive drawn as in production and scaled.
func TestADirectREALITYClientKeepsItsSessionOnASparseDownload(t *testing.T) {
	scaleLegClocks(t)
	restore := tun.SetUplinkKeepaliveDraw(func() time.Duration {
		return strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) / legScale
	})
	t.Cleanup(func() { tun.SetUplinkKeepaliveDraw(restore) })
	out := captureLog(t)
	if err := InitREALITYKeys(&Config{}); err != nil {
		t.Fatal(err)
	}
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExitWith(t, secret, func(cfg *Config) { cfg.REALITYLegacyEnabled = true })
	client := clientVia(t, exit.addr, true, func(m *strategy.Manager) strategy.Strategy {
		s := strategy.NewREALITYStrategy(m, secret)
		s.SetRequireDataV2(true)
		return s
	})
	if !strings.Contains(out.String(), "REALITY: Tunnel established") || strings.Contains(out.String(), "legacy v1 data layer") {
		t.Fatalf("the client is not on REALITY v2 - the test proves nothing:\n%s", out.String())
	}
	w := exitWriterFor(t, exit, client.LocalIP())
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), client.LocalIP())
	pkt[3] = byte(len(pkt))
	span := 3 * tunClientReadTimeout()
	var sent int64
	tick := time.NewTicker(sparseEvery)
	defer tick.Stop()
	for range span / sparseEvery {
		<-tick.C
		if w.SendPacket(pkt) == nil {
			sent++
		}
	}
	waitDown(t, client, sent)
	if n := strings.Count(out.String(), "REALITY: Tunnel established"); n != 1 || strings.Contains(out.String(), "VPN disconnected") {
		t.Fatalf("the session dropped on a sparse download (%d REALITY tunnels):\n%s", n, out.String())
	}
}
