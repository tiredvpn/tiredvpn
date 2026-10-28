package server

import (
	"net"
	"strings"
	"sync"
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
	longTest(t)
	scaleLegClocks(t)
	// The draws and the keepalives sent are recorded, so a run says how
	// late a keepalive came against the period drawn for it and how long
	// the uplink was silent against the exit's deadline.
	var mu sync.Mutex
	var draws []time.Duration
	var sends []time.Time
	restore := tun.SetUplinkKeepaliveDraw(func() time.Duration {
		d := strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) / legScale
		mu.Lock()
		draws = append(draws, d)
		mu.Unlock()
		return d
	})
	tun.SetUplinkKeepaliveSent(func() {
		mu.Lock()
		sends = append(sends, time.Now())
		mu.Unlock()
	})
	t.Cleanup(func() { tun.SetUplinkKeepaliveDraw(restore); tun.SetUplinkKeepaliveSent(nil) })
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
	mu.Lock()
	var silent, late time.Duration
	for i := 1; i < len(sends); i++ {
		gap := sends[i].Sub(sends[i-1])
		silent = max(silent, gap)
		if i < len(draws) {
			late = max(late, gap-draws[i])
		}
	}
	t.Logf("%d keepalives; longest uplink silence between two %v of the exit's %v, latest %v past its draw",
		len(sends), silent.Round(time.Millisecond), tunClientReadTimeout(), late.Round(time.Millisecond))
	mu.Unlock()
	if n := strings.Count(out.String(), "REALITY: Tunnel established"); n != 1 || strings.Contains(out.String(), "VPN disconnected") {
		t.Fatalf("the session dropped on a sparse download (%d REALITY tunnels):\n%s", n, out.String())
	}
}
