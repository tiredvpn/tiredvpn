//go:build linux

package tun

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestStalledTUNWriteIsNotServerSilence is the data-path half of P3-1 of the
// round-3 review: a packet from the TUN whose write to the server runs into
// its deadline on a raw TCP transport is the local uplink, not silence.
func TestStalledTUNWriteIsNotServerSilence(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })

	m := strategy.NewManager()
	m.SetConnectivityChecker(strategy.NewConnectivityChecker("127.0.0.1:1", time.Second, true))
	dev := &TUNDevice{file: r, mtu: 1500, atomicMTU: 1500}
	sc := &stallingConn{}
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, conn: sc, tun: dev,
		connectedAt: time.Now().Add(-time.Minute), lastRx: time.Now().Add(-time.Minute)}
	out := &stopOnDisconnectLog{v: v}
	setLog(t, out)

	// The write deadline readFromTun sets is 30 s; let the stall end at once.
	sc.mu.Lock()
	sc.deadline = time.Now()
	sc.mu.Unlock()
	sc.fixed = true

	done := make(chan struct{})
	go func() { v.readFromTun(); close(done) }()
	if _, err := w.Write(make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "VPN disconnected") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	w.Write(make([]byte, 40)) // wake the reader so it sees running == 0
	<-done
	if !strings.Contains(out.String(), "VPN disconnected") {
		t.Fatal("the stalled write never ended the session - the test proves nothing")
	}
	if m.PreflightArmed() {
		t.Fatal("a stalled TUN write was taken for the server's silence")
	}
}
