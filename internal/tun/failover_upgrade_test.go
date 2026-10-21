package tun

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// rankedPipeStrategy is a pipeStrategy with its own identity and rank, and an
// optional failure, so a test can hold two of them side by side.
type rankedPipeStrategy struct {
	*pipeStrategy
	id       string
	priority int
	fail     error
	dials    atomic.Int64
}

func (s *rankedPipeStrategy) Name() string  { return s.id }
func (s *rankedPipeStrategy) ID() string    { return s.id }
func (s *rankedPipeStrategy) Priority() int { return s.priority }
func (s *rankedPipeStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	s.dials.Add(1)
	if s.fail != nil {
		return nil, s.fail
	}
	return s.pipeStrategy.Connect(ctx, target)
}

// newUpgradeClient is a client whose tunnel rides a fallback strategy, over a
// manager with one endpoint and a better strategy registered next to it. The
// tunnel's addresses are the ones the scripted exit hands out.
func newUpgradeClient(t *testing.T, better *rankedPipeStrategy) (*VPNClient, *rankedPipeStrategy, net.Conn) {
	t.Helper()
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: "203.0.113.10:443"}}, endpoint.V4Only); err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	fallback := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response()}, id: "polling", priority: 6}
	m.Register(fallback)
	m.Register(better)

	oldConn, srv := net.Pipe()
	t.Cleanup(func() { oldConn.Close(); srv.Close() })
	v := &VPNClient{
		running:     1,
		stopCh:      make(chan struct{}),
		manager:     m,
		serverAddr:  "203.0.113.10:443",
		localIP:     callsiteClientIP,
		tun:         &TUNDevice{mtu: 1280, remoteIP: callsiteServerIP},
		conn:        oldConn,
		strategy:    fallback,
		connectedAt: time.Now().Add(-10 * time.Minute),
		lastRx:      time.Now(),
	}
	return v, fallback, oldConn
}

// TestUpgradeMovesTheTunnelMakeBeforeBreak is D3 of the 2026-10-21 stand report
// at the tunnel's end: offered a strategy that ranks above the one carrying the
// tunnel, the client dials it, handshakes, swaps it in and only then closes the
// old conn. The read loop that was blocked on the old conn must not take its
// closing for a lost tunnel and reconnect on top of the new one.
func TestUpgradeMovesTheTunnelMakeBeforeBreak(t *testing.T) {
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "reality", priority: 5}
	v, _, oldConn := newUpgradeClient(t, better)

	out := &stampedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	reader := make(chan struct{})
	go func() {
		v.readFromServer()
		close(reader)
	}()
	t.Cleanup(func() {
		atomic.StoreInt32(&v.running, 0)
		v.mu.Lock()
		if v.conn != nil {
			v.conn.Close()
		}
		v.mu.Unlock()
		<-reader
	})
	time.Sleep(20 * time.Millisecond) // the reader is parked on the old conn

	v.tryStrategyUpgrade([]strategy.Strategy{better})

	v.mu.Lock()
	cur, conn := v.strategy, v.conn
	v.mu.Unlock()
	if cur == nil || cur.ID() != "reality" {
		t.Fatalf("tunnel strategy after the upgrade: %v, want reality; log:\n%s", cur, out)
	}
	if conn == oldConn {
		t.Fatal("the old conn is still installed")
	}
	if _, err := oldConn.Write([]byte{0}); !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) &&
		(err == nil || !strings.Contains(err.Error(), "closed")) {
		t.Fatalf("old conn left open after the swap (write err %v)", err)
	}

	time.Sleep(100 * time.Millisecond)
	if ln, ok := out.first("VPN disconnected"); ok {
		t.Fatalf("closing the replaced conn started a reconnect: %s", ln.text)
	}
}

// TestUpgradeIsOnlyUpward: a candidate that does not rank above the current
// strategy is not dialled.
func TestUpgradeIsOnlyUpward(t *testing.T) {
	worse := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response(), gap: silent}, id: "morph", priority: 10}
	v, _, oldConn := newUpgradeClient(t, worse)
	v.tryStrategyUpgrade([]strategy.Strategy{worse})
	if worse.dials.Load() != 0 || v.conn != oldConn {
		t.Fatal("an upgrade dialled a strategy ranked below the current one")
	}
}

// TestFailedUpgradeLeavesTheTunnelAlone: the dial fails, the tunnel stays where
// it was.
func TestFailedUpgradeLeavesTheTunnelAlone(t *testing.T) {
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: bareV3Response()}, id: "reality", priority: 5,
		fail: errors.New("tls: handshake reset")}
	v, fallback, oldConn := newUpgradeClient(t, better)
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if better.dials.Load() != 1 {
		t.Fatalf("upgrade dialled %d times, want 1", better.dials.Load())
	}
	if v.conn != oldConn || v.strategy != fallback {
		t.Fatal("a failed upgrade touched the tunnel")
	}
}

// TestUpgradeWithDifferentAddressesIsDropped: a new session that comes back
// with another tunnel address would break every flow in the tunnel if swapped
// in. The client keeps the old one.
func TestUpgradeWithDifferentAddressesIsDropped(t *testing.T) {
	resp := []byte{0x00}
	resp = append(resp, callsiteServerIP.To4()...)
	resp = append(resp, net.IPv4(10, 99, 0, 77).To4()...)
	better := &rankedPipeStrategy{pipeStrategy: &pipeStrategy{t: t, resp: resp, gap: silent}, id: "reality", priority: 5}
	v, fallback, oldConn := newUpgradeClient(t, better)
	v.tryStrategyUpgrade([]strategy.Strategy{better})
	if v.conn != oldConn || v.strategy != fallback {
		t.Fatal("swapped in a session with a different tunnel address")
	}
}
