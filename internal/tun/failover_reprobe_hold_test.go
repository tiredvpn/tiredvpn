package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// probeCountingStrategy counts the periodic reprobe's probes and never
// connects, so the reconnect loop keeps going.
type probeCountingStrategy struct{ probes atomic.Int64 }

func (*probeCountingStrategy) Name() string         { return "counting" }
func (*probeCountingStrategy) ID() string           { return "counting" }
func (*probeCountingStrategy) Priority() int        { return 5 }
func (*probeCountingStrategy) RequiresServer() bool { return true }
func (*probeCountingStrategy) Description() string  { return "counts probes" }
func (s *probeCountingStrategy) Probe(context.Context, string) error {
	s.probes.Add(1)
	return errors.New("probe failed")
}
func (*probeCountingStrategy) Connect(context.Context, string) (net.Conn, error) {
	return nil, errors.New("connect failed")
}

// TestNoReprobeWhileReconnecting is part of N8 of the second acceptance of PR
// #126: a periodic reprobe that came due during an outage probed the server
// that had just gone silent, about 16 connects and 30-40 SYNs within 20 s,
// next to a reconnect loop already dialling it. The reconnect holds reprobes
// off until it ends.
func TestNoReprobeWhileReconnecting(t *testing.T) {
	setPoolWaitKnobs(t, true)
	addr, _ := deadThenAliveAddr(t)

	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: addr}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	s := &probeCountingStrategy{}
	m.Register(s)
	m.SetReprobeInterval(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.StartPeriodicReprobe(ctx)
	defer m.StopPeriodicReprobe()

	out := &stampedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// Positive control: with a tunnel up, the reprobe does probe.
	time.Sleep(300 * time.Millisecond)
	if s.probes.Load() == 0 {
		t.Fatal("the reprobe never probed with no reconnect running; the test cannot see a hold")
	}

	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, serverAddr: addr}
	done := make(chan struct{})
	go func() {
		v.handleDisconnect("server read", io.EOF)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond) // the loop has taken the reconnect slot
	before := s.probes.Load()
	time.Sleep(500 * time.Millisecond)
	during := s.probes.Load() - before
	stopReconnectLoop(t, v, done, out)

	if during != 0 {
		t.Fatalf("the reprobe probed %d times while the reconnect was dialling", during)
	}

	// And the hold ends with the reconnect.
	after := s.probes.Load()
	time.Sleep(300 * time.Millisecond)
	if s.probes.Load() == after {
		t.Fatal("the reprobe stayed held after the reconnect ended")
	}
}
