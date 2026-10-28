package strategy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// failingProber fails every probe and counts them.
type failingProber struct {
	probes atomic.Int64
}

func (*failingProber) Name() string         { return "prober" }
func (*failingProber) ID() string           { return "prober" }
func (*failingProber) Priority() int        { return 1 }
func (*failingProber) RequiresServer() bool { return true }
func (*failingProber) Description() string  { return "fails every probe" }
func (p *failingProber) Probe(context.Context, string) error {
	p.probes.Add(1)
	return errors.New("blocked")
}
func (*failingProber) Connect(context.Context, string) (net.Conn, error) {
	return nil, errors.New("blocked")
}

func newEmergencyManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager()
	t.Cleanup(m.Close)
	m.emergencyInterval = 20 * time.Millisecond
	return m
}

func emergencyRunning(m *Manager) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.emergencyReprobeRunning
}

// TestNoEmergencyReprobeWhileReconnecting is P2-5 of the round-3 review of PR
// #126. HoldReprobe kept the periodic reprobe off the wire while the client
// reconnects, but every failed scan of that reconnect started the emergency
// reprobe, which ran ProbeAll against the pinned server every 30 s regardless.
func TestNoEmergencyReprobeWhileReconnecting(t *testing.T) {
	m := newEmergencyManager(t)
	p := &failingProber{}
	m.Register(p)
	m.HoldReprobe(true)

	m.TriggerEmergencyReprobe(context.Background())
	if emergencyRunning(m) {
		t.Fatal("the emergency reprobe started during a reconnect")
	}
	time.Sleep(300 * time.Millisecond)
	if n := p.probes.Load(); n != 0 {
		t.Fatalf("the emergency reprobe probed %d times during a reconnect", n)
	}
	if emergencyRunning(m) {
		t.Fatal("the emergency reprobe is running during a reconnect")
	}
}

// TestEmergencyReprobeEndsWhenAReconnectStarts: one started outside a
// reconnect stops at its next turn once a reconnect holds the reprobe.
func TestEmergencyReprobeEndsWhenAReconnectStarts(t *testing.T) {
	m := newEmergencyManager(t)
	p := &failingProber{}
	m.Register(p)

	m.TriggerEmergencyReprobe(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for p.probes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the emergency reprobe never probed - the test proves nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	m.HoldReprobe(true)
	n := p.probes.Load()
	time.Sleep(150 * time.Millisecond)
	// One probe may have been under way when the hold came.
	if more := p.probes.Load() - n; more > 1 {
		t.Fatalf("%d more probes after a reconnect took over", more)
	}
	deadline = time.Now().Add(2 * time.Second)
	for emergencyRunning(m) {
		if time.Now().After(deadline) {
			t.Fatal("the emergency reprobe kept running after a reconnect took over")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
