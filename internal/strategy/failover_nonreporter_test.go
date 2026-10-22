package strategy

import (
	"context"
	"net"
	"testing"
	"time"
)

// closingStrategy dials on its own (no protect.ProtectDialer, so no connect
// report) and waits for the server to speak; when its context ends it closes
// the conn under its own read, and fails with what that read returns - "use
// of closed network connection", not a timeout. That is how a strategy that
// closes on cancellation reports a cut.
type closingStrategy struct {
	id       string
	priority int
}

func (s *closingStrategy) Name() string                        { return s.id }
func (s *closingStrategy) ID() string                          { return s.id }
func (s *closingStrategy) Priority() int                       { return s.priority }
func (s *closingStrategy) RequiresServer() bool                { return true }
func (s *closingStrategy) Description() string                 { return "closes on cancel" }
func (s *closingStrategy) Probe(context.Context, string) error { return nil }
func (s *closingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// TestACutNonReporterIsNotAnAnswer is P3-11 of the round-3 review. A strategy
// that does not report its TCP connect is held to half of a short cycle as a
// whole, but its attempt was read against the full budget: cut at half, it
// never "burned nearly its whole budget", and the closed-conn error it came
// back with counted as the server answering. Every cycle on a server that
// swallows handshakes then had an answer in it, and the run of swallowed
// cycles never reached its verdict.
func TestACutNonReporterIsNotAnAnswer(t *testing.T) {
	swallower := newBlackholeListener(t)
	healthy := newHelloListener(t)
	m := newSilenceManager(t, 2*time.Second, swallower.addr, healthy.addr)
	geneva := &closingStrategy{id: "geneva", priority: 5}
	m.Register(geneva)
	m.Register(&closingStrategy{id: "ws", priority: 6})
	m.Register(&closingStrategy{id: "polling", priority: 7})
	markConnected(m, geneva)

	if s, cycles := connectCycles(t, m, 3, time.Second); s == nil {
		t.Fatalf("still not connected after %d cycles; A: %+v", cycles, endpointState(t, m, swallower.addr))
	}
	if got := m.GetServerAddr(context.Background()); got != healthy.addr {
		t.Fatalf("connected through %s, want %s", got, healthy.addr)
	}
}
