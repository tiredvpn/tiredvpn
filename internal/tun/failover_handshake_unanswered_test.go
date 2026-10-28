package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// mutePipeStrategy connects at once - like Protocol Confusion, it hears
// nothing from the server before it returns - and the exit behind it reads
// the session handshake and answers it only where answers says so.
type mutePipeStrategy struct {
	t        *testing.T
	id       string
	priority int
	answers  map[string]bool
}

func (s *mutePipeStrategy) Name() string                        { return s.id }
func (s *mutePipeStrategy) ID() string                          { return s.id }
func (s *mutePipeStrategy) Priority() int                       { return s.priority }
func (s *mutePipeStrategy) Probe(context.Context, string) error { return nil }
func (s *mutePipeStrategy) RequiresServer() bool                { return true }
func (s *mutePipeStrategy) Description() string                 { return "connects without an answer" }
func (s *mutePipeStrategy) Connect(_ context.Context, target string) (net.Conn, error) {
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	if s.answers[target] {
		playExit(s.t, srv, bareV3Response(), 0)
	} else {
		go func() { _, _ = io.Copy(io.Discard, srv) }() // takes the request, says nothing
	}
	return cli, nil
}

// TestTwoSwallowingServersDoNotKeepTheClientFromTheThird is R1 of the fix9
// stand run, through the client's own connect: a and b let every transport
// connect and never answer the session handshake, c is healthy. The
// transports here connect without hearing from the server, as Protocol
// Confusion does, so each connect was booked as a success. The fast path
// went back to the same transport on the same server every cycle, the
// server was never parked ("6 candidates, none parked"), the error was a
// plain read timeout, and the backoff grew to 2 minutes; c was not reached
// in 7.2 minutes. An unanswered session handshake is now a cycle that heard
// nothing, and two on a server are its verdict.
func TestTwoSwallowingServersDoNotKeepTheClientFromTheThird(t *testing.T) {
	old := handshakeReadTimeout
	handshakeReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeReadTimeout = old })

	a, b, c := newNetcheckListener(t).addr, newNetcheckListener(t).addr, newNetcheckListener(t).addr
	m := strategy.NewManager()
	var eps []endpoint.Endpoint
	for i, addr := range []string{a, b, c} {
		eps = append(eps, endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: addr, Order: i})
	}
	if err := m.SetEndpoints(eps, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	healthy := map[string]bool{c: true}
	m.Register(&mutePipeStrategy{t: t, id: "confusion", priority: 5, answers: healthy})
	m.Register(&mutePipeStrategy{t: t, id: "morph", priority: 6, answers: healthy})

	v := newCallsiteClient(m)
	var rode []string
	for cycle := 1; cycle <= 10; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := v.connect(ctx)
		cancel()
		addr := m.GetServerAddr(context.Background())
		rode = append(rode, addr)
		if err == nil {
			if addr != c {
				t.Fatalf("connected on %s, want c %s", addr, c)
			}
			t.Logf("on c after %d cycles: %v", cycle, rode)
			return
		}
		if !errors.Is(err, strategy.ErrCycleUnanswered) && !errors.Is(err, strategy.ErrAddrSilent) {
			t.Fatalf("cycle %d on %s: %v - an unanswered handshake read as an ordinary failure, the backoff grows past the silence cap", cycle, addr, err)
		}
	}
	t.Fatalf("not on c after 10 cycles: %v", rode)
}

// TestAnUnansweredTransportGivesWayToAnotherOnTheSameServer: one transport's
// session handshake goes unanswered on a, another's is answered there. The
// next cycle has to try the other transport on a - not the same one again
// through the fast path, and not leave a for b over one transport.
func TestAnUnansweredTransportGivesWayToAnotherOnTheSameServer(t *testing.T) {
	old := handshakeReadTimeout
	handshakeReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeReadTimeout = old })

	a, b := newNetcheckListener(t).addr, newNetcheckListener(t).addr
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&mutePipeStrategy{t: t, id: "confusion", priority: 5, answers: map[string]bool{b: true}})
	m.Register(&mutePipeStrategy{t: t, id: "morph", priority: 6, answers: map[string]bool{a: true, b: true}})

	v := newCallsiteClient(m)
	for cycle := 1; cycle <= 3; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := v.connect(ctx)
		cancel()
		if err == nil {
			if got, s := m.GetServerAddr(context.Background()), v.strategy; got != a || s == nil || s.ID() != "morph" {
				t.Fatalf("connected via %v on %s, want morph on a", s, got)
			}
			if cycle != 2 {
				t.Fatalf("connected in cycle %d, want the second", cycle)
			}
			return
		}
	}
	t.Fatal("no connection in 3 cycles")
}
