package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// lateStrategy connects after dial and plays an exit that answers the TUN
// handshake answerAfter after the request.
type lateStrategy struct {
	t                 *testing.T
	dial, answerAfter time.Duration
}

func (s *lateStrategy) Name() string                        { return "slowexit" }
func (s *lateStrategy) ID() string                          { return "slowexit" }
func (s *lateStrategy) Priority() int                       { return 1 }
func (s *lateStrategy) Probe(context.Context, string) error { return nil }
func (s *lateStrategy) RequiresServer() bool                { return true }
func (s *lateStrategy) Description() string                 { return "connects late, answers late" }
func (s *lateStrategy) Connect(ctx context.Context, _ string) (net.Conn, error) {
	select {
	case <-time.After(s.dial):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		time.Sleep(s.answerAfter)
		resp := append([]byte{0x00}, reconnServerIP.To4()...)
		_, _ = srv.Write(append(resp, reconnClientIP.To4()...))
	}()
	return cli, nil
}

// acceptAll is a TCP listener that takes every connection, for the
// selector's addresses.
func acceptAll(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// TestACutShortReconnectHandshakeIsNotTheServersSilence is P2-2 of the
// round-8 review, through reconnectTUN, the Android core's ReconnectFn: the
// transport connects late and leaves the handshake what is left of the
// reconnect's budget, and the server answers after that. The cut-short wait
// was booked as the server's silence; by the second reconnect the server
// was parked, by the fourth the route. Scaled: a 400 ms budget, a 100 ms
// connect, an answer 500 ms after the request.
func TestACutShortReconnectHandshakeIsNotTheServersSilence(t *testing.T) {
	a, b := acceptAll(t), acceptAll(t)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&lateStrategy{t: t, dial: 100 * time.Millisecond, answerAfter: 500 * time.Millisecond})

	for i := 1; i <= 4; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
		_, _, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
		cancel()
		if err == nil {
			t.Fatalf("reconnect %d: the handshake fit in the budget - the test proves nothing", i)
		}
		if !strings.Contains(err.Error(), "handshake") {
			t.Fatalf("reconnect %d failed before the handshake - the test proves nothing: %v", i, err)
		}
		if errors.Is(err, strategy.ErrCycleUnanswered) || errors.Is(err, strategy.ErrAddrSilent) {
			t.Fatalf("reconnect %d: a wait cut short by the budget was booked as the server's silence: %v", i, err)
		}
	}
	for _, h := range m.EndpointHealth() {
		if h.CooldownUntil.After(time.Now()) {
			t.Fatalf("%s is parked after handshakes the budget cut short", h.Addr)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, sess, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
	if err != nil {
		t.Fatalf("reconnect with the time to answer: %v", err)
	}
	if !sess.hasCand || sess.cand.Addr != a {
		t.Fatalf("reconnected on %v, want a %s - the server was parked for being slow", sess.cand, a)
	}
}

// stuckWriteConn is a conn whose writes time out, as on a path that went
// dead under the request.
type stuckWriteConn struct{ net.Conn }

func (c stuckWriteConn) Write([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

type stuckWriteStrategy struct{ lateStrategy }

func (s *stuckWriteStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	c, err := s.lateStrategy.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return stuckWriteConn{c}, nil
}

// TestAReconnectRequestThatNeverLeftIsNotTheServersSilence: the write of the
// reconnect's handshake request timing out was a timeout like an unanswered
// read, and booked the same way; on the first connect the write error is
// marked as a request that never left, and now here too.
func TestAReconnectRequestThatNeverLeftIsNotTheServersSilence(t *testing.T) {
	a, b := acceptAll(t), acceptAll(t)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&stuckWriteStrategy{lateStrategy{t: t}})
	for i := 1; i <= 2; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, _, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "handshake write failed") {
			t.Fatalf("reconnect %d: %v, want the request's write to fail - the test proves nothing", i, err)
		}
		if errors.Is(err, strategy.ErrCycleUnanswered) || errors.Is(err, strategy.ErrAddrSilent) {
			t.Fatalf("reconnect %d: a request that never left was booked as the server's silence: %v", i, err)
		}
	}
}

// refusingStrategy connects at once; its exit refuses the first handshake
// with "IP pool exhausted" when refuseFirst, and leaves every other one
// unanswered.
type refusingStrategy struct {
	t           *testing.T
	id          string
	prio        int
	refuseFirst bool
	calls       atomic.Int32
}

func (s *refusingStrategy) Name() string                        { return s.id }
func (s *refusingStrategy) ID() string                          { return s.id }
func (s *refusingStrategy) Priority() int                       { return s.prio }
func (s *refusingStrategy) Probe(context.Context, string) error { return nil }
func (s *refusingStrategy) RequiresServer() bool                { return true }
func (s *refusingStrategy) Description() string                 { return "refuses, then says nothing" }
func (s *refusingStrategy) Connect(context.Context, string) (net.Conn, error) {
	refuse := s.refuseFirst && s.calls.Add(1) == 1
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		if refuse {
			_, _ = srv.Write([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})
			return
		}
		_, _ = io.Copy(io.Discard, srv)
	}()
	return cli, nil
}

// TestAReconnectRefusalEndsTheUnansweredRun is P3-4 of the round-8 review on
// the reconnect: unanswered, refused, unanswered parked the server as silent.
func TestAReconnectRefusalEndsTheUnansweredRun(t *testing.T) {
	old := tun.SetHandshakeReadTimeout(200 * time.Millisecond)
	t.Cleanup(func() { tun.SetHandshakeReadTimeout(old) })
	a, b := acceptAll(t), acceptAll(t)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&refusingStrategy{t: t, id: "confusion", prio: 5})
	m.Register(&refusingStrategy{t: t, id: "morph", prio: 6, refuseFirst: true})
	for i := 1; i <= 3; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		_, _, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
		cancel()
		if err == nil {
			t.Fatalf("reconnect %d connected - the test proves nothing", i)
		}
		if i == 2 && !strings.Contains(err.Error(), "server rejected reconnect") {
			t.Fatalf("reconnect 2: %v, want the refusal - the test proves nothing", err)
		}
		if errors.Is(err, strategy.ErrAddrSilent) {
			t.Fatalf("reconnect %d: a's silence verdict, though a refused a session in between: %v", i, err)
		}
	}
}

// TestAFullyUnansweredReconnectIsStillTheServersSilence is the positive
// control of the two above: handshakes that waited the full wait with the
// reconnect's budget to spare are the server's silence, and two of them on
// different transports are its verdict.
func TestAFullyUnansweredReconnectIsStillTheServersSilence(t *testing.T) {
	old := tun.SetHandshakeReadTimeout(200 * time.Millisecond)
	t.Cleanup(func() { tun.SetHandshakeReadTimeout(old) })
	a, b := acceptAll(t), acceptAll(t)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&refusingStrategy{t: t, id: "confusion", prio: 5})
	m.Register(&refusingStrategy{t: t, id: "morph", prio: 6})
	var errs []error
	for range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, _, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
		cancel()
		errs = append(errs, err)
	}
	if !errors.Is(errs[0], strategy.ErrCycleUnanswered) {
		t.Fatalf("reconnect 1: %v, want an unanswered cycle", errs[0])
	}
	if !errors.Is(errs[1], strategy.ErrAddrSilent) {
		t.Fatalf("reconnect 2: %v, want a's silence verdict", errs[1])
	}
}
