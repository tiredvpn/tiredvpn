package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// exitPlay is what a scripted exit does with one session handshake.
type exitPlay int

const (
	playSilent exitPlay = iota // takes the request, says nothing
	playRefuse                 // answers "IP pool exhausted"
	playPart                   // answers 4 bytes of 9 and goes quiet
	playPrefix                 // answers the 9-byte prefix of a success and goes quiet
	playNoTail                 // announces the dual-stack block and does not send it
)

// scriptedPipeStrategy connects at once, like mutePipeStrategy, and its exit
// plays script in order, one entry per connect, the last one from then on.
type scriptedPipeStrategy struct {
	t        *testing.T
	id       string
	priority int
	mu       sync.Mutex
	script   []exitPlay
}

func (s *scriptedPipeStrategy) Name() string                        { return s.id }
func (s *scriptedPipeStrategy) ID() string                          { return s.id }
func (s *scriptedPipeStrategy) Priority() int                       { return s.priority }
func (s *scriptedPipeStrategy) Probe(context.Context, string) error { return nil }
func (s *scriptedPipeStrategy) RequiresServer() bool                { return true }
func (s *scriptedPipeStrategy) Description() string                 { return "scripted exit" }
func (s *scriptedPipeStrategy) Connect(context.Context, string) (net.Conn, error) {
	s.mu.Lock()
	play := s.script[0]
	if len(s.script) > 1 {
		s.script = s.script[1:]
	}
	s.mu.Unlock()
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		switch play {
		case playRefuse:
			_, _ = srv.Write([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})
			return
		case playPart:
			_, _ = srv.Write([]byte{0x00, 10, 0, 0})
		case playPrefix:
			_, _ = srv.Write(bareV3Response())
		case playNoTail:
			_, _ = srv.Write(append(bareV3Response(), tunFlagDualStack))
		}
		_, _ = io.Copy(io.Discard, srv)
	}()
	return cli, nil
}

// TestARefusalEndsTheUnansweredRun is P3-4 of the round-8 review, through
// the client's connect: unanswered, then "IP pool exhausted", then
// unanswered again parked the server as silent, though it had answered in
// between. Only a success ended the run.
func TestARefusalEndsTheUnansweredRun(t *testing.T) {
	old := handshakeReadTimeout
	handshakeReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeReadTimeout = old })

	a, b := newNetcheckListener(t).addr, newNetcheckListener(t).addr
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&scriptedPipeStrategy{t: t, id: "confusion", priority: 5, script: []exitPlay{playSilent}})
	m.Register(&scriptedPipeStrategy{t: t, id: "morph", priority: 6, script: []exitPlay{playRefuse, playSilent}})

	v := newCallsiteClient(m)
	for cycle := 1; cycle <= 3; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := v.connect(ctx)
		cancel()
		if got := m.GetServerAddr(context.Background()); got != a {
			t.Fatalf("cycle %d ran on %s, want a %s", cycle, got, a)
		}
		if err == nil {
			t.Fatalf("cycle %d connected - the test proves nothing", cycle)
		}
		if cycle == 2 && !errors.Is(err, errHandshakeRefused) {
			t.Fatalf("cycle 2: %v, want the refusal - the test proves nothing", err)
		}
		if errors.Is(err, strategy.ErrAddrSilent) {
			t.Fatalf("cycle %d: a's silence verdict, though a refused a session in between: %v", cycle, err)
		}
	}
}

// TestAPartAnswerIsNotTheServersSilence: an exit that answered part of the
// response before going quiet did answer. The read's timeout was booked as
// an unanswered handshake all the same (P2-2 of the round-8 review). Part
// of the 9-byte prefix, the prefix without the flags byte a dual-stack
// client always gets, the flags without the block they announce.
func TestAPartAnswerIsNotTheServersSilence(t *testing.T) {
	for _, tc := range []struct {
		name string
		play exitPlay
		v6   IPv6Policy
	}{
		{"part of the prefix", playPart, IPv6PolicyOff},
		{"the prefix without the flags byte", playPrefix, IPv6PolicyDual},
		{"the flags without the dual-stack block", playNoTail, IPv6PolicyDual},
	} {
		t.Run(tc.name, func(t *testing.T) { partAnswer(t, tc.play, tc.v6) })
	}
}

func partAnswer(t *testing.T, play exitPlay, v6 IPv6Policy) {
	old := handshakeReadTimeout
	handshakeReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeReadTimeout = old })

	a, b := newNetcheckListener(t).addr, newNetcheckListener(t).addr
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(&scriptedPipeStrategy{t: t, id: "confusion", priority: 5, script: []exitPlay{play}})

	v := newCallsiteClient(m)
	v.ipv6Policy = v6
	for cycle := 1; cycle <= 2; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := v.connect(ctx)
		cancel()
		var ne net.Error
		if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("cycle %d: %v, want the read to time out after part of the answer - the test proves nothing", cycle, err)
		}
		if errors.Is(err, strategy.ErrCycleUnanswered) || errors.Is(err, strategy.ErrAddrSilent) {
			t.Fatalf("cycle %d: a part answer was booked as the server's silence: %v", cycle, err)
		}
	}
}
