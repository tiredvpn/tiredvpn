package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestIsHandshakeFailedLeavesOutWhatSaysNothingOfTheServer is P3-2 of the
// round-14 review, findings 2 and 3 of the round-15 one and P3-1 of the
// round-16 one: a failure is
// the server's side ending the handshake - a reset or an end of stream
// after the request, or a request write the peer reset - and nothing the
// client's side did: stopping, a timeout, a socket its own host aborted, a
// network gone.
func TestIsHandshakeFailedLeavesOutWhatSaysNothingOfTheServer(t *testing.T) {
	live := context.Background()
	done, cancel := context.WithCancel(context.Background())
	cancel()
	notSent := func(err error) error { return fmt.Errorf("%w: %w", errHandshakeNotSent, err) }
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"end of stream after the request", live, io.EOF, true},
		{"reset after the request", live, syscall.ECONNRESET, true},
		{"request write reset by the peer", live, notSent(syscall.EPIPE), true},
		{"request write, connection reset", live, notSent(syscall.ECONNRESET), true},
		{"silent for the full wait", live, fmt.Errorf("%w: %w", errHandshakeSilent, errors.New("timeout")), false},
		{"read deadline", live, os.ErrDeadlineExceeded, false},
		{"answered in part", live, fmt.Errorf("%w: %w", errHandshakePartlyAnswered, io.EOF), false},
		{"refused", live, errHandshakeRefused, false},
		{"request write timed out", live, notSent(os.ErrDeadlineExceeded), false},
		{"request write on a conn closed under it", live, notSent(net.ErrClosed), false},
		{"request write while cancelled", done, notSent(syscall.EPIPE), false},
		{"end of stream while cancelled", done, io.EOF, false},
		{"cut short by the budget", live, fmt.Errorf("%w: %w", errHandshakeCutShort, io.EOF), false},
		{"cancelled", live, fmt.Errorf("handshake: %w", context.Canceled), false},
		{"deadline of the caller", live, fmt.Errorf("handshake: %w", context.DeadlineExceeded), false},
		{"socket aborted by the host (netd)", live, &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNABORTED)}, false},
		{"network down", live, syscall.ENETDOWN, false},
		{"network unreachable", live, syscall.ENETUNREACH, false},
		{"host unreachable", live, syscall.EHOSTUNREACH, false},
		{"address gone", live, notSent(syscall.EADDRNOTAVAIL), false},
		{"smux write timeout", live, notSent(errors.New("timeout")), false},
		{"smux write timeout, marked", live, notSent(markWriteTimeout(errors.New("timeout"), time.Now().Add(-time.Second))), false},
		{"request write on a mux closed locally", live, notSent(io.ErrClosedPipe), false},
		{"read on a mux closed locally", live, io.ErrClosedPipe, false},
		{"request write, network reset (macOS)", live, notSent(syscall.ENETRESET), false},
		{"request write, no buffer space", live, notSent(syscall.ENOBUFS), false},
		{"request write, local firewall", live, notSent(syscall.EPERM), false},
		{"request write, not connected", live, notSent(syscall.ENOTCONN), false},
	} {
		if got := IsHandshakeFailed(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: IsHandshakeFailed = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAWriteAtItsDeadlineReportsATimeout: smux names its write deadline
// errors.New("timeout"), no net.Error; the client's clock makes it one.
func TestAWriteAtItsDeadlineReportsATimeout(t *testing.T) {
	smux := errors.New("timeout")
	var ne net.Error
	if err := markWriteTimeout(smux, time.Now().Add(-time.Millisecond)); !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, smux) {
		t.Fatalf("a write at its deadline: %#v, want a timeout wrapping the transport's error", err)
	}
	if err := markWriteTimeout(syscall.EPIPE, time.Now().Add(time.Hour)); err != syscall.EPIPE {
		t.Fatalf("a write before its deadline came back as %#v", err)
	}
}
