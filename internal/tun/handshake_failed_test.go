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
)

// TestIsHandshakeFailedLeavesOutWhatSaysNothingOfTheServer is P3-2 of the
// round-14 review and findings 2 and 3 of the round-15 one: a failure is
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
	} {
		if got := IsHandshakeFailed(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: IsHandshakeFailed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
