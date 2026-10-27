package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

// TestIsHandshakeFailedLeavesOutWhatSaysNothingOfTheServer is P3-2 of the
// round-14 review: the desktop booked a cancellation or a timed-out
// request write - a client stopping - as the candidate's failure. Failed is
// a reset or an end of stream after the request, nothing else.
func TestIsHandshakeFailedLeavesOutWhatSaysNothingOfTheServer(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"end of stream after the request", io.EOF, true},
		{"reset after the request", syscall.ECONNRESET, true},
		{"silent for the full wait", fmt.Errorf("%w: %w", errHandshakeSilent, errors.New("timeout")), false},
		{"read deadline", os.ErrDeadlineExceeded, false},
		{"answered in part", fmt.Errorf("%w: %w", errHandshakePartlyAnswered, io.EOF), false},
		{"refused", errHandshakeRefused, false},
		{"request never left", fmt.Errorf("%w: %w", errHandshakeNotSent, syscall.EPIPE), false},
		{"cut short by the budget", fmt.Errorf("%w: %w", errHandshakeCutShort, io.EOF), false},
		{"cancelled", fmt.Errorf("handshake: %w", context.Canceled), false},
		{"deadline of the caller", fmt.Errorf("handshake: %w", context.DeadlineExceeded), false},
	} {
		if got := IsHandshakeFailed(tc.err); got != tc.want {
			t.Errorf("%s: IsHandshakeFailed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
