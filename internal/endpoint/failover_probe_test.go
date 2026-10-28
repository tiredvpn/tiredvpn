package endpoint

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestProbeCurrentDoesNotBlameTheServerForTheLink is D7 of the 2026-10-21 stand
// report. The client's link was down; the family probe of the pinned server
// failed on it, charged the server, and moved the pin to another server, where
// the client stayed after the link came back with both servers alive.
//
// Two ways the host says "not me, I cannot send": the family is marked
// unroutable (the probe must not even dial), or the dial fails in the local
// stack. Neither may touch health or the pin.
func TestProbeCurrentDoesNotBlameTheServerForTheLink(t *testing.T) {
	t.Run("no physical route", func(t *testing.T) {
		d := newScriptedDialer(v4Addr)
		s, _ := newTestSelector(t, Config{Family: PreferV6, Dial: d.dial})
		s.SetReachable(v6Addr, false)

		cand, kept := s.ProbeCurrent(context.Background())
		if !kept || cand.Addr != v6Addr {
			t.Fatalf("ProbeCurrent = %s (kept=%v), want the pin left on %s", cand.Addr, kept, v6Addr)
		}
		if n := d.count(); n != 0 {
			t.Fatalf("probed an address with no physical route (%d dials)", n)
		}
		if st := stateOf(t, s, v6Addr); st.ConsecutiveFailures != 0 {
			t.Fatalf("the server was charged for the client's missing route: %+v", st)
		}
	})

	for _, errno := range []syscall.Errno{syscall.ENETUNREACH, syscall.ENETDOWN, syscall.EADDRNOTAVAIL} {
		t.Run(errno.Error(), func(t *testing.T) {
			dial := func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
			}
			s, _ := newTestSelector(t, Config{Family: PreferV6, Dial: dial})
			cand, kept := s.ProbeCurrent(context.Background())
			if !kept || cand.Addr != v6Addr {
				t.Fatalf("ProbeCurrent = %s (kept=%v) on a local %v, want the pin left on %s", cand.Addr, kept, errno, v6Addr)
			}
			if st := stateOf(t, s, v6Addr); st.ConsecutiveFailures != 0 {
				t.Fatalf("the server was charged for a local %v: %+v", errno, st)
			}
		})
	}

	// Positive control: a probe that reached the network and heard nothing
	// still moves the pin, as it always did.
	t.Run("server silent", func(t *testing.T) {
		d := newScriptedDialer(v4Addr)
		s, _ := newTestSelector(t, Config{Family: PreferV6, Dial: d.dial})
		if cand, kept := s.ProbeCurrent(context.Background()); kept || cand.Addr != v4Addr {
			t.Fatalf("ProbeCurrent = %s (kept=%v), want the fallback %s", cand.Addr, kept, v4Addr)
		}
	})
}
