package tun

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// disconnectOnce drives the real read loop into one read error and stops the
// client at the disconnect line, so the reconnect loop that follows does not
// dial. What handleDisconnect decided before its first attempt is left in m.
func disconnectOnce(t *testing.T, m *strategy.Manager, readErr error) {
	t.Helper()
	now := time.Now()
	v := &VPNClient{
		running:     1,
		stopCh:      make(chan struct{}),
		manager:     m,
		conn:        &failingConn{err: readErr},
		connectedAt: now.Add(-5 * time.Minute),
		lastRx:      now.Add(-31 * time.Second),
	}
	out := &stopOnDisconnectLog{v: v}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	done := make(chan struct{})
	go func() {
		v.readFromServer()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		atomic.StoreInt32(&v.running, 0)
		t.Fatalf("read loop did not return; log so far:\n%s", out)
	}
}

// TestSilentDisconnectArmsTheGate pins the call site of D1's fix: a tunnel that
// died on the read deadline has the next Connect walk the pool through the
// pre-flight gate. A reset or an EOF proves the server was there and must keep
// the hot path's skip.
func TestSilentDisconnectArmsTheGate(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"read deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"EOF", io.EOF, false},
		{"reset", &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errors.New("connection reset by peer"))}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := strategy.NewManager()
			m.SetConnectivityChecker(strategy.NewConnectivityChecker("127.0.0.1:1", time.Second, true))
			disconnectOnce(t, m, tc.err)
			if got := m.PreflightArmed(); got != tc.want {
				t.Fatalf("after a %s disconnect the gate is armed=%v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
