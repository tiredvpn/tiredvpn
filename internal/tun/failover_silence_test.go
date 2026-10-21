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
	disconnectSession(t, m, nil, readErr, now.Add(-5*time.Minute), now.Add(-31*time.Second))
}

// disconnectSession is disconnectOnce for a session carried by strat, which
// connected at connectedAt and last heard from the server at lastRx.
func disconnectSession(t *testing.T, m *strategy.Manager, strat strategy.Strategy, readErr error, connectedAt, lastRx time.Time) {
	t.Helper()
	v := &VPNClient{
		running:     1,
		stopCh:      make(chan struct{}),
		manager:     m,
		strategy:    strat,
		conn:        &failingConn{err: readErr},
		connectedAt: connectedAt,
		lastRx:      lastRx,
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

// TestSessionEndChargesOnlyADeadSession pins D2's call site. A tunnel that ran
// for minutes and then lost its server to a restart says nothing about the
// transport; v1.11.8 charged it anyway, and one restart put REALITY behind HTTP
// Polling. A session whose downlink died within seconds of connecting is what a
// DPI teardown looks like and still costs the strategy.
func TestSessionEndChargesOnlyADeadSession(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name                string
		err                 error
		connectedAt, lastRx time.Time
		charged             bool
	}{
		{"restart after 15 min", io.EOF, now.Add(-15 * time.Minute), now.Add(-time.Second), false},
		{"silence after 15 min", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, now.Add(-15 * time.Minute), now.Add(-31 * time.Second), false},
		{"downlink died at once", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, now.Add(-32 * time.Second), now.Add(-31 * time.Second), true},
		{"reset after 3 s", io.EOF, now.Add(-3 * time.Second), now.Add(-2 * time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := strategy.NewManager()
			ps := &pipeStrategy{t: t}
			m.Register(ps)
			before := m.GetStats()[ps.ID()].Confidence
			disconnectSession(t, m, ps, tc.err, tc.connectedAt, tc.lastRx)
			after := m.GetStats()[ps.ID()].Confidence
			if charged := after < before; charged != tc.charged {
				t.Fatalf("confidence %.2f -> %.2f: charged=%v, want %v", before, after, charged, tc.charged)
			}
		})
	}
}
