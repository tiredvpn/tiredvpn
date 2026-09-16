package tun

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// netcheckListener counts accepted connections so a test can assert WHICH
// address the network check dialled, not merely what verdict it returned.
type netcheckListener struct {
	ln      net.Listener
	addr    string
	accepts atomic.Int64
	done    chan struct{}
	once    sync.Once
}

func newNetcheckListener(t *testing.T) *netcheckListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &netcheckListener{ln: ln, addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepts.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(l.stop)
	return l
}

func (l *netcheckListener) stop() {
	l.once.Do(func() {
		l.ln.Close()
		<-l.done
	})
}

// waitAccepts polls until the listener has seen at least n connections.
//
// Reading the counter straight after the call under test returns is a race, not
// an assertion: the kernel completes the handshake from the backlog, so the
// dialler is already back while the accept goroutine has not run yet. Polling
// turns "not yet" into "not at all" only after the timeout.
func waitAccepts(t *testing.T, l *netcheckListener, n int64) int64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := l.accepts.Load()
		if got >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCheckNetworkConnectivityUsesTheManagerGate pins the rewrite: the
// reconnect loop asks the manager's connectivity gate, which dials the endpoint
// the selector pinned on the real transport port.
//
// The old code instead derived a port list from v.serverAddr's host and dialled
// :443 and :80 on it - a three-port scan of our own machine on a timer, with a
// signature of its own, and IPv4-only besides. Pointing v.serverAddr at a dead
// address while the gate points at a live one is what tells the two apart: only
// the new path can return true here, and only the gate's listener can see the
// connection.
func TestCheckNetworkConnectivityUsesTheManagerGate(t *testing.T) {
	gateTarget := newNetcheckListener(t)

	dead := newNetcheckListener(t)
	deadAddr := dead.addr
	dead.stop()

	m := strategy.NewManager()
	checker := strategy.NewConnectivityChecker(gateTarget.addr, 500*time.Millisecond, true)
	m.SetConnectivityChecker(checker)

	v := &VPNClient{manager: m, serverAddr: deadAddr}

	if !v.checkNetworkConnectivity() {
		t.Fatal("checkNetworkConnectivity = false while the gate's address answers")
	}
	if n := waitAccepts(t, gateTarget, 1); n == 0 {
		t.Fatal("the gate's address saw no connection - the check did not go through the gate")
	}
}

// TestCheckNetworkConnectivityWithoutAGate covers the callers that never set
// one (macOS, benchmarks). It is coverage of the fallback branch, not evidence
// about the port scan: the discriminating case is the test above.
func TestCheckNetworkConnectivityWithoutAGate(t *testing.T) {
	server := newNetcheckListener(t)
	v := &VPNClient{manager: strategy.NewManager(), serverAddr: server.addr}

	if !v.checkNetworkConnectivity() {
		t.Fatal("checkNetworkConnectivity = false while the server address answers")
	}
	if n := waitAccepts(t, server, 1); n == 0 {
		t.Fatal("the server address was never dialled")
	}
}

// A dial that comes back with ECONNREFUSED still proves the path is alive:
// something answered with an RST. Only silence (timeout) means "down". The
// network check relies on this because its physical probe dials the
// default-route gateway, whose port 53 is usually closed.
func TestErrMeansPathAlive(t *testing.T) {
	refused := &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	if !errMeansPathAlive(refused) {
		t.Fatal("ECONNREFUSED must count as an alive path")
	}
	timedOut := &net.OpError{Op: "dial", Err: os.NewSyscallError("i/o timeout", syscall.ETIMEDOUT)}
	if errMeansPathAlive(timedOut) {
		t.Fatal("a timeout must not count as an alive path")
	}
	if errMeansPathAlive(nil) {
		t.Fatal("nil error must not count as an alive path via the error path")
	}
}

func TestDialMeansAliveRefusedCountsAsAlive(t *testing.T) {
	// Grab a port the kernel just released; dialing it must come back with
	// ECONNREFUSED on loopback, which dialMeansAlive reports as alive.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if !dialMeansAlive(addr) {
		t.Fatal("connection refused on loopback must be reported as an alive path")
	}
}
