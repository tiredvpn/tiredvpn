//go:build linux

package tun

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// silentExit is an exit that accepts the TUN handshake request and never
// answers it - the state a stop on a device kept landing in.
type silentExit struct {
	cli, srv net.Conn
	gotReq   chan struct{}
	closed   atomic.Bool
}

func newSilentExit(t *testing.T) *silentExit {
	t.Helper()
	cli, srv := net.Pipe()
	e := &silentExit{cli: cli, srv: srv, gotReq: make(chan struct{})}
	go func() {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(srv, buf); err == nil {
			close(e.gotReq)
		}
		// Keep reading until the client side goes away.
		for {
			if _, err := srv.Read(buf); err != nil {
				e.closed.Store(true)
				return
			}
		}
	}()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return e
}

// closeWithin runs Close and reports how long it took, giving up waiting
// after limit so a Close that hangs fails the test instead of the run.
func closeWithin(cs *ControlServer, limit time.Duration) time.Duration {
	done := make(chan struct{})
	begin := time.Now()
	go func() { _ = cs.Close(); close(done) }()
	select {
	case <-done:
		return time.Since(begin)
	case <-time.After(limit):
		return limit
	}
}

func openFdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func goroutinesIn(fns ...string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	c := 0
	for _, fn := range fns {
		c += strings.Count(string(buf), fn)
	}
	return c
}

// newLifetimeHarness is a harness whose server has no session yet: "connect"
// goes through ConnectFn.
func newLifetimeHarness(t *testing.T, connect func(ctx context.Context) (net.Conn, error)) *ctlHarness {
	t.Helper()
	h := newCtlHarness(t)
	h.cs.mu.Lock()
	h.cs.serverConn = nil
	h.cs.assignedIP = nil
	h.cs.serverIP = nil
	h.cs.waitingForFd = false
	h.cs.config.ConnectFn = func(ctx context.Context) (net.IP, net.IP, net.Conn, error) {
		conn, err := connect(ctx)
		return net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), conn, err
	}
	h.cs.mu.Unlock()
	return h
}

// TestControlCloseInterruptsConnect: "connect" holds the server lock while it
// waits up to 10s for the exit's TUN handshake response, and Close used to
// queue behind it - on a device that pushed stop past the host's 5s deadline.
// Close has to cut the connect short, and the connect must leave nothing
// behind: no session, no connection, no goroutine, no descriptor.
func TestControlCloseInterruptsConnect(t *testing.T) {
	exit := newSilentExit(t)
	h := newLifetimeHarness(t, func(context.Context) (net.Conn, error) { return exit.cli, nil })
	h.stillServing() // the control connection is accepted and idle
	fdsBefore := openFdCount(t)
	gBefore := goroutinesIn("performTUNHandshake(", "readHandshakeResponse(", "handleConnect(")

	respCh := h.sendAsync(`{"command":"connect"}`+"\n", -1)
	select {
	case <-exit.gotReq:
	case <-time.After(3 * time.Second):
		t.Fatal("positive control: connect never sent the handshake")
	}

	closeAt := time.Now()
	if d := closeWithin(h.cs, 15*time.Second); d > time.Second {
		t.Errorf("Close took %v while a connect waited on a silent exit", d)
	}

	select {
	case resp := <-respCh:
		if resp.Status != "error" {
			t.Errorf("interrupted connect answered %+v", resp)
		}
		// The connect itself has to end, not just Close return around it.
		if d := time.Since(closeAt); d > time.Second {
			t.Errorf("connect kept waiting for the handshake %v after Close", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("interrupted connect never answered")
	}
	h.cs.mu.Lock()
	half := h.cs.serverConn != nil || h.cs.assignedIP != nil || h.cs.waitingForFd
	h.cs.mu.Unlock()
	if half {
		t.Error("the interrupted connect left a half-built session")
	}
	if !waitFor(2*time.Second, exit.closed.Load) {
		t.Error("the interrupted connect left its exit connection open")
	}
	if !waitFor(2*time.Second, func() bool {
		return goroutinesIn("performTUNHandshake(", "readHandshakeResponse(", "handleConnect(") <= gBefore
	}) {
		t.Error("a connect goroutine outlived Close")
	}
	if !waitFor(2*time.Second, func() bool { return openFdCount(t) <= fdsBefore }) {
		t.Errorf("descriptors: %d before the connect, %d after Close", fdsBefore, openFdCount(t))
	}
}

// TestControlCloseBoundedWhenConnectIgnoresCancel: a dial that does not honour
// cancellation still must not hold Close. Whatever it returns afterwards is
// dropped, not installed as a session.
func TestControlCloseBoundedWhenConnectIgnoresCancel(t *testing.T) {
	exit := newSilentExit(t)
	release := make(chan struct{})
	// Deaf to ctx; lets go on its own after 2s so a Close that waits for it
	// shows up as slow instead of deadlocking the test.
	time.AfterFunc(2*time.Second, func() { close(release) })
	h := newLifetimeHarness(t, func(context.Context) (net.Conn, error) {
		<-release
		return exit.cli, nil
	})
	h.stillServing()
	respCh := h.sendAsync(`{"command":"connect"}`+"\n", -1)
	time.Sleep(100 * time.Millisecond)

	if d := closeWithin(h.cs, 15*time.Second); d > time.Second {
		t.Errorf("Close took %v behind a dial that ignores cancellation", d)
	}

	select {
	case resp := <-respCh:
		if resp.Status != "error" {
			t.Errorf("connect finishing after Close answered %+v", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("connect never answered")
	}
	h.cs.mu.Lock()
	half := h.cs.serverConn != nil || h.cs.assignedIP != nil || h.cs.waitingForFd
	h.cs.mu.Unlock()
	if half {
		t.Error("a connect that finished after Close installed a session")
	}
	if !waitFor(2*time.Second, exit.closed.Load) {
		t.Error("the connection a late dial returned was not closed")
	}
}

// TestControlCloseKeepsNewerSocket: after a stop that gave up waiting, the
// old core is still running when the host starts a new one on the same path.
// When the old one finally closes it must remove only its own socket file,
// not the one the new core is listening on.
func TestControlCloseKeepsNewerSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	oldSrv, err := NewControlServer(path, &ControlConfig{MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	newSrv, err := NewControlServer(path, &ControlConfig{MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); newSrv.Close() })
	go func() { _ = newSrv.Run(ctx) }()

	_ = oldSrv.Close()

	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the old server's Close removed the new server's socket file: %v", err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the new server no longer accepts connections: %v", err)
	}
	conn.Close()
}

// TestControlCloseRemovesOwnSocket: the positive side of the same rule - a
// server that still owns the path removes its socket file on Close.
func TestControlCloseRemovesOwnSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	srv, err := NewControlServer(path, &ControlConfig{MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket file left behind after Close: %v", err)
	}
}

// TestControlCloseInterruptsNetworkChanged: network_changed redials and
// redoes the handshake through ReconnectFn with cs.mu held. Close has to
// cancel that too, and nothing it was building may survive.
func TestControlCloseInterruptsNetworkChanged(t *testing.T) {
	h := sessionWithTun(t)
	entered := make(chan struct{})
	h.cs.mu.Lock()
	h.cs.config.ReconnectFn = func(ctx context.Context, _ net.IP, _ int) (ReconnectResult, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return ReconnectResult{}, ctx.Err()
		case <-time.After(3 * time.Second): // a stand-in for the 10s handshake read
			return ReconnectResult{}, context.DeadlineExceeded
		}
	}
	h.cs.mu.Unlock()
	next := newFakeTun(t, false)
	respCh := h.sendAsync(`{"command":"network_changed","reason":"wifi_to_lte"}`+"\n", next.host)
	next.dropHostCopy()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("positive control: network_changed never reached ReconnectFn")
	}

	closeAt := time.Now()
	if d := closeWithin(h.cs, 15*time.Second); d > time.Second {
		t.Errorf("Close took %v while network_changed was reconnecting", d)
	}
	select {
	case resp := <-respCh:
		if resp.Status != "error" {
			t.Errorf("interrupted network_changed answered %+v", resp)
		}
		if d := time.Since(closeAt); d > time.Second {
			t.Errorf("network_changed kept reconnecting %v after Close", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("interrupted network_changed never answered")
	}
	if !next.peerSeesHangup(3 * time.Second) {
		t.Error("the TUN fd network_changed brought survived Close")
	}
	h.cs.mu.Lock()
	half := h.cs.serverConn != nil || h.cs.relay != nil || h.cs.tunDev != nil
	h.cs.mu.Unlock()
	if half {
		t.Error("the interrupted network_changed left a session behind")
	}
}
