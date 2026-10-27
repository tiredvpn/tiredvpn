package tun

import (
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// P2-2 of the round-18 review: every teardown drained. Close on HTTP
// polling and on the ICMP tunnel sends what is queued for up to 5 s, and
// Stop, a dead session, a forced reconnect and the Android core's
// disconnect all called it - a user's disconnect, or a failover off a dead
// path, waited that long, under v.mu or cs.mu. They abort now (closeNow).

// drainingConn is a transport conn whose Close drains for slowClose and
// whose CloseNow returns at once, as HTTP polling's and the ICMP tunnel's
// do.
type drainingConn struct {
	slowClose time.Duration
	closed    atomic.Int64
	aborted   atomic.Int64
}

func (c *drainingConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (c *drainingConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *drainingConn) Close() error {
	c.closed.Add(1)
	time.Sleep(c.slowClose)
	return nil
}
func (c *drainingConn) CloseNow() error {
	c.aborted.Add(1)
	return nil
}
func (c *drainingConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (c *drainingConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (c *drainingConn) SetDeadline(time.Time) error      { return nil }
func (c *drainingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *drainingConn) SetWriteDeadline(time.Time) error { return nil }

// tearDownWithin runs teardown and fails if it took longer than limit, or
// if inner was drained instead of aborted.
func tearDownWithin(t *testing.T, inner *drainingConn, limit time.Duration, teardown func()) {
	t.Helper()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		teardown()
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		if took > limit {
			t.Fatalf("teardown took %v, want the conn aborted instead of drained", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("teardown hung on the conn's drain")
	}
	if inner.aborted.Load() != 1 || inner.closed.Load() != 0 {
		t.Fatalf("CloseNow %d times, Close %d times: want one abort and no drain", inner.aborted.Load(), inner.closed.Load())
	}
}

func stoppableClient(t *testing.T, conn net.Conn) *VPNClient {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	v := &VPNClient{stopCh: make(chan struct{}), tun: &TUNDevice{file: r, hostOwnedLink: true}, conn: conn}
	atomic.StoreInt32(&v.running, 1)
	return v
}

// TestStopAbortsTheTransport: a user's disconnect on the desktop, the
// transport conn behind the handshake reader's replayConn as it often is.
func TestStopAbortsTheTransport(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	v := stoppableClient(t, &replayConn{Conn: inner})
	tearDownWithin(t, inner, time.Second, v.Stop)
}

// TestADeadSessionAbortsTheTransport: the session's read failed; the
// failover does not wait for the dead path to take a drain.
func TestADeadSessionAbortsTheTransport(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	v := stoppableClient(t, inner)
	atomic.StoreInt32(&v.running, 0) // no reconnect after it: only the close is measured
	tearDownWithin(t, inner, time.Second, func() { v.disconnect(inner, "server read", io.EOF) })
}

// TestAForcedReconnectAbortsTheTransport: a network change forces a
// reconnect; the old path is not waited on.
func TestAForcedReconnectAbortsTheTransport(t *testing.T) {
	inner := &drainingConn{slowClose: 3 * time.Second}
	v := stoppableClient(t, inner)
	tearDownWithin(t, inner, time.Second, v.ForceReconnect)
}

// TestAnAndroidDisconnectAbortsTheTransport: the Android core's disconnect
// closes the server conn holding cs.mu, so a drain there held every other
// command - status included - for as long.
func TestAnAndroidDisconnectAbortsTheTransport(t *testing.T) {
	h := newCtlHarnessWith(t, &ControlConfig{MTU: 1280})
	inner := &drainingConn{slowClose: 3 * time.Second}
	h.cs.mu.Lock()
	h.cs.serverConn = inner
	h.cs.mu.Unlock()
	tearDownWithin(t, inner, time.Second, func() {
		select {
		case <-h.sendAsync(`{"command":"disconnect"}`+"\n", -1):
		case <-time.After(5 * time.Second):
		}
	})
}
