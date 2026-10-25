package tun

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// abortableConn models the transports Stop closes: Close delivers whatever
// the shaper still has queued and can take seconds, CloseNow gives that up
// and returns at once (MorphedConn and RTTMaskingConn both do this).
type abortableConn struct {
	net.Conn
	slowClose time.Duration
	closed    atomic.Int64
	abortions atomic.Int64
}

func (c *abortableConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (c *abortableConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *abortableConn) Close() error {
	c.closed.Add(1)
	time.Sleep(c.slowClose)
	return nil
}
func (c *abortableConn) CloseNow() error {
	c.abortions.Add(1)
	return nil
}
func (c *abortableConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *abortableConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *abortableConn) SetDeadline(t time.Time) error      { return nil }
func (c *abortableConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *abortableConn) SetWriteDeadline(t time.Time) error { return nil }

// TestStopAbortsTheTunnelConn: Stop must not wait for the tunnel conn to
// deliver its queued tail. It used to call Close, which drains for up to
// its close timeout, and the TUN writer's +30 s write deadline could land
// between Stop's SetDeadline(now) and that Close and undo the abort.
func TestStopAbortsTheTunnelConn(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	conn := &abortableConn{slowClose: 5 * time.Second}
	var v VPNClient
	v.stopCh = make(chan struct{})
	v.tun = &TUNDevice{file: r, hostOwnedLink: true}
	v.conn = conn
	atomic.StoreInt32(&v.running, 1)

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		v.Stop()
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		if took > time.Second {
			t.Fatalf("Stop took %v, want the conn aborted instead of drained", took)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Stop hung on the tunnel conn")
	}
	if got := conn.abortions.Load(); got != 1 {
		t.Fatalf("CloseNow called %d times, want once", got)
	}
	if got := conn.closed.Load(); got != 0 {
		t.Fatalf("plain Close called %d times, want none", got)
	}
}
