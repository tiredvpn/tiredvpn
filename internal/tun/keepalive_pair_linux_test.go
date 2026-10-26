package tun

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// blockingKeepaliveConn holds the first keepalive written on it until it is
// released, and counts the keepalives.
type blockingKeepaliveConn struct {
	net.Conn
	once       sync.Once
	inWrite    chan struct{}
	release    chan struct{}
	mu         sync.Mutex
	nKeepalive int
}

func (c *blockingKeepaliveConn) Write(p []byte) (int, error) {
	if bytes.Equal(p, []byte{0, 0, 0, 0}) {
		c.mu.Lock()
		c.nKeepalive++
		c.mu.Unlock()
		first := false
		c.once.Do(func() { first = true })
		if first {
			close(c.inWrite)
			<-c.release
		}
	}
	return c.Conn.Write(p)
}

func (c *blockingKeepaliveConn) keepalives() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nKeepalive
}

// TestTwoKeepalivesNeverGoBackToBack is the client half of P3-5 of the
// round-9 review: while the server-silence keepalive's write was blocked,
// the uplink keepalive saw the old lastTx and wrote too, a pair. Here the
// silence keepalive blocks in its write exactly when the uplink keepalive
// takes the conn; once it is let go, only one keepalive may have gone.
func TestTwoKeepalivesNeverGoBackToBack(t *testing.T) {
	var bc *blockingKeepaliveConn
	h := newQuietStallHarness(t, func(c net.Conn) net.Conn {
		bc = &blockingKeepaliveConn{Conn: c, inWrite: make(chan struct{}), release: make(chan struct{})}
		return bc
	})
	const period = 200 * time.Millisecond
	restore := SetUplinkKeepaliveDraw(func() time.Duration { return period })
	t.Cleanup(func() { SetUplinkKeepaliveDraw(restore) })
	var once sync.Once
	taken := func() {
		once.Do(func() {
			go h.v.writeSilenceKeepalive(bc)
			<-bc.inWrite
			// The uplink keepalive goes on while the other one's write is
			// still blocked; let that one finish a little later.
			time.AfterFunc(100*time.Millisecond, func() { close(bc.release) })
		})
	}
	uplinkConnTaken.Store(&taken)
	t.Cleanup(func() { uplinkConnTaken.Store(nil) })
	resets := make(chan struct{}, 16)
	f := func(_, _, _ time.Duration) {
		select {
		case resets <- struct{}{}:
		default:
		}
	}
	uplinkTimerReset.Store(&f)
	t.Cleanup(func() { uplinkTimerReset.Store(nil) })
	go h.v.keepUplinkAlive()
	select {
	case <-resets:
	case <-time.After(3 * time.Second):
		t.Fatal("the uplink keepalive never came round - the test proves nothing")
	}
	time.Sleep(150 * time.Millisecond)
	if n := bc.keepalives(); n != 1 {
		t.Fatalf("%d keepalives went up back to back, want 1", n)
	}
}

// TestASilenceKeepaliveRightAfterAnUplinkOneIsSkipped is the other order,
// P3-7 of the round-10 review: the uplink keepalive goes first and its
// write blocks; the server-silence keepalive, decided on the server's
// silence rather than on lastTx, waits for it and then must not write a
// second one back to back. Only writeSilenceKeepalive's half-interval skip
// stops it, and removing the skip left every keepalive test green.
func TestASilenceKeepaliveRightAfterAnUplinkOneIsSkipped(t *testing.T) {
	var bc *blockingKeepaliveConn
	h := newQuietStallHarness(t, func(c net.Conn) net.Conn {
		bc = &blockingKeepaliveConn{Conn: c, inWrite: make(chan struct{}), release: make(chan struct{})}
		return bc
	})
	restore := SetUplinkKeepaliveDraw(func() time.Duration { return 200 * time.Millisecond })
	t.Cleanup(func() { SetUplinkKeepaliveDraw(restore) })
	go h.v.keepUplinkAlive()
	select {
	case <-bc.inWrite:
	case <-time.After(3 * time.Second):
		t.Fatal("the uplink keepalive never wrote - the test proves nothing")
	}
	silence := make(chan struct{})
	go func() {
		h.v.writeSilenceKeepalive(bc)
		close(silence)
	}()
	time.AfterFunc(100*time.Millisecond, func() { close(bc.release) })
	select {
	case <-silence:
	case <-time.After(3 * time.Second):
		t.Fatal("the silence keepalive never returned")
	}
	if n := bc.keepalives(); n != 1 {
		t.Fatalf("%d keepalives went up back to back, want 1", n)
	}
}
