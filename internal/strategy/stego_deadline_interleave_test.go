package strategy

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// deadlineConn records every write deadline set on it, in order.
type deadlineConn struct {
	net.Conn
	mu  sync.Mutex
	set []time.Time
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.set = append(c.set, t)
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.set = append(c.set, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineConn) last() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.set) == 0 {
		return time.Time{}
	}
	return c.set[len(c.set)-1]
}

// stegoOverRecorder is a stego conn over a pipe whose far end drains
// everything, the pipe recording the write deadlines set on it.
func stegoOverRecorder(t *testing.T) (*HTTP2StegoConn, *deadlineConn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() { _, _ = io.Copy(io.Discard, b) }()
	rec := &deadlineConn{Conn: a}
	return NewHTTP2StegoConn(rec, []byte("stego-interleave-secret"), true, NaivePaddingMinimal, nil), rec
}

func setRestoreHook(t *testing.T, f func(at string)) {
	t.Helper()
	stegoRestoreHook.Store(&f)
	t.Cleanup(func() { stegoRestoreHook.Store(nil) })
}

// TestARestoreNeverPutsBackAReplacedOwnerDeadline is P3-1 of the round-9
// review: restoreOwnerWD read the owner's deadline under wdMu and applied it
// after letting go, so an owner's SetWriteDeadline in between was undone by
// the stale one - a passed deadline fails the next write for good. The
// owner's set is started where the restore is about to apply. Holding wdMu
// across the apply makes it wait, so the owner's deadline is the last one on
// the socket; without it the owner's set lands first and the restore buries
// it.
func TestARestoreNeverPutsBackAReplacedOwnerDeadline(t *testing.T) {
	sc, rec := stegoOverRecorder(t)
	stale := time.Now().Add(-time.Second)
	fresh := time.Now().Add(time.Hour)
	if err := sc.SetWriteDeadline(stale); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	setRestoreHook(t, func(at string) {
		if at != "apply" {
			return
		}
		once.Do(func() {
			done := make(chan struct{})
			go func() {
				_ = sc.SetWriteDeadline(fresh)
				close(done)
			}()
			// With wdMu held across the apply the owner waits here, and
			// this times out; without it, the owner's set finishes first.
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
			}
		})
	})
	sc.mu.Lock()
	sc.readPathWrite(func() {})
	sc.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for !rec.last().Equal(fresh) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rec.last(); !got.Equal(fresh) {
		t.Fatalf("the socket's write deadline is %v, the owner set %v after the stale %v", got, fresh, stale)
	}
}

// TestARestoreLeavesClosesBoundAlone is P3-2 of the round-9 review: Close
// bounds its GOAWAY with a 1 s deadline and then waits for sc.mu; a write of
// the conn's own that held sc.mu put the owner's deadline - zero on a relay -
// back over that bound, and the GOAWAY could wait forever on a peer that had
// stopped reading. Here the restore of a read-path write waits until Close
// has set its bound.
func TestARestoreLeavesClosesBoundAlone(t *testing.T) {
	sc, rec := stegoOverRecorder(t)
	release := make(chan struct{})
	var once sync.Once
	setRestoreHook(t, func(at string) {
		if at == "enter" {
			once.Do(func() { <-release })
		}
	})
	written := make(chan struct{})
	go func() {
		defer close(written)
		sc.mu.Lock()
		sc.readPathWrite(func() {})
		sc.mu.Unlock()
	}()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = sc.Close()
	}()
	select {
	case <-sc.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close never set its bound")
	}
	close(release)
	<-written
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	if got := rec.last(); got.IsZero() {
		t.Fatal("the restore put the owner's zero deadline back over Close's bound")
	}
}
