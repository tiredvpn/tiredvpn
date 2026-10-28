package strategy

import (
	"net"
	"sync"
	"testing"
	"time"
)

// wdRecorder records the write deadlines set on a conn.
type wdRecorder struct {
	net.Conn
	mu  sync.Mutex
	wds []time.Time
}

func (c *wdRecorder) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wds = append(c.wds, t)
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *wdRecorder) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.wds = append(c.wds, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *wdRecorder) last() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wds[len(c.wds)-1]
}

// TestCloseKeepsItsBound is P3-8 of the round-10 review: Close bounds the
// conn's last writes to a second, but an owner that set its deadline after
// that put 30 s back over the bound, and Close's wait for sc.mu - held by
// a write - had no bound of its own. The peer here never reads, so every
// write blocks until its deadline.
func TestCloseKeepsItsBound(t *testing.T) {
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	rec := &wdRecorder{Conn: near}
	sc := NewHTTP2StegoConn(rec, []byte("relay-leg-secret-0123456789abcdef"), true, NaivePaddingStandard, nil)

	// A write holds sc.mu, the way one blocked on a peer that stopped
	// reading does.
	sc.mu.Lock()
	t.Cleanup(sc.mu.Unlock)
	start := time.Now()
	done := make(chan struct{})
	go func() {
		_ = sc.Close()
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		sc.wdMu.Lock()
		closing := sc.closing
		sc.wdMu.Unlock()
		if closing || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// The owner, which took the conn before Close, sets its deadline now.
	if err := sc.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if bound := rec.last(); bound.After(start.Add(2 * stegoCloseBound)) {
		t.Fatalf("the owner's deadline %v went over Close's bound", time.Until(bound).Round(time.Second))
	}
	if err := sc.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if bound := rec.last(); bound.After(start.Add(2 * stegoCloseBound)) {
		t.Fatalf("the owner's SetDeadline %v went over Close's bound", time.Until(bound).Round(time.Second))
	}
	select {
	case <-done:
	case <-time.After(4 * stegoCloseBound):
		t.Fatalf("Close waited %v for a write holding the conn", time.Since(start).Round(time.Millisecond))
	}
}
