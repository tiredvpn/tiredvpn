package strategy

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// burstOnlyOnClose is a burst config whose ticker never fires inside a
// test, so only Close flushes.
var burstOnlyOnClose = RTTMaskingConfig{
	Enabled:       true,
	BurstMode:     true,
	BurstSize:     100,
	BurstInterval: time.Hour,
}

// failAfterConn takes ok writes and fails every later one with
// errFakeWrite.
type failAfterConn struct {
	net.Conn
	ok     int64
	writes atomic.Int64
}

func (c *failAfterConn) Write(b []byte) (int, error) {
	if c.writes.Add(1) > c.ok {
		return 0, errFakeWrite
	}
	return len(b), nil
}
func (c *failAfterConn) Close() error                     { return nil }
func (c *failAfterConn) SetWriteDeadline(time.Time) error { return nil }

// TestRTTMaskingWriteAfterClose: in burst mode Write only buffers, so
// after Close it returned success for a packet nothing would ever flush.
func TestRTTMaskingWriteAfterClose(t *testing.T) {
	c := NewRTTMaskingConn(&failAfterConn{ok: 1 << 30}, burstOnlyOnClose)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n, err := c.Write([]byte("after close")); !errors.Is(err, net.ErrClosed) || n != 0 {
		t.Fatalf("Write after Close = (%d, %v), want (0, net.ErrClosed)", n, err)
	}
}

// TestRTTMaskingKeepsTickerFlushError: a ticker flush that fails has
// already taken the burst out of the buffer, so Close's own flush finds
// nothing and returned nil. The failure must reach Close, and a Write
// after it must not buffer into a dead conn.
func TestRTTMaskingKeepsTickerFlushError(t *testing.T) {
	cfg := burstOnlyOnClose
	cfg.BurstInterval = 10 * time.Millisecond
	conn := &failAfterConn{}
	c := NewRTTMaskingConn(conn, cfg)
	if _, err := c.Write([]byte{1, 2, 3}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	failed := func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.flushErr != nil
	}
	for deadline := time.Now().Add(10 * time.Second); !failed(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the ticker never flushed")
		}
	}
	if _, err := c.Write([]byte{4}); !errors.Is(err, errFakeWrite) {
		t.Fatalf("Write after a failed flush = %v, want the flush error", err)
	}
	if err := c.Close(); !errors.Is(err, errFakeWrite) {
		t.Fatalf("Close = %v, want the ticker's flush error", err)
	}
}

// TestRTTMaskingFlushCountsWhatItLeft: a flush that fails partway loses
// the rest of the buffer too; the error says how much.
func TestRTTMaskingFlushCountsWhatItLeft(t *testing.T) {
	c := NewRTTMaskingConn(&failAfterConn{ok: 1}, burstOnlyOnClose)
	for _, p := range [][]byte{{1}, {2, 2}, {3, 3, 3}} {
		if _, err := c.Write(p); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	err := c.Flush()
	if !errors.Is(err, errFakeWrite) || !strings.Contains(err.Error(), "2 of 3 packets (5 bytes) not written") {
		t.Fatalf("Flush = %v, want it to count the 2 packets (5 bytes) left", err)
	}
}

// TestRTTMaskingCloseJoinsSocketError: Close reports the socket's own
// Close error.
func TestRTTMaskingCloseJoinsSocketError(t *testing.T) {
	cli, srv := net.Pipe()
	defer srv.Close()
	c := NewRTTMaskingConn(closeErrConn{cli}, burstOnlyOnClose)
	if err := c.Close(); !errors.Is(err, errSockClose) {
		t.Fatalf("Close = %v, want the socket's error", err)
	}
}

// TestRTTMaskingCloseBounded: the final flush of a pending burst wrote
// into the conn with no deadline at all, so a peer that does not read held
// Close forever, before the transport under it got to apply any bound.
// Now the flush runs under the earlier of the caller's deadline and
// rttCloseTimeout, and the deadline reaches a MorphedConn underneath, so
// the whole stack drains within that one bound.
func TestRTTMaskingCloseBounded(t *testing.T) {
	// Long enough that only the close deadline can end Close in time.
	setForTest(t, &closeAbortGrace, time.Minute)
	cases := []struct {
		name  string
		abort bool // Stop: an expired deadline right before Close
		morph bool // a shaped MorphedConn between the wrapper and TCP
		limit time.Duration
	}{
		{"tcp, close deadline", false, false, 2300 * time.Millisecond},
		{"tcp, caller's expired deadline", true, false, time.Second},
		{"morph over tcp, close deadline", false, true, 2300 * time.Millisecond},
		{"morph over tcp, caller's expired deadline", true, true, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.abort {
				setForTest(t, &rttCloseTimeout, 300*time.Millisecond)
			}
			// With an expired deadline from the caller, the default 5 s
			// rttCloseTimeout must not be what ends Close.
			raw, _ := tcpPair(t)
			var inner net.Conn = raw
			if tc.morph {
				// The default pacerCloseTimeout: it must not be what bounds
				// Close here.
				inner = &MorphedConn{Conn: raw, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
			}
			c := NewRTTMaskingConn(inner, burstOnlyOnClose)
			fillSendBuffer(t, raw)
			for range 20 {
				if _, err := c.Write(make([]byte, 1200)); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			if tc.abort {
				_ = c.SetDeadline(time.Now())
			}
			closed := make(chan error, 1)
			start := time.Now()
			go func() { closed <- c.Close() }()
			select {
			case err := <-closed:
				if took := time.Since(start); took > tc.limit {
					t.Fatalf("Close took %v, want under %v", took, tc.limit)
				}
				if err == nil {
					t.Fatal("Close = nil, want the burst it could not flush reported")
				}
			case <-time.After(20 * time.Second):
				t.Fatal("Close hung on a peer that does not read")
			}
		})
	}
}

// TestRTTMaskingCloseBoundedWithoutDeadlines: on a conn whose write
// deadlines do nothing, the close deadline cannot cut the final flush
// short; Close closes the conn closeAbortGrace past it instead.
func TestRTTMaskingCloseBoundedWithoutDeadlines(t *testing.T) {
	setForTest(t, &rttCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 300*time.Millisecond)
	cli, srv := net.Pipe()
	defer srv.Close()
	c := NewRTTMaskingConn(deafConn{cli}, burstOnlyOnClose)
	if _, err := c.Write([]byte{1, 2, 3}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if took := time.Since(start); took > rttCloseTimeout+closeAbortGrace+2*time.Second {
			t.Errorf("Close took %v", took)
		}
		if err == nil || !errors.Is(err, errSockClose) {
			t.Fatalf("Close = %v, want the lost burst joined with the socket's error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung on a conn that ignores write deadlines")
	}
}
