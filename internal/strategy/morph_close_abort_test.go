package strategy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// TestMorphedConnCloseNowBeatsLateExtension is VPNClient.Stop racing the
// TUN writer: Stop sets an expired deadline, the writer sets its +30 s one
// before Stop gets to Close, and a plain Close took that as the caller's
// deadline and spent the full 5 s draining. CloseNow aborts whatever the
// deadline says.
func TestMorphedConnCloseNowBeatsLateExtension(t *testing.T) {
	for _, tr := range closeTransports {
		t.Run(tr.name, func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc, sh := parkedClient(t, conn, raw)
			_ = mc.SetDeadline(time.Now())
			_ = mc.SetWriteDeadline(time.Now().Add(30 * time.Second))
			took, err := closeParkedWith(t, mc, sh, mc.CloseNow, nil, 20*time.Second)
			if took > time.Second {
				t.Fatalf("CloseNow took %v", took)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("CloseNow = %v, want the queue reported lost", err)
			}
		})
	}
}

// TestMorphedConnCloseFollowsShorterDeadline: a caller may bring the close
// deadline closer while Close runs, and a write deadline set before Close
// bounds it too.
func TestMorphedConnCloseFollowsShorterDeadline(t *testing.T) {
	setForTest(t, &closeAbortGrace, time.Minute)
	for _, tr := range closeTransports {
		t.Run(tr.name+", shortened during close", func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc, sh := parkedClient(t, conn, raw)
			_ = mc.SetWriteDeadline(time.Time{})
			shorten := func() { _ = mc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)) }
			took, err := closeParked(t, mc, sh, shorten, 20*time.Second)
			if took > 1500*time.Millisecond {
				t.Fatalf("Close took %v after the deadline was cut to 100 ms", took)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
			}
		})
		t.Run(tr.name+", set before close", func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc, sh := parkedClient(t, conn, raw)
			_ = mc.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
			took, err := closeParked(t, mc, sh, nil, 20*time.Second)
			if took > 1500*time.Millisecond {
				t.Fatalf("Close took %v with a 300 ms write deadline", took)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
			}
		})
	}
}

// TestMorphedConnCloseIdlePacerAfterAbort: Stop on a conn whose pacer has
// nothing queued. The drain is clean, but tls.Conn.Close then replaced the
// expired deadline with its own 5 s one for close_notify, and only the
// abort timer ended it, a second later. With the deadline already passed
// Close goes straight to the socket.
func TestMorphedConnCloseIdlePacerAfterAbort(t *testing.T) {
	for _, tr := range closeTransports {
		t.Run(tr.name, func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc := &MorphedConn{Conn: conn, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
			if _, err := mc.Write(make([]byte, 1000)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			// Let the pacer write it and go idle, then shut the window.
			time.Sleep(50 * time.Millisecond)
			fillSendBuffer(t, raw)
			_ = mc.SetDeadline(time.Now())
			start := time.Now()
			_ = mc.Close()
			if took := time.Since(start); took > 500*time.Millisecond {
				t.Fatalf("Close after an expired deadline took %v with an empty queue", took)
			}
		})
	}
}

// TestMorphedConnCloseNowWithoutPacer: CloseNow on a conn that never
// shaped a write skips close_notify too.
func TestMorphedConnCloseNowWithoutPacer(t *testing.T) {
	conn, raw := closeTransports[1].dial(t)
	mc := &MorphedConn{Conn: conn, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	fillSendBuffer(t, raw)
	start := time.Now()
	_ = mc.CloseNow()
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("CloseNow took %v", took)
	}
}

// TestMorphedConnCloseAbortFollowsDeadline: on a conn that ignores write
// deadlines only the abort timer ends a blocked write, and it has to move
// when the deadline does. It stayed at the first deadline, so cutting the
// deadline to now 100 ms into a 5 s Close still cost 6 s.
func TestMorphedConnCloseAbortFollowsDeadline(t *testing.T) {
	setForTest(t, &closeAbortGrace, 300*time.Millisecond)
	cli, srv := net.Pipe()
	defer srv.Close()
	mc := &MorphedConn{Conn: deafConn{cli}, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	if _, err := mc.Write(closeTestPayload(64 << 10)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- mc.Close() }()
	time.Sleep(100 * time.Millisecond)
	_ = mc.SetWriteDeadline(time.Now())
	select {
	case err := <-closed:
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("Close took %v after the deadline was cut to now", took)
		}
		if !errors.Is(err, ErrShaperCloseIncomplete) {
			t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung")
	}
}

// lateConn takes each write only at a fixed time after it was made and
// ignores deadlines; Close makes a pending write fail.
type lateConn struct {
	net.Conn
	after  time.Duration
	closed chan struct{}
	shut   atomic.Bool
}

func (c *lateConn) Write(b []byte) (int, error) {
	select {
	case <-time.After(c.after):
		return len(b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (c *lateConn) Close() error {
	if c.shut.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return nil
}
func (*lateConn) SetDeadline(time.Time) error      { return nil }
func (*lateConn) SetWriteDeadline(time.Time) error { return nil }

// TestMorphedConnCloseWaitsGraceBeforeAbort: a conn that ignores write
// deadlines but finishes its write a little past the close deadline must
// get to: the socket is closed only closeAbortGrace past it.
func TestMorphedConnCloseWaitsGraceBeforeAbort(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 2*time.Second)
	c := &lateConn{after: 300 * time.Millisecond, closed: make(chan struct{})}
	mc := &MorphedConn{Conn: c, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	if _, err := mc.Write(make([]byte, 1000)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := mc.Close(); err != nil {
		t.Fatalf("Close = %v, want the write that ends inside the grace delivered", err)
	}
}

// releaseConn is a wrapper with resources of its own: it reports whether
// its Close ran, and NetConn exposes the socket under it.
type releaseConn struct {
	net.Conn
	released atomic.Bool
}

func (c *releaseConn) NetConn() net.Conn { return c.Conn }
func (c *releaseConn) Close() error {
	c.released.Store(true)
	return c.Conn.Close()
}

// TestMorphedConnCloseReleasesWrapperAfterLoss: when the tail is lost the
// socket is closed under the wrapper, and the wrapper must still be
// closed.
func TestMorphedConnCloseReleasesWrapperAfterLoss(t *testing.T) {
	raw, _ := tcpPair(t)
	w := &releaseConn{Conn: raw}
	mc, sh := parkedClient(t, w, raw)
	took, err := closeParkedWith(t, mc, sh, mc.CloseNow, nil, 20*time.Second)
	if !errors.Is(err, ErrShaperCloseIncomplete) {
		t.Fatalf("CloseNow = %v after %v, want the tail reported lost", err, took)
	}
	if !w.released.Load() {
		t.Fatal("the wrapper under MorphedConn was never closed")
	}
}

// TestMorphedConnCloseTwice: repeated and concurrent Close calls return
// the first result, without a "use of closed" error of their own.
func TestMorphedConnCloseTwice(t *testing.T) {
	conn, raw := closeTransports[0].dial(t)
	mc, sh := parkedClient(t, conn, raw)
	_ = mc.SetDeadline(time.Now())
	second := make(chan error, 1)
	go func() {
		<-mc.pacer.done
		second <- mc.Close()
	}()
	_, first := closeParked(t, mc, sh, nil, 20*time.Second)
	if !errors.Is(first, ErrShaperCloseIncomplete) {
		t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", first)
	}
	if err := <-second; err != first {
		t.Fatalf("concurrent Close = %v, want the first result %v", err, first)
	}
	if err := mc.Close(); err != first {
		t.Fatalf("third Close = %v, want the first result %v", err, first)
	}
}

// TestRTTMaskingCloseBoundsInnerClose: the abort timer used to stop before
// the wrapped conn's own Close, and tls.Conn.Close then spent its own 5 s
// on close_notify; on a conn that ignores deadlines, forever. It now stays
// armed through it, and closes the socket at the bottom of the chain.
func TestRTTMaskingCloseBoundsInnerClose(t *testing.T) {
	setForTest(t, &rttCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 300*time.Millisecond)
	for _, burst := range []int{0, 3} {
		t.Run(map[int]string{0: "empty burst", 3: "pending burst"}[burst], func(t *testing.T) {
			c, s := tcpPair(t)
			srvCfg, cliCfg := testTLSConfigs(t)
			srv := tls.Server(s, srvCfg)
			go func() { _, _ = io.Copy(io.Discard, srv) }()
			sc := &stallConn{Conn: c, closed: make(chan struct{})}
			cli := tls.Client(sc, cliCfg)
			if err := cli.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			rc := NewRTTMaskingConn(cli, burstOnlyOnClose)
			for range burst {
				if _, err := rc.Write(make([]byte, 100)); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			sc.stall.Store(true)
			closed := make(chan error, 1)
			start := time.Now()
			go func() { closed <- rc.Close() }()
			select {
			case err := <-closed:
				if took := time.Since(start); took > rttCloseTimeout+closeAbortGrace+2*time.Second {
					t.Errorf("Close took %v", took)
				}
				if burst > 0 && err == nil {
					t.Fatal("Close = nil, want the lost burst reported")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Close hung in the wrapped conn's Close")
			}
		})
	}
}

// TestRTTMaskingCloseOverTLS: RTT directly over a tls.Conn with a peer
// that does not read took 10 s: 5 s of flush, then 5 s of close_notify.
// Stop through CloseNow, over TLS and over Morph over TLS, takes no time.
func TestRTTMaskingCloseOverTLS(t *testing.T) {
	stacks := []struct {
		name  string
		morph bool
	}{{"rtt over tls", false}, {"rtt over morph over tls", true}}
	for _, st := range stacks {
		for _, burst := range []int{0, 20} {
			for _, stop := range []bool{false, true} {
				name := st.name
				name += map[int]string{0: ", empty burst", 20: ", pending burst"}[burst]
				name += map[bool]string{false: ", close", true: ", stop"}[stop]
				t.Run(name, func(t *testing.T) {
					if !stop {
						setForTest(t, &rttCloseTimeout, 300*time.Millisecond)
						setForTest(t, &closeAbortGrace, 300*time.Millisecond)
					} else {
						// Only an abort, not the grace, may end Close here.
						setForTest(t, &closeAbortGrace, time.Minute)
					}
					conn, raw := closeTransports[1].dial(t)
					inner := conn
					if st.morph {
						inner = &MorphedConn{Conn: conn, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
					}
					rc := NewRTTMaskingConn(inner, burstOnlyOnClose)
					fillSendBuffer(t, raw)
					for range burst {
						if _, err := rc.Write(make([]byte, 1000)); err != nil {
							t.Fatalf("Write: %v", err)
						}
					}
					limit := rttCloseTimeout + closeAbortGrace + 2*time.Second
					closeFn := rc.Close
					if stop {
						limit = time.Second
						_ = rc.SetDeadline(time.Now())
						_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
						closeFn = rc.CloseNow
					}
					closed := make(chan error, 1)
					start := time.Now()
					go func() { closed <- closeFn() }()
					select {
					case err := <-closed:
						if took := time.Since(start); took > limit {
							t.Fatalf("Close took %v, want under %v", took, limit)
						}
						if burst > 0 && err == nil {
							t.Fatal("Close = nil, want the lost burst reported")
						}
					case <-time.After(20 * time.Second):
						t.Fatal("Close hung")
					}
				})
			}
		}
	}
}

// TestRTTMaskingCloseAbortFollowsDeadline is the RTT side of
// TestMorphedConnCloseAbortFollowsDeadline.
func TestRTTMaskingCloseAbortFollowsDeadline(t *testing.T) {
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
	time.Sleep(100 * time.Millisecond)
	_ = c.SetWriteDeadline(time.Now())
	select {
	case err := <-closed:
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("Close took %v after the deadline was cut to now", took)
		}
		if err == nil {
			t.Fatal("Close = nil, want the lost burst reported")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung")
	}
}

// TestRTTMaskingCloseReleasesWrapperAfterLoss: like the Morph test, for a
// wrapper under RTT that cannot CloseNow.
func TestRTTMaskingCloseReleasesWrapperAfterLoss(t *testing.T) {
	raw, _ := tcpPair(t)
	w := &releaseConn{Conn: raw}
	c := NewRTTMaskingConn(w, burstOnlyOnClose)
	fillSendBuffer(t, raw)
	if _, err := c.Write(make([]byte, 1000)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.CloseNow(); err == nil || !strings.Contains(err.Error(), "rtt burst") {
		t.Fatalf("CloseNow = %v, want the lost burst", err)
	}
	if !w.released.Load() {
		t.Fatal("the wrapper under RTTMaskingConn was never closed")
	}
}

// TestRTTMaskingCloseTwice: repeated Close returns the first result.
func TestRTTMaskingCloseTwice(t *testing.T) {
	c := NewRTTMaskingConn(&failAfterConn{}, burstOnlyOnClose)
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first := c.Close()
	if !errors.Is(first, errFakeWrite) {
		t.Fatalf("Close = %v, want the failed flush", first)
	}
	if second := c.Close(); second != first {
		t.Fatalf("second Close = %v, want the first result %v", second, first)
	}
}

// TestCloseAbortDoesNotAddSpuriousErrors: when the abort timer has already
// closed the socket, the close path must not report that same socket as
// "use of closed network connection". Both wrappers cache the socket close
// in a sync.OnceValue for this.
func TestCloseAbortDoesNotAddSpuriousErrors(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 100*time.Millisecond)
	setForTest(t, &rttCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 200*time.Millisecond)
	spurious := func(t *testing.T, err error) {
		t.Helper()
		if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
			t.Fatalf("Close = %v, want no error about the socket it closed itself", err)
		}
	}
	t.Run("morph", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer srv.Close()
		mc := &MorphedConn{Conn: deafConnKeepErr{cli}, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
		if _, err := mc.Write(closeTestPayload(64 << 10)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		err := mc.Close()
		if !errors.Is(err, ErrShaperCloseIncomplete) {
			t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
		}
		spurious(t, err)
	})
	t.Run("rtt", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer srv.Close()
		c := NewRTTMaskingConn(deafConnKeepErr{cli}, burstOnlyOnClose)
		if _, err := c.Write([]byte{1, 2, 3}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		err := c.Close()
		if err == nil {
			t.Fatal("Close = nil, want the lost burst reported")
		}
		spurious(t, err)
	})
}

// deafConnKeepErr ignores deadlines and reports its socket's own Close
// error, unlike deafConn which always answers errSockClose.
type deafConnKeepErr struct{ net.Conn }

func (deafConnKeepErr) SetDeadline(time.Time) error      { return nil }
func (deafConnKeepErr) SetReadDeadline(time.Time) error  { return nil }
func (deafConnKeepErr) SetWriteDeadline(time.Time) error { return nil }

// TestMorphedConnCloseNowDuringClose: Stop can land while another Close is
// already draining (handleDisconnect and ForceReconnect both close under
// v.mu, and client.go closes from an AfterFunc). CloseNow must cut that
// drain short, not wait out its deadline.
func TestMorphedConnCloseNowDuringClose(t *testing.T) {
	// Only the abort may end Close here: neither the grace nor the close
	// timeout may run out while the test waits for the abort to land.
	setForTest(t, &closeAbortGrace, time.Minute)
	setForTest(t, &pacerCloseTimeout, time.Minute)
	for _, tr := range closeTransports {
		t.Run(tr.name, func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc, sh := parkedClient(t, conn, raw)
			_ = mc.SetWriteDeadline(time.Time{})
			var abortAt time.Time
			nowClosed := make(chan error, 1)
			during := func() {
				go func() { nowClosed <- mc.CloseNow() }()
				// Wait for the abort itself to land, so a goroutine the
				// scheduler holds off under load does not look like a
				// Close that ignored it.
				for deadline := time.Now().Add(3 * time.Second); !mc.wdl.expired(); time.Sleep(time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatal("CloseNow did not expire the close deadline")
					}
				}
				abortAt = time.Now()
			}
			_, err := closeParked(t, mc, sh, during, 30*time.Second)
			if took := time.Since(abortAt); took > 2*time.Second {
				t.Fatalf("Close ran %v past the CloseNow that should have cut it short", took)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
			}
			if err := <-nowClosed; err == nil {
				t.Fatal("CloseNow = nil, want the first Close's result")
			}
		})
	}
}

// TestMorphedConnCloseGraceAfterShortening: the abort timer moves with a
// deadline that is cut short, and it must keep the grace when it does. A
// write that finishes inside the grace past the new deadline still counts.
func TestMorphedConnCloseGraceAfterShortening(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 5*time.Second)
	setForTest(t, &closeAbortGrace, 5*time.Second)
	c := &lateConn{after: 300 * time.Millisecond, closed: make(chan struct{})}
	mc := &MorphedConn{Conn: c, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	if _, err := mc.Write(make([]byte, 1000)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- mc.Close() }()
	time.Sleep(100 * time.Millisecond)
	_ = mc.SetWriteDeadline(time.Now())
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close = %v, want the write that ends inside the grace delivered", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung")
	}
}

// secondCloseConn answers errSecondClose from its second Close on, and
// ignores deadlines so only the abort timer ends a write.
type secondCloseConn struct {
	net.Conn
	closes atomic.Int64
}

var errSecondClose = errors.New("socket closed twice")

func (c *secondCloseConn) Close() error {
	if c.closes.Add(1) > 1 {
		return errSecondClose
	}
	return c.Conn.Close()
}
func (*secondCloseConn) SetDeadline(time.Time) error      { return nil }
func (*secondCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (*secondCloseConn) SetWriteDeadline(time.Time) error { return nil }

// TestCloseDoesNotCloseTheSocketTwice: the abort timer and the close path
// share one socket close, so the second one's error never reaches the
// caller.
func TestCloseDoesNotCloseTheSocketTwice(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 100*time.Millisecond)
	setForTest(t, &rttCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 200*time.Millisecond)
	t.Run("morph", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer srv.Close()
		mc := &MorphedConn{Conn: &secondCloseConn{Conn: cli}, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
		if _, err := mc.Write(closeTestPayload(64 << 10)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := mc.Close(); errors.Is(err, errSecondClose) {
			t.Fatalf("Close = %v, want no error from closing the same socket twice", err)
		}
	})
	t.Run("rtt", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer srv.Close()
		c := NewRTTMaskingConn(&secondCloseConn{Conn: cli}, burstOnlyOnClose)
		if _, err := c.Write([]byte{1, 2, 3}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := c.Close(); errors.Is(err, errSecondClose) {
			t.Fatalf("Close = %v, want no error from closing the same socket twice", err)
		}
	})
}

// captureLogs sends the logger's output to a buffer for the rest of the
// test and returns a reader for what was logged.
func captureLogs(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	log.SetOutput(&lockedWriter{mu: &mu, w: &buf})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// lockedWriter serialises writes from the logger against the test reading
// the buffer.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// TestCloseLogsALostTail: no caller reads the Close error, so the one
// place a lost tail becomes visible is the log. Both wrappers must say so,
// and only once however often Close is called.
func TestCloseLogsALostTail(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 100*time.Millisecond)
	setForTest(t, &rttCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 200*time.Millisecond)
	cases := []struct {
		name string
		want string
		conn func(net.Conn) net.Conn
		send func(net.Conn) error
	}{
		{
			name: "morph",
			want: "close lost the queued tail",
			conn: func(c net.Conn) net.Conn {
				return &MorphedConn{Conn: deafConnKeepErr{c}, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
			},
			send: func(c net.Conn) error {
				_, err := c.Write(closeTestPayload(64 << 10))
				return err
			},
		},
		{
			name: "rtt",
			want: "close lost the pending burst",
			conn: func(c net.Conn) net.Conn {
				return NewRTTMaskingConn(deafConnKeepErr{c}, burstOnlyOnClose)
			},
			send: func(c net.Conn) error {
				_, err := c.Write([]byte{1, 2, 3})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLogs(t)
			cli, srv := net.Pipe()
			defer srv.Close()
			c := tc.conn(cli)
			if err := tc.send(c); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := c.Close(); err == nil {
				t.Fatal("Close = nil, want the lost tail reported")
			}
			_ = c.Close()
			if got := strings.Count(logged(), tc.want); got != 1 {
				t.Fatalf("%q logged %d times, want once:\n%s", tc.want, got, logged())
			}
		})
	}
}

// TestCloseSocketStopsAtANilInnerConn: a wrapper whose NetConn() is nil
// must not take closeSocket down with it.
func TestCloseSocketStopsAtANilInnerConn(t *testing.T) {
	cli, srv := net.Pipe()
	defer srv.Close()
	if err := closeSocket(nilNetConn{cli}); err != nil {
		t.Fatalf("closeSocket = %v, want the wrapper itself closed", err)
	}
}

// nilNetConn reports no inner conn, the way a wrapper does before it is
// connected (ktls_linux.go guards the same case).
type nilNetConn struct{ net.Conn }

func (nilNetConn) NetConn() net.Conn { return nil }
