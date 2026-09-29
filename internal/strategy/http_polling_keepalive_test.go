package strategy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// scriptedPollServer answers the i-th poll request on any connection with
// bodies[i] (an empty body once the script runs out).
type scriptedPollServer struct {
	mu     sync.Mutex
	bodies [][]byte
	next   int
}

func (s *scriptedPollServer) nextBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.bodies) {
		return nil
	}
	b := s.bodies[s.next]
	s.next++
	return b
}

func (s *scriptedPollServer) serve(c net.Conn) {
	defer c.Close()
	if _, err := protocol.ReadDispatch(c); err != nil {
		return
	}
	r := bufio.NewReader(c)
	for {
		cl := 0
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "Content-Length:") {
				fmt.Sscanf(line, "Content-Length: %d", &cl)
			}
			if line == "\r\n" {
				break
			}
		}
		if cl > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(cl)); err != nil {
				return
			}
		}
		body := s.nextBody()
		head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(body))
		if _, err := c.Write(append([]byte(head), body...)); err != nil {
			return
		}
	}
}

// newScriptedPollingConn starts a TLS polling server that plays bodies back in
// order and returns a client HTTPPollingConn pointed at it. No poll worker or
// feeder goroutine runs: the test drives poll() and feedKeepalive() itself.
func newScriptedPollingConn(t *testing.T, bodies [][]byte) *HTTPPollingConn {
	t.Helper()
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &scriptedPollServer{bodies: bodies}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(c)
		}
	}()

	mgr := NewManager()
	setTestEndpoint(mgr, ln.Addr().String())
	c := &HTTPPollingConn{
		manager:         mgr,
		secret:          []byte("keepalive-secret"),
		host:            "localhost",
		path:            "/x",
		sessionID:       "sess-keepalive00",
		sendBuf:         bytes.NewBuffer(nil),
		recvBuf:         bytes.NewBuffer(nil),
		pollInterval:    50 * time.Millisecond,
		closed:          make(chan struct{}),
		tlsSessionCache: tls.NewLRUClientSessionCache(4),
		sendSignal:      make(chan struct{}, 1),
		ready:           make(chan struct{}),
	}
	c.recvCond = sync.NewCond(&c.recvLock)
	c.sendCond = sync.NewCond(&c.sendLock)
	t.Cleanup(func() { c.Close() })
	return c
}

// drain reads everything currently buffered, without blocking.
func drain(t *testing.T, c *HTTPPollingConn) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, 1500) // small reads, like a packet reader
	for {
		c.recvLock.Lock()
		empty := c.recvBuf.Len() == 0
		c.recvLock.Unlock()
		if empty {
			return out
		}
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		out = append(out, buf[:n]...)
	}
}

// useFakeClock switches c's liveness clock to a fake one.
func useFakeClock(c *HTTPPollingConn) *fakeClock {
	fc := newFakeClock() // shared with the storm tests
	c.now = fc.Now
	return fc
}

// runPollScript polls once per scripted body, and after each poll drains the
// receive buffer and gives the keepalive feeder its chance, exactly as a
// feeder tick landing right after the reader emptied the buffer would. The
// fake clock then moves 2s on, so a poll is never inside the handshake peek
// guard of the one before it. It returns the byte stream the reader saw and
// after which polls the feeder spliced a keepalive.
func runPollScript(t *testing.T, c *HTTPPollingConn, fc *fakeClock, polls int) (stream []byte, spliced []int) {
	t.Helper()
	for i := range polls {
		if ok, _ := c.poll(); !ok {
			t.Fatalf("poll %d failed", i)
		}
		stream = append(stream, drain(t, c)...)
		if c.feedKeepalive() {
			spliced = append(spliced, i)
			stream = append(stream, drain(t, c)...)
		}
		fc.Advance(2 * time.Second)
	}
	return stream, spliced
}

// TestPollingFeederNeverTouchesSOCKSStream pins the 1.11.4 corruption: a SOCKS
// download through http_polling that ran past the first feeder tick (10s) got
// four zero bytes spliced in every tick, because the feeder's only condition
// was "receive buffer empty". Here every poll is followed by a feeder chance on
// an empty buffer; the reader must see the target's bytes and nothing else.
func TestPollingFeederNeverTouchesSOCKSStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		fill func([]byte)
	}{
		{"random payload", func(b []byte) { rand.Read(b) }},
		// The adversarial case: the success byte plus an all-zero file parses
		// as a TUN handshake followed by keepalive frames, so only the mode
		// gate keeps the feeder out of it.
		{"zero-filled payload", func([]byte) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want []byte
			bodies := [][]byte{{0x00}} // the exit's SOCKS-mode "connected" byte
			want = append(want, 0x00)
			for range 5 {
				// 2999, not a multiple of 4: read as TUN framing, the zero
				// stream lands on a "frame boundary" after some of the polls.
				b := make([]byte, 2999)
				tc.fill(b)
				bodies = append(bodies, b)
				want = append(want, b...)
			}
			c := newScriptedPollingConn(t, bodies)
			fc := useFakeClock(c)

			// What pool.DialTarget writes first: [addrLen:2][addr].
			target := "198.18.0.10:80"
			hdr := binary.BigEndian.AppendUint16(nil, uint16(len(target)))
			if _, err := c.Write(append(hdr, target...)); err != nil {
				t.Fatalf("write: %v", err)
			}

			got, spliced := runPollScript(t, c, fc, len(bodies))
			if len(spliced) != 0 {
				t.Errorf("feeder spliced a keepalive into a SOCKS stream after polls %v", spliced)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("SOCKS stream altered: got %d bytes, want %d (first diff at %d)",
					len(got), len(want), firstDiff(got, want))
			}
		})
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func tunFrame(n int, fill byte) []byte {
	f := make([]byte, 4+n)
	binary.BigEndian.PutUint32(f, uint32(n))
	for i := range n {
		f[4+i] = fill
	}
	return f
}

// TestPollingFeederSplicesOnlyBetweenTUNFrames pins the TUN half of the same
// defect and that the feeder still does its job. Poll responses are cut without
// regard to framing, so the reader is often parked inside a frame with an
// empty buffer; a keepalive spliced there desyncs the packet loop. The script
// ends polls mid-handshake, mid-header, mid-payload and on boundaries, for each
// handshake layout a polling exit sends. Keepalives must appear after exactly
// the boundary-ending polls, and the frames must come through intact. The poll
// that completes the handshake is a boundary too, but the feeder must stay out
// of it: the handshake reader may be waiting there for an optional flags byte
// (TestPollingFeederSparesHandshakeFlagsPeek runs that against the real reader).
func TestPollingFeederSplicesOnlyBetweenTUNFrames(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version byte
		hs      []byte
	}{
		{"v3 bare 9-byte", 0x03, append([]byte{0}, make([]byte, 8)...)},
		{"v4 flags-only", 0x04, append([]byte{0}, make([]byte, 9)...)},
		{"v4 dual-stack", 0x04, append(append([]byte{0}, make([]byte, 8)...), append([]byte{meekHSFlagDualStack}, bytes.Repeat([]byte{0xfd}, 32)...)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := [][]byte{tunFrame(1400, 0xa1), tunFrame(60, 0xb2), tunFrame(1400, 0xc3), tunFrame(900, 0xd4)}
			var down []byte
			down = append(down, tc.hs...)
			hsEnd := len(down)
			var ends []int // frame boundaries in down
			for _, f := range frames {
				down = append(down, f...)
				ends = append(ends, len(down))
			}
			cuts := []int{3} // mid-handshake
			if hsEnd > meekHSBase+1 {
				cuts = append(cuts, meekHSBase+1) // flags byte in, dual-stack block not
			}
			cuts = append(cuts,
				hsEnd,     // handshake complete: boundary inside the peek guard
				hsEnd+2,   // mid-header of frame 0
				hsEnd+700, // mid-payload of frame 0
				ends[0],   // boundary
				ends[1],   // boundary
				ends[2]-1, // one byte short of a boundary
				ends[3],   // boundary (end of stream)
			)
			var bodies [][]byte
			prev := 0
			wantSplice := []int{}
			for i, cut := range cuts {
				bodies = append(bodies, down[prev:cut])
				prev = cut
				for _, e := range ends {
					if cut == e {
						wantSplice = append(wantSplice, i)
					}
				}
			}

			c := newScriptedPollingConn(t, bodies)
			fc := useFakeClock(c)
			hsReq := []byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, tc.version}
			if _, err := c.Write(hsReq); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, spliced := runPollScript(t, c, fc, len(bodies))

			if fmt.Sprint(spliced) != fmt.Sprint(wantSplice) {
				t.Errorf("keepalives spliced after polls %v, want exactly the boundary-ending polls %v", spliced, wantSplice)
			}
			if !bytes.Equal(got[:hsEnd], tc.hs) {
				t.Fatalf("handshake response altered")
			}
			var gotFrames [][]byte
			rest := got[hsEnd:]
			for len(rest) > 0 {
				if len(rest) < 4 {
					t.Fatalf("stream ends inside a frame header")
				}
				n := int(binary.BigEndian.Uint32(rest))
				if n > meekMaxFrame || 4+n > len(rest) {
					t.Fatalf("stream desynced: frame length %d with %d bytes left", n, len(rest)-4)
				}
				if n > 0 {
					gotFrames = append(gotFrames, rest[:4+n])
				}
				rest = rest[4+n:]
			}
			if len(gotFrames) != len(frames) {
				t.Fatalf("got %d data frames, want %d", len(gotFrames), len(frames))
			}
			for i := range frames {
				if !bytes.Equal(gotFrames[i], frames[i]) {
					t.Fatalf("frame %d altered", i)
				}
			}
		})
	}
}

// TestPollingFeederStopsOnFailedHandshake: a refused TUN session (status != 0)
// carries no frames, so nothing may be spliced after it - even when the refusal
// arrives at full handshake length.
func TestPollingFeederStopsOnFailedHandshake(t *testing.T) {
	c := newScriptedPollingConn(t, [][]byte{{0x01, 0, 0, 0, 0, 0, 0, 0, 0}})
	fc := useFakeClock(c)
	if _, err := c.Write([]byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, 0x03}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Two polls: the second runs past the handshake peek guard, where the
	// feeder would splice if it mistook the refusal for a handshake.
	if _, spliced := runPollScript(t, c, fc, 2); len(spliced) != 0 {
		t.Fatalf("feeder spliced a keepalive after a refused handshake")
	}
}

// TestPollingReadDeadlineIsTimeout pins that an expired read deadline returns
// the net.Conn timeout error. pool.PooledRelay keeps a silent direction open
// only when the error reports Timeout(); the old errors.New("read timeout")
// killed every SOCKS stream whose downlink stayed quiet for 30s - an upload
// through http_polling died at the 30s mark.
func TestPollingReadDeadlineIsTimeout(t *testing.T) {
	c := newScriptedPollingConn(t, nil)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := c.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after deadline returned %v, want os.ErrDeadlineExceeded", err)
	}
	if ne, ok := errors.AsType[net.Error](err); !ok || !ne.Timeout() {
		t.Fatalf("Read deadline error %v does not report net.Error Timeout()", err)
	}
}

// tunSessionPastHandshake opens a scripted v4 TUN session whose first poll
// delivers the 10-byte handshake response and whose second delivers frames,
// then moves the fake clock past the handshake peek guard.
func tunSessionPastHandshake(t *testing.T, frames []byte) (*HTTPPollingConn, *fakeClock) {
	t.Helper()
	hs := append([]byte{0}, make([]byte, 9)...)
	c := newScriptedPollingConn(t, [][]byte{hs, frames})
	fc := useFakeClock(c)
	if _, err := c.Write([]byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, 0x04}); err != nil {
		t.Fatalf("write: %v", err)
	}
	return c, fc
}

// TestPollingFeederTickerSplices pins that the ticker goroutine actually calls
// the feeder: with the TUN session idle on a frame boundary and polls healthy,
// a keepalive frame must show up within a few ticks.
func TestPollingFeederTickerSplices(t *testing.T) {
	c, fc := tunSessionPastHandshake(t, tunFrame(40, 0x11))
	runPollScript(t, c, fc, 2)
	c.lastPollOK.Store(fc.Now().UnixNano())

	c.feedEvery = 5 * time.Millisecond
	go c.runKeepaliveFeeder()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.recvLock.Lock()
		got := bytes.Clone(c.recvBuf.Bytes())
		c.recvLock.Unlock()
		if len(got) > 0 {
			if !bytes.Equal(got, []byte{0, 0, 0, 0}) {
				t.Fatalf("ticker produced % x, want one keepalive frame", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("feeder ticker never spliced a keepalive into an idle, healthy TUN session")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPollingTrackerStopsOnOversizedFrame pins the fail-safe for a tracker that
// lost the framing: a length over the protocol ceiling turns splicing off for
// good, so a later position the tracker would take for a boundary is not used.
func TestPollingTrackerStopsOnOversizedFrame(t *testing.T) {
	const n = meekMaxFrame + 1
	bogus := make([]byte, 4+n)
	binary.BigEndian.PutUint32(bogus, n)
	c, fc := tunSessionPastHandshake(t, bogus)
	if _, spliced := runPollScript(t, c, fc, 2); len(spliced) != 0 {
		t.Fatalf("feeder spliced after polls %v although the stream carried a %d-byte frame", spliced, n)
	}
}

// TestPollingTrackerStopsOnPortHopHandshake: polling exits never advertise
// port hopping, and the tracker does not follow that layout; seeing it must
// turn splicing off rather than guess the handshake length.
func TestPollingTrackerStopsOnPortHopHandshake(t *testing.T) {
	hs := append([]byte{0}, make([]byte, 8)...)
	hs = append(hs, meekHSFlagPortHop)
	c := newScriptedPollingConn(t, [][]byte{hs, tunFrame(40, 0x22)})
	fc := useFakeClock(c)
	if _, err := c.Write([]byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, 0x04}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, spliced := runPollScript(t, c, fc, 2); len(spliced) != 0 {
		t.Fatalf("feeder spliced after polls %v into a stream whose handshake layout it cannot follow", spliced)
	}
}

// TestPollingWriteBoundedAndFailsWhenPollsDie pins the uplink bound. With the
// exit gone the relay no longer dies of a bogus read error, so the queue has to
// be bounded on its own: Write must block at maxPollingSendBuffered instead of
// growing sendBuf, and must fail once no poll has succeeded for the health
// grace, so the relay ends.
func TestPollingWriteBoundedAndFailsWhenPollsDie(t *testing.T) {
	c := newScriptedPollingConn(t, nil) // nothing polls: the exit is dead
	fc := useFakeClock(c)
	c.lastPollOK.Store(fc.Now().UnixNano())

	chunk := make([]byte, 32*1024)
	const total = 4 * maxPollingSendBuffered
	errc := make(chan error, 1)
	go func() {
		for written := 0; written < total; written += len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()

	time.Sleep(300 * time.Millisecond)
	c.sendLock.Lock()
	queued := c.sendBuf.Len()
	c.sendLock.Unlock()
	if queued > maxPollingSendBuffered+len(chunk) {
		t.Fatalf("uplink queue grew to %d bytes with nothing polling, bound is %d", queued, maxPollingSendBuffered)
	}
	select {
	case err := <-errc:
		t.Fatalf("Write returned (%v) while polls were still healthy and the queue full", err)
	default:
	}

	fc.Advance(pollingPollHealthGrace + time.Second)
	select {
	case err := <-errc:
		if !errors.Is(err, errPollingDead) {
			t.Fatalf("Write after the poll layer died returned %v, want errPollingDead", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Write stayed blocked after the poll layer died; the relay would hang forever")
	}
}

// TestPollingReadFailsWhenPollsDie: a read deadline on a dead poll layer must
// end the relay (non-timeout error), while on a healthy one it stays a plain
// timeout so a quiet downlink survives.
func TestPollingReadFailsWhenPollsDie(t *testing.T) {
	c := newScriptedPollingConn(t, nil)
	fc := useFakeClock(c)
	c.lastPollOK.Store(fc.Now().UnixNano())

	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("healthy poll layer: Read returned %v, want a timeout", err)
	}

	fc.Advance(pollingPollHealthGrace + time.Second)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := c.Read(make([]byte, 16))
	if !errors.Is(err, errPollingDead) {
		t.Fatalf("dead poll layer: Read returned %v, want errPollingDead", err)
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		t.Fatal("dead poll layer reported as a timeout; the SOCKS relay would keep it open")
	}
}

// TestPollingDeadWhenNoPollSucceedsAfterInit: the init round-trip starts the
// liveness clock, so a session whose polls all fail after it is declared dead
// once the health grace runs out, instead of counting as "never polled".
func TestPollingDeadWhenNoPollSucceedsAfterInit(t *testing.T) {
	c := newScriptedPollingConn(t, [][]byte{[]byte("OK")})
	fc := useFakeClock(c)
	if err := c.init(t.Context()); err != nil {
		t.Fatalf("init: %v", err)
	}
	fc.Advance(pollingPollHealthGrace + time.Second)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 16)); !errors.Is(err, errPollingDead) {
		t.Fatalf("no poll since init past the grace: Read returned %v, want errPollingDead", err)
	}
}
