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

// runPollScript polls once per scripted body, and after each poll drains the
// receive buffer and gives the keepalive feeder its chance, exactly as a
// feeder tick landing between two polls would. It returns the byte stream the
// reader saw and after which polls the feeder spliced a keepalive.
func runPollScript(t *testing.T, c *HTTPPollingConn, polls int) (stream []byte, spliced []int) {
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
	}
	return stream, spliced
}

// TestPollingFeederNeverTouchesSOCKSStream pins the 1.11.4 corruption: a SOCKS
// download through http_polling that ran past the first feeder tick (10s) got
// four zero bytes spliced in every tick, because the feeder's only condition
// was "receive buffer empty". Here every poll is followed by a feeder chance on
// an empty buffer; the reader must see the target's bytes and nothing else.
func TestPollingFeederNeverTouchesSOCKSStream(t *testing.T) {
	var want []byte
	var bodies [][]byte
	for range 5 {
		b := make([]byte, 3000)
		rand.Read(b)
		bodies = append(bodies, b)
		want = append(want, b...)
	}
	c := newScriptedPollingConn(t, bodies)

	// What pool.DialTarget writes first: [addrLen:2][addr].
	target := "198.18.0.10:80"
	hdr := binary.BigEndian.AppendUint16(nil, uint16(len(target)))
	if _, err := c.Write(append(hdr, target...)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, spliced := runPollScript(t, c, len(bodies))
	if len(spliced) != 0 {
		t.Errorf("feeder spliced a keepalive into a SOCKS stream after polls %v", spliced)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SOCKS stream altered: got %d bytes, want %d (first diff at %d)",
			len(got), len(want), firstDiff(got, want))
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
// the boundary-ending polls, and the frames must come through intact.
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
			cuts := []int{
				3,           // mid-handshake
				hsEnd,       // handshake complete: first boundary
				hsEnd + 2,   // mid-header of frame 0
				hsEnd + 700, // mid-payload of frame 0
				ends[0],     // boundary
				ends[1],     // boundary
				ends[2] - 1, // one byte short of a boundary
				ends[3],     // boundary (end of stream)
			}
			var bodies [][]byte
			prev := 0
			wantSplice := []int{}
			for i, cut := range cuts {
				bodies = append(bodies, down[prev:cut])
				prev = cut
				for _, e := range append([]int{hsEnd}, ends...) {
					if cut == e {
						wantSplice = append(wantSplice, i)
					}
				}
			}

			c := newScriptedPollingConn(t, bodies)
			hsReq := []byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, tc.version}
			if _, err := c.Write(hsReq); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, spliced := runPollScript(t, c, len(bodies))

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
	if _, err := c.Write([]byte{meekTUNMode, 0, 0, 0, 0, 0x05, 0xdc, 0x03}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, spliced := runPollScript(t, c, 1); len(spliced) != 0 {
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
