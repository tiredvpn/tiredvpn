package strategy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// Issue #131: HTTPPollingConn.Close dropped what Write had accepted and no
// poll had sent yet - up to 1 MiB - and returned nil, the pattern #129 fixed
// in MorphedConn.Close. Close now sends it, bounded, and reports what it
// could not send.

// pollingSink is a polling server that counts the uplink body bytes it got,
// answering every request after delay; mute takes requests and never
// answers.
type pollingSink struct {
	got   atomic.Int64
	delay time.Duration
	mute  bool
	addr  string
}

func newPollingSink(t *testing.T, delay time.Duration, mute bool) *pollingSink {
	t.Helper()
	cert, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &pollingSink{delay: delay, mute: mute, addr: ln.Addr().String()}
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.serve(c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *pollingSink) serve(c net.Conn) {
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
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		if cl > 0 {
			n, err := io.CopyN(io.Discard, r, int64(cl))
			if s.mute {
				// The request reached it; nothing comes back, so the client
				// can't know - and keeps the bytes for another try.
				_ = n
			} else {
				s.got.Add(n)
			}
			if err != nil {
				return
			}
		}
		if s.mute {
			_, _ = io.Copy(io.Discard, r)
			return
		}
		time.Sleep(s.delay)
		if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")); err != nil {
			return
		}
	}
}

// pollingConnTo is an HTTPPollingConn to addr with its poll worker running,
// as Connect leaves one, without Connect's init request.
func pollingConnTo(t *testing.T, addr string) *HTTPPollingConn {
	t.Helper()
	mgr := NewManager()
	setTestEndpoint(mgr, addr)
	c := &HTTPPollingConn{
		manager:         mgr,
		secret:          []byte("close-secret"),
		host:            "localhost",
		path:            "/x",
		sessionID:       "sess-close",
		sendBuf:         bytes.NewBuffer(nil),
		recvBuf:         bytes.NewBuffer(nil),
		pollInterval:    50 * time.Millisecond,
		numWorkers:      1,
		closed:          make(chan struct{}),
		tlsSessionCache: tls.NewLRUClientSessionCache(4),
		sendSignal:      make(chan struct{}, 1),
		ready:           make(chan struct{}),
	}
	c.recvCond = sync.NewCond(&c.recvLock)
	c.sendCond = sync.NewCond(&c.sendLock)
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		c.pollWorker(0)
	}()
	return c
}

// TestAPollingCloseSendsWhatWriteAccepted: 256 KiB written and Close called
// at once, against a server that answers each poll after 20 ms - 32 polls of
// 8 KiB, about 0.7 s. Every byte reaches the server, and Close reports no
// loss; a Write after it fails.
func TestAPollingCloseSendsWhatWriteAccepted(t *testing.T) {
	sink := newPollingSink(t, 20*time.Millisecond, false)
	c := pollingConnTo(t, sink.addr)
	payload := bytes.Repeat([]byte{0xab}, 256<<10)
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: %d, %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v (the server got %d of %d bytes)", err, sink.got.Load(), len(payload))
	}
	if got := sink.got.Load(); got != int64(len(payload)) {
		t.Fatalf("the server got %d of %d bytes accepted before Close", got, len(payload))
	}
	if _, err := c.Write([]byte{1}); err == nil {
		t.Fatal("a Write after Close was accepted")
	}
}

// TestAPollingCloseOnAMutePeerReportsTheLossInItsBound: the server takes
// the requests and never answers. Close returns within its bound, with
// ErrPollingCloseIncomplete, instead of hanging or saying nothing.
func TestAPollingCloseOnAMutePeerReportsTheLossInItsBound(t *testing.T) {
	old := pollingCloseTimeout
	pollingCloseTimeout = 500 * time.Millisecond
	t.Cleanup(func() { pollingCloseTimeout = old })
	sink := newPollingSink(t, 0, true)
	c := pollingConnTo(t, sink.addr)
	if _, err := c.Write(bytes.Repeat([]byte{0xcd}, 64<<10)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := c.Close()
	took := time.Since(start)
	if !errors.Is(err, ErrPollingCloseIncomplete) || !strings.Contains(err.Error(), "65536 bytes") {
		t.Fatalf("close on a mute peer: %v, want ErrPollingCloseIncomplete for all 65536 bytes", err)
	}
	if took > pollingCloseTimeout+500*time.Millisecond {
		t.Fatalf("close took %v against a %v bound", took, pollingCloseTimeout)
	}
	if err2 := c.Close(); !errors.Is(err2, ErrPollingCloseIncomplete) {
		t.Fatalf("a second Close said %v", err2)
	}
}

// TestAPollingCloseNowSendsNothing: CloseNow does not wait on the peer and
// reports what it left.
func TestAPollingCloseNowSendsNothing(t *testing.T) {
	sink := newPollingSink(t, 200*time.Millisecond, false)
	c := pollingConnTo(t, sink.addr)
	if _, err := c.Write(bytes.Repeat([]byte{0xef}, 256<<10)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := c.CloseNow()
	if took := time.Since(start); took > pollTimeout+time.Second {
		t.Fatalf("CloseNow took %v", took)
	}
	if !errors.Is(err, ErrPollingCloseIncomplete) {
		t.Fatalf("CloseNow with bytes left: %v, want ErrPollingCloseIncomplete", err)
	}
}

// TestAPollingCloseDoesNotWaitOnAPeerThatRefusesPolls: every poll fails at
// once - the server closes each connection after the dispatch. Close does
// not spend its 5 s bound retrying: it reports the loss as soon as the
// worker is out of its poll. A conn closed after its server went silent
// (a failed handshake, a reconnect) must not hold the caller.
func TestAPollingCloseDoesNotWaitOnAPeerThatRefusesPolls(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = protocol.ReadDispatch(c)
				c.Close()
			}()
		}
	}()
	c := pollingConnTo(t, ln.Addr().String())
	if _, err := c.Write(bytes.Repeat([]byte{0x11}, 16<<10)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !c.pollFailing.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !c.pollFailing.Load() {
		t.Fatal("no poll failed - the test proves nothing")
	}
	start := time.Now()
	err = c.Close()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("close took %v retrying a peer that refuses every poll", took)
	}
	if !errors.Is(err, ErrPollingCloseIncomplete) {
		t.Fatalf("close: %v, want ErrPollingCloseIncomplete", err)
	}
}

// TestAPollingCloseCountsTheChunkAPollHolds is P2-1 of the round-18 review:
// a mute peer, a poll in flight with 4 KiB, and 2 KiB more written - a
// pending sendSignal and a tail under one chunk. Close counted sendBuf
// while the worker still held its chunk, reported 2 KiB, or nothing if the
// worker had taken the tail into a new poll after Close, and waited out
// that poll's own 3 s. All 6 KiB are reported, within the bound.
func TestAPollingCloseCountsTheChunkAPollHolds(t *testing.T) {
	old := pollingCloseTimeout
	pollingCloseTimeout = 500 * time.Millisecond
	t.Cleanup(func() { pollingCloseTimeout = old })
	sink := newPollingSink(t, 0, true)
	c := pollingConnTo(t, sink.addr)
	if _, err := c.Write(bytes.Repeat([]byte{0x21}, 4096)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.inflight.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.inflight.Load() == nil {
		t.Fatal("no poll in flight - the test proves nothing")
	}
	if _, err := c.Write(bytes.Repeat([]byte{0x22}, 2048)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := c.Close()
	took := time.Since(start)
	if !errors.Is(err, ErrPollingCloseIncomplete) || !strings.Contains(err.Error(), "6144 bytes") {
		t.Fatalf("close: %v, want ErrPollingCloseIncomplete for all 6144 bytes", err)
	}
	if took > pollingCloseTimeout+500*time.Millisecond {
		t.Fatalf("close took %v against a %v bound: it waited out the poll in flight", took, pollingCloseTimeout)
	}
}

// TestPollingCloseNowCutsACloseInProgress is P2-2 of the round-18 review:
// CloseNow ran behind a Close already sending, inside the same once, and
// waited out its whole bound. It cuts it.
func TestPollingCloseNowCutsACloseInProgress(t *testing.T) {
	sink := newPollingSink(t, 0, true)
	c := pollingConnTo(t, sink.addr)
	if _, err := c.Write(bytes.Repeat([]byte{0x31}, 16<<10)); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	err := c.CloseNow()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("CloseNow took %v behind a Close in progress", took)
	}
	if !errors.Is(err, ErrPollingCloseIncomplete) {
		t.Fatalf("CloseNow: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("the Close in progress did not end with the CloseNow")
	}
}

// TestAPollingCloseTriesOnePollOfItsOwn is P3-2 of the round-18 review: one
// failed poll - a stale keep-alive - made Close give up at once. It makes
// one poll of its own first; here the server failed the first connection
// only, and everything arrives.
func TestAPollingCloseTriesOnePollOfItsOwn(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sink := &pollingSink{}
	var first atomic.Bool
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if first.CompareAndSwap(false, true) {
				go func() {
					_, _ = protocol.ReadDispatch(conn)
					conn.Close()
				}()
				continue
			}
			go sink.serve(conn)
		}
	}()
	c := pollingConnTo(t, ln.Addr().String())
	payload := bytes.Repeat([]byte{0x41}, 4096)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !c.pollFailing.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !c.pollFailing.Load() {
		t.Fatal("no poll failed - the test proves nothing")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close after one failed poll: %v", err)
	}
	if got := sink.got.Load(); got != int64(len(payload)) {
		t.Fatalf("the server got %d of %d bytes", got, len(payload))
	}
}

// TestAPollingCloseDoesNotTakeAnEmptyBufferForSent: everything written is
// in the poll in flight to a mute peer, and sendBuf is empty. Close read
// that as all sent and said nil; it waits for the worker and reports the
// 4 KiB (P2-1 of the round-18 review).
func TestAPollingCloseDoesNotTakeAnEmptyBufferForSent(t *testing.T) {
	old := pollingCloseTimeout
	pollingCloseTimeout = 500 * time.Millisecond
	t.Cleanup(func() { pollingCloseTimeout = old })
	sink := newPollingSink(t, 0, true)
	c := pollingConnTo(t, sink.addr)
	if _, err := c.Write(bytes.Repeat([]byte{0x51}, 4096)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.inflight.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.sendLock.Lock()
	queued := c.sendBuf.Len()
	c.sendLock.Unlock()
	if c.inflight.Load() == nil || queued != 0 {
		t.Fatalf("in flight %v, %d bytes still queued - the test proves nothing", c.inflight.Load() != nil, queued)
	}
	if err := c.Close(); !errors.Is(err, ErrPollingCloseIncomplete) || !strings.Contains(err.Error(), "4096 bytes") {
		t.Fatalf("close: %v, want ErrPollingCloseIncomplete for the 4096 bytes in flight", err)
	}
}
