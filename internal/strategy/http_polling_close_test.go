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
	if !errors.Is(err, ErrPollingCloseIncomplete) {
		t.Fatalf("close on a mute peer: %v, want ErrPollingCloseIncomplete", err)
	}
	// The poll the worker was in has its own 3 s; the bound is on what
	// Close adds after it.
	if took > pollTimeout+pollingCloseTimeout+time.Second {
		t.Fatalf("close took %v", took)
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
