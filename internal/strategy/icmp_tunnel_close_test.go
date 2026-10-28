package strategy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Close dropped what Write had queued for the rate-limited send loop (the
// pattern of issue #131 and #129). It sends it now, at the tunnel's rate,
// within icmpCloseTimeout, and reports what it could not send.

func icmpSentBytes(f *icmpFakeNet) int {
	n := 0
	for _, d := range f.frames() {
		n += len(d)
	}
	return n
}

// TestAnICMPCloseSendsWhatWasQueued: 3 KiB in 30 writes, then Close at
// once. At the stealth rate that is 3 packets; every byte leaves, and
// Close reports no loss. A Write after Close fails.
func TestAnICMPCloseSendsWhatWasQueued(t *testing.T) {
	c, fake, _ := icmpDeadlineConn(t)
	c.startSendLoop()
	want := 0
	for i := range 30 {
		b := bytes.Repeat([]byte{byte(i)}, 100)
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
		want += len(b)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v (sent %d of %d)", err, icmpSentBytes(fake), want)
	}
	if got := icmpSentBytes(fake); got != want {
		t.Fatalf("%d of %d queued bytes left the client", got, want)
	}
	if _, err := c.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("a Write after Close: %v", err)
	}
}

// TestAnICMPCloseIsBoundedAndReportsTheRest: 40 full packets queued, 4 s at
// the stealth rate, against a 300 ms bound. Close returns in about the bound
// with ErrICMPCloseIncomplete, and what it sent plus what it reports is
// what was queued.
func TestAnICMPCloseIsBoundedAndReportsTheRest(t *testing.T) {
	old := icmpCloseTimeout
	icmpCloseTimeout = 300 * time.Millisecond
	t.Cleanup(func() { icmpCloseTimeout = old })
	c, fake, _ := icmpDeadlineConn(t)
	c.startSendLoop()
	for i := range 40 {
		if _, err := c.Write(bytes.Repeat([]byte{byte(i)}, MaxPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	err := c.Close()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("close took %v against a 300 ms bound", took)
	}
	if !errors.Is(err, ErrICMPCloseIncomplete) {
		t.Fatalf("close with most of the queue unsent: %v", err)
	}
	if sent, left := int64(icmpSentBytes(fake)), c.left.Load(); sent+left != int64(40*MaxPayloadSize) {
		t.Fatalf("sent %d and reported %d, of %d queued", sent, left, 40*MaxPayloadSize)
	}
}

// icmpTroubledNet is the fake ICMP network whose sends fail (down) or block
// until their write deadline or the socket's close (stuck).
type icmpTroubledNet struct {
	*icmpFakeNet
	down        atomic.Bool
	downClosing atomic.Pointer[func() bool] // down once this reports true
	stuck       bool
	attempts    atomic.Int64
	mu          sync.Mutex
	wd          time.Time
}

func (n *icmpTroubledNet) SetWriteDeadline(t time.Time) error {
	n.mu.Lock()
	n.wd = t
	n.mu.Unlock()
	return nil
}

func (n *icmpTroubledNet) WriteTo(b []byte, addr net.Addr) (int, error) {
	n.attempts.Add(1)
	switch {
	case n.down.Load() || (n.downClosing.Load() != nil && (*n.downClosing.Load())()):
		return 0, &net.OpError{Op: "write", Net: "ip4:icmp", Err: syscall.ENETUNREACH}
	case n.stuck:
		n.mu.Lock()
		wd := n.wd
		n.mu.Unlock()
		select {
		case <-n.closed:
			return 0, net.ErrClosed
		case <-time.After(time.Until(wd)):
			return 0, os.ErrDeadlineExceeded
		}
	}
	return n.icmpFakeNet.WriteTo(b, addr)
}

// icmpCloseConnOver is icmpDeadlineConn over a troubled network, with its
// send loop running.
func icmpCloseConnOver(t *testing.T, down, stuck bool) (*icmpTunnelConn, *icmpTroubledNet) {
	t.Helper()
	secret := []byte("icmp-close-secret")
	n := &icmpTroubledNet{icmpFakeNet: newICMPFakeNet(secret, false), stuck: stuck}
	n.down.Store(down)
	masterKey := DeriveICMPKey(secret)
	const sessionID = 0x0badcafe
	sendCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "c2s"))
	recvCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "s2c"))
	c := &icmpTunnelConn{
		icmpConn:   n,
		serverIP:   n.serverIP,
		sendCipher: sendCipher,
		recvCipher: recvCipher,
		sessionID:  sessionID,
		tunnelID:   9,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		done:       make(chan struct{}),
		rateLimit:  StealthPacketRate,
	}
	t.Cleanup(func() { c.Close() })
	c.startSendLoop()
	return c, n
}

// TestAnICMPCloseOnADeadRouteReportsWhatTheSocketRefused is P2-3 of the
// round-18 review, with the drain's end of P2-2: every send fails (the
// route is gone). A failed send counted as sent, so Close drained the queue
// into errors at the stealth rate for its whole bound and said nil. It
// stops at the first failure and reports every byte.
func TestAnICMPCloseOnADeadRouteReportsWhatTheSocketRefused(t *testing.T) {
	c, n := icmpCloseConnOver(t, false, false)
	// Full packets, so the send loop is still at the first few - 2 s of
	// them at the stealth rate - when the route goes down at Close.
	const queued = 20 * MaxPayloadSize
	for i := range 20 {
		if _, err := c.Write(bytes.Repeat([]byte{byte(i)}, MaxPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	// The route goes down as Close begins: every send of the drain fails.
	closing := func() bool { return c.closeBy.Load() != 0 }
	n.downClosing.Store(&closing)
	sentBefore := icmpSentBytes(n.icmpFakeNet)
	start := time.Now()
	err := c.Close()
	took := time.Since(start)
	want := queued - icmpSentBytes(n.icmpFakeNet)
	if !errors.Is(err, ErrICMPCloseIncomplete) || !strings.Contains(err.Error(), fmt.Sprintf(": %d bytes", want)) {
		t.Fatalf("close on a dead route: %v, want ErrICMPCloseIncomplete for the %d bytes not sent (%d were before Close)", err, want, sentBefore)
	}
	if took > time.Second {
		t.Fatalf("close took %v draining into a dead route", took)
	}
	if n.attempts.Load() == 0 {
		t.Fatal("no send was tried - the test proves nothing")
	}
}

// TestAnICMPCloseNowCutsACloseInProgress is P2-2 of the round-18 review: a
// Close draining at the stealth rate held a CloseNow behind it for its
// whole bound.
func TestAnICMPCloseNowCutsACloseInProgress(t *testing.T) {
	c, _ := icmpCloseConnOver(t, false, false)
	for i := range 60 {
		if _, err := c.Write(bytes.Repeat([]byte{byte(i)}, MaxPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	time.Sleep(150 * time.Millisecond)
	start := time.Now()
	err := c.CloseNow()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("CloseNow took %v behind a Close in progress", took)
	}
	if !errors.Is(err, ErrICMPCloseIncomplete) {
		t.Fatalf("CloseNow: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("the Close in progress did not end with the CloseNow")
	}
}

// TestAnICMPCloseDoesNotWaitOutABlockedSend is the last P2 of the round-18
// review: a send blocked in the socket kept Close past its bound until the
// send's own 10 s write deadline. The send's deadline is capped at the
// bound, and the socket is closed under it.
func TestAnICMPCloseDoesNotWaitOutABlockedSend(t *testing.T) {
	old := icmpCloseTimeout
	icmpCloseTimeout = 300 * time.Millisecond
	t.Cleanup(func() { icmpCloseTimeout = old })
	c, n := icmpCloseConnOver(t, false, true)
	if _, err := c.Write(bytes.Repeat([]byte{7}, 100)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for n.attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n.attempts.Load() == 0 {
		t.Fatal("no send under way - the test proves nothing")
	}
	start := time.Now()
	_ = c.Close()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("close took %v with a send blocked against a 300 ms bound", took)
	}
}

// TestAnICMPCloseEndsReadsAtOnce is P3-5 of the round-20 review: Read
// ended only when done closed, after the drain, so the tunnel's reader on
// the old session of a hop waited up to the whole bound. A Close under way
// ends reads at once, and the drain goes on.
func TestAnICMPCloseEndsReadsAtOnce(t *testing.T) {
	c, _ := icmpCloseConnOver(t, false, false)
	for i := range 15 {
		if _, err := c.Write(bytes.Repeat([]byte{byte(i)}, MaxPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 64))
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case err := <-read:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read during Close: %v, want io.EOF", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read still blocked 500 ms into a Close that drains 1.5 s of queue")
	}
	select {
	case <-closed:
		t.Fatal("Close finished at once - the queue was not drained, the test proves nothing")
	default:
	}
}
