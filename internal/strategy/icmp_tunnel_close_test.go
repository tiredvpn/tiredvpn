package strategy

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
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
