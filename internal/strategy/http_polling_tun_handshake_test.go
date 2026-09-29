package strategy_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestPollingFeederSparesHandshakeFlagsPeek drives the real TUN handshake
// reader over a polling connection. A polling exit answers a v3 client with
// the bare 9-byte response; the reader then waits up to 300ms for an optional
// flags byte. The feeder tick that lands in that window used to splice
// [0,0,0,0] there: the reader took the first zero as the flags byte, left
// three zeros in front of the first frame header, and the packet loop lost
// sync. The first frame must come through intact.
func TestPollingFeederSparesHandshakeFlagsPeek(t *testing.T) {
	hs := []byte{0x00, 10, 99, 0, 1, 10, 99, 0, 2} // [status][serverIP][clientIP], no flags
	frame := make([]byte, 4+60)
	binary.BigEndian.PutUint32(frame, 60)
	for i := range 60 {
		frame[4+i] = 0x45
	}
	c := strategy.NewScriptedPollingConnForTest(t, [][]byte{hs, frame})
	if _, err := c.Write([]byte{0x02, 0, 0, 0, 0, 0x05, 0x00, 0x03}); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	type result struct {
		hs    []byte
		frame []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := tun.ReadTUNHandshakeResponse(c)
		if err != nil {
			done <- result{err: err}
			return
		}
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(c, hdr); err != nil {
			done <- result{hs: resp, err: err}
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		if n > 65535 {
			done <- result{hs: resp, frame: hdr}
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			done <- result{hs: resp, err: err}
			return
		}
		done <- result{hs: resp, frame: append(hdr, body...)}
	}()

	if !c.PollForTest() {
		t.Fatal("poll 1 failed")
	}
	// Wait until the reader has taken the 9 bytes and sits in the flags peek.
	for deadline := time.Now().Add(2 * time.Second); c.BufferedForTest() != 0; {
		if time.Now().After(deadline) {
			t.Fatal("reader never drained the handshake")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	spliced := c.FeedKeepaliveForTest() // a feeder tick inside the peek window
	time.Sleep(400 * time.Millisecond)  // let the peek window close
	if !c.PollForTest() {
		t.Fatal("poll 2 failed")
	}

	var r result
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader stuck")
	}
	if r.err != nil {
		t.Fatalf("reader: %v", r.err)
	}
	if !bytes.Equal(r.hs, hs) {
		t.Errorf("handshake read as % x (spliced=%v), want the 9 bytes the exit sent", r.hs, spliced)
	}
	if !bytes.Equal(r.frame, frame) {
		t.Fatalf("first frame desynced (spliced=%v): header % x", spliced, r.frame[:min(4, len(r.frame))])
	}
}
