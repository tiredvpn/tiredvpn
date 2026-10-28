package server

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// hangupTarget accepts one connection, reads it, sends nothing, and
// records when the connection reached it closed.
type hangupTarget struct {
	addr   string
	closed atomic.Int64 // unix nanoseconds, 0 while open
}

func newHangupTarget(t *testing.T) *hangupTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &hangupTarget{addr: ln.Addr().String()}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { c.Close() })
		_, _ = io.Copy(io.Discard, c)
		h.closed.Store(time.Now().UnixNano())
	}()
	return h
}

// TestAHungUpClientsLegEndsOnTheExitsDeadline is P2-1 of the round-10
// review, on real clocks and the kernel's real TCP keepalive: a proxied
// stream through a relay into an exit, whose client hangs up while the
// target stays open and silent. The relay ends its own side of the leg;
// the exit's session has to end on its 60 s read deadline. The exit's
// liveness watch read the age of the last ACK, and the ACKs of the relay
// socket's keepalive probes (Go's default 15 s on accepted conns) kept it
// young: the leg was still open at 330 s, and the target's connection with
// it (97 s before round 15). Only ACKs of new data count now, and the exit
// sends the relay nothing here.
func TestAHungUpClientsLegEndsOnTheExitsDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("real clocks: about 70 s")
	}
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := newPathRelay(t, secret, exit.addr, withREALITY)
	target := newHangupTarget(t)
	conn := strategyStream(realityV2)(t, relay, target.addr)
	time.Sleep(2 * time.Second)
	hungUp := time.Now()
	conn.Close()

	limit := hungUp.Add(h2FrameReadTimeout() + 20*time.Second)
	for target.closed.Load() == 0 && time.Now().Before(limit) {
		time.Sleep(100 * time.Millisecond)
	}
	at := target.closed.Load()
	if at == 0 {
		t.Fatalf("the target's connection is still open %v after the client hung up (exit read deadline %v)",
			time.Since(hungUp).Round(time.Second), h2FrameReadTimeout())
	}
	t.Logf("the target's connection closed %v after the client hung up", time.Unix(0, at).Sub(hungUp).Round(100*time.Millisecond))
}
