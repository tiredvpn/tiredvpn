package strategy

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// icmpDeadlineConn is a connected icmpTunnelConn over a fake socket with its
// receive goroutine running, and a way to put a server packet on the wire.
func icmpDeadlineConn(t *testing.T) (c *icmpTunnelConn, fake *icmpFakeNet, send func(data []byte)) {
	t.Helper()
	secret := []byte("icmp-deadline-secret")
	fake = newICMPFakeNet(secret, false)
	masterKey := DeriveICMPKey(secret)
	const sessionID = 0x0badcafe
	sendCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "c2s"))
	recvCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "s2c"))
	c = &icmpTunnelConn{
		icmpConn:   fake,
		serverIP:   fake.serverIP,
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
	go c.recvLoop()

	var seq uint32
	send = func(data []byte) {
		seq++
		fake.deliver(icmpServerReply(masterKey, sessionID, 9, seq, data, 0))
	}
	return c, fake, send
}

type icmpReadResult struct {
	data    []byte
	err     error
	elapsed time.Duration
}

// icmpReadWithin runs one Read and fails the test if it has not returned
// within limit: a Read that ignores its deadline shows up as a failure rather
// than as a hung test binary.
func icmpReadWithin(t *testing.T, c *icmpTunnelConn, limit time.Duration) icmpReadResult {
	t.Helper()
	ch := make(chan icmpReadResult, 1)
	start := time.Now()
	go func() {
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		ch <- icmpReadResult{buf[:n], err, time.Since(start)}
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(limit):
		t.Fatalf("Read did not return within %v", limit)
		return icmpReadResult{}
	}
}

func icmpWantTimeout(t *testing.T, r icmpReadResult) {
	t.Helper()
	if !errors.Is(r.err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %q, %v; want os.ErrDeadlineExceeded", r.data, r.err)
	}
	var ne net.Error
	if !errors.As(r.err, &ne) || !ne.Timeout() {
		t.Fatalf("Read error %v is not a net.Error timeout", r.err)
	}
}

// TestICMPReadHonoursDeadline pins that a deadline bounds Read on an empty
// queue. Before the fix the deadline went to the ICMP socket, which only the
// receive goroutine reads, and Read waited for the next packet or a close
// (issue #98: a 300 ms peek waited 1.5 s).
func TestICMPReadHonoursDeadline(t *testing.T) {
	for _, set := range []struct {
		name string
		fn   func(c *icmpTunnelConn, t time.Time) error
	}{
		{"SetReadDeadline", (*icmpTunnelConn).SetReadDeadline},
		{"SetDeadline", (*icmpTunnelConn).SetDeadline},
	} {
		t.Run(set.name, func(t *testing.T) {
			c, _, _ := icmpDeadlineConn(t)
			const d = 200 * time.Millisecond
			_ = set.fn(c, time.Now().Add(d))
			r := icmpReadWithin(t, c, 3*time.Second)
			icmpWantTimeout(t, r)
			if r.elapsed < d-20*time.Millisecond || r.elapsed > d+time.Second {
				t.Fatalf("Read timed out after %v, want about %v", r.elapsed, d)
			}
		})
	}
}

// TestICMPReadDeadlineMovedWhileBlocked: a deadline set while Read is already
// waiting applies to that Read, as on a socket.
func TestICMPReadDeadlineMovedWhileBlocked(t *testing.T) {
	c, _, _ := icmpDeadlineConn(t)
	_ = c.SetReadDeadline(time.Now().Add(time.Minute))
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}()
	r := icmpReadWithin(t, c, 3*time.Second)
	icmpWantTimeout(t, r)
}

// TestICMPReadDeadlineReset: a deadline that has passed fails every Read,
// including one with a packet already queued, until it is cleared or moved
// into the future; then the queued data is read as usual.
func TestICMPReadDeadlineReset(t *testing.T) {
	for _, reset := range []struct {
		name string
		to   time.Time
	}{
		{"cleared", time.Time{}},
		{"moved forward", time.Now().Add(time.Minute)},
	} {
		t.Run(reset.name, func(t *testing.T) {
			c, _, send := icmpDeadlineConn(t)
			want := []byte("queued before the deadline passed")
			send(want)
			for len(c.recvQueue) == 0 {
				time.Sleep(time.Millisecond)
			}

			_ = c.SetReadDeadline(time.Unix(1, 0))
			// The packet waits in the queue the whole time; a select that
			// let it race the passed deadline would pick it about half the
			// time, so one try would not tell.
			for range 32 {
				icmpWantTimeout(t, icmpReadWithin(t, c, time.Second))
			}

			_ = c.SetReadDeadline(reset.to)
			r := icmpReadWithin(t, c, 3*time.Second)
			if r.err != nil || !bytes.Equal(r.data, want) {
				t.Fatalf("Read after reset = %q, %v; want %q", r.data, r.err, want)
			}
		})
	}
}

// TestICMPReadDeadlineStaysOffTheSocket: the socket is the receive
// goroutine's, which arms a deadline of its own on every read. The caller's
// deadline used to be forwarded there, where it only cut that goroutine's
// read short and never reached Read. Packets that arrive after a Read timed
// out must still be delivered.
func TestICMPReadDeadlineStaysOffTheSocket(t *testing.T) {
	c, fake, send := icmpDeadlineConn(t)

	mark := time.Date(2100, 1, 2, 3, 4, 5, 0, time.UTC)
	_ = c.SetReadDeadline(mark)
	_ = c.SetDeadline(mark)
	fake.mu.Lock()
	onSocket := fake.readDeadline
	fake.mu.Unlock()
	if onSocket.Equal(mark) {
		t.Fatalf("the caller's read deadline reached the ICMP socket")
	}

	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	icmpWantTimeout(t, icmpReadWithin(t, c, 3*time.Second))
	_ = c.SetReadDeadline(time.Time{})

	want := []byte("after the timeout")
	send(want)
	r := icmpReadWithin(t, c, 3*time.Second)
	if r.err != nil || !bytes.Equal(r.data, want) {
		t.Fatalf("Read after a timeout = %q, %v; want %q", r.data, r.err, want)
	}
}
