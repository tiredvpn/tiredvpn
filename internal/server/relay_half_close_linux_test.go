package server

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// halfCloseTarget is a target that reads everything and, on a signal, sends
// its half of the close - a FIN - while it goes on reading.
type halfCloseTarget struct {
	addr      string
	halfClose chan struct{}
	mu        sync.Mutex
	got       []byte
}

func newHalfCloseTarget(t *testing.T) *halfCloseTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tg := &halfCloseTarget{addr: ln.Addr().String(), halfClose: make(chan struct{})}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			<-tg.halfClose
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
		}()
		buf := make([]byte, 512)
		for {
			n, err := c.Read(buf)
			tg.mu.Lock()
			tg.got = append(tg.got, buf[:n]...)
			tg.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return tg
}

func (tg *halfCloseTarget) received() []byte {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]byte(nil), tg.got...)
}

// TestATargetsHalfCloseKeepsTheClientsUpload is P3-8 of the round-9 review:
// round 13b made the exit pass a target's hang-up on at once instead of
// letting the client wait out the 60 s read deadline, and the tests used a
// target that closed both halves. A target that only half-closes - a server
// that has sent its whole answer and still reads the rest of a request - must
// not lose the client's upload.
//
// Where the client's conn can carry a half-close, handleRawTunnel passes it
// on with CloseWrite and the upload goes on. That covers a plain TCP client
// and a TLS one (REALITY B1, WebSocket and the TLS-terminated paths, whose
// CloseWrite is tls.Conn's). This runs the first.
//
// The limit, decided and left as it is: on a transport whose conn has no
// half-close - smux streams (REALITY, B1 mux), SSH and IMAP camouflage,
// Morph, Confusion, HTTP Polling, the stego stream itself - there is nothing
// to send but a full close, and a client's upload in flight is lost. Keeping
// the conn open instead would put the old 60 s hang back for every client,
// to save an upload the transports cannot signal anyway.
func TestATargetsHalfCloseKeepsTheClientsUpload(t *testing.T) {
	tg := newHalfCloseTarget(t)
	srvCtx := &serverContext{cfg: &Config{}}
	client, relaySide := tcpPair(t)
	t.Cleanup(func() { client.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleRawTunnel(relaySide, srvCtx, testLogger(t), clientIdentity{})
	}()
	addr := []byte(tg.addr)
	if _, err := client.Write(append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("relay ack %x: %v", ack, err)
	}
	_ = client.SetReadDeadline(time.Time{})

	close(tg.halfClose)
	// The relay passes the half-close on: the client reads the end of the
	// stream and may still write.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("the target's half-close did not reach the client: %v", err)
	}
	_ = client.SetReadDeadline(time.Time{})
	if _, err := client.Write([]byte("bye")); err != nil {
		t.Fatalf("the client cannot write after the target's half-close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(tg.received()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := tg.received(); string(got) != "bye" {
		t.Fatalf("the target got %q after its half-close, want the client's bye", got)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay kept the tunnel after the client hung up too")
	}
}
