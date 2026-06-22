package strategy

import (
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// newTestRealityConn builds a realityConn backed by a real smux session over an
// in-memory pipe. It mirrors the production stack (tcpConn → smux session →
// stream) closely enough to exercise realityConn.Close's teardown and, more
// importantly, the isolation guarantee: each conn owns a distinct TCP pipe.
func newTestRealityConn(t *testing.T) (*realityConn, net.Conn) {
	t.Helper()

	clientPipe, serverPipe := net.Pipe()

	// Server side: accept the single stream so the client's OpenStream returns.
	srvSess, err := smux.Server(serverPipe, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	go func() {
		for {
			stream, aerr := srvSess.AcceptStream()
			if aerr != nil {
				return
			}
			// Drain so the pipe never blocks the client side.
			go func(s *smux.Stream) {
				buf := make([]byte, 256)
				for {
					if _, rerr := s.Read(buf); rerr != nil {
						return
					}
				}
			}(stream)
		}
	}()

	cliSess, err := smux.Client(clientPipe, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	stream, err := cliSess.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	rc := &realityConn{Conn: stream, sess: cliSess, tcpConn: clientPipe}
	t.Cleanup(func() {
		_ = srvSess.Close()
		_ = serverPipe.Close()
	})
	return rc, clientPipe
}

// TestRealityConn_CloseTearsDownOwnStack verifies Close shuts down the stream,
// the smux session and the underlying TCP — not just the stream.
func TestRealityConn_CloseTearsDownOwnStack(t *testing.T) {
	rc, tcp := newTestRealityConn(t)

	if err := rc.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if !rc.sess.IsClosed() {
		t.Error("smux session still open after Close")
	}

	// The underlying TCP must be closed: a write should fail.
	_ = tcp.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := tcp.Write([]byte("x")); err == nil {
		t.Error("underlying TCP still writable after Close — leaked connection")
	}
}

// TestRealityConn_CloseIsolation is the regression guard for the reconnect
// storm: closing one caller's conn must not disturb another's. Before the fix
// the strategy held a single shared muxSess/muxConn that every Connect closed,
// so a second dial silently tore down the first caller's live tunnel.
func TestRealityConn_CloseIsolation(t *testing.T) {
	first, _ := newTestRealityConn(t)
	second, secondTCP := newTestRealityConn(t)

	// Close the first connection entirely.
	if err := first.Close(); err != nil {
		t.Fatalf("first.Close: %v", err)
	}

	// The second connection must be completely unaffected.
	if second.sess.IsClosed() {
		t.Fatal("second session closed when first was closed — connections share state")
	}
	_ = secondTCP.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := second.Write([]byte("still alive")); err != nil {
		t.Fatalf("second connection broke when first closed: %v", err)
	}

	if err := second.Close(); err != nil {
		t.Fatalf("second.Close: %v", err)
	}
}
