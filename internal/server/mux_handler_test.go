package server

import (
	"net"
	"testing"
	"time"
)

// TestRelayUnblocksOnAbandonedStream reproduces the relay OOM leak: a downstream
// client abandons its stream while the upstream (a stego conn with no CloseWrite)
// holds its connection open without ever sending EOF. Before the fix the download
// direction stayed parked in the upstream Read forever, wg.Wait never returned,
// and the whole upstream conn leaked. relay() must instead close both ends when
// the upload direction ends and return promptly.
func TestRelayUnblocksOnAbandonedStream(t *testing.T) {
	h := &MuxHandler{}

	// stream: downstream client end. Closing its peer makes reads return EOF,
	// simulating a client that tore down the stream mid-flight.
	stream, streamPeer := net.Pipe()
	// target: upstream exit end. Nothing ever writes to targetPeer, so a Read on
	// target blocks until target itself is closed - the stego "no EOF" behaviour.
	target, targetPeer := net.Pipe()
	defer streamPeer.Close()
	defer targetPeer.Close()

	// Abandon the downstream stream: the upload copy (stream -> target) now hits EOF.
	streamPeer.Close()

	done := make(chan struct{})
	go func() {
		h.relay(stream, target)
		close(done)
	}()

	select {
	case <-done:
		// relay returned: both ends were force-closed, no goroutine leak.
	case <-time.After(3 * time.Second):
		t.Fatal("relay() hung on abandoned stream - upstream conn would leak (OOM regression)")
	}
}
