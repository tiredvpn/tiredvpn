package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// newBridgePipes returns the two bridge-side conns (a, b) plus the peer ends
// (clientEnd talks through a, upstreamEnd talks through b). Closing is the
// caller's responsibility via the bridge.
func newBridgePipes() (a, b, clientEnd, upstreamEnd net.Conn) {
	clientEnd, a = net.Pipe()
	b, upstreamEnd = net.Pipe()
	return a, b, clientEnd, upstreamEnd
}

// TestRunIdleWatchedBridge_IdleCloses verifies a silent bridge is force-closed
// once it goes idle past the timeout (the half-open-downstream reap path).
func TestRunIdleWatchedBridge_IdleCloses(t *testing.T) {
	a, b, clientEnd, upstreamEnd := newBridgePipes()
	defer clientEnd.Close()
	defer upstreamEnd.Close()

	const idle = 200 * time.Millisecond
	done := make(chan struct{})
	go func() {
		runIdleWatchedBridge(a, b, idle, nil)
		close(done)
	}()

	// No traffic flows. The watchdog polls at idle/4, so the bridge should be
	// reaped within ~idle plus a poll tick; allow generous margin.
	select {
	case <-done:
	case <-time.After(idle + 2*time.Second):
		t.Fatal("idle bridge was not force-closed within timeout")
	}

	// After force-close the peer ends must see a closed pipe.
	if _, err := clientEnd.Read(make([]byte, 1)); err == nil {
		t.Fatal("clientEnd read succeeded after bridge close, want error")
	}
}

// TestRunIdleWatchedBridge_TrafficKeepsAlive verifies that ongoing traffic
// (mimicking 10s TUN keepalives) resets the idle timer so a live bridge is not
// reaped, then that it does close once traffic stops.
func TestRunIdleWatchedBridge_TrafficKeepsAlive(t *testing.T) {
	a, b, clientEnd, upstreamEnd := newBridgePipes()
	defer clientEnd.Close()
	defer upstreamEnd.Close()

	const idle = 300 * time.Millisecond
	done := make(chan struct{})
	go func() {
		runIdleWatchedBridge(a, b, idle, nil)
		close(done)
	}()

	// Push a byte client->upstream every idle/3 for ~3x the idle timeout. If the
	// timer were not reset by reads the bridge would close mid-loop.
	deadline := time.Now().Add(3 * idle)
	for time.Now().Before(deadline) {
		writeErr := make(chan error, 1)
		go func() {
			_, err := clientEnd.Write([]byte{0x01})
			writeErr <- err
		}()
		buf := make([]byte, 1)
		if err := upstreamEnd.SetReadDeadline(time.Now().Add(idle)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		if _, err := upstreamEnd.Read(buf); err != nil {
			t.Fatalf("upstream read failed (bridge reaped a live session?): %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("client write failed: %v", err)
		}
		select {
		case <-done:
			t.Fatal("bridge closed while traffic was flowing")
		default:
		}
		time.Sleep(idle / 3)
	}

	// Traffic stopped: the bridge must now reap itself.
	select {
	case <-done:
	case <-time.After(idle + 2*time.Second):
		t.Fatal("bridge did not close after traffic stopped")
	}
}

// TestRunIdleWatchedBridge_PeerCloseEnds verifies the bridge returns promptly
// when a peer closes (normal short-lived bridge), independent of the watchdog.
func TestRunIdleWatchedBridge_PeerCloseEnds(t *testing.T) {
	a, b, clientEnd, upstreamEnd := newBridgePipes()
	defer upstreamEnd.Close()

	done := make(chan struct{})
	go func() {
		runIdleWatchedBridge(a, b, 10*time.Second, nil)
		close(done)
	}()

	// Closing the client end propagates EOF through the copy and tears the bridge
	// down without waiting for the (10s) idle timeout.
	clientEnd.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not close after peer close")
	}
}

// TestCopyWithActivity_StampsAndCopies verifies copyWithActivity forwards bytes
// and advances the activity stamp on reads.
func TestCopyWithActivity_StampsAndCopies(t *testing.T) {
	src, srcPeer := net.Pipe()
	dst, dstPeer := net.Pipe()
	defer src.Close()
	defer dst.Close()

	var stamp atomic.Int64
	stamp.Store(time.Now().Add(-time.Hour).UnixNano())
	before := stamp.Load()

	copyDone := make(chan struct{})
	go func() {
		copyWithActivity(dst, src, &stamp)
		close(copyDone)
	}()

	go func() { srcPeer.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := dstPeer.Read(buf); err != nil {
		t.Fatalf("dst read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("got %q, want %q", buf, "hello")
	}
	if stamp.Load() <= before {
		t.Fatal("activity stamp was not advanced on read")
	}

	srcPeer.Close()
	select {
	case <-copyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("copyWithActivity did not return after src close")
	}
}
