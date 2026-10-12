package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// The meek downlink is the mirror of the uplink: the session's relay reads the
// target (SOCKS mode) or takes packets from the SharedTUN dispatcher (TUN mode)
// and parks the bytes in the session until the client polls them out, at most
// 16 KiB per poll. The target side is usually far faster than the polls, so
// what the session parks has to be bounded by something other than the size
// of the download. These tests drive the real relay loops with a client that
// polls slowly or not at all.

// downlinkLen is how many bytes the session holds for the client right now.
func downlinkLen(sess *HTTPPollingSession) int {
	sess.bufLock.Lock()
	defer sess.bufLock.Unlock()
	return sess.toClient.Len()
}

// startPollingSOCKSRelay runs runPollingSessionRelay for a session whose client
// asked for a target that streams payload as fast as the relay will take it.
// The channel closes when the relay returns.
func startPollingSOCKSRelay(t *testing.T, id string, payload []byte) (*HTTPPollingSession, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(payload)
	}()

	sess := newPollingSession(id)
	t.Cleanup(sess.Close)
	addr := ln.Addr().String()
	head := make([]byte, 2+len(addr))
	binary.BigEndian.PutUint16(head[:2], uint16(len(addr)))
	copy(head[2:], addr)
	sess.WriteFromClient(head)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPollingSessionRelay(sess, newTestServerContext(t), testLogger(t))
	}()
	return sess, done
}

// TestPollingSOCKSDownlinkBoundedForStalledClient covers the OOM: a target that
// sends faster than the client polls. The relay used to read the target with no
// backpressure into an unbounded buffer, so a 100 MB download sat in server
// memory within a second while the client trickled it out at 16 KiB per poll.
// The session must hold no more than pollingMaxToClientBuffered however long
// the client stays away.
func TestPollingSOCKSDownlinkBoundedForStalledClient(t *testing.T) {
	payload := make([]byte, 64<<20)
	rand.New(rand.NewSource(11)).Read(payload)
	sess, _ := startPollingSOCKSRelay(t, "fxpolldownstall0", payload)

	peak := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		peak = max(peak, downlinkLen(sess))
		time.Sleep(5 * time.Millisecond)
	}
	if peak > pollingMaxToClientBuffered {
		t.Fatalf("a client that does not poll left %d bytes parked in the session, bound is %d", peak, pollingMaxToClientBuffered)
	}
	if peak < pollingMaxToClientBuffered/2 {
		// The relay must keep the buffer full, not stop reading altogether:
		// otherwise the bound holds trivially and the download crawls.
		t.Fatalf("the relay parked only %d bytes for a stalled client; expected it to fill toward the bound of %d", peak, pollingMaxToClientBuffered)
	}
}

// TestPollingSOCKSRelayEndsWhenStalledSessionCloses: the relay parked on a full
// downlink must still notice the session closing (client gone, idle cleanup),
// or every abandoned download leaks a goroutine and its target connection.
func TestPollingSOCKSRelayEndsWhenStalledSessionCloses(t *testing.T) {
	payload := make([]byte, 16<<20)
	sess, done := startPollingSOCKSRelay(t, "fxpolldownclose0", payload)
	for deadline := time.Now().Add(5 * time.Second); downlinkLen(sess) < pollingMaxToClientBuffered; {
		if time.Now().After(deadline) {
			t.Fatalf("downlink did not fill (%d bytes)", downlinkLen(sess))
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // let the relay park on the full downlink
	sess.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay still running 5s after its stalled session closed")
	}
}

// TestPollingSOCKSDownlinkIntactUnderBackpressure checks what the bound must not
// cost: the relay pauses reading the target instead of dropping bytes or ending
// the session, so a client that polls slowly still gets the whole stream, in
// order, and the session never holds more than the bound along the way.
func TestPollingSOCKSDownlinkIntactUnderBackpressure(t *testing.T) {
	payload := make([]byte, 8<<20)
	rand.New(rand.NewSource(12)).Read(payload)
	want := sha256.Sum256(payload)
	sess, _ := startPollingSOCKSRelay(t, "fxpolldownslow00", payload)

	rng := rand.New(rand.NewSource(13))
	h := sha256.New()
	var ack int64
	var got int
	status := -1
	peak := 0
	deadline := time.Now().Add(60 * time.Second)
	for got < len(payload) {
		if time.Now().After(deadline) {
			t.Fatalf("client received %d of %d bytes in 60s: the relay stopped instead of pausing", got, len(payload))
		}
		peak = max(peak, downlinkLen(sess))
		chunk := sess.ReadToClient(ack)
		ack += int64(len(chunk))
		if status < 0 && len(chunk) > 0 {
			status = int(chunk[0]) // the relay's connect result comes first
			chunk = chunk[1:]
			if status != 0 {
				t.Fatalf("relay reported connect failure %d", status)
			}
		}
		h.Write(chunk)
		got += len(chunk)
		if len(chunk) == 0 || rng.Intn(8) == 0 {
			time.Sleep(time.Duration(rng.Intn(3000)) * time.Microsecond)
		}
	}
	if got != len(payload) {
		t.Fatalf("client received %d bytes, target sent %d", got, len(payload))
	}
	if s := h.Sum(nil); !bytes.Equal(s, want[:]) {
		t.Fatalf("client stream differs from what the target sent: sha256 %x, want %x", s, want)
	}
	if peak > pollingMaxToClientBuffered {
		t.Fatalf("session held %d bytes for the client, bound is %d", peak, pollingMaxToClientBuffered)
	}
}

// TestPollingTUNDownlinkBoundedDropsWholeFrames covers the TUN-mode downlink.
// There the writer is the SharedTUN dispatcher, which serves every client on
// the node, so it cannot be made to wait for one slow poller; past the bound the
// frame is dropped whole, the way a router queue drops a packet, and the inner
// TCP retransmits. The dispatcher must not see an error (that reads as a dead
// tunnel) and the client must only ever receive whole frames.
func TestPollingTUNDownlinkBoundedDropsWholeFrames(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	dev, err := tun.CreateTUNFromFd(fds[0], "fxpolldn0", 1500)
	if err != nil {
		t.Fatalf("tun from fd: %v", err)
	}
	tunEnd := os.NewFile(uintptr(fds[1]), "tun-far-end")
	defer tunEnd.Close()

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.TunIP = net.IPv4(10, 99, 0, 1).To4()
	srvCtx.sharedTUN = &SharedTUN{
		name:          "fxpolldn0",
		tunDev:        dev,
		clients:       make(map[string]*ClientWriter),
		reconnTracker: newReconnectTracker(10),
		stopCh:        make(chan struct{}),
	}
	sess := newPollingSession("fxpolltundown000")
	defer sess.Close()
	go runPollingTUNMode(sess, []byte{10, 99, 0, 9, 0x05, 0x00, 0x03}, srvCtx, testLogger(t))

	var writer *ClientWriter
	for deadline := time.Now().Add(5 * time.Second); writer == nil || downlinkLen(sess) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("polling TUN session did not register and answer the handshake")
		}
		time.Sleep(time.Millisecond)
		srvCtx.sharedTUN.clientsMu.RLock()
		writer = srvCtx.sharedTUN.clients["10.99.0.9"]
		srvCtx.sharedTUN.clientsMu.RUnlock()
	}
	var ack int64
	hs := sess.ReadToClient(ack) // the handshake response, not a frame
	ack += int64(len(hs))

	// 4x the bound in 1400-byte packets, with nobody polling.
	const pktSize = 1400
	packets := 4 * pollingMaxToClientBuffered / pktSize
	for i := range packets {
		if err := writer.SendPacket(uplinkPacket(uint32(i), pktSize)); err != nil {
			t.Fatalf("packet %d: dispatcher got %v; a full downlink must drop, not fail the tunnel", i, err)
		}
	}
	if n := downlinkLen(sess); n > pollingMaxToClientBuffered {
		t.Fatalf("session holds %d bytes for a client that does not poll, bound is %d", n, pollingMaxToClientBuffered)
	}

	// What is parked is a run of whole frames, oldest first, with no gaps
	// inside it: the queue drops at the tail, never inside a frame.
	var stream []byte
	for {
		chunk := sess.ReadToClient(ack)
		if len(chunk) == 0 {
			break
		}
		ack += int64(len(chunk))
		stream = append(stream, chunk...)
	}
	next := uint32(0)
	frames := 0
	for len(stream) > 0 {
		if len(stream) < 4 {
			t.Fatalf("stream ends in a torn frame header (%d bytes)", len(stream))
		}
		n := int(binary.BigEndian.Uint32(stream[:4]))
		if n != pktSize || len(stream) < 4+n {
			t.Fatalf("frame %d: length %d with %d bytes left - a frame was cut", frames, n, len(stream)-4)
		}
		pkt := stream[4 : 4+n]
		if seq := binary.BigEndian.Uint32(pkt[20:24]); seq != next || !bytes.Equal(pkt, uplinkPacket(seq, pktSize)) {
			t.Fatalf("frame %d: seq %d, want %d intact", frames, seq, next)
		}
		next++
		frames++
		stream = stream[4+n:]
	}
	if frames == 0 || frames >= packets {
		t.Fatalf("client got %d of %d frames: expected the head of the burst, with the tail dropped", frames, packets)
	}
}
