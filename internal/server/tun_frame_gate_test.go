package server

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// splitWriter models a transport whose Write is NOT atomic: it puts a frame on
// the wire in two pieces with a scheduling point between them, the way anything
// that composes a frame out of several underlying writes does (the h2 framer,
// an HTTP body). Two writers without a common lock interleave inside a frame
// here, which is exactly the shape that makes a client read a garbage length.
type splitWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (w *splitWriter) write(p []byte) error {
	half := len(p) / 2
	w.append(p[:half])
	time.Sleep(time.Microsecond) // scheduling point mid-frame
	w.append(p[half:])
	return nil
}

func (w *splitWriter) append(p []byte) {
	w.mu.Lock()
	w.buf = append(w.buf, p...)
	w.mu.Unlock()
}

func (w *splitWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, len(w.buf))
	copy(out, w.buf)
	return out
}

// frameClient parses a [len:4][payload] stream the way the client's TUN relay
// does and returns the payload lengths it saw. An error means the stream
// desynced - the client would have read a garbage length.
func frameClient(t *testing.T, stream []byte) []int {
	t.Helper()
	var lens []int
	for len(stream) > 0 {
		if len(stream) < 4 {
			t.Fatalf("stream ends inside a length header (%d trailing bytes)", len(stream))
		}
		n := int(binary.BigEndian.Uint32(stream[:4]))
		if n > 65535 {
			t.Fatalf("garbage frame length %d - the stream desynced", n)
		}
		if 4+n > len(stream) {
			t.Fatalf("frame length %d runs past the stream (%d bytes left)", n, len(stream)-4)
		}
		lens = append(lens, n)
		stream = stream[4+n:]
	}
	return lens
}

// The handshake response is the first thing on the wire. A frame offered before
// it is refused, not queued: that is the defect behind server_read_oversized -
// a packet queued for the tunnel IP reached the client ahead of the handshake,
// the client parsed the handshake out of a data frame and every length it read
// afterwards was garbage.
func TestTUNFrameGateKeepsHandshakeFirst(t *testing.T) {
	w := &splitWriter{}
	g := newTunFrameGate(w.write)

	frame := make([]byte, 4+20)
	binary.BigEndian.PutUint32(frame[:4], 20)
	for i := range frame[4:] {
		frame[4+i] = 0xAA
	}
	if err := g.Frame(frame); err == nil {
		t.Fatal("a frame offered before the handshake response was accepted")
	} else if !FrameDropped(err) {
		t.Fatalf("pre-handshake frame: got %v, want a drop", err)
	}
	if len(w.bytes()) != 0 {
		t.Fatalf("pre-handshake frame reached the wire: %x", w.bytes())
	}

	resp := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}
	if err := g.Open(resp); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := w.bytes(); len(got) < len(resp) || string(got[:len(resp)]) != string(resp) {
		t.Fatalf("handshake response is not at the head of the stream: %x", got)
	}
	if err := g.Frame(frame); err != nil {
		t.Fatalf("frame after open: %v", err)
	}
	if g.droppedBeforeOpen() != 1 {
		t.Fatalf("dropped count = %d, want 1", g.droppedBeforeOpen())
	}
	if lens := frameClient(t, w.bytes()[len(resp):]); len(lens) != 1 || lens[0] != 20 {
		t.Fatalf("frames after the handshake = %v, want [20]", lens)
	}
}

// Every writer on one tunnel shares the gate's lock, so a keepalive echo can
// never land inside a data frame even on a transport whose Write is not atomic.
func TestTUNFrameGateSerialisesConcurrentWriters(t *testing.T) {
	w := &splitWriter{}
	g := newTunFrameGate(w.write)
	if err := g.Open(nil); err != nil {
		t.Fatalf("open: %v", err)
	}

	const rounds = 200
	keepalive := []byte{0, 0, 0, 0}
	data := make([]byte, 4+1200)
	binary.BigEndian.PutUint32(data[:4], 1200)

	var wg sync.WaitGroup
	for _, p := range [][]byte{data, keepalive} {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := g.Frame(p); err != nil {
					t.Errorf("frame: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	lens := frameClient(t, w.bytes())
	if len(lens) != 2*rounds {
		t.Fatalf("parsed %d frames, want %d", len(lens), 2*rounds)
	}
	var dataFrames, keepalives int
	for _, n := range lens {
		switch n {
		case 1200:
			dataFrames++
		case 0:
			keepalives++
		default:
			t.Fatalf("unexpected frame length %d", n)
		}
	}
	if dataFrames != rounds || keepalives != rounds {
		t.Fatalf("data=%d keepalives=%d, want %d each", dataFrames, keepalives, rounds)
	}
}

// The call site that matters: a client registered with the SharedTUN dispatcher
// before its handshake response is out. The dispatcher must not be able to put a
// frame on the wire in that window - this is the live defect, reproduced in
// netns as "VPN connected (server IP: 0.4.8.0)" followed by frame lengths in the
// tens of millions.
func TestSharedTUNGatedWriterKeepsHandshakeFirst(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	st := &SharedTUN{
		clients:       make(map[string]*ClientWriter),
		reconnTracker: newReconnectTracker(10),
		stopCh:        make(chan struct{}),
	}
	gate := newTunFrameGate(func(frame []byte) error {
		serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err := serverConn.Write(frame)
		return err
	})
	clientIP := net.IPv4(10, 8, 0, 2)
	writer := st.RegisterClientGated(clientIP, "gated-client", serverConn, nil, gate)

	// Dispatch a packet while the gate is still closed: it must be dropped, not
	// queued ahead of the handshake and not reported as a connection error.
	payload := craftV4Packet(clientIP)
	if err := writer.SendPacket(payload); err != nil {
		t.Fatalf("SendPacket before the handshake: %v", err)
	}
	if gate.droppedBeforeOpen() != 1 {
		t.Fatalf("pre-handshake frames dropped = %d, want 1", gate.droppedBeforeOpen())
	}

	resp := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}
	got := make([]byte, len(resp))
	done := make(chan error, 1)
	go func() {
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := readFull(clientConn, got)
		done <- err
	}()
	if err := gate.Open(resp); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("client read of the handshake response: %v", err)
	}
	if string(got) != string(resp) {
		t.Fatalf("client read %x first, want the handshake response %x", got, resp)
	}

	// After the handshake the same writer delivers frames normally.
	full := make([]byte, 4+len(payload))
	hdr := full[:4]
	frameRead := make(chan error, 1)
	go func() {
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := readFull(clientConn, full)
		frameRead <- err
	}()
	if err := writer.SendPacket(payload); err != nil {
		t.Fatalf("SendPacket after the handshake: %v", err)
	}
	if err := <-frameRead; err != nil {
		t.Fatalf("client read of the frame header: %v", err)
	}
	if n := binary.BigEndian.Uint32(hdr); n != uint32(len(payload)) {
		t.Fatalf("frame length = %d, want %d", n, len(payload))
	}
}

// readFull is io.ReadFull, spelled out to keep the test's imports minimal.
func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
