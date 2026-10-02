package server

import (
	"errors"
	"sync"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// tunFrameGate owns the downstream side of one client's TUN tunnel: every frame
// that reaches the client goes through it, under one mutex, and nothing reaches
// the client before the TUN handshake response does.
//
// Why one gate per tunnel rather than a mutex per writer: a TUN-mode tunnel has
// several independent writers - the SharedTUN dispatcher (ClientWriter.SendPacket),
// the keepalive echo in the transport's read loop, the auto-MTU probe reply, the
// relay pump when this node forwards to an upstream exit, and the handshake
// response itself. They used to hold different locks, or none, which left two
// defects:
//
//   - Ordering. Four transports (polling, morph, confusion, h2 stego) registered
//     the client with the dispatcher before writing the handshake response, so a
//     packet that was already queued for that tunnel IP - normal after a
//     reconnect onto the same IP, where the exit is still sending to the old
//     session - could be framed into the stream ahead of the response. The client
//     then reads the handshake out of a data frame ([len:4] first, so status byte
//     0x00 "ok" and garbage addresses), and every length it reads afterwards is
//     garbage. On the Android control-socket relay a garbage length lands in
//     handleOversizedPacket, which reads that many bytes and times out:
//     "server_read_oversized: i/o timeout", with the tunnel dead for good.
//
//   - Atomicity. For a transport whose Write is not atomic (anything that
//     composes a frame out of several underlying writes, like the h2 framer,
//     which also shares one scratch buffer) two writers under two mutexes can
//     interleave inside a frame. The h2 handshake response took no lock at all.
//
// Frames offered before the gate opens are dropped, not queued: they belong to a
// client that is not attached yet, and the inner TCP will retransmit. Queueing
// them would mean holding the dispatcher worker - which serves every client on
// the node - behind one client's handshake.
type tunFrameGate struct {
	mu    sync.Mutex
	open  bool
	write func([]byte) error

	dropped int // frames refused before the handshake, for the log line
}

// errTUNGateClosed reports a frame offered before the handshake response went
// out. Callers treat it as a drop, not as a connection error.
var errTUNGateClosed = errors.New("tun frame gate closed: handshake response not sent yet")

// newTunFrameGate wraps the transport's frame writer. write must put exactly the
// bytes it is given on the wire, as one frame.
func newTunFrameGate(write func([]byte) error) *tunFrameGate {
	return &tunFrameGate{write: write}
}

// Open writes the handshake response and opens the gate. Everything written
// after it is ordered behind it, because both go through the same mutex.
func (g *tunFrameGate) Open(resp []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.open {
		return nil // already opened; the handshake is sent exactly once
	}
	if err := g.write(resp); err != nil {
		return err
	}
	g.open = true
	if g.dropped > 0 {
		log.Debug("TUN gate: dropped %d frame(s) queued before the handshake response", g.dropped)
	}
	return nil
}

// Frame writes one complete frame, or refuses it while the gate is closed.
func (g *tunFrameGate) Frame(p []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.open {
		g.dropped++
		return errTUNGateClosed
	}
	return g.write(p)
}

// FrameDropped reports a frame refused because the gate was still closed, so a
// caller can tell a dropped packet from a dead connection.
func FrameDropped(err error) bool { return errors.Is(err, errTUNGateClosed) }

// droppedBeforeOpen is test-visible accounting of pre-handshake drops.
func (g *tunFrameGate) droppedBeforeOpen() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dropped
}
