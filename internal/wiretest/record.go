// Package wiretest captures the bytes our strategies actually put on a socket
// and matches them against known fingerprints.
//
// Why it exists: an audit that removes a literal marker from a strategy ends
// with a negative measurement — "the marker is gone". A negative measurement is
// worth nothing unless the same instrument was shown to find the marker while
// it was still there (rule 2 in the research repo's verification.md). So every
// detector here is written to FIRE on the current code, and the test asserting
// it is a fixation of the present state, not a wish about the future. The
// executor who removes a marker inverts the assertion in the same change.
//
// Observation points are named, not assumed. A marker that lives inside a TLS
// session is not on the raw wire, and a harness that pretended otherwise would
// be measuring itself. Every Dump therefore carries the Layer it was taken at,
// and a detector declares which Layer it is entitled to look at.
package wiretest

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// Direction is which way a recorded chunk was travelling.
type Direction int

const (
	// C2S is client → server.
	C2S Direction = iota
	// S2C is server → client.
	S2C
)

func (d Direction) String() string {
	if d == C2S {
		return "c2s"
	}
	return "s2c"
}

// Layer names where a Dump was taken. It is descriptive on purpose: "this
// marker is visible to a passive observer of the TCP stream" and "this marker
// is visible to whoever can undo the transport crypto" are different claims,
// and the harness must not blur them.
type Layer string

const (
	// LayerTCP is the raw TCP byte stream, i.e. what a passive DPI box sees.
	LayerTCP Layer = "tcp"
	// LayerTLSPlaintext is the application stream after the server's TLS stack
	// has decrypted it. A DPI box does not see this without the session key.
	LayerTLSPlaintext Layer = "tls-plaintext"
	// LayerFraming is a strategy's own framing layer, recorded without the TLS
	// wrapper production puts around it. Used where the fixture cannot drive the
	// real TLS path; the marker is then one decrypt away from the wire, not on it.
	LayerFraming Layer = "framing"
	// LayerQUICDatagram is the raw UDP datagram stream.
	LayerQUICDatagram Layer = "quic-datagram"
	// LayerQUICStream is the plaintext of a QUIC stream, as the peer reads it.
	LayerQUICStream Layer = "quic-stream"
	// LayerClientHello is a ClientHello as parsed by the peer's TLS stack. For
	// QUIC this is what a DPI box gets by unprotecting the Initial packet with
	// the published salt from RFC 9001 — no session key needed.
	LayerClientHello Layer = "clienthello"
)

// Segment is one chunk as it crossed the observation point, with the boundary
// and the time it was seen. Boundaries matter: fragment sizes and inter-packet
// gaps are fingerprints in their own right.
type Segment struct {
	Dir  Direction
	At   time.Time
	Data []byte
}

// Dump is everything one detector may look at for a single connection.
type Dump struct {
	Name  string
	Layer Layer

	mu   sync.Mutex
	segs []Segment
}

// NewDump creates an empty dump for an observation point.
func NewDump(name string, layer Layer) *Dump {
	return &Dump{Name: name, Layer: layer}
}

// Record appends a chunk. Safe for concurrent use: the two directions of a
// connection are usually pumped by different goroutines.
func (d *Dump) Record(dir Direction, b []byte) {
	if len(b) == 0 {
		return
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	d.mu.Lock()
	d.segs = append(d.segs, Segment{Dir: dir, At: time.Now(), Data: cp})
	d.mu.Unlock()
}

// Segments returns a copy of everything recorded so far.
func (d *Dump) Segments() []Segment {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Segment, len(d.segs))
	copy(out, d.segs)
	return out
}

// Bytes returns the concatenated stream in one direction.
func (d *Dump) Bytes(dir Direction) []byte {
	var buf bytes.Buffer
	for _, s := range d.Segments() {
		if s.Dir == dir {
			buf.Write(s.Data)
		}
	}
	return buf.Bytes()
}

// Sizes returns the observed chunk boundaries in one direction.
//
// Caveat that the callers have to respect: on a TCP socket these are read()
// boundaries, and the kernel is free to hand two segments back in one read. So
// the observed boundaries are a SUBSET of the writer's, never a superset — a
// detector may conclude "the writer split here", never "the writer did not
// split here".
func (d *Dump) Sizes(dir Direction) []int {
	var out []int
	for _, s := range d.Segments() {
		if s.Dir == dir {
			out = append(out, len(s.Data))
		}
	}
	return out
}

// Gaps returns the intervals between consecutive chunks in one direction.
func (d *Dump) Gaps(dir Direction) []time.Duration {
	var prev time.Time
	var out []time.Duration
	for _, s := range d.Segments() {
		if s.Dir != dir {
			continue
		}
		if !prev.IsZero() {
			out = append(out, s.At.Sub(prev))
		}
		prev = s.At
	}
	return out
}

// Len is the total byte count in one direction.
func (d *Dump) Len(dir Direction) int { return len(d.Bytes(dir)) }

// Conn wraps a net.Conn and records both directions into a Dump.
//
// serverSide flips the mapping: on an accepted connection a Read is client →
// server, on a dialled one it is the other way round.
type Conn struct {
	net.Conn
	dump       *Dump
	serverSide bool
}

// NewConn wraps c so that everything crossing it lands in dump.
func NewConn(c net.Conn, dump *Dump, serverSide bool) *Conn {
	return &Conn{Conn: c, dump: dump, serverSide: serverSide}
}

// Dump returns the dump this connection writes into.
func (c *Conn) Dump() *Dump { return c.dump }

func (c *Conn) readDir() Direction {
	if c.serverSide {
		return C2S
	}
	return S2C
}

func (c *Conn) writeDir() Direction {
	if c.serverSide {
		return S2C
	}
	return C2S
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.dump.Record(c.readDir(), b[:n])
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.dump.Record(c.writeDir(), b[:n])
	return n, err
}

// Listener is a TCP listener that hands out recording connections, one Dump
// per accepted connection.
type Listener struct {
	net.Listener
	name  string
	layer Layer

	mu    sync.Mutex
	dumps []*Dump
}

// Listen opens a loopback TCP listener that records every accepted connection
// at the given layer. It is closed when the test ends.
func Listen(t *testing.T, name string, layer Layer) *Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &Listener{Listener: ln, name: name, layer: layer}
	t.Cleanup(func() { _ = ln.Close() })
	return l
}

// Accept returns the next connection, already wrapped in a recorder.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	d := NewDump(l.name, l.layer)
	l.mu.Lock()
	l.dumps = append(l.dumps, d)
	l.mu.Unlock()
	return NewConn(c, d, true), nil
}

// Addr is the address to point a client at.
func (l *Listener) Addr() net.Addr { return l.Listener.Addr() }

// Dumps returns every dump recorded so far, in accept order.
func (l *Listener) Dumps() []*Dump {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Dump, len(l.dumps))
	copy(out, l.dumps)
	return out
}

// First returns the dump of the first accepted connection, or nil.
func (l *Listener) First() *Dump {
	d := l.Dumps()
	if len(d) == 0 {
		return nil
	}
	return d[0]
}

// PacketConn wraps a net.PacketConn and records every datagram. quic-go accepts
// a PacketConn, so this gives a genuine datagram-level capture of a QUIC
// session without a relay in the middle.
type PacketConn struct {
	net.PacketConn
	dump *Dump
}

// NewPacketConn wraps pc so that every datagram lands in dump. Directions are
// from the server's point of view: ReadFrom is client → server.
func NewPacketConn(pc net.PacketConn, dump *Dump) *PacketConn {
	return &PacketConn{PacketConn: pc, dump: dump}
}

// Dump returns the dump this packet conn writes into.
func (p *PacketConn) Dump() *Dump { return p.dump }

func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	p.dump.Record(C2S, b[:n])
	return n, addr, err
}

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(b, addr)
	p.dump.Record(S2C, b[:n])
	return n, err
}
