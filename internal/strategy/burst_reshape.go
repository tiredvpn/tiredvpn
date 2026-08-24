package strategy

// Burst reshaping: splitting the inner TLS handshake with a counter-packet.
//
// The only detection of ours confirmed by measurement is the nDPI burst
// heuristic: on all twelve flows it caught, the Mahalanobis distance to the
// TLS 1.3 centroid sat between 0.815 and 1.668 against a threshold of 3.0.
// The heuristic looks at four consecutive bursts, a burst being consecutive
// packets in one direction. Our tunnelled flows produce roughly
// [530, 2833, 281, 588] - the inner ClientHello, the server flight, and the
// two that follow.
//
// Record padding does not fix this. Pulling short records up to 900-1400 bytes
// walks us out of the Firefox cluster and straight into the Chrome+PQ one, where
// the distance drops from 3.516 to 2.35. Adding bursts at the head of the
// connection does not fix it either, because nDPI opens a fresh window on every
// client-to-server burst and the original four-gram is still in there.
//
// What does work is breaking up the second burst. A burst ends when traffic
// changes direction, so the server's flight is split by getting one packet from
// the client into the middle of it. That turns [530, 2833, 281, 588] into
// [530, ~80, ~50, 2833], which no model recognises.
//
// The exchange happens once per stream, at the head:
//
//  1. client -> server: the first application burst, untouched
//  2. server:           holds the upstream's reply and sends a nudge (60-100 b)
//  3. client:           replies with an ack (40-65 b) the moment it sees one
//  4. server:           releases the held reply
//  5. from here the stream is not touched at all
//
// Sizes are small on purpose: they are the optimum for the worst window across
// the six measured flows. Bigger is worse - at a nudge of ~960 bytes the margin
// collapses to +0.02.
//
// Neither record carries a marker. Both sides identify them by position in the
// stream: the nudge is the first thing the server writes on a fresh stream, the
// ack is the first thing the client writes after seeing it. The ack length is
// derived from the observed nudge length, so the per-connection jitter survives
// without a length field on the wire.
//
// # Holding costs no memory
//
// Holding the upstream reply is exactly the shape that has given us OOM before,
// so it is implemented by blocking the writer rather than buffering. Write does
// not copy the caller's slice; it delays returning. The caller cannot produce
// more data while it is blocked, so the "held buffer" is one pending write and
// the reshaper allocates nothing for it. The 16 KiB cap is then a check on the
// length of that single write, and the 200 ms timeout bounds how long any
// goroutine can sit in it.
//
// # Both ends must agree
//
// There is no capability negotiation here, and there cannot be one at this
// layer: the server has to decide whether to send a nudge before it writes
// anything, and the only pre-write signal is in the REALITY handshake, which
// this layer sits above. A server with reshaping on talking to a client with it
// off would prepend 60-100 bytes of noise to the client's data and corrupt the
// stream. The client-side sanity check below (length must look like a nudge)
// narrows the window but does not close it.
//
// So the mode must be identical on both ends. It defaults to off, and turning it
// on is the rollout task, not this one.

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// reshapeHoldCap is the largest upstream reply we will hold. A first write
	// bigger than this is released immediately: the point is to split the
	// server flight, and a flight that large is already outside every model.
	reshapeHoldCap = 16 << 10

	// reshapeAckTimeout bounds how long a writer may block waiting for the ack.
	// On expiry the reply goes out unreshaped rather than being held longer.
	reshapeAckTimeout = 200 * time.Millisecond

	// Nudge and ack sizes, jittered per stream.
	//
	// The margin is almost flat in the nudge length - across 45..100 bytes the
	// distance to the binding model moves by 0.045 - because the window that
	// binds is [530, nudge, ack, 2833] and its distance is dominated by the
	// server flight, not by the nudge. Still, the whole range costs nothing to
	// move, so it sits at the low end of what stays plausible:
	//
	//   nudge 45..80  -> worst margin 0.945
	//   nudge 60..100 -> worst margin 0.927
	//
	// The floor is not free. A TLS 1.3 record cannot be shorter than about 22
	// bytes (one content byte, a 16-byte tag, a 5-byte header), and records down
	// near that size are alerts, which mid-connection are themselves worth
	// noticing. At 45..80 the record lands where real HTTP/2 control frames land
	// - SETTINGS and WINDOW_UPDATE, 9 to 30 bytes of payload - which is the most
	// common small record on a live h2 connection.
	reshapeNudgeMin = 45
	reshapeNudgeMax = 80
	reshapeAckMin   = 40
	reshapeAckSpan  = 26 // ack length lands in [40, 65]

	// reshapeDefaultMaxStreams caps how many streams may sit in the holding
	// state at once. Past it, new streams run unreshaped - they are never
	// queued, because queueing is what turns a burst of connections into an
	// unbounded backlog.
	reshapeDefaultMaxStreams = 512
)

// BurstReshapeConfig is the per-side configuration. It must match on both ends;
// see the package comment.
type BurstReshapeConfig struct {
	// Enabled turns the exchange on. Off means the wrappers return the stream
	// untouched, with no allocation and no code in the data path.
	Enabled bool

	// PadFlight adds this many bytes in front of the released reply to grow the
	// second burst further. Costs a kilobyte or more per connection for a margin
	// gain of about +1.17 at 6 KiB. Zero, i.e. off, unless measured otherwise.
	// Both ends must use the same value: the client strips exactly this many
	// bytes at exactly this position.
	PadFlight int

	// MaxHoldStreams overrides the global ceiling on concurrent holds.
	MaxHoldStreams int
}

// burstReshapeStats is the exported state. Counters are monotonic, gauges track
// what is happening right now.
var burstReshapeStats struct {
	holdBytes   atomic.Int64 // bytes currently held across all streams
	holdStreams atomic.Int64 // streams currently in the holding state
	reshaped    atomic.Int64 // streams where the exchange completed
	skipped     atomic.Int64 // streams that ran unreshaped, for any reason
}

// BurstReshapeStats is a snapshot for the metrics exporter.
type BurstReshapeStats struct {
	HoldBytes     int64
	HoldStreams   int64
	ReshapedTotal int64
	SkippedTotal  int64
}

// ReadBurstReshapeStats returns the current counters.
func ReadBurstReshapeStats() BurstReshapeStats {
	return BurstReshapeStats{
		HoldBytes:     burstReshapeStats.holdBytes.Load(),
		HoldStreams:   burstReshapeStats.holdStreams.Load(),
		ReshapedTotal: burstReshapeStats.reshaped.Load(),
		SkippedTotal:  burstReshapeStats.skipped.Load(),
	}
}

// resetBurstReshapeStats exists for tests.
func resetBurstReshapeStats() {
	burstReshapeStats.holdBytes.Store(0)
	burstReshapeStats.holdStreams.Store(0)
	burstReshapeStats.reshaped.Store(0)
	burstReshapeStats.skipped.Store(0)
}

// acquireHoldSlot takes a slot in the global ceiling. Returns false when the
// ceiling is reached, and the caller then runs unreshaped.
func acquireHoldSlot(max int) bool {
	if max <= 0 {
		max = reshapeDefaultMaxStreams
	}
	for {
		cur := burstReshapeStats.holdStreams.Load()
		if cur >= int64(max) {
			return false
		}
		if burstReshapeStats.holdStreams.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func releaseHoldSlot() {
	burstReshapeStats.holdStreams.Add(-1)
}

// reshapeRandomLen returns a length uniformly in [min, min+span).
func reshapeRandomLen(min, span int) int {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is fatal elsewhere in this process; here the honest
		// fallback is the midpoint, which is still a legal size.
		return min + span/2
	}
	return min + int(binary.BigEndian.Uint64(b[:])%uint64(span))
}

// reshapeAckLen derives the ack length from the nudge length. Both sides compute
// it from the same observed number, which keeps the jitter without putting a
// length field on the wire.
func reshapeAckLen(nudgeLen int) int {
	return reshapeAckMin + nudgeLen%reshapeAckSpan
}

// randomBytes fills a fresh slice with CSPRNG output.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// server side
// ---------------------------------------------------------------------------

// ReshapeServerStream wraps an accepted smux stream. It holds the first write
// (the upstream's reply), sends a nudge, waits for the client's ack and then
// releases. Everything after that is passed straight through.
//
// With cfg.Enabled false the stream is returned as-is.
func ReshapeServerStream(stream net.Conn, cfg BurstReshapeConfig) net.Conn {
	if !cfg.Enabled {
		return stream
	}
	return &serverReshaper{Conn: stream, cfg: cfg, ackDone: make(chan struct{})}
}

type serverReshaper struct {
	net.Conn
	cfg BurstReshapeConfig

	mu           sync.Mutex
	clientSpoke  bool   // the client's first burst has been read
	swallowLeft  int    // ack bytes still to discard on the read path
	swallowArmed bool   // ackLen has been decided, discarding may begin
	leftover     []byte // bytes read past the ack, owed to the caller

	ackOnce sync.Once
	ackDone chan struct{}

	firstWrite sync.Once
	finished   atomic.Bool // exchange over, everything is a plain passthrough
}

func (s *serverReshaper) signalAck() {
	s.ackOnce.Do(func() { close(s.ackDone) })
}

// Read passes client data through, except for the ack, which is consumed here
// and never reaches the upstream.
func (s *serverReshaper) Read(p []byte) (int, error) {
	// Hand back anything we over-read while swallowing the ack.
	s.mu.Lock()
	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	for {
		n, err := s.Conn.Read(p)
		if n == 0 {
			return n, err
		}

		s.mu.Lock()
		if !s.clientSpoke {
			// First burst from the client: the inner ClientHello. Untouched.
			s.clientSpoke = true
			s.mu.Unlock()
			return n, err
		}
		if !s.swallowArmed || s.swallowLeft == 0 {
			s.mu.Unlock()
			return n, err
		}

		// We are mid-ack. Discard what belongs to it, keep the rest.
		drop := s.swallowLeft
		if drop > n {
			drop = n
		}
		s.swallowLeft -= drop
		rest := n - drop
		done := s.swallowLeft == 0
		if rest > 0 {
			s.leftover = append(s.leftover, p[drop:n]...)
		}
		s.mu.Unlock()

		if done {
			s.signalAck()
		}
		if rest > 0 {
			s.mu.Lock()
			m := copy(p, s.leftover)
			s.leftover = s.leftover[m:]
			s.mu.Unlock()
			return m, err
		}
		if err != nil {
			return 0, err
		}
		// The whole read was ack; go round for real data.
	}
}

// Write holds the first upstream reply behind the nudge/ack exchange.
func (s *serverReshaper) Write(p []byte) (int, error) {
	if s.finished.Load() {
		return s.Conn.Write(p)
	}

	var handled bool
	var n int
	var err error
	s.firstWrite.Do(func() {
		handled = true
		n, err = s.holdAndRelease(p)
	})
	if handled {
		return n, err
	}
	return s.Conn.Write(p)
}

// holdAndRelease runs the exchange for the first write on the stream.
func (s *serverReshaper) holdAndRelease(p []byte) (int, error) {
	defer s.finished.Store(true)

	s.mu.Lock()
	spoke := s.clientSpoke
	s.mu.Unlock()

	// Nothing to split if the client has not sent its burst yet, and nothing
	// worth splitting if the reply is already larger than every model's second
	// burst. Either way, straight through.
	if !spoke || len(p) > reshapeHoldCap {
		burstReshapeStats.skipped.Add(1)
		return s.Conn.Write(p)
	}

	if !acquireHoldSlot(s.cfg.MaxHoldStreams) {
		// Ceiling reached: run unreshaped rather than queue.
		burstReshapeStats.skipped.Add(1)
		return s.Conn.Write(p)
	}
	defer releaseHoldSlot()

	nudgeLen := reshapeRandomLen(reshapeNudgeMin, reshapeNudgeMax-reshapeNudgeMin)
	nudge, err := randomBytes(nudgeLen)
	if err != nil {
		burstReshapeStats.skipped.Add(1)
		return s.Conn.Write(p)
	}

	// Arm the read path before the nudge goes out, otherwise the ack can arrive
	// while we are still deciding what to do with it.
	s.mu.Lock()
	s.swallowLeft = reshapeAckLen(nudgeLen)
	s.swallowArmed = true
	s.mu.Unlock()

	burstReshapeStats.holdBytes.Add(int64(len(p)))
	defer burstReshapeStats.holdBytes.Add(-int64(len(p)))

	if _, err := s.Conn.Write(nudge); err != nil {
		return 0, err
	}

	select {
	case <-s.ackDone:
	case <-time.After(reshapeAckTimeout):
		// No ack in time. Release anyway: a stuck writer is worse than an
		// unreshaped flow. Disarm so a late ack is not eaten from the data.
		s.mu.Lock()
		s.swallowArmed = false
		s.swallowLeft = 0
		s.mu.Unlock()
		burstReshapeStats.skipped.Add(1)
		return s.Conn.Write(p)
	}

	if s.cfg.PadFlight > 0 {
		if pad, err := randomBytes(s.cfg.PadFlight); err == nil {
			if _, err := s.Conn.Write(pad); err != nil {
				return 0, err
			}
		}
	}

	burstReshapeStats.reshaped.Add(1)
	return s.Conn.Write(p)
}

// ---------------------------------------------------------------------------
// client side
// ---------------------------------------------------------------------------

// ReshapeClientStream wraps a freshly opened smux stream. It answers the
// server's nudge with an ack and hides both from the caller.
//
// With cfg.Enabled false the stream is returned as-is.
func ReshapeClientStream(stream net.Conn, cfg BurstReshapeConfig) net.Conn {
	if !cfg.Enabled {
		return stream
	}
	return &clientReshaper{Conn: stream, cfg: cfg}
}

type clientReshaper struct {
	net.Conn
	cfg BurstReshapeConfig

	mu       sync.Mutex
	wrote    bool // our first burst has gone out
	settled  bool // the nudge has been dealt with, or ruled out
	padLeft  int  // pad bytes still to strip
	leftover []byte
}

func (c *clientReshaper) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.wrote = true
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *clientReshaper) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		c.mu.Unlock()
		return n, nil
	}
	settled, wrote := c.settled, c.wrote
	c.mu.Unlock()

	if settled || !wrote {
		return c.Conn.Read(p)
	}

	n, err := c.Conn.Read(p)
	if n == 0 {
		return n, err
	}

	c.mu.Lock()
	if c.settled {
		c.mu.Unlock()
		return n, err
	}
	c.settled = true
	c.mu.Unlock()

	// Positional check: the first thing a reshaping server writes is the nudge,
	// alone, because the real reply is held behind the ack. Anything outside the
	// nudge size range means the peer is not reshaping - hand it to the caller
	// untouched and stop looking.
	if n < reshapeNudgeMin || n > reshapeNudgeMax {
		return n, err
	}

	ack, aerr := randomBytes(reshapeAckLen(n))
	if aerr != nil {
		return n, err
	}
	if _, werr := c.Conn.Write(ack); werr != nil {
		return 0, werr
	}

	if c.cfg.PadFlight > 0 {
		c.mu.Lock()
		c.padLeft = c.cfg.PadFlight
		c.mu.Unlock()
		if derr := c.discard(c.cfg.PadFlight); derr != nil {
			return 0, derr
		}
	}

	if err != nil {
		return 0, err
	}
	// The nudge is consumed; the caller's first Read returns the real reply.
	return c.Conn.Read(p)
}

// discard drops exactly n bytes from the stream.
func (c *clientReshaper) discard(n int) error {
	if n <= 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, c.Conn, int64(n)); err != nil {
		return err
	}
	c.mu.Lock()
	c.padLeft = 0
	c.mu.Unlock()
	return nil
}
