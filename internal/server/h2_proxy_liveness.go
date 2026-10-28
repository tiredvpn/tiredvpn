package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// h2ProxyWatch keeps an HTTP/2 Stego proxy session's read deadline off a
// client that sends nothing but is there.
//
// The frame loop gives the client h2FrameReadTimeout between two frames. A
// proxied stream with a sparse download - the target pushes 28 B every 5 s,
// the client's SOCKS side sends nothing up - has no frame from the client at
// all, and the session ended every 60 s: through a relay on the relay's own
// deadline (proxy-f14-h2-relay on the fix14 stand: the relay's leg to the
// exit lived on its keepalive, the client's session did not), and straight
// to an exit on the exit's. A client of any version sends nothing there, so
// the server decides.
//
// Shortly before the deadline the watch looks at the client's TCP: a client
// that acknowledged new data the server sent it within the last half of the
// period is there, and the deadline moves on by a full period. A client the
// server sends nothing to acknowledges nothing new - the ACKs of keepalive
// probes do not count (TestClientLiveness) - and its session ends on the
// deadline as before.
//
// The deadline is moved while the frame read is still waiting, never after
// it failed: a read that times out inside a frame has consumed part of it,
// and the framer could not go on from there. TUN sessions are not watched:
// their clients keep their own keepalive (the frame loop's echo), and a TUN
// session holds an address lease the deadline is there to free.
type h2ProxyWatch struct {
	conn   net.Conn
	logger *log.Logger
	acks   ackProgress
	// decideAt is when the watch next decides; only its timer goroutine
	// touches it.
	decideAt time.Time

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
}

// h2ProxyWatchLead is how long before the read deadline the watch looks at
// the client, as a fraction of the deadline: 10 s of 60.
const h2ProxyWatchLead = 6

// h2ProxyDeadlineExtended, when a test sets it, is called with the client's
// conn each time the watch moves a session's read deadline. Nil in
// production.
var h2ProxyDeadlineExtended atomic.Pointer[func(net.Conn)]

// watchH2ProxyClient starts the watch. The frame loop has just set the read
// deadline. The watch looks at the client's acknowledged bytes every sixth
// of the deadline - the first look sets the baseline, after the ACK of the
// answer to the client's request - which dates their growth to within one
// look, and decides
// once a deadline has run all but its lead; a deadline it sets starts the
// next. A deadline the loop sets in between, on a frame from the client, is
// later still.
func watchH2ProxyClient(conn net.Conn, logger *log.Logger) *h2ProxyWatch {
	w := &h2ProxyWatch{conn: conn, logger: logger}
	w.decideAt = time.Now().Add(h2ProxyWatchEvery())
	w.mu.Lock()
	w.timer = time.AfterFunc(h2ProxyLookEvery(), w.check)
	w.mu.Unlock()
	return w
}

// h2ProxyWatchEvery is how long a deadline runs before the watch decides on
// it: the deadline less its lead.
func h2ProxyWatchEvery() time.Duration {
	deadline := h2FrameReadTimeout()
	return deadline - deadline/h2ProxyWatchLead
}

// h2ProxyLookEvery is how often the watch looks at the client's
// acknowledged bytes: the lead, a sixth of the deadline. Looking only at the
// decision dated all growth since the last one to the decision itself, and
// the ACK of the answer to the client's request, sent as the watch began,
// kept a session with nothing coming down for one more period.
func h2ProxyLookEvery() time.Duration { return h2FrameReadTimeout() / h2ProxyWatchLead }

func (w *h2ProxyWatch) check() {
	there := w.clientThere()
	now := time.Now()
	if now.Before(w.decideAt) {
		w.rearm(h2ProxyLookEvery())
		return
	}
	if there {
		w.mu.Lock()
		if w.stopped {
			w.mu.Unlock()
			return
		}
		_ = w.conn.SetReadDeadline(now.Add(h2FrameReadTimeout()))
		w.mu.Unlock()
		w.decideAt = now.Add(h2ProxyWatchEvery())
		if w.logger != nil {
			w.logger.Debug("H2 proxy session: no frame from the client, but it acknowledges the downlink - read deadline moved on")
		}
		if f := h2ProxyDeadlineExtended.Load(); f != nil {
			(*f)(w.conn)
		}
	}
	// Not there, the read ends on its deadline - unless a frame comes
	// first and the loop sets a new one, which the next look covers.
	w.rearm(h2ProxyLookEvery())
}

// clientThere reports whether the client's TCP acknowledged new data
// within the last half of the read deadline (ackProgress). Half, not the
// relay's whole window: the answer to the client's request, sent just
// before the period began, is acknowledged within it, and counted it kept a
// session with nothing coming down for a second period. New data, not any
// ACK: the ACK of a TCP keepalive probe refreshes tcpi_last_ack_recv, every
// accepted conn carries Go's 15 s keepalive, and a session whose client had
// hung up - or never sent anything - was extended for as long as its socket
// stayed up (P2-1 of the round-10 review: still open at 330 s). Without
// TCP_INFO the client is not there, and the deadline decides as before.
func (w *h2ProxyWatch) clientThere() bool {
	d, ok := w.acks.sinceGrowth(w.conn)
	return ok && d < h2FrameReadTimeout()/2
}

func (w *h2ProxyWatch) rearm(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.timer.Reset(d)
	}
}

// stop ends the watch; after it returns the watch moves no deadline.
func (w *h2ProxyWatch) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	w.timer.Stop()
}
