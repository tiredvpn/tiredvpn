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
// that acknowledged what the server sent it within the last half of the
// period is there, and the deadline moves on by a full period. A client the
// server sends nothing to acknowledges nothing - keepalive probes do not
// count (TestClientLiveness) - and its session ends on the deadline as
// before.
//
// The deadline is moved while the frame read is still waiting, never after
// it failed: a read that times out inside a frame has consumed part of it,
// and the framer could not go on from there. TUN sessions are not watched:
// their clients keep their own keepalive (the frame loop's echo), and a TUN
// session holds an address lease the deadline is there to free.
type h2ProxyWatch struct {
	conn   net.Conn
	logger *log.Logger

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
// deadline, so the first check falls before it runs out; every check after
// it sets a deadline of its own and is followed by the next. A deadline the
// loop sets in between, on a frame from the client, is later still.
func watchH2ProxyClient(conn net.Conn, logger *log.Logger) *h2ProxyWatch {
	w := &h2ProxyWatch{conn: conn, logger: logger}
	w.mu.Lock()
	w.timer = time.AfterFunc(h2ProxyWatchEvery(), w.check)
	w.mu.Unlock()
	return w
}

// h2ProxyWatchEvery is the period of the checks: the read deadline less its
// lead.
func h2ProxyWatchEvery() time.Duration {
	deadline := h2FrameReadTimeout()
	return deadline - deadline/h2ProxyWatchLead
}

func (w *h2ProxyWatch) check() {
	if w.clientThere() {
		w.mu.Lock()
		if w.stopped {
			w.mu.Unlock()
			return
		}
		_ = w.conn.SetReadDeadline(time.Now().Add(h2FrameReadTimeout()))
		w.mu.Unlock()
		if w.logger != nil {
			w.logger.Debug("H2 proxy session: no frame from the client, but it acknowledges the downlink - read deadline moved on")
		}
		if f := h2ProxyDeadlineExtended.Load(); f != nil {
			(*f)(w.conn)
		}
	}
	// Not there, the read ends on its deadline - unless a frame comes
	// first and the loop sets a new one, which the next check covers.
	w.rearm(h2ProxyWatchEvery())
}

// clientThere reports whether the client's TCP acknowledged data within the
// last half of the read deadline. Half, not relayClientActiveWindow (the
// whole period): the answer to the client's request, sent just before the
// period began, is acknowledged within it, and counted it kept a session
// with nothing coming down for a second period - on the relay and again on
// the exit behind it. A downlink that keeps the client there comes every
// few seconds. Without TCP_INFO the client is not there, and the deadline
// decides as before.
func (w *h2ProxyWatch) clientThere() bool {
	d, ok := sinceAckReceived(w.conn)
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
