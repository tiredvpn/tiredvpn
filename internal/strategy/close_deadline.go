package strategy

import (
	"errors"
	"net"
	"sync"
	"time"
)

// closeAbortGrace is how long past its write deadline a Close keeps waiting
// before it closes the socket to break a write loose. A conn that honours
// write deadlines returns well inside it; one that ignores them (a no-op
// SetWriteDeadline, as on HTTPPollingConn) would otherwise hold Close for
// as long as the peer does not read. A var so tests can change it.
var closeAbortGrace = time.Second

// closeNower is a conn that can be closed at once: no time for the queued
// tail, no TLS close_notify. VPNClient.Stop uses it to abort.
type closeNower interface {
	CloseNow() error
}

// closeDeadline lets a conn wrapper bound the writes its Close still has to
// make without undoing a deadline the caller set. Close writes under the
// earlier of the caller's write deadline and now+limit, and from then on a
// caller can bring that deadline closer but never push it out. Both happen
// in production: VPNClient.Stop sets an expired deadline right before Close
// to abort, and the TUN writer moves the write deadline 30 s out before
// every packet, possibly while Close is running.
//
// While Close runs, an abort timer is armed for closeAbortGrace past the
// deadline, and it moves with the deadline, so the socket is closed in
// time even under a conn that ignores write deadlines.
type closeDeadline struct {
	mu      sync.Mutex
	caller  time.Time // last write deadline the caller set; zero means none
	abortAt time.Time // set by abortNow before Close began; zero means none
	closing bool
	closeBy time.Time // the deadline Close writes under, once closing
	timer   *time.Timer
	ended   bool
}

// earlierDeadline returns the earlier of two deadlines, where the zero
// time means no deadline at all.
func earlierDeadline(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero(), a.Before(b):
		return a
	}
	return b
}

// shortenLocked moves the close deadline to t if t is earlier, puts it on
// c, and moves the abort timer with it. Caller holds mu and is closing.
func (d *closeDeadline) shortenLocked(c net.Conn, t time.Time) error {
	before := d.closeBy
	d.closeBy = earlierDeadline(d.closeBy, t)
	if d.timer != nil && !d.ended && d.closeBy.Before(before) {
		d.timer.Reset(time.Until(d.closeBy) + closeAbortGrace)
	}
	return c.SetWriteDeadline(d.closeBy)
}

// setDeadline is SetDeadline for the wrapper around c.
func (d *closeDeadline) setDeadline(c net.Conn, t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.caller = t
	if !d.closing {
		return c.SetDeadline(t)
	}
	return errors.Join(c.SetReadDeadline(t), d.shortenLocked(c, t))
}

// setWriteDeadline is SetWriteDeadline for the wrapper around c.
func (d *closeDeadline) setWriteDeadline(c net.Conn, t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.caller = t
	if !d.closing {
		return c.SetWriteDeadline(t)
	}
	return d.shortenLocked(c, t)
}

// abortNow makes the close deadline expire now: for a Close that is
// already running, and for one that has not begun yet whatever deadline the
// caller sets in between.
func (d *closeDeadline) abortNow(c net.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if d.closing {
		_ = d.shortenLocked(c, now)
		return
	}
	d.abortAt = now
	_ = c.SetWriteDeadline(now)
}

// begin starts closing: it puts the close deadline - the earlier of the
// caller's write deadline, now+limit and an abort asked for earlier - on c
// as its write deadline, and arms abort for closeAbortGrace past it. Later
// calls keep the deadline the first one set.
func (d *closeDeadline) begin(c net.Conn, limit time.Duration, abort func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closing {
		d.closing = true
		d.closeBy = earlierDeadline(d.caller, time.Now().Add(limit))
		d.closeBy = earlierDeadline(d.closeBy, d.abortAt)
		if abort != nil {
			d.timer = time.AfterFunc(time.Until(d.closeBy)+closeAbortGrace, abort)
		}
	}
	_ = c.SetWriteDeadline(d.closeBy)
}

// end disarms the abort timer once Close is done with the socket.
func (d *closeDeadline) end() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ended = true
	if d.timer != nil {
		d.timer.Stop()
	}
}

// expired reports whether the close deadline has passed, or an abort was
// asked for before Close began.
func (d *closeDeadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closing {
		return !d.abortAt.IsZero()
	}
	return !time.Now().Before(d.closeBy)
}

// closeSocket closes the socket at the bottom of c's NetConn chain, below
// any TLS layer and any wrappers, so no close_notify is attempted: after a
// write cut short by the close deadline the TLS stream is broken anyway,
// and tls.Conn.Close would spend another 5 s of its own trying to send the
// alert into a peer that does not read. The chain is followed at most 16
// levels down, in case a wrapper returns itself.
func closeSocket(c net.Conn) error {
	for range 16 {
		nc, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner := nc.NetConn()
		if inner == nil {
			break
		}
		c = inner
	}
	return c.Close()
}
