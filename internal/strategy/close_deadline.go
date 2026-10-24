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

// closeDeadline lets a conn wrapper bound the writes its Close still has to
// make without undoing a deadline the caller set. Close writes under the
// earlier of the caller's write deadline and now+limit, and from then on a
// caller can bring that deadline closer but never push it out. Both happen
// in production: VPNClient.Stop sets an expired deadline right before Close
// to abort, and the TUN writer moves the write deadline 30 s out before
// every packet, possibly while Close is running.
type closeDeadline struct {
	mu      sync.Mutex
	caller  time.Time // last write deadline the caller set; zero means none
	closing bool
	closeBy time.Time // the deadline Close writes under, once closing
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

// setDeadline is SetDeadline for the wrapper around c.
func (d *closeDeadline) setDeadline(c net.Conn, t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.caller = t
	if !d.closing {
		return c.SetDeadline(t)
	}
	d.closeBy = earlierDeadline(d.closeBy, t)
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(d.closeBy))
}

// setWriteDeadline is SetWriteDeadline for the wrapper around c.
func (d *closeDeadline) setWriteDeadline(c net.Conn, t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.caller = t
	if d.closing {
		d.closeBy = earlierDeadline(d.closeBy, t)
		t = d.closeBy
	}
	return c.SetWriteDeadline(t)
}

// begin starts closing: it puts the close deadline on c as its write
// deadline and returns it. Later calls keep the deadline the first one set.
func (d *closeDeadline) begin(c net.Conn, limit time.Duration) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closing {
		d.closing = true
		d.closeBy = earlierDeadline(d.caller, time.Now().Add(limit))
	}
	_ = c.SetWriteDeadline(d.closeBy)
	return d.closeBy
}

// closeSocket closes the socket under c, below any TLS layer, so no
// close_notify is attempted: after a write cut short by the close deadline
// the TLS stream is broken anyway, and tls.Conn.Close would spend another
// 5 s of its own trying to send the alert into a peer that does not read.
func closeSocket(c net.Conn) error {
	if nc, ok := c.(interface{ NetConn() net.Conn }); ok {
		return nc.NetConn().Close()
	}
	return c.Close()
}
