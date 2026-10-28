package server

import (
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// clientLiveness says whether a relay's downstream client is still there,
// which is what keeps its upstream leg alive (relayTUNSink's keepalive, the
// upstream conn's KeepAlive).
//
// Heard from within relayClientActiveWindow is alive, as since round 11. A
// client may also send nothing for minutes: a desktop client older than
// 1.11.9 on a sparse download - a push every few seconds - sends no
// keepalive, because the server is never silent for 9 s. Its leg died every
// 60 s on the exit's read deadline, while the client was there all along
// (the fix12-slow stand run). So where the transport is TCP and the kernel
// can say, a client whose TCP acknowledged new data the relay sent it
// within the window is alive too (ackProgress): a phone that left stops
// acknowledging. It used to be the age of the last ACK of any kind
// (tcpi_last_ack_recv), and the ACK of a TCP keepalive probe refreshes
// that: every accepted conn carries Go's 15 s keepalive, so any socket
// still up counted as a client, and a leg whose client had hung up lived
// as long as its target stayed open (P2-1 of the round-10 review). A
// transport that is not TCP says so itself: a QUIC conn is open while its
// client's packets keep coming (peerAlive), an HTTP Polling session is heard
// by its requests (seen). Without any of these the first rule alone decides.
type clientLiveness struct {
	// conn is the downstream conn, nil for a transport without one (HTTP
	// Polling's requests).
	conn net.Conn
	// heard is how long ago the client was last heard, false if never.
	heard func() (time.Duration, bool)
	// seen is how long ago the client last showed itself where the relay
	// has no conn of it - an HTTP Polling session's last request - false if
	// never. Nil for none.
	seen func() (time.Duration, bool)
	// acks follows conn's acknowledged bytes from one look to the next;
	// nil reads no ACKs. It has to outlive the look: one per downstream
	// client, held by whoever asks.
	acks *ackProgress
}

// ackProgress follows a conn's tcpi_bytes_acked from one look to the next
// and remembers when it last grew. Only an ACK of new data moves the
// count: the ACK of a keepalive probe acknowledges nothing new. Measured on
// this kernel (Linux 7.0, loopback, keepalive at 1 s, a peer that never
// reads or writes): last_ack_recv stayed under 1 s for as long as it ran,
// bytes_acked stayed at 1 (the SYN); 100 bytes written moved it to 101.
type ackProgress struct {
	last  atomic.Uint64 // bytes acked at the last look
	grew  atomic.Int64  // when a look last saw them grow, a monoNow stamp plus one, 0 for never
	begun atomic.Bool   // a first look has set last
}

// start takes the baseline the first look compares with. Called when the
// watch on conn begins: without it the first look only set the baseline,
// and a session whose deadline came before a second look lost it.
func (a *ackProgress) start(conn net.Conn) {
	if a == nil {
		return
	}
	if n, ok := bytesAcked(conn); ok {
		a.last.Store(n)
		a.begun.Store(true)
	}
}

// sinceGrowth looks at conn's acknowledged bytes and reports how long ago
// a look first saw them grow, false if none has, or where the kernel cannot
// say. Without a baseline (start) the first look only sets it. Looks come
// at least once per quiet period, so growth is seen at most one look late.
func (a *ackProgress) sinceGrowth(conn net.Conn) (time.Duration, bool) {
	if a == nil {
		return 0, false
	}
	n, ok := bytesAcked(conn)
	if !ok {
		return 0, false
	}
	// The monotonic clock: a wall-clock step back made the age negative,
	// which read as fresh (P3-8 of the round-11 review).
	now := monoNow() + 1
	if prev := a.last.Swap(n); a.begun.Swap(true) && n > prev {
		a.grew.Store(now)
	}
	at := a.grew.Load()
	if at == 0 {
		return 0, false
	}
	return time.Duration(now - at), true
}

// peerAlive is a conn that knows whether its peer is still there: a QUIC
// conn, which quic-go closes once the client has sent nothing for its idle
// timeout.
type peerAlive interface{ PeerAlive() bool }

func (l clientLiveness) alive() bool {
	window := relayClientActiveWindow()
	for _, f := range []func() (time.Duration, bool){l.heard, l.seen} {
		if f == nil {
			continue
		}
		if d, ok := f(); ok && d < window {
			return true
		}
	}
	if p, ok := l.conn.(peerAlive); ok && p.PeerAlive() {
		return true
	}
	if d, ok := l.acks.sinceGrowth(l.conn); ok && d < window {
		return true
	}
	return false
}

// bytesAcked is how many bytes conn's TCP peer has acknowledged, false
// where that cannot be told: not TCP underneath, or no TCP_INFO.
func bytesAcked(conn net.Conn) (uint64, bool) {
	sc := transportSyscallConn(conn)
	if sc == nil {
		return 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var n uint64
	var ok bool
	if cerr := raw.Control(func(fd uintptr) { n, ok = tcpBytesAcked(fd) }); cerr != nil {
		return 0, false
	}
	return n, ok
}

// transportConn is a conn carried over another, which it names: an smux
// stream over its session's conn.
type transportConn interface{ TransportConn() net.Conn }

// transportSyscallConn walks conn's wrappers down to the socket.
func transportSyscallConn(conn net.Conn) syscall.Conn {
	for range 8 {
		switch c := conn.(type) {
		case nil:
			return nil
		case *net.TCPConn:
			return c
		case transportConn:
			conn = c.TransportConn()
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		case interface{ Unwrap() net.Conn }:
			conn = c.Unwrap()
		case syscall.Conn:
			return c
		default:
			return nil
		}
	}
	return nil
}

// overTransport names the conn a stream is carried over, for clientLiveness.
type overTransport struct {
	net.Conn
	transport net.Conn
}

func (c overTransport) TransportConn() net.Conn { return c.transport }

// upstreamKeepaliveSent, when a test sets it, is called for each keepalive
// a relay's upstream conn sends (keepUpstreamAlive). Nil in production.
var upstreamKeepaliveSent atomic.Pointer[func()]

// keepUpstreamAlive keeps the exit's 60 s read deadline fed on a relay's
// upstream conn while its downstream client is alive, for the relay paths
// that copy bytes up as they come - the TUN bridge and every relay over
// UpstreamDialer.Dial. They wrote nothing up while the client wrote
// nothing, and a sparse download - a push every 5 s, nothing up - lost its
// leg every minute (fix12-slow). The keepalive is an empty stego DATA frame
// after a quiet period drawn like the TUN leg's (relayKeepaliveAfter), so
// the exit, of any version, reads a frame and delivers nothing. A conn that
// is not an upstream stego conn is left alone.
//
// What this rule counts as a client being there, and what it does not
// (P3-10 of the round-9 review):
//
//   - It is the ACK of new data the relay sent (ackProgress). The round-14
//     measurement that keepalive probes leave tcpi_last_ack_recv alone was
//     wrong - it looked before the first probe went out - and the rule built
//     on it kept every socket still up alive (P2-1 of the round-10 review).
//     A client the relay sends nothing to goes away by the old rule alone.
//   - While the relay does keep sending - a sparse download, which is the
//     case the rule was changed for - whatever acknowledges it counts as
//     the client: a sleeping phone, which is the point, but also a client
//     process frozen with its socket open, or an L4 proxy that terminates
//     the TCP in front of one. Such a client keeps the leg and the exit's
//     session while its target keeps talking. What ends it is the socket
//     going away, which the relay's copy up sees as the end of its stream.
//   - TCP_INFO is Linux only. Elsewhere, and on Polling and QUIC, the rule
//     falls back to what the transport itself can say.
//
// live says what the relay can read of its downstream client; the client
// also counts as heard whenever its bytes go up the leg.
func keepUpstreamAlive(up *strategy.HTTP2StegoConn, live clientLiveness, logger *log.Logger) {
	if up == nil {
		return
	}
	live.heard = up.SinceOwnerWrite
	if live.acks == nil {
		live.acks = &ackProgress{}
	}
	live.acks.start(live.conn)
	go up.KeepAlive(relayKeepaliveAfter, live.alive, func() {
		if logger != nil {
			logger.Debug("Relay: keepalive up the upstream leg")
		}
		if f := upstreamKeepaliveSent.Load(); f != nil {
			(*f)()
		}
	})
}
