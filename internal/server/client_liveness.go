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
// can say, a client whose TCP acknowledged what the relay sent it within
// the window is alive too: a phone that left stops acknowledging. Without
// TCP_INFO the first rule alone decides.
type clientLiveness struct {
	// conn is the downstream conn, nil for a transport without one (HTTP
	// Polling's requests).
	conn net.Conn
	// heard is how long ago the client was last heard, false if never.
	heard func() (time.Duration, bool)
}

func (l clientLiveness) alive() bool {
	window := relayClientActiveWindow()
	if l.heard != nil {
		if d, ok := l.heard(); ok && d < window {
			return true
		}
	}
	if d, ok := sinceAckReceived(l.conn); ok && d < window {
		return true
	}
	return false
}

// sinceAckReceived is how long ago conn's TCP last received an ACK, false
// where that cannot be told: not TCP underneath, or no TCP_INFO.
func sinceAckReceived(conn net.Conn) (time.Duration, bool) {
	sc := transportSyscallConn(conn)
	if sc == nil {
		return 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var d time.Duration
	var ok bool
	if cerr := raw.Control(func(fd uintptr) { d, ok = tcpSinceAckReceived(fd) }); cerr != nil {
		return 0, false
	}
	return d, ok
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
// client is the downstream conn, nil without one. The client counts as
// heard whenever its bytes go up the leg.
func keepUpstreamAlive(up *strategy.HTTP2StegoConn, client net.Conn, logger *log.Logger) {
	if up == nil {
		return
	}
	live := clientLiveness{conn: client, heard: up.SinceOwnerWrite}
	go up.KeepAlive(relayKeepaliveAfter, live.alive, func() {
		if logger != nil {
			logger.Debug("Relay: keepalive up the upstream leg")
		}
		if f := upstreamKeepaliveSent.Load(); f != nil {
			(*f)()
		}
	})
}
