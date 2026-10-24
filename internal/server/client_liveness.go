package server

import (
	"net"
	"syscall"
	"time"
)

// clientLiveness says whether a relay's downstream client is still there,
// which is what keeps its upstream leg alive (relayTUNSink's keepalive).
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
