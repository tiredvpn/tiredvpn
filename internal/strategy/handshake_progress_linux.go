package strategy

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// handshakeProgressed reports whether the handshake on conn has got through
// to the server: past the SYN, the server's TCP has acknowledged data and
// either the server has answered or everything written so far is
// acknowledged. False where it cannot be told.
//
// Any acknowledged byte was not enough. A transport that opens with a decoy
// - Seqovl - had the decoy acknowledged while a censor dropped the
// ClientHello behind it, so it was held past its share for the whole cycle,
// every cycle, and Geneva came up three cycles later than before (the
// fix17 stand, r9-rx_hs_ab: 24 s to 76 s). Nor is "nothing in flight right
// now" alone: HTTP/2 Stego writes its preface, settings and auth after the
// server has answered TLS and waits for the ack, and for a round trip its
// writes are in flight - a share that ran out then cut a live attempt
// (P2 of the round-14 review). A server that has answered has let the
// flight through. A slow but live server still acknowledges the whole
// first flight at once (P2-4 of the round-10 review).
func handshakeProgressed(conn net.Conn) bool {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var info *unix.TCPInfo
	if cerr := raw.Control(func(fd uintptr) {
		info, _ = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); cerr != nil || info == nil {
		return false
	}
	return flightThrough(info)
}

// flightThrough: data past the SYN is acknowledged, and the server has
// answered or nothing is left in flight or unsent. The acknowledged data is
// asked for with an answer too: a server that speaks first answers a client
// that sent nothing.
func flightThrough(info *unix.TCPInfo) bool {
	if info.Bytes_acked <= 1 {
		return false
	}
	return info.Bytes_received > 0 || (info.Unacked == 0 && info.Notsent_bytes == 0)
}
