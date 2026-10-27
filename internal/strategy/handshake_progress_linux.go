package strategy

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// handshakeProgressed reports whether the handshake's first flight on conn
// has got through to the server: its TCP has acknowledged everything
// written so far, past the SYN. False where it cannot be told.
//
// Any acknowledged byte was not enough. A transport that opens with a decoy
// - Seqovl - had the decoy acknowledged while a censor dropped the
// ClientHello behind it, so it was held past its share for the whole cycle,
// every cycle, and Geneva came up three cycles later than before (the
// fix17 stand, r9-rx_hs_ab: 24 s to 76 s). A slow but live server still
// acknowledges the whole first flight at once (P2-4 of the round-10
// review).
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

// flightThrough: data past the SYN is acknowledged, and nothing is left in
// flight or unsent.
func flightThrough(info *unix.TCPInfo) bool {
	return info.Bytes_acked > 1 && info.Unacked == 0 && info.Notsent_bytes == 0
}
