package strategy

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// handshakeProgressed reports whether the server's TCP has acknowledged
// data on conn beyond its SYN: the first bytes of the handshake reached it.
// False where it cannot be told.
func handshakeProgressed(conn net.Conn) bool {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var acked uint64
	if cerr := raw.Control(func(fd uintptr) {
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			acked = info.Bytes_acked
		}
	}); cerr != nil {
		return false
	}
	return acked > 1
}
