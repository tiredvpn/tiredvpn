package server

import (
	"time"

	"golang.org/x/sys/unix"
)

// tcpSinceAckReceived reads tcpi_last_ack_recv off the socket fd.
func tcpSinceAckReceived(fd uintptr) (time.Duration, bool) {
	info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return 0, false
	}
	return time.Duration(info.Last_ack_recv) * time.Millisecond, true
}
