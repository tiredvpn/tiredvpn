package server

import "golang.org/x/sys/unix"

// tcpBytesAcked reads tcpi_bytes_acked off the socket fd: how many bytes
// the peer has acknowledged, the SYN counting one.
func tcpBytesAcked(fd uintptr) (uint64, bool) {
	info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return 0, false
	}
	return info.Bytes_acked, true
}
