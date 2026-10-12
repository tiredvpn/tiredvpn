package strategy

import (
	"net"

	"golang.org/x/sys/unix"
)

// icmpRouteMTU returns the MTU the kernel would use towards ip: the route's
// MTU, or the path MTU it has learned from Fragmentation Needed messages.
// A connected UDP socket answers IP_MTU without sending anything. Returns 0
// when the kernel will not say.
func icmpRouteMTU(ip net.IP) int {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 9})
	if err != nil {
		return 0
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	mtu := 0
	if err := raw.Control(func(fd uintptr) {
		v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU)
		if err == nil {
			mtu = v
		}
	}); err != nil {
		return 0
	}
	return mtu
}
