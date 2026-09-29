package tun

import (
	"fmt"
	"net"
)

// subnetAddr returns the IPv4 address the server-side TUN carries in subnet
// mode: localIP itself with the pool's prefix length, e.g. 10.99.0.1/24 for
// -tun-ip 10.99.0.1 and -ip-pool 10.99.0.0/24.
//
// It must not be built with net.ParseCIDR: its second result is the network
// (10.99.0.0/24), and handing that to AddrAdd puts the network address on the
// link. The connected route comes out the same, so forwarding still works,
// but the server no longer owns its -tun-ip: nothing answers on it, and the
// kernel sources its own packets into the tunnel from the network address.
func subnetAddr(localIP net.IP, network *net.IPNet) (*net.IPNet, error) {
	ip := localIP.To4()
	if ip == nil {
		return nil, fmt.Errorf("TUN IP must be IPv4: %q", localIP)
	}
	if network == nil {
		return nil, fmt.Errorf("no IPv4 network for TUN IP %s", ip)
	}
	ones, bits := network.Mask.Size()
	if bits != 8*net.IPv4len {
		return nil, fmt.Errorf("network %s is not IPv4", network)
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, bits)}, nil
}

// p2pAddrPlan computes the IPv4 addresses for the client-side TUN. The primary
// form is localIP/32 with peer remoteIP/32. The fallback, for kernels that
// reject a peer address, is localIP with a /24 prefix - the host address, not
// the /24 network (see subnetAddr for why the difference matters). fallback
// is nil when localIP is not IPv4; the caller then has no second attempt.
func p2pAddrPlan(localIP, remoteIP net.IP) (local, peer, fallback *net.IPNet) {
	local = &net.IPNet{IP: localIP, Mask: net.CIDRMask(32, 32)}
	peer = &net.IPNet{IP: remoteIP, Mask: net.CIDRMask(32, 32)}
	if l := localIP.To4(); l != nil {
		fallback = &net.IPNet{IP: l, Mask: net.CIDRMask(24, 32)}
	}
	return local, peer, fallback
}
