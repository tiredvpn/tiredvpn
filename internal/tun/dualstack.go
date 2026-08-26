package tun

import (
	"fmt"
	"net"
)

// dualStackRouteCIDRs are the two IPv6 half-default routes installed into the
// tunnel when dual-stack is negotiated. Together they cover all of IPv6
// except ::/128 and outrank any RA-learned ::/0 on prefix length, while
// leaving the host's real default route (and the RA machinery that maintains
// it) untouched. This mirrors the 0.0.0.0/1 + 128.0.0.0/1 split-default
// trick used on the IPv4 side.
var dualStackRouteCIDRs = []string{"::/1", "8000::/1"}

// v6HalfDefaultMetricBase is the metric floor for the half-default routes in
// dualStackRouteCIDRs.
//
// Why 100 rather than the kernel's default 1024: another VPN on the same host
// installs its own ::/1 with the kernel default, and ours has to win that
// comparison or the full tunnel silently stops being full. Against the
// RA-learned ::/0 the metric never comes into it — a /1 beats a /0 on prefix
// length alone — so the choice of base does not affect that relationship in
// either direction.
const v6HalfDefaultMetricBase = 100

// v6HalfDefaultPriority is the metric for a half-default route on the tunnel
// with index linkIndex.
//
// The link index is the summand because it is unique across the interfaces
// alive at any one moment: two tunnels on the same host therefore get two
// distinct (dst, metric) pairs, which the kernel keeps as two separate routing
// entries instead of collapsing them into one that the second RouteReplace
// would steal from the first. It is also stable for the lifetime of an
// interface, so RouteReplace on a reconnect still updates our own entry rather
// than accumulating a new one per reconnect.
//
// The consequence is that the tunnel brought up first has the lower index,
// hence the lower metric, hence the default: a deliberate choice in favour of
// the primary tunnel over a test client started later.
func v6HalfDefaultPriority(linkIndex int) int {
	if linkIndex < 0 {
		// Not a real index; keep the metric at the base rather than letting it
		// slide below it.
		linkIndex = 0
	}
	return v6HalfDefaultMetricBase + linkIndex
}

// dualStackRouteNets parses dualStackRouteCIDRs. The constants are known-good,
// so a parse failure is a programmer error and reported as such.
func dualStackRouteNets() ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(dualStackRouteCIDRs))
	for _, cidr := range dualStackRouteCIDRs {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid dual-stack route %q: %w", cidr, err)
		}
		nets = append(nets, dst)
	}
	return nets, nil
}

// dualStackAddrPlan computes the IPv6 addresses to install on the TUN link
// for a negotiated dual-stack session. The primary form mirrors the IPv4
// point-to-point setup: clientIP6/128 with peer serverIP6/128. The fallback
// (for kernels that reject a v6 peer address) is clientIP6 with the /64 pool
// prefix, which is what the exit assigns from in practice. Both are derived
// purely from the handshake-provided addresses; an input that is not a real
// IPv6 address is an error.
func dualStackAddrPlan(clientIP6, serverIP6 net.IP) (p2pLocal, p2pPeer, fallback *net.IPNet, err error) {
	c := clientIP6.To16()
	s := serverIP6.To16()
	if c == nil || clientIP6.To4() != nil {
		return nil, nil, nil, fmt.Errorf("invalid client IPv6 address %q", clientIP6)
	}
	if s == nil || serverIP6.To4() != nil {
		return nil, nil, nil, fmt.Errorf("invalid server IPv6 address %q", serverIP6)
	}
	p2pLocal = &net.IPNet{IP: c, Mask: net.CIDRMask(128, 128)}
	p2pPeer = &net.IPNet{IP: s, Mask: net.CIDRMask(128, 128)}
	fallback = &net.IPNet{IP: c, Mask: net.CIDRMask(64, 128)}
	return p2pLocal, p2pPeer, fallback, nil
}

// deriveClientIP6 recomputes the client's tunnel IPv6 address after the exit
// assigned a new IPv4 address. The exit assigns client v6 as
// pool-prefix | client-v4-uint32, so the new v6 keeps the old address's first
// 12 bytes and takes the new v4 address as its last 4. Returns nil when the
// inputs are not a valid (v6, v4) pair.
func deriveClientIP6(oldClientIP6, newLocalV4 net.IP) net.IP {
	base := oldClientIP6.To16()
	v4 := newLocalV4.To4()
	if base == nil || oldClientIP6.To4() != nil || v4 == nil {
		return nil
	}
	out := make(net.IP, net.IPv6len)
	copy(out, base)
	copy(out[12:16], v4)
	return out
}
