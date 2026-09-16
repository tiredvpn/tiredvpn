//go:build linux

package tun

import (
	"net"
	"strconv"

	"github.com/vishvananda/netlink"
)

// routeIsDefault reports whether r is a default route. netlink represents a
// default either as a nil Dst or as an explicit zero-length prefix
// (0.0.0.0/0, ::/0) depending on version and kernel serialization - netlink
// v1.3.x fills in the explicit form - so both must count. Testing Dst for
// nil alone drops every default route and leaves the probe list empty, which
// is how the first version of this helper shipped dead.
func routeIsDefault(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	return ones == 0
}

// gatewayDialAddr renders a default-route gateway as a dial address. A
// link-local IPv6 gateway (the usual v6 default on RA-configured links) has
// no meaning without a scope: without %zone the dial fails with EINVAL
// instead of reaching the neighbor, so the interface index becomes part of
// the address. The zone also keeps gateways of different links distinct in
// the caller's dedup.
func gatewayDialAddr(gw net.IP, linkIndex int) string {
	host := gw.String()
	if gw.IsLinkLocalUnicast() || gw.IsLinkLocalMulticast() {
		host += "%" + strconv.Itoa(linkIndex)
	}
	return net.JoinHostPort(host, "53")
}

// physicalGateAddrs returns dial targets that cannot enter the VPN tunnel: the
// default route's gateway is a link-scoped neighbor on the physical interface,
// so kernel routing never sends packets to it through the TUN device, no matter
// which CIDRs the tunnel installed. internetReachable uses it to tell "the
// physical network is down" from "the tunnel died while its routes are still
// up" - from inside the tunnel the two look identical. Tunnel routes never
// qualify: this client installs them without a gateway.
func physicalGateAddrs() []string {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	var out []string
	seen := make(map[string]bool, 2)
	for _, r := range routes {
		if !routeIsDefault(r) || r.Gw == nil || r.LinkIndex == 0 {
			continue
		}
		addr := gatewayDialAddr(r.Gw, r.LinkIndex)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}
