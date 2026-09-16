//go:build linux

package tun

import (
	"net"

	"github.com/vishvananda/netlink"
)

// physicalGateAddrs returns dial targets that cannot enter the VPN tunnel: the
// default route's gateway is a link-scoped neighbor on the physical interface,
// so kernel routing never sends packets to it through the TUN device, no matter
// which CIDRs the tunnel installed. internetReachable uses it to tell "the
// physical network is down" from "the tunnel died while its routes are still
// up" - from inside the tunnel the two look identical.
func physicalGateAddrs() []string {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	var out []string
	seen := make(map[string]bool, 2)
	for _, r := range routes {
		// Default routes have no Dst; a gateway and a link index are what make
		// the address dialable over the physical link.
		if r.Dst != nil || r.Gw == nil || r.LinkIndex == 0 {
			continue
		}
		gw := r.Gw.String()
		if gw == "" || seen[gw] {
			continue
		}
		seen[gw] = true
		out = append(out, net.JoinHostPort(gw, "53"))
	}
	return out
}
