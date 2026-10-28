//go:build linux

package tun

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

// physicalGateAddrs returns dial targets that cannot enter the VPN tunnel: the
// default route's gateway is a link-scoped neighbor on the physical interface,
// so kernel routing never sends packets to it through the TUN device, no matter
// which CIDRs the tunnel installed. internetReachable uses it to tell "the
// physical network is down" from "the tunnel died while its routes are still
// up" - from inside the tunnel the two look identical. Tunnel routes never
// qualify: this client installs them without a gateway.
func physicalGateAddrs() []string {
	if out := gatewaysOfRoutes(listRoutes(unix.RT_TABLE_MAIN)); len(out) > 0 {
		return out
	}
	// Android keeps a network's default route in that network's own table,
	// not in main, so main alone found nothing there and no endpoint was ever
	// charged on a phone. Every table, then, when main has no default.
	return gatewaysOfRoutes(listRoutes(unix.RT_TABLE_UNSPEC))
}

// listRoutes lists the routes of one table, or of every table for
// RT_TABLE_UNSPEC. Replaceable in tests.
var listRoutes = func(table int) ([]netlink.Route, error) {
	if table == unix.RT_TABLE_MAIN {
		return netlink.RouteList(nil, netlink.FAMILY_ALL)
	}
	return netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
}

func gatewaysOfRoutes(routes []netlink.Route, err error) []string {
	if err != nil {
		return nil
	}
	rib := make([]ribRoute, 0, len(routes))
	for _, r := range routes {
		if routeIsDefault(r) {
			rib = append(rib, ribRoute{gw: r.Gw, link: r.LinkIndex})
		}
	}
	return defaultGatewayAddrs(rib)
}
