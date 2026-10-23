package tun

import (
	"net"
	"strconv"
)

// ribRoute is a default route of the host's routing table, as much of it as
// the gateway probe needs: the next hop and the interface it is reached on.
type ribRoute struct {
	gw   net.IP
	link int
}

// defaultGatewayAddrs renders the gateways of default routes as dial targets,
// once each. Routes without a gateway - tunnel routes, which this client
// installs without one, and point-to-point links - do not qualify.
func defaultGatewayAddrs(routes []ribRoute) []string {
	var out []string
	seen := make(map[string]bool, 2)
	for _, r := range routes {
		if r.gw == nil || r.gw.IsUnspecified() || r.link == 0 {
			continue
		}
		addr := gatewayDialAddr(r.gw, r.link)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
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

// ribAddr is one address slot of a BSD routing message; nil when the slot is
// absent or not an IP address (a link-layer gateway, say).
type ribAddr struct {
	ip   net.IP
	zone int
}

// bsdDefaultRoute reads one BSD routing message as a default route: an
// all-zero destination with an all-zero or absent netmask, and an IP
// gateway, reached on interface index unless the gateway carries its own
// zone. The tunnel's 0/1 and 128/1 carry a one-bit netmask and are not
// defaults; a gateway that is a link-layer address is not an IP to dial.
//
// An interface-scoped default (RTF_IFSCOPE on macOS) is not the host's
// default: macOS keeps one per interface, including "default fe80::%utunN"
// on the tunnel's own utun, and dialling those only adds silent addresses
// to the link check.
func bsdDefaultRoute(dst, mask, gw *ribAddr, index int, ifscope bool) (ribRoute, bool) {
	if ifscope || dst == nil || !dst.ip.IsUnspecified() {
		return ribRoute{}, false
	}
	if mask != nil && !mask.ip.IsUnspecified() {
		return ribRoute{}, false
	}
	if gw == nil {
		return ribRoute{}, false
	}
	link := index
	if gw.zone != 0 {
		link = gw.zone
	}
	return ribRoute{gw: gw.ip, link: link}, true
}
