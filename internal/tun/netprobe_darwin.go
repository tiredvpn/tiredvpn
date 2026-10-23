//go:build darwin

package tun

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// physicalGateAddrs returns the gateways of the host's default routes, read
// from the routing socket. The tunnel claims the address space with two
// half-default routes on the utun and leaves the real default in place, so
// the default route's gateway is still the router on the physical link: an
// on-link neighbour the tunnel's routes never capture.
func physicalGateAddrs() []string {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	var routes []ribRoute
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_UP == 0 || rm.Flags&syscall.RTF_GATEWAY == 0 {
			continue
		}
		if r, ok := darwinDefaultRoute(rm.Addrs, rm.Index, rm.Flags&syscall.RTF_IFSCOPE != 0); ok {
			routes = append(routes, r)
		}
	}
	return defaultGatewayAddrs(routes)
}

// darwinDefaultRoute reads a routing message's addresses, indexed by RTAX_*,
// as a default route (see bsdDefaultRoute).
func darwinDefaultRoute(addrs []route.Addr, index int, ifscope bool) (ribRoute, bool) {
	at := func(i int) *ribAddr {
		if i >= len(addrs) {
			return nil
		}
		switch a := addrs[i].(type) {
		case *route.Inet4Addr:
			return &ribAddr{ip: net.IP(a.IP[:])}
		case *route.Inet6Addr:
			return &ribAddr{ip: net.IP(a.IP[:]), zone: a.ZoneID}
		}
		return nil
	}
	return bsdDefaultRoute(at(syscall.RTAX_DST), at(syscall.RTAX_NETMASK), at(syscall.RTAX_GATEWAY), index, ifscope)
}
