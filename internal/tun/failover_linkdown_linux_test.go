package tun

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestLinkdownRouteIsNoPath is the root of D7 in the 2026-10-21 stand report.
// The link lost carrier; the kernel dropped the IPv4 routes and kept the IPv6
// ones, flagged linkdown. The physical-route lookup took them, the IPv6 family
// stayed "reachable", and the endpoint probe ran into the dead link and
// charged a live server for it.
func TestLinkdownRouteIsNoPath(t *testing.T) {
	ip := net.ParseIP("fd42:f0f0::11")
	_, onlink, _ := net.ParseCIDR("fd42:f0f0::/64")
	_, host, _ := net.ParseCIDR("fd42:f0f0::11/128")
	const tunIdx = 9

	down := []netlink.Route{
		{LinkIndex: 2, Dst: host, Flags: unix.RTNH_F_LINKDOWN},
		{LinkIndex: 2, Dst: onlink, Flags: unix.RTNH_F_LINKDOWN},
		{LinkIndex: tunIdx, Dst: onlink},
	}
	if r := bestPhysicalRoute(down, ip, tunIdx); r != nil {
		t.Fatalf("picked %v: a linkdown route counted as a path off the tunnel", r)
	}

	up := []netlink.Route{
		{LinkIndex: 2, Dst: host, Flags: unix.RTNH_F_LINKDOWN},
		{LinkIndex: 3, Dst: onlink},
	}
	if r := bestPhysicalRoute(up, ip, tunIdx); r == nil || r.LinkIndex != 3 {
		t.Fatalf("picked %v, want the live /64 on link 3 over the dead /128", r)
	}
}
