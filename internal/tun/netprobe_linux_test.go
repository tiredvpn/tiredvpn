//go:build linux

package tun

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// netlink represents a default route either as a nil Dst or as an explicit
// zero-length prefix depending on version (v1.3.x fills in 0.0.0.0/0). The
// first version of the filter tested only for nil and dropped every default
// route on v1.3.x, leaving the probe list empty.
func TestRouteIsDefault(t *testing.T) {
	_, v4Default, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6Default, _ := net.ParseCIDR("::/0")
	_, lanPrefix, _ := net.ParseCIDR("192.168.1.0/24")

	cases := []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		{"nil dst", netlink.Route{Dst: nil}, true},
		{"explicit v4 default", netlink.Route{Dst: v4Default}, true},
		{"explicit v6 default", netlink.Route{Dst: v6Default}, true},
		{"lan prefix", netlink.Route{Dst: lanPrefix}, false},
	}
	for _, tc := range cases {
		if got := routeIsDefault(tc.route); got != tc.want {
			t.Errorf("%s: routeIsDefault = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGatewayDialAddr(t *testing.T) {
	cases := []struct {
		name string
		gw   string
		link int
		want string
	}{
		{"ipv4 gateway", "192.168.1.254", 10, "192.168.1.254:53"},
		{"global v6 gateway", "2a00:1370::1", 10, "[2a00:1370::1]:53"},
		{"link-local v6 gets zone", "fe80::1", 10, "[fe80::1%10]:53"},
	}
	for _, tc := range cases {
		got := gatewayDialAddr(net.ParseIP(tc.gw), tc.link)
		if got != tc.want {
			t.Errorf("%s: gatewayDialAddr = %q, want %q", tc.name, got, tc.want)
		}
	}

	// The zone is the interface: same link-local address on two links must
	// render as two distinct dial targets, not dedup into one.
	a := gatewayDialAddr(net.ParseIP("fe80::1"), 2)
	b := gatewayDialAddr(net.ParseIP("fe80::1"), 5)
	if a == b {
		t.Fatalf("link-local gateways on different links must differ: %q == %q", a, b)
	}
}

// On a live table with a default route the probe list must be non-empty and
// well-formed. Skipped where the table has no default (some sandboxes), so it
// cannot flake there.
func TestPhysicalGateAddrsLiveTable(t *testing.T) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		t.Skipf("route list unavailable: %v", err)
	}
	hasDefault := false
	for _, r := range routes {
		if routeIsDefault(r) && r.Gw != nil && r.LinkIndex != 0 {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Skip("no default route with a gateway in the live table")
	}

	addrs := physicalGateAddrs()
	if len(addrs) == 0 {
		t.Fatal("default route with gateway exists but physicalGateAddrs returned nothing")
	}
	for _, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			t.Errorf("malformed dial target %q: %v", addr, err)
		}
	}
}
