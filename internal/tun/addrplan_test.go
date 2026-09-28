package tun

import (
	"net"
	"testing"
)

func poolCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// TestSubnetAddrIsTheHostNotTheNetwork pins the server TUN address to -tun-ip.
// Deriving it from net.ParseCIDR's network result put 10.99.0.0/24 on the link
// for -tun-ip 10.99.0.1, and the server stopped answering on its own address.
func TestSubnetAddrIsTheHostNotTheNetwork(t *testing.T) {
	cases := []struct {
		ip, pool, want string
	}{
		{"10.99.0.1", "10.99.0.0/24", "10.99.0.1/24"},
		{"10.99.0.254", "10.99.0.0/24", "10.99.0.254/24"},
		{"198.18.0.1", "198.18.0.0/15", "198.18.0.1/15"},
		{"198.18.3.7", "198.18.0.0/22", "198.18.3.7/22"},
	}
	for _, c := range cases {
		got, err := subnetAddr(net.ParseIP(c.ip), poolCIDR(t, c.pool))
		if err != nil {
			t.Fatalf("subnetAddr(%s, %s): %v", c.ip, c.pool, err)
		}
		if got.String() != c.want {
			t.Errorf("subnetAddr(%s, %s) = %s, want %s", c.ip, c.pool, got, c.want)
		}
		if len(got.IP) != net.IPv4len {
			t.Errorf("subnetAddr(%s, %s) IP is %d bytes, want 4", c.ip, c.pool, len(got.IP))
		}
	}
}

func TestSubnetAddrRejectsBadInput(t *testing.T) {
	v4 := poolCIDR(t, "10.99.0.0/24")
	if _, err := subnetAddr(net.ParseIP("fd00::1"), v4); err == nil {
		t.Error("IPv6 TUN IP accepted")
	}
	if _, err := subnetAddr(nil, v4); err == nil {
		t.Error("nil TUN IP accepted")
	}
	if _, err := subnetAddr(net.ParseIP("10.99.0.1"), nil); err == nil {
		t.Error("nil network accepted")
	}
	if _, err := subnetAddr(net.ParseIP("10.99.0.1"), poolCIDR(t, "fd00::/64")); err == nil {
		t.Error("IPv6 network accepted")
	}
}

// TestP2PAddrPlan covers the client side: the /32 peer pair is unchanged, and
// the fallback carries the client's own address, not the /24 network.
func TestP2PAddrPlan(t *testing.T) {
	local, peer, fallback := p2pAddrPlan(net.ParseIP("10.99.0.7"), net.ParseIP("10.99.0.1"))
	if local.String() != "10.99.0.7/32" || peer.String() != "10.99.0.1/32" {
		t.Errorf("p2p pair = %s peer %s, want 10.99.0.7/32 peer 10.99.0.1/32", local, peer)
	}
	if fallback == nil || fallback.String() != "10.99.0.7/24" {
		t.Errorf("fallback = %v, want 10.99.0.7/24", fallback)
	}
	if _, _, fb := p2pAddrPlan(nil, net.ParseIP("10.99.0.1")); fb != nil {
		t.Errorf("fallback for nil local IP = %s, want nil", fb)
	}
}
