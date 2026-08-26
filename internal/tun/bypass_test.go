//go:build linux

package tun

import (
	"net"
	"testing"
)

func TestRoutesCoverIP(t *testing.T) {
	server := net.ParseIP("31.44.3.165")
	cases := []struct {
		name   string
		routes []string
		ip     net.IP
		want   bool
	}{
		{"ipv4 default", []string{"0.0.0.0/0"}, server, true},
		{"default among others", []string{"10.0.0.0/8", "0.0.0.0/0", "192.168.0.0/16"}, server, true},
		// The half-default pair is how a full tunnel is expressed in practice; it
		// used to slip past the old literal 0.0.0.0/0 check and leave the bypass
		// unpinned, which wedged the client after any link flap.
		{"half defaults", []string{"0.0.0.0/1", "128.0.0.0/1"}, server, true},
		{"half default covering server", []string{"0.0.0.0/1"}, server, true},
		{"half default not covering server", []string{"128.0.0.0/1"}, server, false},
		{"ipv6 default vs ipv6 server", []string{"::/0"}, net.ParseIP("2001:db8::1"), true},
		{"ipv6 default vs ipv4 server", []string{"::/0"}, server, false},
		{"split tunnel only", []string{"10.8.0.0/24", "1.1.1.1/32"}, server, false},
		{"split tunnel hitting server", []string{"31.44.0.0/16"}, server, true},
		{"bare ip route", []string{"31.44.3.165"}, server, true},
		{"empty", nil, server, false},
		{"nil ip", []string{"0.0.0.0/0"}, nil, false},
		{"garbage route", []string{"not-a-route"}, server, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := routesCoverIP(c.routes, c.ip); got != c.want {
				t.Errorf("routesCoverIP(%v, %v) = %v, want %v", c.routes, c.ip, got, c.want)
			}
		})
	}
}

// TestResolveBypassIPs covers the address forms a -server flag can carry.
// Getting this wrong at either end is costly: a false positive pins a host
// route to the wrong address, a false negative drops the client's own
// transport socket into its own tunnel the moment a full-tunnel route lands.
func TestResolveBypassIPs(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string // empty = expect nothing
	}{
		{"ipv4 host:port", "31.44.3.165:995", "31.44.3.165"},
		{"ipv4 no port", "31.44.3.165", "31.44.3.165"},
		{"ipv6 host:port", "[2001:db8::1]:995", "2001:db8::1"},
		{"bare v6 literal", "2001:db8::1", "2001:db8::1"},
		// A v4-mapped literal is an IPv4 address wearing v6 syntax. It resolves
		// to the v4 form, which is what a route can actually be pinned for;
		// serverIP6s drops it so the v6 leak block never punches a hole for an
		// address the kernel has no v6 route to.
		{"v4-mapped literal", "::ffff:1.2.3.4", "1.2.3.4"},
		// ParseIP rejects a zone, but LookupIP accepts a zoned literal and
		// hands back a net.IP, which has nowhere to keep the zone. Pinned as
		// current behaviour, not as desirable: an fe80:: route without an
		// interface is ambiguous on a multi-homed host.
		{"link-local with zone", "[fe80::1%eth0]:995", "fe80::1"},
		{"bogus host no port", "not a host", ""},
		{"empty", "", ""},
		{"bracket without close", "[2001:db8::1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveBypassIPs(c.addr)
			if c.want == "" {
				if len(got) != 0 {
					t.Errorf("resolveBypassIPs(%q) = %v, want none", c.addr, got)
				}
				return
			}
			if len(got) == 0 || !got[0].Equal(net.ParseIP(c.want)) {
				t.Errorf("resolveBypassIPs(%q) = %v, want %s", c.addr, got, c.want)
			}
		})
	}
}

// TestServerBypassIPsCoversEveryAddress pins the property the whole multi-server
// bypass rests on: every configured transport address gets a route, not just
// the preferred one. Miss an address and a dial to that server, once a full
// tunnel is up, goes into the tunnel it is meant to carry and dies there.
func TestServerBypassIPsCoversEveryAddress(t *testing.T) {
	cfg := VPNConfig{
		ServerAddr:   "1.2.3.4:995",
		ServerAddrV6: "[2001:db8::2]:995",
		ServerAddrs: []string{
			"1.2.3.4:995",       // duplicate of ServerAddr: must not repeat
			"[2001:db8::9]:995", // second endpoint, v6
			"5.6.7.8:443",       // second endpoint, v4
		},
	}
	got := serverBypassIPs(cfg)

	for _, want := range []string{"1.2.3.4", "2001:db8::2", "2001:db8::9", "5.6.7.8"} {
		if !containsIP(got, net.ParseIP(want)) {
			t.Errorf("bypass set %v is missing %s", got, want)
		}
	}
	if len(got) != 4 {
		t.Errorf("bypass set = %v (%d entries), want 4 deduplicated", got, len(got))
	}
}

// TestServerIP6sSkipsV4Mapped keeps the v6 leak block from punching a hole for
// an address the kernel has no IPv6 route to.
func TestServerIP6sSkipsV4Mapped(t *testing.T) {
	cfg := VPNConfig{
		ServerAddr:   "[::ffff:1.2.3.4]:997",
		ServerAddrV6: "[2001:db8::2]:995",
	}
	got := serverIP6s(cfg)
	if len(got) != 1 || !got[0].Equal(net.ParseIP("2001:db8::2")) {
		t.Errorf("serverIP6s = %v, want just 2001:db8::2", got)
	}
}
