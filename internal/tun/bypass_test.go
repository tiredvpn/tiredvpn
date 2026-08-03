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

func TestResolveServerBypassIP(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string // empty = expect nil
	}{
		{"ipv4 host:port", "31.44.3.165:995", "31.44.3.165"},
		{"ipv4 no port", "31.44.3.165", "31.44.3.165"},
		{"ipv6 host:port", "[2001:db8::1]:995", "2001:db8::1"},
		{"bogus host no port", "not a host", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveServerBypassIP(c.addr)
			if c.want == "" {
				if got != nil {
					t.Errorf("resolveServerBypassIP(%q) = %v, want nil", c.addr, got)
				}
				return
			}
			if got == nil || !got.Equal(net.ParseIP(c.want)) {
				t.Errorf("resolveServerBypassIP(%q) = %v, want %s", c.addr, got, c.want)
			}
		})
	}
}
