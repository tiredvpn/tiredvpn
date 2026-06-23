//go:build linux

package tun

import (
	"net"
	"testing"
)

func TestRoutesHaveDefault(t *testing.T) {
	cases := []struct {
		name   string
		routes []string
		want   bool
	}{
		{"ipv4 default", []string{"0.0.0.0/0"}, true},
		{"ipv6 default", []string{"::/0"}, true},
		{"default among others", []string{"10.0.0.0/8", "0.0.0.0/0", "192.168.0.0/16"}, true},
		{"bare-ip default normalizes", []string{"0.0.0.0/0"}, true},
		{"split tunnel only", []string{"10.8.0.0/24", "1.1.1.1/32"}, false},
		{"empty", nil, false},
		{"single host", []string{"8.8.8.8"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := routesHaveDefault(c.routes); got != c.want {
				t.Errorf("routesHaveDefault(%v) = %v, want %v", c.routes, got, c.want)
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
