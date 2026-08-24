package server

import (
	"net"
	"testing"
)

// The uplink guard counts only globally routable v6 addresses: no v4, no
// link-local, no ULA (including the tunnel pool prefix itself).
func TestIsGlobalIPv6(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"2606:4700:4700::1111", true},
		{"2001:db8::1", true}, // documentation prefix is "global" per IsGlobalUnicast; fine for a guard
		{"::1", false},        // loopback is not an uplink
		{"fe80::1", false},    // link-local
		{"fd00:10:8::1", false},
		{"fc00::1", false},
		{"10.8.0.1", false},
		{"192.168.1.1", false},
	}
	for _, c := range cases {
		if got := isGlobalIPv6(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isGlobalIPv6(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if isGlobalIPv6(nil) {
		t.Error("isGlobalIPv6(nil) = true, want false")
	}
}
