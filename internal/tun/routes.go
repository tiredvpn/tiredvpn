package tun

import (
	"fmt"
	"net"
)

// normalizeRoute parses a route string and returns it in canonical CIDR form.
//
// It accepts both real CIDRs ("10.0.0.0/24", "2001:db8::/32") and bare IP
// addresses without a prefix. A bare IPv4 address is normalized to "/32" and a
// bare IPv6 address to "/128", matching the kernel's treatment of host routes.
//
// This is required because callers add routes via netlink, which needs an
// *net.IPNet; net.ParseCIDR rejects bare IPs ("invalid CIDR address"). The
// previous behaviour silently dropped such routes, so traffic to single-host
// destinations passed outside the tunnel.
func normalizeRoute(s string) (string, error) {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return s, nil
	}

	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return s + "/32", nil
		}
		return s + "/128", nil
	}

	return "", fmt.Errorf("invalid route %q: not a CIDR or IP address", s)
}
