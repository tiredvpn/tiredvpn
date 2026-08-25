package server

import (
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// warnIfNoGlobalIPv6Uplink logs a loud warning when dual-stack is configured
// but no interface carries a global (non-ULA, non-link-local) IPv6 address,
// because client v6 traffic would then be masqueraded onto an address that
// cannot reach the internet. It deliberately does NOT fail startup: some
// setups route v6 without a global address on any local interface (tunnel
// brokers, BGP-announced prefixes), and NAT66 failures are already
// warn-and-continue like the v4 NAT path.
func warnIfNoGlobalIPv6Uplink() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Warn("Dual-stack: could not list interfaces to check for a global IPv6 uplink: %v", err)
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if isGlobalIPv6(ip) {
				return
			}
		}
	}
	log.Warn("Dual-stack: no global IPv6 address on any interface - in-tunnel IPv6 will BLACKHOLE for clients unless v6 is routed some other way (e.g. tunnel broker). Set up a v6 uplink or drop -ip-pool-v6.")
}

// isGlobalIPv6 reports whether ip is a globally routable IPv6 address:
// global-unicast but not loopback, link-local (fe80::/10) or ULA (fc00::/7,
// which includes the fd00::/8 pool prefix itself).
func isGlobalIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return false
	}
	// ULA fc00::/7: IsGlobalUnicast reports true for these, but they are not
	// internet-routable, so they don't count as a v6 uplink.
	return ip[0]&0xfe != 0xfc
}
