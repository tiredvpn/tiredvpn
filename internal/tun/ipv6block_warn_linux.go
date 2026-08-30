//go:build linux
// +build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
)

// Operator warnings for the IPv6 leak block.
//
// The block is one chain, hooked at ip6 OUTPUT. That hook only sees packets
// this host originates: netfilter sends an incoming packet to input or forward
// after the routing decision, and never to output. So on a router the block
// does NOT touch the IPv6 it forwards for its LAN — the traffic that stops is
// the router's own. That distinction is the whole reason these warnings exist
// as text rather than as a copy of "forwarding is on, transit will break",
// which would have been false.
//
// What did break in the field was a node holding a Hurricane Electric 6in4
// tunnel: locally originated packets routed out he6 hit the output hook, fell
// through every accept, and were rejected. Nothing was being forwarded at the
// time.

// ipv6ForwardingSysctl is the switch the operator asked to be warned about.
const ipv6ForwardingSysctl = "/proc/sys/net/ipv6/conf/all/forwarding"

// v6TunnelKinds are netlink link kinds that carry IPv6 somewhere on purpose.
// An interface of one of these kinds with a global address is infrastructure
// somebody configured — a 6in4/6rd tunnel, a GRE link, a WireGuard peering —
// as opposed to eth0/wlan0, whose global IPv6 is exactly the leak the block is
// there to stop and needs no warning.
var v6TunnelKinds = map[string]bool{
	"sit":       true, // 6in4, what Hurricane Electric hands out
	"ip6tnl":    true,
	"ipip":      true,
	"gre":       true,
	"gretap":    true,
	"ip6gre":    true,
	"vti":       true,
	"vti6":      true,
	"wireguard": true,
	"tun":       true, // another VPN's TUN device
	"ppp":       true,
}

// hostV6Iface is one interface as the warning sees it: its name, its netlink
// kind and the global IPv6 addresses it holds.
type hostV6Iface struct {
	Name   string
	Kind   string
	Global []net.IP
}

// hostV6State is the snapshot the warnings are computed from. Split from the
// netlink/procfs reads so the message text can be tested without a router.
type hostV6State struct {
	Forwarding bool
	Ifaces     []hostV6Iface
}

// ipv6BlockWarnings returns what the operator should be told before the block
// goes in, given the tunnel's name, the exceptions in force and the host's
// state. Empty when there is nothing to say.
//
// Two messages, in this order:
//
//  1. A v6 tunnel interface that keeps global addresses and is not excepted.
//     This is the ruhop case: the interface will stay up, its addresses will
//     stay assigned, and every packet the host sends over it will be rejected.
//  2. IPv6 forwarding is on. Said only to place the first message correctly:
//     a router keeps routing, so the operator does not go looking for a
//     transit outage that is not there, and looks at the host's own traffic
//     instead.
func ipv6BlockWarnings(tunName string, extra IPv6AllowList, st hostV6State) []string {
	var cut []hostV6Iface
	for _, iface := range st.Ifaces {
		if iface.Name == loopbackIfName || iface.Name == tunName || len(iface.Global) == 0 {
			continue
		}
		if !v6TunnelKinds[iface.Kind] || extra.hasInterface(iface.Name) {
			continue
		}
		if allCovered(iface.Global, extra) {
			continue
		}
		cut = append(cut, iface)
	}

	var out []string
	if len(cut) > 0 {
		parts := make([]string, 0, len(cut))
		names := make([]string, 0, len(cut))
		for _, iface := range cut {
			parts = append(parts, fmt.Sprintf("%s (%s, %s)", iface.Name, iface.Kind, iface.Global[0]))
			names = append(names, iface.Name)
		}
		out = append(out, fmt.Sprintf(
			"IPv6 leak block: %s carries global IPv6 and is not excepted, so IPv6 this host sends over it "+
				"will be rejected while the tunnel is up — the interface stays up and keeps its addresses, "+
				"which is what makes this look like a routing fault rather than a firewall one. "+
				"Keep it working with -tun-ipv6-allow=%s (or -tun-ipv6=off to drop the block entirely).",
			strings.Join(parts, ", "), strings.Join(names, ",")))
	}
	if st.Forwarding {
		out = append(out, fmt.Sprintf(
			"IPv6 leak block: %s=1, this host routes IPv6 for others. The block is hooked at ip6 output, "+
				"which only sees locally originated packets, so IPv6 this host FORWARDS is not affected — "+
				"what stops is the host's own outbound IPv6 (DNS, updates, tunnel and monitoring traffic). "+
				"Except what has to keep working with -tun-ipv6-allow.",
			ipv6ForwardingSysctl))
	}
	return out
}

// allCovered reports whether every address is already inside an excepted
// prefix, i.e. the interface is spared without being named.
func allCovered(addrs []net.IP, extra IPv6AllowList) bool {
	for _, ip := range addrs {
		if !extra.coversIP(ip) {
			return false
		}
	}
	return true
}

// readHostV6State collects the facts the warnings need. Every failure degrades
// to "nothing to report": a warning that cannot be computed must not stop a
// block the user asked for, and must not turn into a message about the client's
// own troubles reading procfs.
func readHostV6State() hostV6State {
	st := hostV6State{Forwarding: ipv6ForwardingEnabled()}
	links, err := netlink.LinkList()
	if err != nil {
		return st
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			continue
		}
		iface := hostV6Iface{Name: attrs.Name, Kind: link.Type()}
		for _, a := range addrs {
			// Global unicast minus ULA: a public address is the one whose loss
			// is visible outside the host.
			if a.IP == nil || !a.IP.IsGlobalUnicast() || a.IP.IsPrivate() {
				continue
			}
			iface.Global = append(iface.Global, a.IP)
		}
		if len(iface.Global) > 0 {
			st.Ifaces = append(st.Ifaces, iface)
		}
	}
	return st
}

// ipv6ForwardingEnabled reads net.ipv6.conf.all.forwarding. An unreadable
// sysctl reads as "off": the warning it drives is advisory, and inventing one
// from a read error would be noise.
func ipv6ForwardingEnabled() bool {
	b, err := os.ReadFile(ipv6ForwardingSysctl)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}
