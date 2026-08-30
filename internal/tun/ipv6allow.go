package tun

import (
	"fmt"
	"net"
	"strings"
)

// The -tun-ipv6-allow exception list.
//
// The IPv6 leak block (ipv6block_linux.go) rejects every outbound IPv6 packet
// that is not going through the tunnel. On a plain host that is the whole
// point. On a host that carries IPv6 for a reason of its own it is a
// regression: a node holding a Hurricane Electric 6in4 tunnel (interface he6,
// 2001:db8:77b::2/64) lost its IPv6 outright the moment four tiredvpn
// clients came up on it — none of them had -tun-ipv6 set, the default dual
// policy found exits that could not carry IPv6, and each installed a block
// whose final reject swallowed everything leaving through he6.
//
// The exceptions are the operator's answer to that: name the interface, or the
// prefix, that has to keep working, and it gets an accept rule ahead of the
// reject.

// ipv6AllowMaxIfNameLen is IFNAMSIZ-1: the longest interface name the kernel
// stores. The nftables oifname match is a fixed 16-byte field, so a longer name
// would be silently truncated into a match on something else — rejected at
// parse time instead.
const ipv6AllowMaxIfNameLen = 15

// IPv6AllowList is a parsed -tun-ipv6-allow value: outbound interfaces whose
// IPv6 stays untouched, and destination prefixes that stay reachable whatever
// interface they leave through.
//
// The zero value is an empty list, which is the pre-flag behaviour.
type IPv6AllowList struct {
	// Interfaces are matched on oifname, the same way the tunnel's own accept
	// rule is. This is the form that fits a v6 transport the host owns (he6,
	// a WireGuard link, another VPN): the operator knows the device, not the
	// set of addresses that will travel over it.
	Interfaces []string

	// Prefixes are matched on the destination address. A bare address parses
	// to its /128, so "keep this one peer reachable" needs no mask.
	Prefixes []*net.IPNet
}

// Empty reports whether the list holds nothing, i.e. the block is built exactly
// as it was before the flag existed.
func (a IPv6AllowList) Empty() bool {
	return len(a.Interfaces) == 0 && len(a.Prefixes) == 0
}

// String renders the list the way it was written on the command line, for logs.
func (a IPv6AllowList) String() string {
	parts := make([]string, 0, len(a.Interfaces)+len(a.Prefixes))
	parts = append(parts, a.Interfaces...)
	for _, p := range a.Prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// ParseIPv6AllowList parses a comma-separated -tun-ipv6-allow value. Each entry
// is either an interface name ("he6"), an IPv6 prefix
// ("2001:db8:77b::/64") or a single IPv6 address, which becomes its /128.
// An empty string parses to an empty list.
//
// Telling the two forms apart is not a guess: the kernel's dev_valid_name
// rejects '/' and ':' in an interface name, and every IPv6 literal contains a
// ':'. So an entry with either character is an address and is parsed as one;
// anything else is a device name.
//
// What is an error and what is not follows from when it can be detected:
//
//   - An interface that does not exist is NOT an error. Names come and go — a
//     6in4 tunnel is created by a unit that may start after the client, and
//     nftables stores an oifname match for a device that does not exist yet,
//     matching it once it appears. Refusing to start here would turn a boot
//     ordering detail into a failure.
//   - A malformed prefix IS an error. "2001:db8:77b::/129" or "2001:db8:::/64"
//     cannot become correct later; skipping it silently would leave the
//     operator with a running client, no message, and a hole they believe is
//     open. The same goes for an IPv4 entry: the block is an ip6 table and
//     never sees IPv4, so a v4 exception is a misunderstanding worth stopping
//     for rather than a no-op.
func ParseIPv6AllowList(spec string) (IPv6AllowList, error) {
	var out IPv6AllowList
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.ContainsAny(entry, ":/") {
			netw, err := parseIPv6AllowPrefix(entry)
			if err != nil {
				return IPv6AllowList{}, err
			}
			out.Prefixes = append(out.Prefixes, netw)
			continue
		}
		// A bare IPv4 address has neither ':' nor '/', so the rule above would
		// file it as a device name and the client would start with an
		// exception matching an interface literally called "192.0.2.1". It is
		// a misunderstanding of what the block filters, and it is caught here
		// rather than left to look like it worked.
		if ip := net.ParseIP(entry); ip != nil && ip.To4() != nil {
			return IPv6AllowList{}, fmt.Errorf(
				"tun-ipv6-allow: %q is an IPv4 address; the leak block only filters IPv6, so IPv4 needs no exception", entry)
		}
		if len(entry) > ipv6AllowMaxIfNameLen {
			return IPv6AllowList{}, fmt.Errorf(
				"tun-ipv6-allow: interface name %q is %d characters, the kernel allows at most %d",
				entry, len(entry), ipv6AllowMaxIfNameLen)
		}
		out.Interfaces = append(out.Interfaces, entry)
	}
	return out, nil
}

// parseIPv6AllowPrefix turns one address-shaped entry into the network its
// accept rule matches: a prefix as written (masked, so host bits in
// "2001:db8::1/64" do not narrow the rule), a bare address as its /128.
func parseIPv6AllowPrefix(entry string) (*net.IPNet, error) {
	if strings.Contains(entry, "/") {
		ip, netw, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("tun-ipv6-allow: %q is not a valid IPv6 prefix: %w", entry, err)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf(
				"tun-ipv6-allow: %q is an IPv4 prefix; the leak block only filters IPv6, so IPv4 needs no exception", entry)
		}
		return netw, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("tun-ipv6-allow: %q is neither an interface name nor an IPv6 address", entry)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf(
			"tun-ipv6-allow: %q is an IPv4 address; the leak block only filters IPv6, so IPv4 needs no exception", entry)
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}, nil
}

// coversIP reports whether some prefix in the list contains ip. Used by the
// router warning to tell "this interface loses its IPv6" from "this interface
// is already excepted".
func (a IPv6AllowList) coversIP(ip net.IP) bool {
	for _, p := range a.Prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// hasInterface reports whether name is excepted by device name.
func (a IPv6AllowList) hasInterface(name string) bool {
	for _, iface := range a.Interfaces {
		if iface == name {
			return true
		}
	}
	return false
}
