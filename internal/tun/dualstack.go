package tun

import (
	"fmt"
	"net"
	"strings"
)

// dualStackRouteCIDRs are the two IPv6 half-default routes installed into the
// tunnel when dual-stack is negotiated. Together they cover all of IPv6
// except ::/128 and outrank any RA-learned ::/0 on prefix length, while
// leaving the host's real default route (and the RA machinery that maintains
// it) untouched. This mirrors the 0.0.0.0/1 + 128.0.0.0/1 split-default
// trick used on the IPv4 side.
var dualStackRouteCIDRs = []string{"::/1", "8000::/1"}

// v6HalfDefaultMetricBase is the metric floor for the half-default routes in
// dualStackRouteCIDRs.
//
// Why 100 rather than the kernel's default 1024: another VPN on the same host
// installs its own ::/1 with the kernel default, and ours has to win that
// comparison or the full tunnel silently stops being full. Against the
// RA-learned ::/0 the metric never comes into it — a /1 beats a /0 on prefix
// length alone — so the choice of base does not affect that relationship in
// either direction.
const v6HalfDefaultMetricBase = 100

// v6HalfDefaultPriority is the metric for a half-default route on the tunnel
// with index linkIndex.
//
// The link index is the summand because it is unique across the interfaces
// alive at any one moment: two tunnels on the same host therefore get two
// distinct (dst, metric) pairs, which the kernel keeps as two separate routing
// entries instead of collapsing them into one that the second RouteReplace
// would steal from the first. It is also stable for the lifetime of an
// interface, so RouteReplace on a reconnect still updates our own entry rather
// than accumulating a new one per reconnect.
//
// The consequence is that the tunnel brought up first has the lower index,
// hence the lower metric, hence the default: a deliberate choice in favour of
// the primary tunnel over a test client started later.
func v6HalfDefaultPriority(linkIndex int) int {
	if linkIndex < 0 {
		// Not a real index; keep the metric at the base rather than letting it
		// slide below it.
		linkIndex = 0
	}
	return v6HalfDefaultMetricBase + linkIndex
}

// ipv6RoutesNoneValue is the -tun-routes6 value for "the tunnel claims no IPv6
// destination at all". It exists because the empty string already means
// something else — the flag was not given, i.e. the half-defaults — and on the
// IPv6 side those two cannot be collapsed the way they are on the IPv4 side,
// where an absent -tun-routes installs nothing.
const ipv6RoutesNoneValue = "none"

// IPv6RouteSpec is the parsed -tun-routes6 value: which IPv6 destinations the
// tunnel claims once dual-stack is negotiated.
//
// This is the IPv6 counterpart of -tun-routes, and it exists because the two
// families disagreed about who owns the main routing table. An absent
// -tun-routes installs no IPv4 route at all, which is what lets an operator put
// the tunnel's default into a table of their own (ip rule / ip route ... table
// X) and keep the host's own routing in main. Dual-stack IPv6 had no such
// lever: it wrote ::/1 + 8000::/1 into main unconditionally, and since a /1
// beats a /0 on prefix length — metrics never enter that comparison — it took
// over the host's own IPv6 default as well.
//
// That is fine, and wanted, on a laptop: it is issue #55, where a v4-only
// tunnel is bypassed by every application with a working v6 default. It is
// wrong on a node that carries IPv6 for a reason of its own (a 6in4 tunnel, a
// second VPN, a router's uplink), which loses that IPv6 outright.
//
// The zero value is "not given" and resolves to the half-defaults, so the
// default behaviour is unchanged.
type IPv6RouteSpec struct {
	// set records that the operator named a value at all. "No list" and "an
	// empty list" mean opposite things here — the half-defaults versus nothing
	// — so they must stay distinguishable, and a nil slice cannot carry that.
	set bool
	// nets are the destinations to install. Empty with set means the operator
	// took over IPv6 routing entirely.
	nets []*net.IPNet
	// raw is the value as written, for logs and for String.
	raw string
}

// OperatorManaged reports whether the operator named the tunnel's IPv6
// destinations themselves, rather than leaving the half-defaults in place.
//
// Beyond route installation this also decides the leak block: rejecting every
// outbound IPv6 packet is the right fallback only while the tunnel is claiming
// all of IPv6, which is exactly what the half-defaults do and exactly what an
// operator-supplied list does not. On a node that routes IPv6 itself, a blanket
// block does not prevent a leak — there is nothing meant to be inside the
// tunnel to leak out of — it just kills the host's own IPv6.
func (s IPv6RouteSpec) OperatorManaged() bool { return s.set }

// String renders the spec the way it was written, for logs.
func (s IPv6RouteSpec) String() string {
	if !s.set {
		return strings.Join(dualStackRouteCIDRs, ",")
	}
	if len(s.nets) == 0 {
		return ipv6RoutesNoneValue
	}
	return s.raw
}

// Nets resolves the destinations to install into the tunnel. Without a spec
// that is the pair of half-defaults; with one it is exactly what the operator
// asked for, down to the empty set.
func (s IPv6RouteSpec) Nets() ([]*net.IPNet, error) {
	if !s.set {
		return dualStackRouteNets()
	}
	out := make([]*net.IPNet, len(s.nets))
	copy(out, s.nets)
	return out, nil
}

// CIDRs resolves the destinations as strings, for the platforms that hand
// routes to a command line rather than to netlink.
func (s IPv6RouteSpec) CIDRs() ([]string, error) {
	nets, err := s.Nets()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out, nil
}

// ParseIPv6Routes parses a -tun-routes6 value. An empty string is "not given"
// and keeps the half-defaults. The literal "none" claims no destination at all,
// leaving the host's IPv6 routing untouched while the tunnel still carries a v6
// address for the operator to route into from their own tables. Anything else
// is a comma-separated list of IPv6 prefixes, or bare addresses standing for
// their /128.
//
// A malformed or IPv4 entry is an error rather than a skipped line: it cannot
// become correct later, and a client that started anyway would leave the
// operator with routing they believe is in place and is not.
func ParseIPv6Routes(spec string) (IPv6RouteSpec, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return IPv6RouteSpec{}, nil
	}
	if trimmed == ipv6RoutesNoneValue {
		return IPv6RouteSpec{set: true, raw: trimmed}, nil
	}
	out := IPv6RouteSpec{set: true, raw: trimmed}
	for _, raw := range strings.Split(trimmed, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		netw, err := parseIPv6RouteEntry(entry)
		if err != nil {
			return IPv6RouteSpec{}, err
		}
		out.nets = append(out.nets, netw)
	}
	if len(out.nets) == 0 {
		// Reachable only from a value that is all separators (",", " , ").
		// Silently treating it as "none" would hand the operator a kill of
		// their IPv6 routing from what is plainly a typo.
		return IPv6RouteSpec{}, fmt.Errorf(
			"tun-routes6: %q lists no prefix; use %q to claim no IPv6 destination", spec, ipv6RoutesNoneValue)
	}
	return out, nil
}

// parseIPv6RouteEntry turns one entry into the destination it installs: a
// prefix as written (masked, so host bits do not narrow it), a bare address as
// its /128.
func parseIPv6RouteEntry(entry string) (*net.IPNet, error) {
	if strings.Contains(entry, "/") {
		ip, netw, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("tun-routes6: %q is not a valid IPv6 prefix: %w", entry, err)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf(
				"tun-routes6: %q is an IPv4 prefix; IPv4 routes belong to -tun-routes", entry)
		}
		return netw, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("tun-routes6: %q is not a valid IPv6 prefix or address", entry)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf(
			"tun-routes6: %q is an IPv4 address; IPv4 routes belong to -tun-routes", entry)
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}, nil
}

// dualStackRouteNets parses dualStackRouteCIDRs. The constants are known-good,
// so a parse failure is a programmer error and reported as such.
func dualStackRouteNets() ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(dualStackRouteCIDRs))
	for _, cidr := range dualStackRouteCIDRs {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid dual-stack route %q: %w", cidr, err)
		}
		nets = append(nets, dst)
	}
	return nets, nil
}

// dualStackAddrPlan computes the IPv6 addresses to install on the TUN link
// for a negotiated dual-stack session. The primary form mirrors the IPv4
// point-to-point setup: clientIP6/128 with peer serverIP6/128. The fallback
// (for kernels that reject a v6 peer address) is clientIP6 with the /64 pool
// prefix, which is what the exit assigns from in practice. Both are derived
// purely from the handshake-provided addresses; an input that is not a real
// IPv6 address is an error.
func dualStackAddrPlan(clientIP6, serverIP6 net.IP) (p2pLocal, p2pPeer, fallback *net.IPNet, err error) {
	c := clientIP6.To16()
	s := serverIP6.To16()
	if c == nil || clientIP6.To4() != nil {
		return nil, nil, nil, fmt.Errorf("invalid client IPv6 address %q", clientIP6)
	}
	if s == nil || serverIP6.To4() != nil {
		return nil, nil, nil, fmt.Errorf("invalid server IPv6 address %q", serverIP6)
	}
	p2pLocal = &net.IPNet{IP: c, Mask: net.CIDRMask(128, 128)}
	p2pPeer = &net.IPNet{IP: s, Mask: net.CIDRMask(128, 128)}
	fallback = &net.IPNet{IP: c, Mask: net.CIDRMask(64, 128)}
	return p2pLocal, p2pPeer, fallback, nil
}

// deriveClientIP6 recomputes the client's tunnel IPv6 address after the exit
// assigned a new IPv4 address. The exit assigns client v6 as
// pool-prefix | client-v4-uint32, so the new v6 keeps the old address's first
// 12 bytes and takes the new v4 address as its last 4. Returns nil when the
// inputs are not a valid (v6, v4) pair.
func deriveClientIP6(oldClientIP6, newLocalV4 net.IP) net.IP {
	base := oldClientIP6.To16()
	v4 := newLocalV4.To4()
	if base == nil || oldClientIP6.To4() != nil || v4 == nil {
		return nil
	}
	out := make(net.IP, net.IPv6len)
	copy(out, base)
	copy(out[12:16], v4)
	return out
}
