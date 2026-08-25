//go:build linux
// +build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/vishvananda/netlink"
)

// natTableNameFor returns the nftables table used for the server's TUN-mode
// NAT bootstrap (MASQUERADE + FORWARD accept for the client IP pool). Kept
// separate from the per-interface MSS clamping tables (nftablesTableName) so
// the two subsystems never collide.
//
// The pool is part of the name because installNATRules replaces its table
// wholesale: with one shared name, every instance on a multi-instance host
// wiped the NAT of all the others each time it started. Instances that predate
// this still use the old flat "tiredvpn-nat" table, which is deliberately left
// alone so a half-upgraded host keeps working.
func natTableNameFor(pool string) string {
	return "tiredvpn-nat-" + sanitizeNftName(pool)
}

// nat6TableNameFor is the IPv6 twin of natTableNameFor.
func nat6TableNameFor(pool string) string {
	return "tiredvpn-nat6-" + sanitizeNftName(pool)
}

// sanitizeNftName turns a CIDR into something usable as an nftables table name
// ("10.8.9.0/24" -> "10-8-9-0-24", "fd00:10:9::/64" -> "fd00-10-9---64").
func sanitizeNftName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
}

// SetupServerNAT installs IPv4 forwarding, MASQUERADE and FORWARD-accept
// rules for pool egressing via the WAN interface, replacing the iptables
// rules the Docker entrypoint and packaging/tiredvpn-nat.sh used to install
// by shelling out to `sysctl`/`ip`/`iptables`. wanOverride, if non-empty,
// skips autodetection (mirrors the old TIREDVPN_WAN_IFACE env override).
//
// A no-op if pool is empty (proxy-only mode). Every other failure is
// returned rather than logged directly, so the caller can decide how loud to
// be - the old shell scripts warned and continued rather than failing
// startup, and callers should do the same here.
func SetupServerNAT(pool string, wanOverride string) error {
	if pool == "" {
		return nil
	}

	if err := enableIPForward(); err != nil {
		log.Warn("could not enable net.ipv4.ip_forward: %v", err)
	}

	wan := wanOverride
	if wan == "" {
		var err error
		wan, err = detectWANInterface()
		if err != nil {
			return fmt.Errorf("detect WAN interface (set TIREDVPN_WAN_IFACE to override): %w", err)
		}
	}
	log.Info("NAT: using WAN interface %s for pool %s", wan, pool)

	_, ipnet, err := net.ParseCIDR(pool)
	if err != nil {
		return fmt.Errorf("invalid pool %q: %w", pool, err)
	}

	if err := installNATRules(ipnet, wan); err != nil {
		return fmt.Errorf("install nftables NAT rules: %w", err)
	}

	log.Info("NAT: installed MASQUERADE %s -> %s and FORWARD accept via nftables", pool, wan)
	warnIfForeignForwardDrop(nftables.TableFamilyIPv4, "NAT")
	return nil
}

// warnIfForeignForwardDrop reports a base forward chain owned by somebody else
// (an iptables-nft FORWARD with policy drop, a firewall's own table, Docker)
// that will drop the traffic our accept rules let through.
//
// nftables evaluates every base chain registered on a hook: an accept verdict
// in ours does not overrule a drop policy in theirs. So on such a host the
// tunnel comes up, the NAT rules read as correct, and packets still vanish
// until an explicit rule is added over there. That is a five-minute fix and an
// hour-long diagnosis, hence the loud warning; we deliberately do not edit a
// table we do not own.
func warnIfForeignForwardDrop(family nftables.TableFamily, logPrefix string) {
	conn, err := nftables.New()
	if err != nil {
		return
	}
	chains, err := conn.ListChains()
	if err != nil {
		return
	}
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Family != family {
			continue
		}
		if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookForward {
			continue
		}
		if strings.HasPrefix(ch.Table.Name, "tiredvpn-") {
			continue // one of ours
		}
		if ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop {
			log.Warn("%s: chain %s/%s on the forward hook has policy drop and is not ours; "+
				"our accept does not override it, so client traffic may be dropped there. "+
				"Add an explicit rule for the tunnel interface if forwarding does not work.",
				logPrefix, ch.Table.Name, ch.Name)
			return
		}
	}
}

// SetupServerNAT6 installs IPv6 forwarding, MASQUERADE (NAT66) and
// FORWARD-accept rules for the dual-stack tunnel prefix (a ULA such as
// fd00:10:8::/64) egressing via the WAN interface. It mirrors SetupServerNAT
// exactly, just in the ip6 family: same table structure, same idempotent
// flush-and-replace semantics, same wanOverride escape hatch.
//
// A no-op if pool is empty (dual-stack disabled). Every other failure is
// returned so the caller can warn-and-continue, matching SetupServerNAT.
func SetupServerNAT6(pool string, wanOverride string) error {
	if pool == "" {
		return nil
	}

	if err := enableIPv6Forward(); err != nil {
		log.Warn("could not enable net.ipv6.conf.all.forwarding: %v", err)
	}

	wan := wanOverride
	if wan == "" {
		var err error
		// Detection follows the IPv6 route, not the IPv4 one: an exit whose v6
		// arrives over a tunnel broker (HE sit device, wireguard, ...) egresses
		// v6 on a different interface than v4, and masquerading on the v4
		// uplink would push pool addresses out unmasqueraded - they are ULA, so
		// nothing comes back. Falls back to the v4 uplink when the box has no
		// v6 route at all, which keeps the previous behaviour for a plain
		// dual-stacked NIC. TIREDVPN_WAN_IFACE overrides both.
		wan, err = detectWANInterface6()
		if err != nil {
			log.Warn("NAT66: no IPv6 uplink route (%v), falling back to the IPv4 uplink interface", err)
			wan, err = detectWANInterface()
			if err != nil {
				return fmt.Errorf("detect WAN interface (set TIREDVPN_WAN_IFACE to override): %w", err)
			}
		}
	}
	log.Info("NAT66: using WAN interface %s for pool %s", wan, pool)

	// Forwarding=1 makes the kernel stop honouring Router Advertisements
	// unless accept_ra=2, so this has to run after the uplink is known.
	ensureIPv6AcceptRA(wan)

	_, ipnet, err := net.ParseCIDR(pool)
	if err != nil {
		return fmt.Errorf("invalid pool %q: %w", pool, err)
	}
	if ipnet.IP.To4() != nil {
		return fmt.Errorf("invalid pool %q: not an IPv6 CIDR", pool)
	}

	if err := installNAT6Rules(ipnet, wan); err != nil {
		return fmt.Errorf("install nftables NAT66 rules: %w", err)
	}

	log.Info("NAT66: installed MASQUERADE %s -> %s and FORWARD accept via nftables (ip6)", pool, wan)
	warnIfForeignForwardDrop(nftables.TableFamilyIPv6, "NAT66")
	return nil
}

// enableIPForward turns on IPv4 forwarding by writing directly to the proc
// sysctl, replacing the `sysctl -w net.ipv4.ip_forward=1` shell-out.
func enableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

// enableIPv6Forward turns on IPv6 forwarding by writing directly to the proc
// sysctl, replacing the `sysctl -w net.ipv6.conf.all.forwarding=1` shell-out.
func enableIPv6Forward() error {
	return os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0644)
}

// ensureIPv6AcceptRA keeps an RA-learned IPv6 uplink alive once forwarding is
// on. With net.ipv6.conf.all.forwarding=1 the kernel treats the box as a
// router and ignores incoming Router Advertisements unless the interface has
// accept_ra=2. On an exit whose IPv6 default route came from an RA — exactly
// the setup warnIfNoGlobalIPv6Uplink probes for — that route silently expires
// at the end of its RA lifetime and every client's IPv6 goes into a blackhole
// while IPv4 keeps working.
//
// This writes host state that lives outside the VPN's own tables (the uplink
// NIC's sysctl), so it is deliberately narrow: only the detected WAN
// interface, only the 1 -> 2 transition (0 means RAs are off by policy and
// forwarding changes nothing), and a warning rather than a failure when it
// cannot be applied. Not reverted on shutdown: accept_ra=2 is harmless without
// forwarding, and restoring 1 mid-lifetime would reintroduce the expiry.
func ensureIPv6AcceptRA(iface string) {
	ensureIPv6AcceptRAAt(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", iface), iface)
}

// ensureIPv6AcceptRAAt is ensureIPv6AcceptRA with the sysctl path injected so
// it can be exercised without /proc.
func ensureIPv6AcceptRAAt(path, iface string) {
	cur, err := os.ReadFile(path)
	if err != nil {
		log.Warn("NAT66: cannot read %s: %v (an RA-learned IPv6 default route may expire under forwarding=1)", path, err)
		return
	}
	switch strings.TrimSpace(string(cur)) {
	case "2":
		return // already "accept RAs even as a router"
	case "0":
		return // RAs disabled by policy (static addressing); nothing to preserve
	}
	if err := os.WriteFile(path, []byte("2\n"), 0644); err != nil {
		log.Warn("NAT66: %s is 1 with forwarding enabled, so the RA-learned IPv6 default route will expire; could not set it to 2: %v", path, err)
		return
	}
	log.Info("NAT66: set net.ipv6.conf.%s.accept_ra=2 (host sysctl) so the RA-learned IPv6 default route survives forwarding=1", iface)
}

// installNAT6Rules is the ip6-family twin of installNATRules: a dedicated
// tiredvpn-nat6 table with postrouting MASQUERADE for pool traffic leaving
// wan and forward-accept rules for traffic to/from the pool. Re-running
// replaces the table wholesale, same as the v4 path.
func installNAT6Rules(pool *net.IPNet, wan string) error {
	// See installNATRules for why the delete runs in its own flush.
	if delConn, err := nftables.New(); err == nil {
		delConn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: nat6TableNameFor(pool.String())})
		_ = delConn.Flush()
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables unavailable: %w", err)
	}

	natTbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   nat6TableNameFor(pool.String()),
	})

	postrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    natTbl,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   chainPolicyAcceptPtr(),
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: postrouting,
		Exprs: masqRule6(pool, wan),
	})

	forward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    natTbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicyAcceptPtr(),
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: forward,
		Exprs: poolMatchAcceptRule6(pool, true), // ip6 saddr in pool
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: forward,
		Exprs: poolMatchAcceptRule6(pool, false), // ip6 daddr in pool
	})

	return conn.Flush()
}

// masqRule6 is the ip6 twin of masqRule: packets leaving via wan whose source
// address is in pool get masqueraded (NAT66).
func masqRule6(pool *net.IPNet, wan string) []expr.Any {
	exprs := []expr.Any{
		// oifname == wan
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnamePad(wan)},
	}
	exprs = append(exprs, ip6InPoolExprs(pool, 8)...) // ip6 saddr in pool
	return append(exprs, &expr.Masq{})
}

// poolMatchAcceptRule6 is the ip6 twin of poolMatchAcceptRule: match ip6
// saddr (src=true) or daddr (src=false) against pool with an ACCEPT verdict.
func poolMatchAcceptRule6(pool *net.IPNet, src bool) []expr.Any {
	offset := uint32(24) // daddr
	if src {
		offset = 8 // saddr
	}
	exprs := ip6InPoolExprs(pool, offset)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

// ip6InPoolExprs loads the 16-byte IPv6 address at the given network-header
// offset (8=saddr, 24=daddr) and compares it, masked by pool's netmask,
// against pool's network address.
func ip6InPoolExprs(pool *net.IPNet, offset uint32) []expr.Any {
	network := pool.IP.To16()
	mask := net.IP(pool.Mask)

	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 16},
		&expr.Bitwise{DestRegister: 1, SourceRegister: 1, Len: 16, Mask: mask, Xor: make([]byte, 16)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
	}
}

// detectWANInterface returns the name of the interface the kernel would use
// to reach the public internet, mirroring `ip route get 1.1.1.1 | ... dev`.
func detectWANInterface() (string, error) {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil {
		return "", fmt.Errorf("route lookup: %w", err)
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return "", fmt.Errorf("no route to 1.1.1.1")
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", fmt.Errorf("resolve link %d: %w", routes[0].LinkIndex, err)
	}
	return link.Attrs().Name, nil
}

// detectWANInterface6 is the IPv6 twin of detectWANInterface, mirroring
// `ip -6 route get 2606:4700:4700::1111 | ... dev`. The probe address is only a
// route lookup target - nothing is sent to it - and any global v6 address
// resolves the same default route.
func detectWANInterface6() (string, error) {
	routes, err := netlink.RouteGet(net.ParseIP("2606:4700:4700::1111"))
	if err != nil {
		return "", fmt.Errorf("v6 route lookup: %w", err)
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return "", fmt.Errorf("no IPv6 route to the internet")
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", fmt.Errorf("resolve link %d: %w", routes[0].LinkIndex, err)
	}
	return link.Attrs().Name, nil
}

// installNATRules creates the tiredvpn-nat table with a postrouting chain
// (MASQUERADE for pool traffic leaving wan) and a forward chain (accept
// traffic to/from pool). Re-running replaces the table's rules wholesale, so
// this is safe to call again after a config change without leaving stale
// duplicate rules behind - the same idempotency the old scripts got from
// their `iptables -C ... || iptables -A ...` check-then-append pattern.
func installNATRules(pool *net.IPNet, wan string) error {
	// nftables commits a Flush() as one atomic batch: if any message in it
	// fails, the kernel rolls back the whole batch. Deleting a stale table
	// from a previous run has to happen in its own flush, separate from the
	// create-and-populate one below, because DelTable on a table that
	// doesn't exist yet (first run) would otherwise abort that batch too.
	// Best-effort: ignore the error either way.
	if delConn, err := nftables.New(); err == nil {
		delConn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: natTableNameFor(pool.String())})
		_ = delConn.Flush()
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables unavailable: %w", err)
	}

	natTbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   natTableNameFor(pool.String()),
	})

	postrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    natTbl,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   chainPolicyAcceptPtr(),
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: postrouting,
		Exprs: masqRule(pool, wan),
	})

	forward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    natTbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicyAcceptPtr(),
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: forward,
		Exprs: poolMatchAcceptRule(pool, true), // saddr in pool
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: forward,
		Exprs: poolMatchAcceptRule(pool, false), // daddr in pool
	})

	return conn.Flush()
}

// masqRule matches packets leaving via wan whose source address is in pool,
// then masquerades them (equivalent to
// `iptables -t nat -A POSTROUTING -s pool -o wan -j MASQUERADE`).
func masqRule(pool *net.IPNet, wan string) []expr.Any {
	exprs := []expr.Any{
		// oifname == wan
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnamePad(wan)},
	}
	exprs = append(exprs, ipInPoolExprs(pool, 12)...) // ip saddr in pool
	return append(exprs, &expr.Masq{})
}

// poolMatchAcceptRule matches ip saddr (src=true) or daddr (src=false)
// against pool with a plain ACCEPT verdict (equivalent to
// `iptables -A FORWARD -s/-d pool -j ACCEPT`).
func poolMatchAcceptRule(pool *net.IPNet, src bool) []expr.Any {
	offset := uint32(16) // daddr
	if src {
		offset = 12 // saddr
	}
	exprs := ipInPoolExprs(pool, offset)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

// ipInPoolExprs loads the 4-byte IPv4 address at the given network-header
// offset (12=saddr, 16=daddr) and compares it, masked by pool's netmask,
// against pool's network address.
func ipInPoolExprs(pool *net.IPNet, offset uint32) []expr.Any {
	network := pool.IP.To4()
	mask := net.IP(pool.Mask).To4()

	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
		&expr.Bitwise{DestRegister: 1, SourceRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
	}
}
