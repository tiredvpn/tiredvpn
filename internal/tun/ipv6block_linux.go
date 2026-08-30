//go:build linux
// +build linux

package tun

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// The IPv6 leak block. When the tunnel cannot carry IPv6 — the exit declined
// dual-stack, or the operator asked for -tun-ipv6=block outright — outbound
// IPv6 has to be stopped at the host, otherwise every application with a
// working v6 default route reaches the internet outside the VPN and hands out
// the user's real address (issue #55).
//
// The block is an nftables chain in the ip6 family hooked at output, built on
// the same principles as the MSS clamp in tun_linux.go: its own table, named
// per interface so one tunnel's teardown never touches another's, installed
// and removed together with the tunnel.
//
// It rejects rather than drops: a rejected connect fails immediately with
// EACCES/EHOSTUNREACH and the application falls back to IPv4 (which the tunnel
// does carry) within the same call, while a silent drop makes it sit through a
// connect timeout first.

// nftRejectICMPUnreach is NFT_REJECT_ICMP_UNREACH (enum nft_reject_types) and
// icmp6AdminProhibited is ICMPV6_ADM_PROHIBITED, the ICMPv6 "destination
// unreachable" code meaning administratively prohibited. Neither is exported
// by x/sys/unix, so both are spelled out here.
const (
	nftRejectICMPUnreach  = 0
	icmp6AdminProhibited  = 1
	ipv6BlockChainName    = "v6block"
	ipv6BlockLinkLocalNet = "fe80::/10"
	ipv6BlockMulticastNet = "ff00::/8"
)

// loopbackIfName is the interface local IPv6 (::1) leaves through. Traffic on
// it never leaves the host, so blocking it would only break local services.
const loopbackIfName = "lo"

// v6BlockTableName returns the per-interface ip6 table holding this tunnel's
// leak block. Distinct from mssTableName even though both live in the ip6
// family: the clamp table is deleted by DisableIPv6 exactly when the block is
// installed, so sharing a table would make one tear down the other.
func v6BlockTableName(ifName string) string {
	return nftablesTableName + "-v6block-" + ifName
}

// v6BlockRule is one rule of the leak-block chain: a human-readable name for
// diagnostics and tests, plus the expressions to install.
type v6BlockRule struct {
	Name  string
	Exprs []expr.Any
}

// ipv6BlockPlan builds the ordered rule set of the leak-block chain. Kept
// separate from the netlink call so the policy — what stays reachable — can be
// tested without root and without touching the host's firewall.
//
// Order matters: every accept has to precede the final reject, which matches
// everything left.
//
//  1. oifname lo        — local IPv6 (::1) never leaves the host
//  2. oifname <tunnel>  — the tunnel's own v6, if dual-stack is live
//  3. fe80::/10         — link-local: neighbour discovery, DAD, RS/RA
//  4. ff00::/8          — multicast: RA/NS/MLD, mDNS, LLMNR
//  5. <allow>/128       — the VPN server itself, so the transport can still
//     reach an exit dialled over IPv6
//  6. <extra>           — the operator's -tun-ipv6-allow exceptions, by
//     outbound interface and by destination prefix
//  7. reject            — everything else, including all global unicast
//
// The exceptions come last among the accepts on purpose: with an empty list the
// plan is the one that shipped before the flag existed, rule for rule.
func ipv6BlockPlan(ifName string, allow []net.IP, extra IPv6AllowList) []v6BlockRule {
	rules := []v6BlockRule{
		{Name: "accept " + loopbackIfName, Exprs: v6AcceptOifRule(loopbackIfName)},
	}
	if ifName != "" {
		rules = append(rules, v6BlockRule{
			Name:  "accept " + ifName,
			Exprs: v6AcceptOifRule(ifName),
		})
	}
	for _, cidr := range []string{ipv6BlockLinkLocalNet, ipv6BlockMulticastNet} {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			// Compile-time constants; a parse failure is a programmer error.
			log.Error("IPv6 block: cannot parse %s: %v", cidr, err)
			continue
		}
		rules = append(rules, v6BlockRule{
			Name:  "accept " + cidr,
			Exprs: v6AcceptDaddrRule(dst),
		})
	}
	for _, ip := range allow {
		host := v6HostNet(ip)
		if host == nil {
			continue
		}
		rules = append(rules, v6BlockRule{
			Name:  "accept " + host.String(),
			Exprs: v6AcceptDaddrRule(host),
		})
	}
	// Operator exceptions. Both forms are already expressible: an interface is
	// the same oifname match the tunnel's own accept uses, a prefix the same
	// destination match as the server holes — the only thing the server holes
	// could not express is a mask other than /128, which ParseIPv6AllowList
	// hands over ready-made.
	for _, iface := range extra.Interfaces {
		if iface == "" {
			continue
		}
		rules = append(rules, v6BlockRule{
			Name:  "accept " + iface,
			Exprs: v6AcceptOifRule(iface),
		})
	}
	for _, pfx := range extra.Prefixes {
		if pfx == nil {
			continue
		}
		rules = append(rules, v6BlockRule{
			Name:  "accept " + pfx.String(),
			Exprs: v6AcceptDaddrRule(pfx),
		})
	}
	return append(rules, v6BlockRule{Name: "reject", Exprs: v6RejectRule()})
}

// v6HostNet turns an IPv6 address into its /128 network, or nil when ip is not
// a usable IPv6 address (nil, or an IPv4 one — the v4 path is untouched by the
// block, so an IPv4 server address needs no hole).
func v6HostNet(ip net.IP) *net.IPNet {
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

// v6AcceptOifRule accepts anything leaving through ifName.
func v6AcceptOifRule(ifName string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnamePad(ifName)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// v6AcceptDaddrRule accepts traffic whose IPv6 destination falls inside dst.
// The address match reuses ip6InPoolExprs (offset 24 = daddr in the v6 header).
func v6AcceptDaddrRule(dst *net.IPNet) []expr.Any {
	return append(ip6InPoolExprs(dst, 24), &expr.Verdict{Kind: expr.VerdictAccept})
}

// v6RejectRule rejects unconditionally with ICMPv6 administratively
// prohibited, so the sending socket fails at once instead of timing out.
func v6RejectRule() []expr.Any {
	return []expr.Any{&expr.Reject{Type: nftRejectICMPUnreach, Code: icmp6AdminProhibited}}
}

// installIPv6LeakBlock creates (or replaces) the leak-block table for ifName
// and fills its chain with plan. The delete runs in its own flush first,
// mirroring installNAT6Rules, so re-running after a reconnect replaces the rule
// set wholesale instead of appending a second copy of every accept.
//
// It takes the finished plan rather than the inputs it is built from, so the
// caller's plan and the installed plan cannot be two different things.
func installIPv6LeakBlock(ifName string, plan []v6BlockRule) error {
	if delConn, err := nftables.New(); err == nil {
		delConn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: v6BlockTableName(ifName)})
		_ = delConn.Flush()
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables unavailable: %w", err)
	}

	tbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   v6BlockTableName(ifName),
	})
	// Policy accept with an explicit reject rule at the end: a chain whose
	// policy is drop would black-hole IPv6 the moment it is created, before
	// the accept rules of the same batch are visible.
	chain := conn.AddChain(&nftables.Chain{
		Name:     ipv6BlockChainName,
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicyAcceptPtr(),
	})
	for _, r := range plan {
		conn.AddRule(&nftables.Rule{Table: tbl, Chain: chain, Exprs: r.Exprs})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush ip6 leak-block rules: %w", err)
	}
	return nil
}

// removeIPv6LeakBlockTable deletes the leak-block table for ifName.
func removeIPv6LeakBlockTable(ifName string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables unavailable: %w", err)
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: v6BlockTableName(ifName)})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush ip6 leak-block table delete: %w", err)
	}
	return nil
}

// SetIPv6Policy records what the client wants done with IPv6 for the life of
// this tunnel. Must be set before Configure. Only called for interfaces we own
// — on Android the host owns both routing and filtering via VpnService, so the
// device is left at IPv6PolicyOff and none of the block code runs.
func (t *TUNDevice) SetIPv6Policy(p IPv6Policy) {
	t.ipv6Policy = p
	t.dualStack = p.NegotiatesDualStack()
}

// SetIPv6BlockAllow records the IPv6 addresses that must stay reachable while
// the leak block is up — the VPN server's own transport addresses. Without
// this hole a client whose exit is dialled over IPv6 would block itself out of
// its own tunnel. Same role as the /128 bypass route, one layer down.
func (t *TUNDevice) SetIPv6BlockAllow(ips []net.IP) {
	t.bypassMu.Lock()
	t.v6BlockAllow = append(t.v6BlockAllow[:0], ips...)
	t.bypassMu.Unlock()
}

// SetIPv6BlockAllowList records the operator's -tun-ipv6-allow exceptions:
// interfaces and destination prefixes that keep working while the block is up.
// Unlike SetIPv6BlockAllow, which the client computes from its own endpoints,
// this list is configuration — the host has IPv6 of its own (a 6in4 tunnel,
// another VPN, a routed prefix) that the block must not take down.
func (t *TUNDevice) SetIPv6BlockAllowList(a IPv6AllowList) {
	t.bypassMu.Lock()
	t.v6BlockAllowList = a
	t.bypassMu.Unlock()
}

// blockAllow returns a copy of the allow list under the lock.
func (t *TUNDevice) blockAllow() []net.IP {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	return append([]net.IP(nil), t.v6BlockAllow...)
}

// blockAllowList returns the operator exceptions under the lock. The slices
// inside are not copied: nothing mutates them after ParseIPv6AllowList built
// them.
func (t *TUNDevice) blockAllowList() IPv6AllowList {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	return t.v6BlockAllowList
}

// v6BlockPlan is the rule set this device would install right now. Everything
// that decides the chain's content goes through here — the server holes, the
// operator exceptions and the interface name — so a test can ask what the
// device will actually do instead of what ipv6BlockPlan does when called with
// hand-picked arguments.
func (t *TUNDevice) v6BlockPlan() []v6BlockRule {
	return ipv6BlockPlan(t.name, t.blockAllow(), t.blockAllowList())
}

// setV6BlockInstalled records the block's state and returns the previous one.
// Under bypassMu because Close (teardown) races a reconnect re-asserting the
// block, the same way it races the bypass watcher. Callers must not hold the
// lock — blockAllow takes it too.
func (t *TUNDevice) setV6BlockInstalled(installed bool) (was bool) {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	was, t.v6BlockInstalled = t.v6BlockInstalled, installed
	return was
}

// v6BlockIsInstalled reports whether the leak-block table exists.
func (t *TUNDevice) v6BlockIsInstalled() bool {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	return t.v6BlockInstalled
}

// wantsIPv6Block reports whether this device should carry the leak block: the
// policy asks for it and there is an interface to key the table on. An unnamed
// device is either torn down or was never configured.
func (t *TUNDevice) wantsIPv6Block() bool {
	return t.ipv6Policy.BlocksLeakedIPv6() && t.name != ""
}

// ApplyIPv6LeakBlock installs the block when the policy asks for it. Called
// once the tunnel's IPv6 fate is known: right after a declined dual-stack
// negotiation, or right after connect under -tun-ipv6=block. Never before —
// routes are deferred until the tunnel works, and cutting IPv6 while the host
// still has its normal routing would take away connectivity the client is not
// yet replacing.
//
// Idempotent: re-running on a reconnect replaces the rule set (the server
// allow list may have changed with the endpoint).
func (t *TUNDevice) ApplyIPv6LeakBlock() {
	if !t.wantsIPv6Block() {
		return
	}
	allow := t.blockAllow()
	extra := t.blockAllowList()
	if err := installIPv6LeakBlock(t.name, t.v6BlockPlan()); err != nil {
		log.Error("IPv6 leak block: failed to install nftables rules: %v; "+
			"IPv6 traffic may leave outside the tunnel", err)
		return
	}
	if t.setV6BlockInstalled(true) {
		log.Debug("IPv6 leak block re-asserted for %s (allow: %v %s)", t.name, allow, extra)
		return
	}
	log.Info("IPv6 leak block active: outbound IPv6 rejected except %s, %s, %s, %v and %q "+
		"(the tunnel is not carrying IPv6; use -tun-ipv6=off to opt out). "+
		"If the client is killed without cleanup, remove it with "+
		"'nft delete table ip6 %s'",
		loopbackIfName, ipv6BlockLinkLocalNet, ipv6BlockMulticastNet, allow, extra,
		v6BlockTableName(t.name))
}

// RemoveIPv6LeakBlock takes the block down. Failures are loud: a table left
// behind keeps the host's IPv6 dead after the tunnel is gone, and the message
// has to say how to clear it by hand.
func (t *TUNDevice) RemoveIPv6LeakBlock() {
	if !t.v6BlockIsInstalled() || t.name == "" {
		return
	}
	if err := removeIPv6LeakBlockTable(t.name); err != nil {
		log.Error("IPv6 leak block: failed to remove nftables table: %v; "+
			"host IPv6 stays blocked — remove it with 'nft delete table ip6 %s'",
			err, v6BlockTableName(t.name))
		return
	}
	t.setV6BlockInstalled(false)
	log.Info("IPv6 leak block removed from %s", t.name)
}
