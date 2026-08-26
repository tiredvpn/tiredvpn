//go:build linux
// +build linux

package tun

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// evalV6BlockPlan interprets the leak-block rule set the way the kernel would:
// it walks the rules in order, simulating register 1, and returns the verdict
// for a packet leaving through oif towards dst.
//
// Testing the plan through an evaluator rather than by counting expressions is
// what makes the test say something: it answers "what stays reachable", which
// is the only property the block has to get right. An expression-shape
// assertion would pass just as happily on a rule set that accepts everything.
func evalV6BlockPlan(t *testing.T, plan []v6BlockRule, oif string, dst net.IP) string {
	t.Helper()
	for _, r := range plan {
		var reg1 []byte
		matched := true
		for _, e := range r.Exprs {
			switch x := e.(type) {
			case *expr.Meta:
				if x.Key != expr.MetaKeyOIFNAME {
					t.Fatalf("rule %q: unexpected meta key %v", r.Name, x.Key)
				}
				reg1 = ifnamePad(oif)
			case *expr.Payload:
				if x.Base != expr.PayloadBaseNetworkHeader || x.Offset != 24 || x.Len != 16 {
					t.Fatalf("rule %q: payload load is not the v6 daddr: %+v", r.Name, x)
				}
				reg1 = append([]byte(nil), dst.To16()...)
			case *expr.Bitwise:
				// nft bitwise: reg = (reg & mask) ^ xor
				out := make([]byte, len(reg1))
				for i := range reg1 {
					out[i] = (reg1[i] & x.Mask[i]) ^ x.Xor[i]
				}
				reg1 = out
			case *expr.Cmp:
				if x.Op != expr.CmpOpEq {
					t.Fatalf("rule %q: unexpected cmp op %v", r.Name, x.Op)
				}
				matched = bytes.Equal(reg1, x.Data)
			case *expr.Verdict:
				if x.Kind != expr.VerdictAccept {
					t.Fatalf("rule %q: unexpected verdict %v", r.Name, x.Kind)
				}
				if matched {
					return "accept"
				}
			case *expr.Reject:
				if matched {
					return "reject"
				}
			default:
				t.Fatalf("rule %q: unhandled expression %T", r.Name, e)
			}
			if !matched {
				break
			}
		}
	}
	return "fallthrough"
}

// TestIPv6BlockPlanVerdicts is the policy statement of the leak block: which
// IPv6 destinations survive it and which do not. Every "reject" row is a leak
// that would otherwise carry the user's real address around the tunnel; every
// "accept" row is something whose loss breaks the host or the client itself.
func TestIPv6BlockPlanVerdicts(t *testing.T) {
	const ifName = "tiredvpn0"
	server6 := net.ParseIP("2001:db8::10")
	plan := ipv6BlockPlan(ifName, []net.IP{server6})

	for _, tc := range []struct {
		name string
		oif  string
		dst  string
		want string
	}{
		{"loopback stays local", loopbackIfName, "::1", "accept"},
		{"tunnel traffic passes", ifName, "2606:4700:4700::1111", "accept"},
		{"neighbour discovery", "wlan0", "fe80::1", "accept"},
		{"router solicitation", "wlan0", "ff02::2", "accept"},
		{"mDNS", "wlan0", "ff02::fb", "accept"},
		{"the client's own exit", "wlan0", "2001:db8::10", "accept"},
		{"global unicast leaks", "wlan0", "2606:4700:4700::1111", "reject"},
		{"another global unicast", "wlan0", "2a00:1450:4001:80f::200e", "reject"},
		{"neighbour of the exit", "wlan0", "2001:db8::11", "reject"},
		{"ULA off the tunnel", "wlan0", "fd00:dead:beef::1", "reject"},
		{"unspecified", "wlan0", "::", "reject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := net.ParseIP(tc.dst)
			if dst == nil {
				t.Fatalf("bad test address %q", tc.dst)
			}
			if got := evalV6BlockPlan(t, plan, tc.oif, dst); got != tc.want {
				t.Errorf("%s via %s = %s, want %s", tc.dst, tc.oif, got, tc.want)
			}
		})
	}
}

// TestIPv6BlockPlanShape pins the structural invariants the evaluator above
// takes for granted: the reject is last and unconditional, and nothing follows
// it.
func TestIPv6BlockPlanShape(t *testing.T) {
	plan := ipv6BlockPlan("tiredvpn0", nil)
	if len(plan) < 2 {
		t.Fatalf("plan has %d rules, want the accepts plus a reject", len(plan))
	}
	last := plan[len(plan)-1]
	if len(last.Exprs) != 1 {
		t.Fatalf("last rule %q has %d expressions, want exactly the reject", last.Name, len(last.Exprs))
	}
	rej, ok := last.Exprs[0].(*expr.Reject)
	if !ok {
		t.Fatalf("last rule %q is %T, want *expr.Reject", last.Name, last.Exprs[0])
	}
	if rej.Type != nftRejectICMPUnreach || rej.Code != icmp6AdminProhibited {
		t.Errorf("reject = type %d code %d, want ICMPv6 unreachable / admin prohibited (%d/%d)",
			rej.Type, rej.Code, nftRejectICMPUnreach, icmp6AdminProhibited)
	}
	for i, r := range plan[:len(plan)-1] {
		if _, isReject := r.Exprs[len(r.Exprs)-1].(*expr.Reject); isReject {
			t.Errorf("rule %d (%q) rejects before the accepts are done", i, r.Name)
		}
	}
}

// TestIPv6BlockPlanAllowList checks what makes it into the allow holes: only
// real IPv6 addresses. An IPv4 server address needs no hole (the block is ip6
// only) and a nil entry must not turn into a match-anything rule.
func TestIPv6BlockPlanAllowList(t *testing.T) {
	base := len(ipv6BlockPlan("tiredvpn0", nil))

	junk := []net.IP{nil, net.ParseIP("203.0.113.10"), net.IPv4(10, 0, 0, 1)}
	if got := len(ipv6BlockPlan("tiredvpn0", junk)); got != base {
		t.Errorf("non-IPv6 allow entries added %d rules, want 0", got-base)
	}

	real6 := []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20")}
	if got := len(ipv6BlockPlan("tiredvpn0", real6)); got != base+2 {
		t.Errorf("two IPv6 allow entries produced %d rules, want %d", got, base+2)
	}

	// A device with no interface name must not produce a rule matching the
	// empty ifname, which would accept traffic leaving through an unnamed
	// interface.
	if got := len(ipv6BlockPlan("", nil)); got != base-1 {
		t.Errorf("empty ifname produced %d rules, want %d", got, base-1)
	}
}

// TestV6BlockTableNameDistinctFromMSS guards a collision that would make the
// two features tear each other down: both tables live in the ip6 family, and
// DisableIPv6 deletes the MSS one at exactly the moment the block goes in.
func TestV6BlockTableNameDistinctFromMSS(t *testing.T) {
	const ifName = "tiredvpn0"
	if v6BlockTableName(ifName) == mssTableName(ifName) {
		t.Fatalf("leak-block and MSS clamp share the ip6 table name %q", v6BlockTableName(ifName))
	}
	// Per-interface, like the clamp table: one tunnel's teardown must not
	// touch another's.
	if v6BlockTableName("tun0") == v6BlockTableName("tun1") {
		t.Error("leak-block table name is not per-interface")
	}
}

// TestWantsIPv6Block covers the gate in front of every nftables call: only the
// blocking policies, and only on a device that still has an interface.
func TestWantsIPv6Block(t *testing.T) {
	for _, tc := range []struct {
		policy IPv6Policy
		name   string
		want   bool
	}{
		{IPv6PolicyOff, "tiredvpn0", false},
		{IPv6PolicyDual, "tiredvpn0", true},
		{IPv6PolicyBlock, "tiredvpn0", true},
		{IPv6PolicyBlock, "", false},
		{IPv6PolicyDual, "", false},
	} {
		td := &TUNDevice{name: tc.name, ipv6Policy: tc.policy}
		if got := td.wantsIPv6Block(); got != tc.want {
			t.Errorf("policy=%v name=%q: wantsIPv6Block() = %v, want %v",
				tc.policy, tc.name, got, tc.want)
		}
	}
}

// TestIPv6LeakBlockInstallRemove exercises the real netlink path: the table
// appears, a re-install replaces it instead of doubling the rules, and removal
// leaves nothing behind. Needs root, so it self-skips when run unprivileged.
//
// The interface name is a fake one — nftables happily stores an oifname match
// for a device that does not exist, and no packet in the test can hit the
// chain anyway.
func TestIPv6LeakBlockInstallRemove(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installing nftables rules needs root")
	}
	const ifName = "tiredvpn-test0"
	allow := []net.IP{net.ParseIP("2001:db8::10")}

	if err := installIPv6LeakBlock(ifName, allow); err != nil {
		t.Skipf("cannot install nftables rules here: %v", err)
	}
	defer func() { _ = removeIPv6LeakBlockTable(ifName) }()

	rules := countBlockRules(t, ifName)
	if want := len(ipv6BlockPlan(ifName, allow)); rules != want {
		t.Errorf("installed %d rules, want %d", rules, want)
	}

	// Re-install (what a reconnect does) must replace, not append.
	if err := installIPv6LeakBlock(ifName, allow); err != nil {
		t.Fatalf("re-install: %v", err)
	}
	if got := countBlockRules(t, ifName); got != rules {
		t.Errorf("re-install produced %d rules, want %d (rules were appended, not replaced)", got, rules)
	}

	if err := removeIPv6LeakBlockTable(ifName); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if tableExists(t, ifName) {
		t.Error("leak-block table survived removal; host IPv6 would stay blocked")
	}
}

// countBlockRules returns the number of rules in the installed leak-block
// chain, failing the test if the table or chain is missing.
func countBlockRules(t *testing.T, ifName string) int {
	t.Helper()
	conn, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv6, Name: v6BlockTableName(ifName)}
	rules, err := conn.GetRules(tbl, &nftables.Chain{Name: ipv6BlockChainName, Table: tbl})
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	return len(rules)
}

// tableExists reports whether the leak-block table is still present.
func tableExists(t *testing.T, ifName string) bool {
	t.Helper()
	conn, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv6)
	if err != nil {
		t.Fatalf("ListTablesOfFamily: %v", err)
	}
	for _, tbl := range tables {
		if tbl.Name == v6BlockTableName(ifName) {
			return true
		}
	}
	return false
}
