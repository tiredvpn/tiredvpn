//go:build linux
// +build linux

package tun

import (
	"bytes"
	"net"
	"os"
	"reflect"
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
	plan := ipv6BlockPlan(ifName, []net.IP{server6}, IPv6AllowList{})

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
	plan := ipv6BlockPlan("tiredvpn0", nil, IPv6AllowList{})
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
	base := len(ipv6BlockPlan("tiredvpn0", nil, IPv6AllowList{}))

	junk := []net.IP{nil, net.ParseIP("203.0.113.10"), net.IPv4(10, 0, 0, 1)}
	if got := len(ipv6BlockPlan("tiredvpn0", junk, IPv6AllowList{})); got != base {
		t.Errorf("non-IPv6 allow entries added %d rules, want 0", got-base)
	}

	real6 := []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20")}
	if got := len(ipv6BlockPlan("tiredvpn0", real6, IPv6AllowList{})); got != base+2 {
		t.Errorf("two IPv6 allow entries produced %d rules, want %d", got, base+2)
	}

	// A device with no interface name must not produce a rule matching the
	// empty ifname, which would accept traffic leaving through an unnamed
	// interface.
	if got := len(ipv6BlockPlan("", nil, IPv6AllowList{})); got != base-1 {
		t.Errorf("empty ifname produced %d rules, want %d", got, base-1)
	}
}

// TestIPv6BlockPlanExceptions is the flag doing its job: the interface and the
// prefix named in -tun-ipv6-allow survive the block, and everything the block
// was there for still does not.
//
// The Hurricane Electric case is the row that made the flag exist: he6 is up,
// keeps its address, and every packet the host sends over it is rejected by a
// chain installed for an unrelated tunnel.
func TestIPv6BlockPlanExceptions(t *testing.T) {
	const ifName = "tiredvpn0"
	allow, err := ParseIPv6AllowList("he6,2001:db8:77b::/64")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	plan := ipv6BlockPlan(ifName, nil, allow)

	for _, tc := range []struct {
		name string
		oif  string
		dst  string
		want string
	}{
		{"the excepted interface", "he6", "2606:4700:4700::1111", "accept"},
		{"the excepted prefix, any interface", "eth0", "2001:db8:77b::2", "accept"},
		{"a neighbour of the excepted prefix", "eth0", "2001:db8:77c::2", "reject"},
		{"an interface with a similar name", "he60", "2606:4700:4700::1111", "reject"},
		{"everything else still leaks nothing", "eth0", "2606:4700:4700::1111", "reject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalV6BlockPlan(t, plan, tc.oif, net.ParseIP(tc.dst)); got != tc.want {
				t.Errorf("%s via %s = %s, want %s", tc.dst, tc.oif, got, tc.want)
			}
		})
	}

	// The verdicts above are only true because the accepts come first: an
	// exception appended after the reject would evaluate the same way in a
	// careless reading of the plan and do nothing in the kernel.
	rejectAt := -1
	for i, r := range plan {
		if r.Name == "reject" {
			rejectAt = i
		}
	}
	if rejectAt != len(plan)-1 {
		t.Fatalf("reject is rule %d of %d, want last", rejectAt, len(plan))
	}
	for _, want := range []string{"accept he6", "accept 2001:db8:77b::/64"} {
		at := -1
		for i, r := range plan {
			if r.Name == want {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("no rule %q in the plan (%v)", want, planNames(plan))
		}
		if at > rejectAt {
			t.Errorf("rule %q is at %d, after the reject at %d — it can never match", want, at, rejectAt)
		}
	}
}

// TestIPv6BlockPlanUnchangedWithoutExceptions pins what an empty
// -tun-ipv6-allow must leave behind: exactly the rule set that shipped before
// the flag existed, in the same order. The exceptions may only be inserted
// between the last accept and the reject.
func TestIPv6BlockPlanUnchangedWithoutExceptions(t *testing.T) {
	const ifName = "tiredvpn0"
	server6 := net.ParseIP("2001:db8::10")

	base := ipv6BlockPlan(ifName, []net.IP{server6}, IPv6AllowList{})
	want := []string{
		"accept lo",
		"accept tiredvpn0",
		"accept fe80::/10",
		"accept ff00::/8",
		"accept 2001:db8::10/128",
		"reject",
	}
	if got := planNames(base); !equalStrings(got, want) {
		t.Fatalf("plan without exceptions = %v, want %v", got, want)
	}

	allow, err := ParseIPv6AllowList("he6")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	withExtra := ipv6BlockPlan(ifName, []net.IP{server6}, allow)
	if len(withExtra) != len(base)+1 {
		t.Fatalf("one exception produced %d rules, want %d", len(withExtra), len(base)+1)
	}
	// Everything up to the reject must be untouched, expression for
	// expression: an exception that rewrote or reordered an existing accept
	// would be a second change hiding inside this one.
	for i := range base[:len(base)-1] {
		if !reflect.DeepEqual(base[i], withExtra[i]) {
			t.Errorf("rule %d changed: %q -> %q", i, base[i].Name, withExtra[i].Name)
		}
	}
	if last := base[len(base)-1]; !reflect.DeepEqual(last, withExtra[len(withExtra)-1]) {
		t.Errorf("the reject rule changed")
	}
}

// TestTUNDeviceV6BlockPlanUsesExceptions checks the wiring one level up: the
// list handed to the device is the list the device installs. Testing
// ipv6BlockPlan alone would pass just as well with SetIPv6BlockAllowList
// writing into a field nobody reads.
func TestTUNDeviceV6BlockPlanUsesExceptions(t *testing.T) {
	allow, err := ParseIPv6AllowList("he6")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	td := &TUNDevice{name: "tiredvpn0", ipv6Policy: IPv6PolicyDual}
	td.SetIPv6BlockAllow([]net.IP{net.ParseIP("2001:db8::10")})
	td.SetIPv6BlockAllowList(allow)

	plan := td.v6BlockPlan()
	if got := evalV6BlockPlan(t, plan, "he6", net.ParseIP("2606:4700:4700::1111")); got != "accept" {
		t.Errorf("he6 via the device's own plan = %s, want accept (plan: %v)", got, planNames(plan))
	}
	if got := evalV6BlockPlan(t, plan, "eth0", net.ParseIP("2606:4700:4700::1111")); got != "reject" {
		t.Errorf("eth0 = %s, want reject", got)
	}
	if got := evalV6BlockPlan(t, plan, "eth0", net.ParseIP("2001:db8::10")); got != "accept" {
		t.Error("the server hole disappeared once exceptions were set")
	}
}

// TestApplyIPv6BlockConfigCarriesExceptions closes the last gap between the
// flag and the chain: VPNConfig.IPv6Allow has to reach the device. This is the
// step that has been wrong before elsewhere in the tree — a value parsed
// correctly, then not passed on, behaves exactly like a value never given.
func TestApplyIPv6BlockConfigCarriesExceptions(t *testing.T) {
	allow, err := ParseIPv6AllowList("he6")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	td := &TUNDevice{name: "tiredvpn0"}
	applyIPv6BlockConfig(td, VPNConfig{
		IPv6Policy: IPv6PolicyDual,
		ServerAddr: "203.0.113.10:443",
		IPv6Allow:  allow,
	})

	if !td.wantsIPv6Block() {
		t.Fatal("the dual policy did not reach the device")
	}
	if got := evalV6BlockPlan(t, td.v6BlockPlan(), "he6", net.ParseIP("2606:4700:4700::1111")); got != "accept" {
		t.Errorf("he6 = %s, want accept: the config's exceptions did not reach the device", got)
	}
}

func planNames(plan []v6BlockRule) []string {
	out := make([]string, 0, len(plan))
	for _, r := range plan {
		out = append(out, r.Name)
	}
	return out
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

	plan := ipv6BlockPlan(ifName, allow, IPv6AllowList{})
	if err := installIPv6LeakBlock(ifName, plan); err != nil {
		t.Skipf("cannot install nftables rules here: %v", err)
	}
	defer func() { _ = removeIPv6LeakBlockTable(ifName) }()

	rules := countBlockRules(t, ifName)
	if want := len(plan); rules != want {
		t.Errorf("installed %d rules, want %d", rules, want)
	}

	// Re-install (what a reconnect does) must replace, not append.
	if err := installIPv6LeakBlock(ifName, plan); err != nil {
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
