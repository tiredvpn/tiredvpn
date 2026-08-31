package tun

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestParseIPv6RoutesValues covers the three shapes the flag can take. The
// distinction that matters is between "not given" and "given as empty": they
// resolve to opposite route sets, and a bool-less representation would collapse
// them.
func TestParseIPv6RoutesValues(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		managed bool
		want    []string
	}{
		{"unset keeps the half-defaults", "", false, dualStackRouteCIDRs},
		{"none claims nothing", "none", true, nil},
		{"single prefix", "2001:db8::/32", true, []string{"2001:db8::/32"}},
		{"list", "2001:db8::/32,2001:db9::/48", true, []string{"2001:db8::/32", "2001:db9::/48"}},
		{"bare address is its /128", "2001:db8::1", true, []string{"2001:db8::1/128"}},
		{"host bits do not narrow the prefix", "2001:db8::1/32", true, []string{"2001:db8::/32"}},
		{"whitespace around entries", " 2001:db8::/32 , 2001:db9::/48 ", true, []string{"2001:db8::/32", "2001:db9::/48"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := ParseIPv6Routes(c.spec)
			if err != nil {
				t.Fatalf("ParseIPv6Routes(%q): %v", c.spec, err)
			}
			if spec.OperatorManaged() != c.managed {
				t.Errorf("OperatorManaged() = %v, want %v", spec.OperatorManaged(), c.managed)
			}
			nets, err := spec.Nets()
			if err != nil {
				t.Fatalf("Nets: %v", err)
			}
			got := make([]string, 0, len(nets))
			for _, n := range nets {
				got = append(got, n.String())
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("Nets() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestParseIPv6RoutesRejects checks the entries that cannot become correct
// later. Skipping them would leave the operator with a running client and
// routing they believe is in place — the same reasoning as the allow list.
func TestParseIPv6RoutesRejects(t *testing.T) {
	for _, spec := range []string{
		"0.0.0.0/0",      // IPv4 prefix: belongs to -tun-routes
		"192.0.2.1",      // IPv4 address, same
		"2001:db8::/129", // impossible mask
		"not-a-prefix",   // not an address at all
		"he6",            // an interface name; that is -tun-ipv6-allow
		",",              // all separators, no prefix
		" , ",            // the same with whitespace
	} {
		if _, err := ParseIPv6Routes(spec); err == nil {
			t.Errorf("ParseIPv6Routes(%q) = nil error, want a rejection", spec)
		}
	}

	// A stray separator next to a real entry is not fatal: the prefix the
	// operator wrote is unambiguous, so it is taken rather than refused.
	spec, err := ParseIPv6Routes("2001:db8::/32,,")
	if err != nil {
		t.Fatalf("a trailing separator should not be fatal: %v", err)
	}
	nets, err := spec.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if len(nets) != 1 || nets[0].String() != "2001:db8::/32" {
		t.Errorf("got %v, want just 2001:db8::/32", nets)
	}
}

// TestIPv6RouteSpecString keeps the log honest: it is read to find out what the
// kernel was told, so it has to name the resolved set rather than the constant.
func TestIPv6RouteSpecString(t *testing.T) {
	unset, _ := ParseIPv6Routes("")
	if got := unset.String(); got != "::/1,8000::/1" {
		t.Errorf("unset spec prints %q, want the half-defaults", got)
	}
	none, _ := ParseIPv6Routes("none")
	if got := none.String(); got != "none" {
		t.Errorf("none spec prints %q", got)
	}
	list, _ := ParseIPv6Routes("2001:db8::/32")
	if got := list.String(); got != "2001:db8::/32" {
		t.Errorf("list spec prints %q", got)
	}
}

// TestNetsReturnsACopy guards the shared backing array: EnableDualStack stores
// what Nets returns in t.routes6 and DisableIPv6 later walks it, so handing out
// the spec's own slice would let one tunnel's teardown reorder another's.
func TestNetsReturnsACopy(t *testing.T) {
	spec, err := ParseIPv6Routes("2001:db8::/32,2001:db9::/48")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	first, err := spec.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	first[0] = nil
	second, err := spec.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if second[0] == nil {
		t.Error("Nets returned the spec's own slice; mutating one caller's copy changed the next")
	}
}

// --- the ruhop and the laptop, at the level the device actually decides ---

// TestRuhopConfigKeepsItsOwnDefault is the configuration this flag exists for:
// a node with a Hurricane Electric 6in4 tunnel and several tiredvpn clients,
// each of which used to install ::/1 + 8000::/1 into the main table and beat
// `default dev he6` on prefix length.
//
// Two things have to hold together, and both are checked because either alone
// still leaves the node without IPv6: the tunnel claims no destination, and the
// blanket leak block does not fire when an exit declines dual-stack.
func TestRuhopConfigKeepsItsOwnDefault(t *testing.T) {
	spec, err := ParseIPv6Routes("none")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dev := &TUNDevice{name: "tiredvpn-usa"}
	applyIPv6BlockConfig(dev, VPNConfig{
		IPv6Policy: IPv6PolicyDual,
		ServerAddr: "203.0.113.10:443",
		IPv6Routes: spec,
	})

	nets, err := dev.ipv6Routes.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if len(nets) != 0 {
		t.Errorf("the tunnel claims %v; on this node that steals `default dev he6`", nets)
	}
	if dev.wantsIPv6Block() {
		t.Error("the leak block still applies; on this node it rejects the host's own he6 traffic")
	}
}

// TestUserConfigStillLosesItsIPv6Default is the symmetric case and the reason
// the default cannot simply be flipped: on a laptop the half-defaults are
// wanted. Without them a v4-only tunnel is bypassed by every application with a
// working v6 default route, which is issue #55.
func TestUserConfigStillLosesItsIPv6Default(t *testing.T) {
	dev := &TUNDevice{name: "tiredvpn0"}
	applyIPv6BlockConfig(dev, VPNConfig{
		IPv6Policy: IPv6PolicyDual,
		ServerAddr: "203.0.113.10:443",
		// No IPv6Routes: the zero value, i.e. the flag was not given.
	})

	nets, err := dev.ipv6Routes.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	got := make([]string, 0, len(nets))
	for _, n := range nets {
		got = append(got, n.String())
	}
	if strings.Join(got, ",") != strings.Join(dualStackRouteCIDRs, ",") {
		t.Errorf("default config claims %v, want the half-defaults %v", got, dualStackRouteCIDRs)
	}
	if !dev.wantsIPv6Block() {
		t.Error("the leak block stopped applying to a plain client; that is issue #55 back")
	}
	// The half-defaults have to beat an RA-learned ::/0, which they do on
	// prefix length alone. Assert the property rather than the constant, since
	// the constant is what a regression would rewrite.
	for _, n := range nets {
		ones, _ := n.Mask.Size()
		if ones == 0 {
			t.Errorf("%s is a /0 and would tie with the host's default instead of beating it", n)
		}
	}
}

// TestBlockGateIgnoresAnExplicitList checks the gate reads "did the operator
// name the destinations", not "is the list empty": a narrow list leaves most of
// IPv6 outside the tunnel by the operator's own choice, and a blanket reject
// would cut exactly that.
func TestBlockGateIgnoresAnExplicitList(t *testing.T) {
	spec, err := ParseIPv6Routes("2001:db8::/32")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dev := &TUNDevice{name: "tiredvpn0", ipv6Policy: IPv6PolicyDual}
	dev.SetIPv6Routes(spec)
	if dev.wantsIPv6Block() {
		t.Error("a narrow -tun-routes6 list still armed the blanket block")
	}
}

// TestBlockPolicyStillBlocksWithoutTheFlag pins the other half: -tun-ipv6=block
// is unaffected as long as the operator did not take routing over.
func TestBlockPolicyStillBlocksWithoutTheFlag(t *testing.T) {
	dev := &TUNDevice{name: "tiredvpn0", ipv6Policy: IPv6PolicyBlock}
	if !dev.wantsIPv6Block() {
		t.Error("-tun-ipv6=block stopped blocking")
	}
}

// --- the call sites ---

// TestEnableDualStackReadsTheSpec is the test that survives the mistake this
// change is most likely to make: a spec parsed correctly, stored correctly,
// covered by its own tests, and then not consulted by the one function that
// installs routes. Every assertion above would pass with EnableDualStack still
// calling dualStackRouteNets() and putting ::/1 on the ruhop node.
//
// Installing routes for real needs netlink and root, so the binding is checked
// in the source instead: the function must reach the destinations through
// ipv6Routes and must not name the package-level constants.
func TestEnableDualStackReadsTheSpec(t *testing.T) {
	for _, c := range []struct {
		file string
		fn   string
	}{
		{"tun_linux.go", "EnableDualStack"},
		{"tun_darwin.go", "EnableDualStack"},
		// Install and delete have to agree about which destinations exist:
		// re-deriving the list on teardown is how a delete ends up looking for
		// a route that was never added.
		{"tun_darwin.go", "DisableIPv6"},
	} {
		t.Run(c.file+"."+c.fn, func(t *testing.T) {
			body := funcBodySource(t, c.file, c.fn)
			if !strings.Contains(body, "routes6") && !strings.Contains(body, "ipv6Routes") {
				t.Errorf("%s.%s does not consult the -tun-routes6 spec at all", c.file, c.fn)
			}
			for _, forbidden := range []string{"dualStackRouteNets", "dualStackRouteCIDRs"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("%s.%s still reaches the routes through %s, so -tun-routes6 does not reach the kernel",
						c.file, c.fn, forbidden)
				}
			}
		})
	}
}

// TestApplyIPv6ConfigCarriesTheRouteSpec closes the gap between the flag and
// the device, the step that has been wrong before in this tree: a value parsed
// correctly and then not passed on behaves exactly like a value never given.
func TestApplyIPv6ConfigCarriesTheRouteSpec(t *testing.T) {
	spec, err := ParseIPv6Routes("2001:db8::/32")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dev := &TUNDevice{name: "tiredvpn0"}
	applyIPv6BlockConfig(dev, VPNConfig{IPv6Policy: IPv6PolicyDual, IPv6Routes: spec})

	nets, err := dev.ipv6Routes.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if len(nets) != 1 || nets[0].String() != "2001:db8::/32" {
		t.Errorf("device holds %v; the config's route spec did not reach it", nets)
	}
}

// funcBodySource returns the source text of one top-level function or method
// body, so a test can assert what it does and does not reference.
func funcBodySource(t *testing.T, file, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("%s not found in %s", name, file)
	return ""
}
