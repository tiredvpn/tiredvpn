package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// dialTargets returns the addresses the dialer is handed for cfg, in order:
// the endpoint list the client resolves, expanded by the selector's own
// candidate builder. Candidate.Addr is the exact string the selector passes to
// Dial and the connectivity gate passes to net.Dial, so this is the value that
// decides whether the connect can work at all.
func dialTargets(t *testing.T, cfg *client.Config) []string {
	t.Helper()
	eps, err := client.ResolveEndpoints(cfg)
	if err != nil {
		t.Fatalf("ResolveEndpoints: %v", err)
	}
	sel, err := endpoint.NewSelector(endpoint.Config{Endpoints: eps, Family: endpoint.PreferV6})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	var out []string
	for _, c := range sel.Candidates() {
		out = append(out, c.Addr)
	}
	return out
}

// v6Target picks the IPv6 candidate out of dialTargets' result.
func v6Target(t *testing.T, targets []string) string {
	t.Helper()
	for _, a := range targets {
		if strings.Contains(a, "2001:db8") {
			return a
		}
	}
	t.Fatalf("no IPv6 candidate in %q", targets)
	return ""
}

// addrInputs is the table every path below is driven with. port is the port
// the server listens on for both families, which is what -server carries and
// what port_v6 defaults to.
var addrInputs = []struct {
	name   string
	v6     string
	wantV6 string
}{
	{"bare v6 literal", "2001:db8::2", "[2001:db8::2]:995"},
	{"bracketed v6 without port", "[2001:db8::2]", "[2001:db8::2]:995"},
	{"bracketed v6 with port", "[2001:db8::2]:8443", "[2001:db8::2]:8443"},
}

// TestSingleServerV6_AndroidArgv is the bug as it was found: the app with one
// server passes -server host:port and -server-v6 exactly as the user typed it,
// usually the bare address. The candidate must come out as [v6]:port, never as
// the bare literal (which logs as "2001:db8::2/v6" and fails every dial).
func TestSingleServerV6_AndroidArgv(t *testing.T) {
	for _, tc := range addrInputs {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseClientArgs([]string{
				"-server", "203.0.113.10:995",
				"-server-v6", tc.v6,
				"-prefer-ipv6", "true",
				"-fallback-v4", "true",
			})
			if err != nil {
				t.Fatalf("parseClientArgs: %v", err)
			}
			got := dialTargets(t, cfg)
			want := []string{tc.wantV6, "203.0.113.10:995"}
			if !slices.Equal(got, want) {
				t.Fatalf("dial targets = %q, want %q", got, want)
			}
			if cfg.ServerAddrV6 != tc.wantV6 {
				// ServerAddrV6 is read by the TUN bypass and the startup log
				// after ResolveEndpoints; it must carry the same normalised form.
				t.Fatalf("cfg.ServerAddrV6 = %q after resolve, want %q", cfg.ServerAddrV6, tc.wantV6)
			}
		})
	}
}

// TestSingleServerV6_SameAsPool: one server and a pool of N must produce the
// same candidate for the same input. The pool path is the one that worked on
// the device, so it is the reference.
func TestSingleServerV6_SameAsPool(t *testing.T) {
	for _, tc := range addrInputs {
		t.Run(tc.name, func(t *testing.T) {
			pool := writeClientTOML(t, fmt.Sprintf(`
[[servers]]
name = "a"
address = "203.0.113.10"
port = 995
address_v6 = %q

[[servers]]
name = "b"
address = "198.51.100.20"
port = 995
`, tc.v6))
			pcfg, err := parseClientArgs([]string{"-config", pool})
			if err != nil {
				t.Fatalf("parseClientArgs(pool): %v", err)
			}
			poolV6 := v6Target(t, dialTargets(t, pcfg))

			scfg, err := parseClientArgs([]string{"-server", "203.0.113.10:995", "-server-v6", tc.v6})
			if err != nil {
				t.Fatalf("parseClientArgs(single): %v", err)
			}
			singleV6 := v6Target(t, dialTargets(t, scfg))

			if poolV6 != tc.wantV6 || singleV6 != tc.wantV6 {
				t.Fatalf("pool v6 = %q, single v6 = %q, want both %q", poolV6, singleV6, tc.wantV6)
			}
		})
	}
}

// TestSingleServerV6_DesktopTOML covers the desktop shapes: a config file with
// one [[servers]] entry carrying address_v6, the same file with -server-v6 on
// top of it, and plain flags with no file (runClient binds -server-v6 straight
// into cfg.ServerAddrV6, which is the literal below).
func TestSingleServerV6_DesktopTOML(t *testing.T) {
	for _, tc := range addrInputs {
		t.Run(tc.name+"/file", func(t *testing.T) {
			path := writeClientTOML(t, fmt.Sprintf(`
[[servers]]
name = "only"
address = "203.0.113.10"
port = 995
address_v6 = %q
`, tc.v6))
			fs := clientFlagSetForTOML()
			if err := fs.Parse(nil); err != nil {
				t.Fatal(err)
			}
			cfg := &client.Config{PreferIPv6: true, FallbackToV4: true}
			if err := applyClientTOMLConfig(cfg, path, fs); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if got := v6Target(t, dialTargets(t, cfg)); got != tc.wantV6 {
				t.Fatalf("v6 target = %q, want %q", got, tc.wantV6)
			}
		})
		t.Run(tc.name+"/file+flag", func(t *testing.T) {
			path := writeClientTOML(t, `
[[servers]]
name = "only"
address = "203.0.113.10"
port = 995
`)
			fs := clientFlagSetForTOML()
			if err := fs.Parse([]string{"-server-v6", tc.v6}); err != nil {
				t.Fatal(err)
			}
			cfg := &client.Config{PreferIPv6: true, FallbackToV4: true}
			if err := applyClientTOMLConfig(cfg, path, fs); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if got := v6Target(t, dialTargets(t, cfg)); got != tc.wantV6 {
				t.Fatalf("v6 target = %q, want %q", got, tc.wantV6)
			}
		})
		t.Run(tc.name+"/flags", func(t *testing.T) {
			cfg := &client.Config{ServerAddr: "203.0.113.10:995", ServerAddrV6: tc.v6, PreferIPv6: true, FallbackToV4: true}
			if got := v6Target(t, dialTargets(t, cfg)); got != tc.wantV6 {
				t.Fatalf("v6 target = %q, want %q", got, tc.wantV6)
			}
		})
	}
}

// TestSingleServerV4_SameAsPool is the other half of the input table: the IPv4
// slot with and without a port, by address and by name. One server and a pool
// must agree here too, and a slot without a port takes the other family's.
func TestSingleServerV4_SameAsPool(t *testing.T) {
	cases := []struct {
		name, v4, want string
	}{
		{"v4", "203.0.113.10", "203.0.113.10:995"},
		{"v4:port", "203.0.113.10:8443", "203.0.113.10:8443"},
		{"hostname", "vpn.example.org", "vpn.example.org:995"},
		{"hostname:port", "vpn.example.org:8443", "vpn.example.org:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := writeClientTOML(t, fmt.Sprintf(`
[[servers]]
name = "a"
address = %q
port = 995
address_v6 = "2001:db8::2"

[[servers]]
name = "b"
address = "198.51.100.20"
port = 995
`, tc.v4))
			pcfg, err := parseClientArgs([]string{"-config", pool})
			if err != nil {
				t.Fatalf("parseClientArgs(pool): %v", err)
			}
			pt := dialTargets(t, pcfg)

			scfg, err := parseClientArgs([]string{"-server", tc.v4, "-server-v6", "[2001:db8::2]:995"})
			if err != nil {
				t.Fatalf("parseClientArgs(single): %v", err)
			}
			st := dialTargets(t, scfg)

			want := []string{"[2001:db8::2]:995", tc.want}
			if !slices.Equal(st, want) || !slices.Equal(pt[:2], want) {
				t.Fatalf("single = %q, pool = %q, want both to start with %q", st, pt, want)
			}
		})
	}
}

// TestSingleServer_NoPortAnywhere: with no port on either family there is
// nothing to default from. That has to be a startup error naming the address,
// not a candidate that fails every dial and reads as "No TCP connectivity".
func TestSingleServer_NoPortAnywhere(t *testing.T) {
	cfg, err := parseClientArgs([]string{"-server", "203.0.113.10", "-server-v6", "2001:db8::2"})
	if err != nil {
		t.Fatalf("parseClientArgs: %v", err)
	}
	if _, err := client.ResolveEndpoints(cfg); err == nil || !strings.Contains(err.Error(), "no port") {
		t.Fatalf("ResolveEndpoints error = %v, want one about the missing port", err)
	}
}
