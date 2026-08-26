package toml

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTOML drops body into a temp file and returns its path.
func writeTOML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newFullClientFlagSet mirrors every client flag that participates in the
// server-list mapping. Tests that go through ResolveClient need the real set:
// familyFromLegacyFlags reads -fallback-v4 even when only -prefer-ipv6 was
// passed, so a FlagSet missing one of them would exercise a shape the binary
// never has.
func newFullClientFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.String("server", "", "Remote server address (host:port)")
	fs.String("server-v6", "", "Server IPv6 address")
	fs.String("server-policy", "", "Server selection policy")
	fs.Bool("prefer-ipv6", true, "Prefer IPv6 transport if available")
	fs.Bool("fallback-v4", true, "Fallback to IPv4 if IPv6 fails")
	fs.String("strategy", "", "Force specific strategy")
	fs.Bool("debug", false, "Enable debug logging")
	return fs
}

// TestExampleConfigStillLoads is the regression that matters most: the shipped
// template is what operators copy, and a schema change that invalidates it
// breaks them at startup, not at review time.
func TestExampleConfigStillLoads(t *testing.T) {
	c, err := LoadClient(filepath.Join("..", "..", "..", "configs", "client.example.toml"))
	if err != nil {
		t.Fatalf("configs/client.example.toml no longer loads: %v", err)
	}
	list := c.ServerList()
	if len(list) != 1 || list[0].Address != "vpn.example.org" || list[0].Port != 443 {
		t.Fatalf("example resolves to %+v, want the single vpn.example.org:443 endpoint", list)
	}
}

func TestServerList_PreservesOrderAndDefaults(t *testing.T) {
	path := writeTOML(t, `
[[servers]]
name = "ams"
address = "203.0.113.10"
port = 443
address_v6 = "2001:db8::10"
weight = 100

[[servers]]
name = "fra"
address = "203.0.113.20"
port = 8443

[[servers]]
name = "v6only"
address_v6 = "2001:db8::30"
port_v6 = 995
`)
	c, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	list := c.ServerList()
	if len(list) != 3 {
		t.Fatalf("got %d entries, want 3", len(list))
	}
	if list[0].Name != "ams" || list[1].Name != "fra" || list[2].Name != "v6only" {
		t.Fatalf("order not preserved: %s, %s, %s", list[0].Name, list[1].Name, list[2].Name)
	}
	// port_v6 follows port when omitted...
	if list[0].PortV6 != 443 {
		t.Errorf("ams port_v6 = %d, want it to follow port (443)", list[0].PortV6)
	}
	// ...and port itself defaults to 443 when the entry names only IPv6.
	if list[2].Port != DefaultPort || list[2].PortV6 != 995 {
		t.Errorf("v6only ports = %d/%d, want %d/995", list[2].Port, list[2].PortV6, DefaultPort)
	}
}

func TestValidate_ServerAndServersAreExclusive(t *testing.T) {
	path := writeTOML(t, `
[server]
address = "vpn.example.org"
port = 443

[[servers]]
name = "ams"
address = "203.0.113.10"
`)
	_, err := LoadClient(path)
	if err == nil {
		t.Fatal("[server] together with [[servers]] must be rejected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error should say why, got: %v", err)
	}
}

func TestValidate_ServersRules(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "entry without any address",
			body: "[[servers]]\nname = \"empty\"\nport = 443\n",
			want: "address or address_v6 is required",
		},
		{
			name: "port out of range",
			body: "[[servers]]\naddress = \"203.0.113.10\"\nport = 70000\n",
			want: "1..65535",
		},
		{
			name: "v6 port out of range",
			body: "[[servers]]\naddress_v6 = \"2001:db8::10\"\nport_v6 = -1\n",
			want: "port_v6",
		},
		{
			name: "duplicate names",
			body: "[[servers]]\nname = \"ams\"\naddress = \"203.0.113.10\"\n\n[[servers]]\nname = \"ams\"\naddress = \"203.0.113.20\"\n",
			want: "duplicate server name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadClient(writeTOML(t, tc.body))
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestValidate_StrategyModeOptional pins the loosening: an empty mode means
// "let the manager choose", which is unreachable from a config file as long as
// Validate demands one.
func TestValidate_StrategyModeOptional(t *testing.T) {
	c, err := LoadClient(writeTOML(t, "[server]\naddress = \"vpn.example.org\"\nport = 443\n"))
	if err != nil {
		t.Fatalf("a config without [strategy] must load, got: %v", err)
	}
	if c.Strategy.Mode != "" {
		t.Fatalf("strategy.mode = %q, want empty", c.Strategy.Mode)
	}
}

func TestSelection_StrictRejectsTypo(t *testing.T) {
	path := writeTOML(t, `
[server]
address = "vpn.example.org"

[selection]
policy = "priority"
cooldwon = "1m"
`)
	_, err := LoadClient(path)
	if err == nil {
		t.Fatal("a misspelled [selection] key must fail the load, not be ignored")
	}
	if !strings.Contains(err.Error(), "cooldwon") {
		t.Fatalf("error should name the offending key, got: %v", err)
	}
}

func TestSelection_Resolve(t *testing.T) {
	t.Run("nil block resolves to defaults", func(t *testing.T) {
		var s *Selection
		got, err := s.Resolve()
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != (ResolvedSelection{}) {
			t.Fatalf("nil selection resolved to %+v, want the zero value", got)
		}
	})

	t.Run("durations parse", func(t *testing.T) {
		s := &Selection{Cooldown: "90s", MaxCooldown: "30m", MinDwell: "5m", RecheckInterval: "1h"}
		got, err := s.Resolve()
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got.Cooldown != 90*time.Second || got.MaxCooldown != 30*time.Minute ||
			got.MinDwell != 5*time.Minute || got.RecheckInterval != time.Hour {
			t.Fatalf("durations = %+v", got)
		}
	})

	bad := []struct {
		name string
		sel  Selection
		want string
	}{
		{"unknown policy", Selection{Policy: "fastest"}, "selection.policy"},
		{"unknown family", Selection{Family: "prefer_v5"}, "selection.family"},
		{"unknown health check", Selection{HealthCheck: "sometimes"}, "selection.health_check"},
		{"unparsable duration", Selection{Cooldown: "1 minute"}, "selection.cooldown"},
		{"negative duration", Selection{MinDwell: "-5m"}, "must not be negative"},
		{"negative threshold", Selection{FailureThreshold: -1}, "failure_threshold"},
		{"ceiling below floor", Selection{Cooldown: "10m", MaxCooldown: "1m"}, "shorter than"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			sel := tc.sel
			if _, err := sel.Resolve(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resolve() = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// TestServerFlagCollapsesList pins the documented override: a single address
// on the command line beats a list in the file, and says so.
func TestServerFlagCollapsesList(t *testing.T) {
	path := writeTOML(t, `
[[servers]]
name = "ams"
address = "203.0.113.10"
port = 443
address_v6 = "2001:db8::10"
secret = "shared"

[[servers]]
name = "fra"
address = "203.0.113.20"
`)

	t.Run("-server keeps the first entry and replaces its address", func(t *testing.T) {
		fs := newFullClientFlagSet()
		if err := fs.Parse([]string{"-server", "198.51.100.1:9443"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := ResolveClient(path, fs)
		if err != nil {
			t.Fatalf("ResolveClient: %v", err)
		}
		if len(cfg.Servers) != 0 {
			t.Fatalf("list survived the flag: %+v", cfg.Servers)
		}
		list := cfg.ServerList()
		if len(list) != 1 {
			t.Fatalf("got %d endpoints, want 1", len(list))
		}
		if list[0].Address != "198.51.100.1" || list[0].Port != 9443 {
			t.Errorf("address = %s:%d, want 198.51.100.1:9443", list[0].Address, list[0].Port)
		}
		// The rest of entry 0 is carried over, not thrown away.
		if list[0].Name != "ams" || list[0].Secret != "shared" || list[0].AddressV6 != "2001:db8::10" {
			t.Errorf("entry 0 lost its other fields: %+v", list[0])
		}
	})

	// An entry that never spelled out port_v6 keeps following port, so
	// -server host:9443 moves the IPv6 port too. Pinned here because it is a
	// decision, not an accident: the alternative freezes an implicit value
	// that the file never stated.
	t.Run("-server carries the new port to an implicit port_v6", func(t *testing.T) {
		fs := newFullClientFlagSet()
		if err := fs.Parse([]string{"-server", "198.51.100.1:9443"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := ResolveClient(path, fs)
		if err != nil {
			t.Fatalf("ResolveClient: %v", err)
		}
		if got := cfg.ServerList()[0].PortV6; got != 9443 {
			t.Fatalf("port_v6 = %d, want it to follow the new port (9443)", got)
		}
	})

	t.Run("-server-v6 alone keeps the IPv4 address", func(t *testing.T) {
		fs := newFullClientFlagSet()
		if err := fs.Parse([]string{"-server-v6", "[2001:db8::99]:995"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := ResolveClient(path, fs)
		if err != nil {
			t.Fatalf("ResolveClient: %v", err)
		}
		list := cfg.ServerList()
		if len(list) != 1 {
			t.Fatalf("got %d endpoints, want 1", len(list))
		}
		if list[0].Address != "203.0.113.10" {
			t.Errorf("IPv4 address lost: %+v", list[0])
		}
		if list[0].AddressV6 != "2001:db8::99" || list[0].PortV6 != 995 {
			t.Errorf("v6 = %s/%d, want 2001:db8::99/995", list[0].AddressV6, list[0].PortV6)
		}
	})
}

// TestLegacyFamilyFlagMapping is the table from the plan, executed.
//
// The row that matters is -prefer-ipv6=false: it maps to v4_only, not
// prefer_v4, because today that flag means "IPv4 and do not probe IPv6 at
// all". Mapping it to prefer_v4 would hand those clients a fallback they never
// had.
func TestLegacyFamilyFlagMapping(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"neither flag passed leaves family unset", nil, ""},
		{"prefer true, fallback true", []string{"-prefer-ipv6=true", "-fallback-v4=true"}, "prefer_v6"},
		{"prefer true, fallback false", []string{"-prefer-ipv6=true", "-fallback-v4=false"}, "v6_only"},
		{"prefer false, fallback true", []string{"-prefer-ipv6=false", "-fallback-v4=true"}, "v4_only"},
		{"prefer false, fallback false", []string{"-prefer-ipv6=false", "-fallback-v4=false"}, "v4_only"},
		{"only prefer=false passed (fallback at default true)", []string{"-prefer-ipv6=false"}, "v4_only"},
		{"only fallback=false passed (prefer at default true)", []string{"-fallback-v4=false"}, "v6_only"},
		{"only prefer=true passed", []string{"-prefer-ipv6=true"}, "prefer_v6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFullClientFlagSet()
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			cfg := DefaultClient()
			cfg.Server.Address = "vpn.example.org"
			if err := ApplyClientFlags(cfg, fs); err != nil {
				t.Fatalf("ApplyClientFlags: %v", err)
			}
			got := ""
			if cfg.Selection != nil {
				got = cfg.Selection.Family
			}
			if got != tc.want {
				t.Fatalf("selection.family = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFamilyFlagDefaultsDoNotBeatTOML: both legacy flags default to true, so a
// client that never mentions them must not overwrite a family the file chose.
func TestFamilyFlagDefaultsDoNotBeatTOML(t *testing.T) {
	path := writeTOML(t, `
[server]
address = "vpn.example.org"

[selection]
family = "prefer_v4"
`)
	fs := newFullClientFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	cfg, err := ResolveClient(path, fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if cfg.Selection == nil || cfg.Selection.Family != "prefer_v4" {
		t.Fatalf("family = %+v, want prefer_v4 to survive untouched flag defaults", cfg.Selection)
	}
}

func TestServerPolicyFlag(t *testing.T) {
	fs := newFullClientFlagSet()
	if err := fs.Parse([]string{"-server-policy", "latency"}); err != nil {
		t.Fatal(err)
	}
	path := writeTOML(t, "[server]\naddress = \"vpn.example.org\"\n\n[selection]\npolicy = \"priority\"\n")
	cfg, err := ResolveClient(path, fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if cfg.Selection == nil || cfg.Selection.Policy != "latency" {
		t.Fatalf("policy = %+v, want the flag to win over the file", cfg.Selection)
	}

	fs = newFullClientFlagSet()
	if err := fs.Parse([]string{"-server-policy", "nonsense"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveClient(path, fs); err == nil {
		t.Fatal("an unknown -server-policy must be rejected, not silently ignored")
	}
}
