package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/client"
)

func writeClientTOML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func clientFlagSetForTOML() *flag.FlagSet {
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

// TestApplyClientTOMLConfig_ServerList checks the whole mapping the runtime
// depends on: addresses joined into host:port, order preserved, and
// cfg.ServerAddr pointing at the first entry (the "-server is required" check
// and the startup log both read it before the client resolves endpoints).
func TestApplyClientTOMLConfig_ServerList(t *testing.T) {
	path := writeClientTOML(t, `
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

[selection]
policy = "priority"
family = "prefer_v6"
failure_threshold = 3
cooldown = "90s"
max_cooldown = "10m"
min_dwell = "4m"
health_check = "off"
`)
	cfg := &client.Config{}
	if err := applyClientTOMLConfig(cfg, path, clientFlagSetForTOML()); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "ams" || cfg.Servers[1].Name != "fra" {
		t.Fatalf("order not preserved: %+v", cfg.Servers)
	}
	if cfg.Servers[0].Addr != "203.0.113.10:443" {
		t.Errorf("ams addr = %q", cfg.Servers[0].Addr)
	}
	// IPv6 has to arrive bracketed: that is the form the transport, the
	// connectivity gate and the TUN bypass all expect.
	if cfg.Servers[0].AddrV6 != "[2001:db8::10]:443" {
		t.Errorf("ams v6 addr = %q, want it bracketed with the inherited port", cfg.Servers[0].AddrV6)
	}
	if cfg.Servers[1].Addr != "203.0.113.20:8443" || cfg.Servers[1].AddrV6 != "" {
		t.Errorf("fra = %+v", cfg.Servers[1])
	}
	if cfg.ServerAddr != "203.0.113.10:443" || cfg.ServerAddrV6 != "[2001:db8::10]:443" {
		t.Errorf("ServerAddr/V6 = %q / %q, want the first entry", cfg.ServerAddr, cfg.ServerAddrV6)
	}

	sel := cfg.Selection
	if sel.Policy != "priority" || sel.Family != "prefer_v6" || sel.FailureThreshold != 3 {
		t.Errorf("selection = %+v", sel)
	}
	if sel.Cooldown != 90*time.Second || sel.MaxCooldown != 10*time.Minute || sel.MinDwell != 4*time.Minute {
		t.Errorf("selection durations = %+v", sel)
	}
	if sel.HealthCheck != "off" {
		t.Errorf("health_check = %q", sel.HealthCheck)
	}
}

// TestApplyClientTOMLConfig_SingleServerBlock: a lone [server] is a
// one-element list, and the legacy ServerAddr mapping is unchanged.
func TestApplyClientTOMLConfig_SingleServerBlock(t *testing.T) {
	path := writeClientTOML(t, "[server]\naddress = \"vpn.example.org\"\nport = 8443\naddress_v6 = \"2001:db8::1\"\n")
	cfg := &client.Config{}
	if err := applyClientTOMLConfig(cfg, path, clientFlagSetForTOML()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(cfg.Servers))
	}
	if cfg.ServerAddr != "vpn.example.org:8443" {
		t.Errorf("ServerAddr = %q", cfg.ServerAddr)
	}
	if cfg.ServerAddrV6 != "[2001:db8::1]:8443" {
		t.Errorf("ServerAddrV6 = %q, want port_v6 to follow port", cfg.ServerAddrV6)
	}
}

// TestApplyClientTOMLConfig_FlagCollapsesList is the CLI-beats-file path all
// the way through: -server leaves exactly one endpoint, and it is the one the
// flag names.
func TestApplyClientTOMLConfig_FlagCollapsesList(t *testing.T) {
	path := writeClientTOML(t, `
[[servers]]
name = "ams"
address = "203.0.113.10"

[[servers]]
name = "fra"
address = "203.0.113.20"
`)
	fs := clientFlagSetForTOML()
	if err := fs.Parse([]string{"-server", "198.51.100.1:9443"}); err != nil {
		t.Fatal(err)
	}
	cfg := &client.Config{}
	if err := applyClientTOMLConfig(cfg, path, fs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("got %d servers, want the list collapsed to 1: %+v", len(cfg.Servers), cfg.Servers)
	}
	if cfg.Servers[0].Addr != "198.51.100.1:9443" || cfg.ServerAddr != "198.51.100.1:9443" {
		t.Fatalf("collapsed to %+v / %q", cfg.Servers[0], cfg.ServerAddr)
	}
}

// TestApplyClientTOMLConfig_SelectionAbsentKeepsFlagValue: a file that says
// nothing about selection must not wipe what -server-policy set.
func TestApplyClientTOMLConfig_SelectionAbsentKeepsFlagValue(t *testing.T) {
	path := writeClientTOML(t, "[server]\naddress = \"vpn.example.org\"\n")
	cfg := &client.Config{Selection: client.SelectionSpec{Policy: "latency"}}
	if err := applyClientTOMLConfig(cfg, path, clientFlagSetForTOML()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cfg.Selection.Policy != "latency" {
		t.Fatalf("policy = %q, want the pre-set value to survive a silent file", cfg.Selection.Policy)
	}
}

// TestApplyClientTOMLConfig_NoConfigLeavesServersEmpty is the fleet's path:
// no -config at all, so nothing in this file runs and the legacy single
// address stands.
func TestApplyClientTOMLConfig_NoConfigLeavesServersEmpty(t *testing.T) {
	cfg := &client.Config{ServerAddr: "203.0.113.10:995"}
	if err := applyClientTOMLConfig(cfg, "", clientFlagSetForTOML()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Fatalf("a client without -config must have no server list, got %+v", cfg.Servers)
	}
	if cfg.ServerAddr != "203.0.113.10:995" {
		t.Fatalf("ServerAddr = %q", cfg.ServerAddr)
	}
}

func TestScanArgValue(t *testing.T) {
	args := []string{"-android", "-config", "/etc/tiredvpn/client.toml", "-server", "host:443"}
	if got := scanArgValue(args, "-config"); got != "/etc/tiredvpn/client.toml" {
		t.Fatalf("scanArgValue = %q", got)
	}
	if got := scanArgValue(args, "-secret"); got != "" {
		t.Fatalf("missing flag returned %q", got)
	}
	// A trailing flag with no value must not read past the end.
	if got := scanArgValue([]string{"-config"}, "-config"); got != "" {
		t.Fatalf("dangling flag returned %q", got)
	}
}

func TestCollapseServers(t *testing.T) {
	list := []client.ServerSpec{
		{Name: "ams", Addr: "203.0.113.10:443", AddrV6: "[2001:db8::10]:443", Secret: "shared"},
		{Name: "fra", Addr: "203.0.113.20:443"},
	}

	got := collapseServers(list, "198.51.100.1:9443", "")
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Addr != "198.51.100.1:9443" {
		t.Errorf("addr = %q", got[0].Addr)
	}
	// Only the addresses are replaced; the rest of entry 0 survives.
	if got[0].Name != "ams" || got[0].Secret != "shared" || got[0].AddrV6 != "[2001:db8::10]:443" {
		t.Errorf("entry lost its other fields: %+v", got[0])
	}

	if got := collapseServers(nil, "198.51.100.1:9443", ""); got != nil {
		t.Errorf("collapsing an empty list = %+v, want nil", got)
	}
}
