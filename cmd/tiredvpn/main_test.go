package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/server"
)

// TestVersion_DefaultIsDev guards against accidental hardcoding of a release
// version in source. Release artifacts override this via -ldflags.
func TestVersion_DefaultIsDev(t *testing.T) {
	if version != "dev" {
		t.Fatalf("default version = %q, want %q (release builds inject the tag via -ldflags)", version, "dev")
	}
}

// TestApplyClientTOMLConfig_EmptyPath_NoOp verifies that omitting --config
// leaves the existing CLI-derived client.Config untouched (legacy code path).
func TestApplyClientTOMLConfig_EmptyPath_NoOp(t *testing.T) {
	cfg := &client.Config{ServerAddr: "from-cli:1234", StrategyName: "morph"}
	fs := flag.NewFlagSet("client", flag.ContinueOnError)

	if err := applyClientTOMLConfig(cfg, "", fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerAddr != "from-cli:1234" || cfg.StrategyName != "morph" {
		t.Fatalf("config mutated by no-op call: %+v", cfg)
	}
	if cfg.Shaper != nil {
		t.Fatalf("shaper unexpectedly set: %v", cfg.Shaper)
	}
}

// TestApplyServerTOMLConfig_EmptyPath_NoOp mirrors the client test for server.
func TestApplyServerTOMLConfig_EmptyPath_NoOp(t *testing.T) {
	cfg := &server.Config{ListenAddr: ":443", CertFile: "x.crt", KeyFile: "x.key"}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	if err := applyServerTOMLConfig(cfg, "", fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":443" || cfg.CertFile != "x.crt" || cfg.KeyFile != "x.key" {
		t.Fatalf("config mutated by no-op call: %+v", cfg)
	}
}

// TestApplyClientTOMLConfig_AppliesFields verifies a minimal valid client
// config is mapped onto runtime fields (server address, strategy mode,
// shaper).
func TestApplyClientTOMLConfig_AppliesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	body := `
[server]
address = "vpn.example.org"
port = 8443

[strategy]
mode = "morph"

[shaper]
preset = "youtube_streaming"

[tls]

[logging]
level = "info"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &client.Config{}
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	if err := applyClientTOMLConfig(cfg, path, fs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, want := cfg.ServerAddr, "vpn.example.org:8443"; got != want {
		t.Errorf("ServerAddr = %q, want %q", got, want)
	}
	if got, want := cfg.StrategyName, "morph"; got != want {
		t.Errorf("StrategyName = %q, want %q", got, want)
	}
	if cfg.Shaper == nil {
		t.Errorf("Shaper = nil, want non-nil for preset=youtube_streaming")
	}
}

// TestApplyClientTOMLConfig_InvalidTOML surfaces a clear error path so the
// CLI can fail-fast with a useful message.
func TestApplyClientTOMLConfig_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.toml")
	if err := os.WriteFile(path, []byte("not = valid = toml = content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &client.Config{}
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	if err := applyClientTOMLConfig(cfg, path, fs); err == nil {
		t.Fatal("expected error for malformed TOML, got nil")
	}
}
