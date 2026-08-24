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

// TestRegisterServerFlags_REALITYCoverDomain guards issue #50.2: the
// REALITYCoverDomain config field is consumed in reality.go but was never bound
// to any flag, leaving it permanently empty (dead code). This asserts the
// -reality-cover-domain flag wires an operator-set value onto Config.
func TestRegisterServerFlags_REALITYCoverDomain(t *testing.T) {
	cfg := &server.Config{}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	registerServerFlags(fs, cfg)

	// Default must stay empty (empty = silently drop; SSRF-safe no-op).
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse (defaults): %v", err)
	}
	if cfg.REALITYCoverDomain != "" {
		t.Fatalf("default REALITYCoverDomain = %q, want empty", cfg.REALITYCoverDomain)
	}

	cfg = &server.Config{}
	fs = flag.NewFlagSet("server", flag.ContinueOnError)
	registerServerFlags(fs, cfg)
	if err := fs.Parse([]string{"-reality-cover-domain", "www.microsoft.com"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.REALITYCoverDomain != "www.microsoft.com" {
		t.Fatalf("REALITYCoverDomain = %q, want %q", cfg.REALITYCoverDomain, "www.microsoft.com")
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

// TestRegisterServerFlags_REALITYB1 guards the same failure mode as the
// cover-domain test above: a config field consumed by the server but bound to
// no flag is dead weight nobody notices. These five are the whole operator
// surface of B1, so each is checked for both its default and a set value.
func TestRegisterServerFlags_REALITYB1(t *testing.T) {
	cfg := &server.Config{}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	registerServerFlags(fs, cfg)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse (defaults): %v", err)
	}

	// B1 defaults off while its handler is a stub: on would make a server
	// without a static key refuse to start, for a code path that does nothing.
	if cfg.REALITYB1Enabled {
		t.Error("default -reality-b1 = true; turning it on brings the static-key requirement with it")
	}
	if !cfg.REALITYLegacyEnabled {
		t.Error("default -reality-legacy = false; every existing client speaks the legacy transport")
	}
	if cfg.REALITYMaxTimeDiff != 300 {
		t.Errorf("default -reality-max-time-diff = %d, want 300", cfg.REALITYMaxTimeDiff)
	}
	if cfg.REALITYMirrorMode != "off" {
		t.Errorf("default -reality-mirror = %q, want off", cfg.REALITYMirrorMode)
	}
	if cfg.REALITYPrivateKey != "" || cfg.REALITYMinClientVer != "" {
		t.Error("key and min-version must default to empty")
	}

	cfg = &server.Config{}
	fs = flag.NewFlagSet("server", flag.ContinueOnError)
	registerServerFlags(fs, cfg)
	err := fs.Parse([]string{
		"-reality-b1",
		"-reality-legacy=false",
		"-reality-private-key", "dGVzdA",
		"-reality-max-time-diff", "60",
		"-reality-min-client-ver", "1.4.0",
		"-reality-mirror", "adaptive",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.REALITYB1Enabled || cfg.REALITYLegacyEnabled {
		t.Error("transport switches did not take")
	}
	if cfg.REALITYPrivateKey != "dGVzdA" || cfg.REALITYMinClientVer != "1.4.0" {
		t.Errorf("string flags did not take: %+v", cfg)
	}
	if cfg.REALITYMaxTimeDiff != 60 || cfg.REALITYMirrorMode != "adaptive" {
		t.Errorf("skew/mirror flags did not take: %+v", cfg)
	}
}

// TestRegisterClientFlags_REALITYServerPubKey checks the client half of the
// pair. Empty means the legacy transport, so the default carries meaning.
func TestRegisterClientFlags_REALITYServerPubKey(t *testing.T) {
	cfg := &client.Config{}
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	registerClientREALITYFlags(fs, cfg)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse (defaults): %v", err)
	}
	if cfg.REALITYServerPubKey != "" {
		t.Fatalf("default = %q, want empty (legacy transport)", cfg.REALITYServerPubKey)
	}

	cfg = &client.Config{}
	fs = flag.NewFlagSet("client", flag.ContinueOnError)
	registerClientREALITYFlags(fs, cfg)
	if err := fs.Parse([]string{"-reality-server-pubkey", "cHVia2V5"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.REALITYServerPubKey != "cHVia2V5" {
		t.Fatalf("REALITYServerPubKey = %q, want %q", cfg.REALITYServerPubKey, "cHVia2V5")
	}
}
