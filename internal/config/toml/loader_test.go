package toml

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	gotoml "github.com/pelletier/go-toml/v2"
)

func testdata(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", name)
}

func TestLoadClient_Minimal(t *testing.T) {
	c, err := LoadClient(testdata(t, "client_minimal.toml"))
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if c.Server.Address != "vpn.example.org" || c.Server.Port != 443 {
		t.Fatalf("server fields wrong: %+v", c.Server)
	}
	if c.Strategy.Mode != "reality" {
		t.Fatalf("strategy.mode: %q", c.Strategy.Mode)
	}
	if c.Shaper != nil {
		t.Fatalf("shaper should be nil when omitted, got %+v", c.Shaper)
	}
}

func TestLoadClient_Preset(t *testing.T) {
	c, err := LoadClient(testdata(t, "client_preset.toml"))
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if c.Shaper == nil || c.Shaper.Preset != "chrome_browsing" {
		t.Fatalf("preset not loaded: %+v", c.Shaper)
	}
	if c.Shaper.Seed == nil || *c.Shaper.Seed != 1234567890 {
		t.Fatalf("seed not loaded: %+v", c.Shaper.Seed)
	}
}

func TestLoadClient_Custom(t *testing.T) {
	c, err := LoadClient(testdata(t, "client_custom.toml"))
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if c.Shaper == nil || c.Shaper.Custom == nil {
		t.Fatalf("custom shaper not loaded")
	}
	ps := c.Shaper.Custom.PacketSize
	if ps == nil || ps.Type != DistHistogram || ps.Histogram == nil {
		t.Fatalf("packet_size histogram not loaded: %+v", ps)
	}
	if len(ps.Histogram.Bins) != 3 {
		t.Fatalf("expected 3 bins, got %d", len(ps.Histogram.Bins))
	}
	ia := c.Shaper.Custom.InterArrival
	if ia == nil || ia.Type != DistLogNormal || ia.LogNormal == nil {
		t.Fatalf("inter_arrival lognormal not loaded: %+v", ia)
	}
	if ia.LogNormal.Mu != -4.0 || ia.LogNormal.Sigma != 1.2 {
		t.Fatalf("lognormal params wrong: %+v", ia.LogNormal)
	}
}

func TestLoadServer_Minimal(t *testing.T) {
	c, err := LoadServer(testdata(t, "server_minimal.toml"))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if c.Listen.Port != 443 {
		t.Fatalf("listen.port: %d", c.Listen.Port)
	}
	if c.Auth.Mode != "token" || len(c.Auth.Tokens) != 2 {
		t.Fatalf("auth: %+v", c.Auth)
	}
}

func TestLoadServer_Full(t *testing.T) {
	c, err := LoadServer(testdata(t, "server_full.toml"))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if c.Shaper == nil || c.Shaper.Custom == nil {
		t.Fatalf("shaper.custom missing")
	}
	burst := c.Shaper.Custom.Burst
	if burst == nil || burst.Type != DistMarkov || burst.Markov == nil {
		t.Fatalf("burst markov: %+v", burst)
	}
	if len(burst.Markov.States) != 2 || len(burst.Markov.Transitions) != 2 {
		t.Fatalf("markov shape: %+v", burst.Markov)
	}
	ps := c.Shaper.Custom.PacketSize
	if ps == nil || ps.Type != DistPareto || ps.Pareto == nil {
		t.Fatalf("packet_size pareto: %+v", ps)
	}
}

func TestLoadClient_StrictRejectsUnknownField(t *testing.T) {
	_, err := LoadClient(testdata(t, "invalid_unknown_field.toml"))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "typo_field") {
		t.Fatalf("error should mention offending field, got: %v", err)
	}
}

func TestLoadClient_PresetAndCustomMutuallyExclusive(t *testing.T) {
	_, err := LoadClient(testdata(t, "invalid_preset_and_custom.toml"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadClient_FileNotFound(t *testing.T) {
	_, err := LoadClient(testdata(t, "does_not_exist.toml"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRoundTrip_ClientPreset(t *testing.T) {
	original, err := LoadClient(testdata(t, "client_preset.toml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var buf bytes.Buffer
	enc := gotoml.NewEncoder(&buf)
	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "rt.toml")
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reloaded, err := LoadClient(tmp)
	if err != nil {
		t.Fatalf("reload: %v\nencoded:\n%s", err, buf.String())
	}
	if !reflect.DeepEqual(original, reloaded) {
		t.Fatalf("round-trip mismatch:\noriginal: %+v\nreloaded: %+v", original, reloaded)
	}
}

func TestRoundTrip_ClientCustom(t *testing.T) {
	original, err := LoadClient(testdata(t, "client_custom.toml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var buf bytes.Buffer
	if err := gotoml.NewEncoder(&buf).Encode(original); err != nil {
		t.Fatalf("encode: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "rt.toml")
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reloaded, err := LoadClient(tmp)
	if err != nil {
		t.Fatalf("reload: %v\nencoded:\n%s", err, buf.String())
	}
	if !reflect.DeepEqual(original, reloaded) {
		t.Fatalf("round-trip mismatch:\noriginal: %+v\nreloaded: %+v", original, reloaded)
	}
}

func TestRoundTrip_ServerFull(t *testing.T) {
	original, err := LoadServer(testdata(t, "server_full.toml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var buf bytes.Buffer
	if err := gotoml.NewEncoder(&buf).Encode(original); err != nil {
		t.Fatalf("encode: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "rt.toml")
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reloaded, err := LoadServer(tmp)
	if err != nil {
		t.Fatalf("reload: %v\nencoded:\n%s", err, buf.String())
	}
	if !reflect.DeepEqual(original, reloaded) {
		t.Fatalf("round-trip mismatch:\noriginal: %+v\nreloaded: %+v", original, reloaded)
	}
}
