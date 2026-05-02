package toml

import (
	"flag"
	"strings"
	"testing"
)

// newClientFlagSet replicates the subset of cmd/tiredvpn client flags that
// participate in the TOML mapping, so tests exercise the real surface.
func newClientFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.String("server", "", "Remote server address (host:port)")
	fs.String("strategy", "", "Force specific strategy")
	fs.Bool("debug", false, "Enable debug logging")
	return fs
}

func newServerFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.String("listen", ":443", "Listen address")
	fs.String("cert", "server.crt", "TLS certificate file")
	fs.String("key", "server.key", "TLS key file")
	fs.Bool("debug", false, "Enable debug logging")
	return fs
}

func TestResolveClient_DefaultsOnly(t *testing.T) {
	fs := newClientFlagSet()
	// No TOML, no flags parsed → defaults must surface, but Validate fails
	// because required fields (server.address, strategy.mode) are unset.
	_, err := ResolveClient("", fs)
	if err == nil {
		t.Fatal("expected validation error from bare defaults")
	}
	if !strings.Contains(err.Error(), "server.address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultClient_Shape(t *testing.T) {
	d := DefaultClient()
	if d.Server.Port != 443 {
		t.Fatalf("default port: %d", d.Server.Port)
	}
	if d.Logging.Level != "info" {
		t.Fatalf("default level: %q", d.Logging.Level)
	}
	if len(d.TLS.ALPN) != 2 {
		t.Fatalf("default ALPN: %+v", d.TLS.ALPN)
	}
}

func TestDefaultServer_Shape(t *testing.T) {
	d := DefaultServer()
	if d.Listen.Address != "0.0.0.0" || d.Listen.Port != 443 {
		t.Fatalf("default listen: %+v", d.Listen)
	}
	if d.Auth.Mode != "token" {
		t.Fatalf("default auth: %+v", d.Auth)
	}
}

func TestResolveClient_TOMLOnly(t *testing.T) {
	fs := newClientFlagSet()
	cfg, err := ResolveClient(testdata(t, "client_minimal.toml"), fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if cfg.Server.Address != "vpn.example.org" || cfg.Server.Port != 443 {
		t.Fatalf("server: %+v", cfg.Server)
	}
	if cfg.Strategy.Mode != "reality" {
		t.Fatalf("strategy: %+v", cfg.Strategy)
	}
	// Defaults preserved where TOML is silent.
	if cfg.Logging.Level != "info" {
		t.Fatalf("logging level should default to info, got %q", cfg.Logging.Level)
	}
}

func TestResolveClient_FlagOverridesTOML(t *testing.T) {
	fs := newClientFlagSet()
	if err := fs.Parse([]string{
		"-server", "alt.example.com:8443",
		"-strategy", "morph",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := ResolveClient(testdata(t, "client_minimal.toml"), fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if cfg.Server.Address != "alt.example.com" || cfg.Server.Port != 8443 {
		t.Fatalf("flag did not override server: %+v", cfg.Server)
	}
	if cfg.Strategy.Mode != "morph" {
		t.Fatalf("flag did not override strategy: %q", cfg.Strategy.Mode)
	}
}

func TestResolveClient_DefaultFlagDoesNotOverrideTOML(t *testing.T) {
	fs := newClientFlagSet()
	// Parse with no args — flags retain defaults but fs.Visit yields nothing.
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := ResolveClient(testdata(t, "client_minimal.toml"), fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if cfg.Server.Address != "vpn.example.org" {
		t.Fatalf("flag default leaked over TOML: %+v", cfg.Server)
	}
}

func TestResolveClient_DebugFlagSetsLogLevel(t *testing.T) {
	fs := newClientFlagSet()
	if err := fs.Parse([]string{"-debug"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := ResolveClient(testdata(t, "client_preset.toml"), fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("expected debug, got %q", cfg.Logging.Level)
	}
}

func TestResolveClient_InvalidPortFromFlag(t *testing.T) {
	fs := newClientFlagSet()
	if err := fs.Parse([]string{"-server", "host:99999"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := ResolveClient(testdata(t, "client_minimal.toml"), fs)
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected port validation error, got: %v", err)
	}
}

func TestResolveClient_BadHostPortFlag(t *testing.T) {
	fs := newClientFlagSet()
	if err := fs.Parse([]string{"-server", "no-port-here"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := ResolveClient(testdata(t, "client_minimal.toml"), fs)
	if err == nil {
		t.Fatal("expected error parsing -server without port")
	}
}

func TestResolveServer_TOMLOnly(t *testing.T) {
	fs := newServerFlagSet()
	cfg, err := ResolveServer(testdata(t, "server_minimal.toml"), fs)
	if err != nil {
		t.Fatalf("ResolveServer: %v", err)
	}
	if cfg.Listen.Port != 443 {
		t.Fatalf("listen.port: %d", cfg.Listen.Port)
	}
	if cfg.TLS.CertFile != "/etc/tiredvpn/server.crt" {
		t.Fatalf("cert_file: %q", cfg.TLS.CertFile)
	}
}

func TestResolveServer_FlagOverridesTOML(t *testing.T) {
	fs := newServerFlagSet()
	if err := fs.Parse([]string{
		"-listen", "127.0.0.1:9443",
		"-cert", "/tmp/c.pem",
		"-key", "/tmp/k.pem",
		"-debug",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := ResolveServer(testdata(t, "server_minimal.toml"), fs)
	if err != nil {
		t.Fatalf("ResolveServer: %v", err)
	}
	if cfg.Listen.Address != "127.0.0.1" || cfg.Listen.Port != 9443 {
		t.Fatalf("listen override: %+v", cfg.Listen)
	}
	if cfg.TLS.CertFile != "/tmp/c.pem" || cfg.TLS.KeyFile != "/tmp/k.pem" {
		t.Fatalf("tls override: %+v", cfg.TLS)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("debug flag did not set log level: %q", cfg.Logging.Level)
	}
}

func TestResolveServer_NoTOML_NeedsFlags(t *testing.T) {
	fs := newServerFlagSet()
	if err := fs.Parse([]string{
		"-cert", "/tmp/c.pem",
		"-key", "/tmp/k.pem",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Defaults set listen, auth.mode, cert/key from flags. strategy.mode still missing.
	_, err := ResolveServer("", fs)
	if err == nil || !strings.Contains(err.Error(), "strategy.mode") {
		t.Fatalf("expected strategy.mode validation error, got: %v", err)
	}
}

func TestApplyClientFlags_NilGuards(t *testing.T) {
	if err := ApplyClientFlags(nil, nil); err == nil {
		t.Fatal("expected error on nil cfg")
	}
	if err := ApplyClientFlags(DefaultClient(), nil); err != nil {
		t.Fatalf("nil flagset must be tolerated: %v", err)
	}
}

func TestApplyServerFlags_NilGuards(t *testing.T) {
	if err := ApplyServerFlags(nil, nil); err == nil {
		t.Fatal("expected error on nil cfg")
	}
	if err := ApplyServerFlags(DefaultServer(), nil); err != nil {
		t.Fatalf("nil flagset must be tolerated: %v", err)
	}
}

func TestResolveClient_StrictRejectsBadTOML(t *testing.T) {
	fs := newClientFlagSet()
	_, err := ResolveClient(testdata(t, "invalid_unknown_field.toml"), fs)
	if err == nil {
		t.Fatal("strict decode should have rejected unknown field")
	}
}

func TestSplitHostPort_OnlyPort(t *testing.T) {
	host, port, err := splitHostPort(":443")
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}
	if host != "" || port != 443 {
		t.Fatalf("got host=%q port=%d", host, port)
	}
}
