package main

import (
	"flag"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/server"
)

// TestServersSNIBothSpellings: `sni` in a [[servers]] entry takes a list, and
// the bare string it took before still works. An entry without it is left to
// -reality-sni, then to the built-in pool.
func TestServersSNIBothSpellings(t *testing.T) {
	path := writeClientTOML(t, `
[[servers]]
name = "gcp-north"
address = "203.0.113.10"
port = 995
sni = ["www.google.com", "WWW.GSTATIC.COM"]

[[servers]]
name = "old-style"
address = "203.0.113.20"
port = 995
sni = "storage.googleapis.com"

[[servers]]
name = "plain"
address = "203.0.113.30"
port = 995
`)
	cfg := &client.Config{REALITYSNIs: []string{"github.com"}}
	if err := applyClientTOMLConfig(cfg, path, clientFlagSetForTOML()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := cfg.Servers[0].SNI; !slices.Equal(got, []string{"www.google.com", "www.gstatic.com"}) {
		t.Errorf("list spelling = %v", got)
	}
	if got := cfg.Servers[1].SNI; !slices.Equal(got, []string{"storage.googleapis.com"}) {
		t.Errorf("string spelling = %v", got)
	}

	eps, err := client.ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(eps[0].SNI, []string{"www.google.com", "www.gstatic.com"}) {
		t.Errorf("an entry's own sni lost to -reality-sni: %v", eps[0].SNI)
	}
	if !slices.Equal(eps[2].SNI, []string{"github.com"}) {
		t.Errorf("an entry without sni did not take -reality-sni: %v", eps[2].SNI)
	}
}

// TestServersSNIRejectsNonHostnames: a comma or a port inside a name would
// split it or smuggle a destination into a ClientHello.
func TestServersSNIRejectsNonHostnames(t *testing.T) {
	for _, bad := range []string{`sni = ["a.example,b.example"]`, `sni = ["a.example:443"]`, `sni = [""]`, `sni = [1]`,
		`sni = ["*.googleapis.com"]`, `sni = ["203.0.113.10"]`, `sni = "www.google.com."`} {
		path := writeClientTOML(t, "[[servers]]\naddress = \"203.0.113.10\"\nport = 995\n"+bad+"\n")
		if err := applyClientTOMLConfig(&client.Config{}, path, clientFlagSetForTOML()); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// TestServersEmptySNIStringIsNoPool is P3-13 of the round-3 review: `sni = ""`,
// what the field held while it was recorded and never applied, turned into a
// startup error. It means no pool.
func TestServersEmptySNIStringIsNoPool(t *testing.T) {
	path := writeClientTOML(t, "[[servers]]\naddress = \"203.0.113.10\"\nport = 995\nsni = \"\"\n")
	cfg := &client.Config{}
	if err := applyClientTOMLConfig(cfg, path, clientFlagSetForTOML()); err != nil {
		t.Fatalf("sni = \"\" rejected: %v", err)
	}
	if got := cfg.Servers[0].SNI; len(got) != 0 {
		t.Fatalf("sni = \"\" gave the pool %v", got)
	}
}

// TestRealitySNIFlags: the client and the server each take -reality-sni.
func TestRealitySNIFlags(t *testing.T) {
	ccfg := &client.Config{}
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	registerClientREALITYFlags(fs, ccfg)
	if err := fs.Parse([]string{"-reality-sni", "www.google.com, www.gstatic.com,www.google.com"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ccfg.REALITYSNIs, []string{"www.google.com", "www.gstatic.com"}) {
		t.Errorf("client -reality-sni = %v", ccfg.REALITYSNIs)
	}

	scfg := &server.Config{}
	fs = flag.NewFlagSet("server", flag.ContinueOnError)
	registerServerFlags(fs, scfg)
	if err := fs.Parse([]string{"-reality-sni", "www.google.com"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(scfg.REALITYSNIs, []string{"www.google.com"}) {
		t.Errorf("server -reality-sni = %v", scfg.REALITYSNIs)
	}

	fs = flag.NewFlagSet("client", flag.ContinueOnError)
	registerClientREALITYFlags(fs, &client.Config{})
	if err := fs.Parse([]string{"-reality-sni", "evil.example:8443"}); err == nil {
		t.Error("a name with a port was accepted")
	}
}

// TestJNIRealitySNI: the app's argv reaches the same pool as the CLI flag, and
// -cover stays HTTP/2 Stego's own host next to it. A bad list is dropped with
// a warning, as the parser does for every bad value, and leaves the built-in
// pool.
func TestJNIRealitySNI(t *testing.T) {
	cfg, err := parseClientArgs([]string{"-server", "203.0.113.10:995", "-secret", "s",
		"-cover", "api.googleapis.com", "-reality-sni", "www.google.com, WWW.GSTATIC.COM"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.REALITYSNIs, []string{"www.google.com", "www.gstatic.com"}) {
		t.Errorf("REALITYSNIs = %v", cfg.REALITYSNIs)
	}
	if cfg.CoverHost != "api.googleapis.com" {
		t.Errorf("CoverHost = %q", cfg.CoverHost)
	}

	cfg, err = parseClientArgs([]string{"-server", "203.0.113.10:995", "-secret", "s", "-reality-sni", "a.example,b.example:443"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.REALITYSNIs != nil {
		t.Errorf("an invalid list was taken: %v", cfg.REALITYSNIs)
	}
}

// TestConnectionStringCarriesTheSNIPool: admin add and admin qr write the pool
// as sni=, comma-separated like the flag, and leave it out when there is none,
// so strings for clients without a pool do not change.
func TestConnectionStringCarriesTheSNIPool(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
		has  bool
	}{
		{nil, "", false},
		{[]string{"-reality-sni", "www.google.com,www.gstatic.com"}, "www.google.com,www.gstatic.com", true},
	} {
		fs := flag.NewFlagSet("admin", flag.ContinueOnError)
		conn := registerAdminConnFlags(fs)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		s := conn.connectionString("vpn.example.com:995", "s")
		_, q, _ := strings.Cut(s, "?")
		v, err := url.ParseQuery(q)
		if err != nil {
			t.Fatal(err)
		}
		if v.Has("sni") != tc.has || v.Get("sni") != tc.want {
			t.Errorf("%v: sni=%q (present %v) in %s", tc.args, v.Get("sni"), v.Has("sni"), s)
		}
		if v.Get("cover") != "api.googleapis.com" {
			t.Errorf("%v: cover changed: %s", tc.args, s)
		}
	}
}
