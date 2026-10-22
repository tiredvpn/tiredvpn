package main

import (
	"flag"
	"slices"
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
	for _, bad := range []string{`sni = ["a.example,b.example"]`, `sni = ["a.example:443"]`, `sni = [""]`, `sni = [1]`} {
		path := writeClientTOML(t, "[[servers]]\naddress = \"203.0.113.10\"\nport = 995\n"+bad+"\n")
		if err := applyClientTOMLConfig(&client.Config{}, path, clientFlagSetForTOML()); err == nil {
			t.Errorf("%s was accepted", bad)
		}
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
