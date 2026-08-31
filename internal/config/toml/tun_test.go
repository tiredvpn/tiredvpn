package toml

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTunTOML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func tunFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.String("server", "", "")
	fs.String("tun-ipv6-allow", "", "")
	fs.String("tun-routes6", "", "")
	return fs
}

// TestClientTOML_TunIPv6Allow: the whole point of putting the exceptions in the
// schema is that a unit configured from a file - the server pool - can carry
// them. A flag-only knob would be unreachable there.
func TestClientTOML_TunIPv6Allow(t *testing.T) {
	path := writeTunTOML(t, `
[server]
address = "203.0.113.10"
port = 443

[tun]
ipv6_allow = ["he6", "2001:db8:77b::/64"]
`)
	cfg, err := ResolveClient(path, tunFlagSet())
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got := strings.Join(cfg.Tun.IPv6Allow, ","); got != "he6,2001:db8:77b::/64" {
		t.Errorf("tun.ipv6_allow = %q, want the two entries from the file", got)
	}
}

// TestClientTOML_TunIPv6AllowFlagWins pins the precedence the rest of the
// schema follows: an explicit flag replaces the file's list rather than adding
// to it.
func TestClientTOML_TunIPv6AllowFlagWins(t *testing.T) {
	path := writeTunTOML(t, `
[server]
address = "203.0.113.10"

[tun]
ipv6_allow = ["he6"]
`)
	fs := tunFlagSet()
	if err := fs.Parse([]string{"-tun-ipv6-allow", "wg0, 2001:db8::/32"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := ResolveClient(path, fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got := strings.Join(cfg.Tun.IPv6Allow, "|"); got != "wg0|2001:db8::/32" {
		t.Errorf("tun.ipv6_allow = %q, want the flag's two entries with whitespace trimmed", got)
	}
}

// TestClientTOML_TunIPv6AllowUntouched: a file that says nothing about the
// block leaves it alone. An empty flag value must not read as "the operator
// asked for an empty list".
func TestClientTOML_TunIPv6AllowUntouched(t *testing.T) {
	path := writeTunTOML(t, `
[server]
address = "203.0.113.10"

[tun]
ipv6_allow = ["he6"]
`)
	cfg, err := ResolveClient(path, tunFlagSet()) // flag registered, never passed
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got := strings.Join(cfg.Tun.IPv6Allow, ","); got != "he6" {
		t.Errorf("an unpassed flag overwrote the file: %q", got)
	}
}

// TestClientTOML_TunIPv6AllowRejectsUnjoinable guards the representation: the
// list is joined with commas on the way to the runtime, so an entry holding one
// would silently become two exceptions.
func TestClientTOML_TunIPv6AllowRejectsUnjoinable(t *testing.T) {
	for _, body := range []string{
		`ipv6_allow = ["he6,wg0"]`,
		`ipv6_allow = ["he6", "  "]`,
	} {
		path := writeTunTOML(t, "[server]\naddress = \"203.0.113.10\"\n\n[tun]\n"+body+"\n")
		if _, err := ResolveClient(path, tunFlagSet()); err == nil {
			t.Errorf("%s was accepted", body)
		}
	}
}

// TestClientTOML_TunRoutes6 reads the key the way an operator writes it.
func TestClientTOML_TunRoutes6(t *testing.T) {
	cfg, err := ResolveClient(writeTunTOML(t, `
[server]
address = "203.0.113.10"

[tun]
routes6 = ["2001:db8::/32"]
`), tunFlagSet())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := strings.Join(cfg.Tun.Routes6, ","); got != "2001:db8::/32" {
		t.Errorf("Tun.Routes6 = %q", got)
	}
}

// TestClientTOML_TunRoutes6RejectsMixedNone: "none" is a statement about the
// whole list, so a file that also names prefixes says two contradictory things
// and is refused rather than resolved by guessing which one won.
func TestClientTOML_TunRoutes6RejectsMixedNone(t *testing.T) {
	_, err := ResolveClient(writeTunTOML(t, `
[server]
address = "203.0.113.10"

[tun]
routes6 = ["none", "2001:db8::/32"]
`), tunFlagSet())
	if err == nil {
		t.Fatal("a list mixing none with a prefix was accepted")
	}
	if !strings.Contains(err.Error(), "routes6") {
		t.Errorf("error %q does not name the key at fault", err)
	}
}

// TestClientTOML_TunRoutes6RejectsUnjoinable guards the representation: the
// entries are joined with commas on the way to the runtime, so a comma inside
// one would silently become two destinations.
func TestClientTOML_TunRoutes6RejectsUnjoinable(t *testing.T) {
	_, err := ResolveClient(writeTunTOML(t, `
[server]
address = "203.0.113.10"

[tun]
routes6 = ["2001:db8::/32,2001:db9::/48"]
`), tunFlagSet())
	if err == nil {
		t.Fatal("an entry containing a comma was accepted")
	}
}

// TestClientTOML_TunRoutes6FlagWins pins the precedence the rest of the schema
// follows: naming the destinations is one statement, so an explicit flag
// replaces the file's list rather than extending it.
func TestClientTOML_TunRoutes6FlagWins(t *testing.T) {
	path := writeTunTOML(t, `
[server]
address = "203.0.113.10"

[tun]
routes6 = ["2001:db8::/32"]
`)
	fs := tunFlagSet()
	if err := fs.Parse([]string{"-tun-routes6", "none"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := ResolveClient(path, fs)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got := strings.Join(cfg.Tun.Routes6, ","); got != "none" {
		t.Errorf("Tun.Routes6 = %q, want the flag to replace the file's list", got)
	}
}
