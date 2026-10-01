package toml

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	gotoml "github.com/pelletier/go-toml/v2"
)

// Placeholder values written into the fixtures. None of them may show up in
// an error text.
const (
	markSecret = "PLACEHOLDER-SECRET-0451"
	markAddr   = "203.0.113.77"
	markNum    = "4510451"
	markName   = "PLACEHOLDER-NAME-0451"
)

// hexKey has the shape of a generated secret (64 hex characters).
const hexKey = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

var fileMarkers = []string{markSecret, markAddr, markNum, markName, hexKey}

// fixture expands {S}, {A}, {N} and {NAME} to the placeholders.
func fixture(body string) string {
	return strings.NewReplacer("{S}", markSecret, "{A}", markAddr, "{N}", markNum, "{NAME}", markName).Replace(body)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := os.WriteFile(p, []byte(fixture(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// assertNoFileValues fails when msg holds a value from the file, a character
// go-toml quoted from it (%#U renders as "U+0061 'a'"), or a line break: the
// Android error state embeds the text in a one-line JSON string.
func assertNoFileValues(t *testing.T, msg string) {
	t.Helper()
	for _, m := range fileMarkers {
		if strings.Contains(msg, m) {
			t.Errorf("error text holds the file value %q: %s", m, msg)
		}
	}
	if strings.Contains(msg, "U+") {
		t.Errorf("error text quotes a character from the file: %s", msg)
	}
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("error text spans lines: %q", msg)
	}
}

// rawGoTOMLText is what the loader used to print: go-toml's rendering of the
// same error, with the quoted document lines.
func rawGoTOMLText(t *testing.T, body string) string {
	t.Helper()
	err := gotoml.NewDecoder(strings.NewReader(fixture(body))).DisallowUnknownFields().Decode(&ClientConfig{})
	if serr, ok := errors.AsType[*gotoml.StrictMissingError](err); ok {
		return serr.String()
	}
	if derr, ok := errors.AsType[*gotoml.DecodeError](err); ok {
		return derr.String()
	}
	t.Fatalf("go-toml accepted the fixture or failed oddly: %v", err)
	return ""
}

// TestDecodeErrorsCarryNoValues covers every spot a decode error can sit
// relative to a secret and every string form go-toml quotes. For each fixture
// the positive control shows go-toml's own text quoting the value; the
// loader's text must hold the position, the kind and the key, and no value.
func TestDecodeErrorsCarryNoValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		leak string // value go-toml's own text quotes for this fixture
		line int
		kind string
		key  string
	}{
		{"error on the secret line", "[server]\naddress = \"{A}\"\nport = 995\nsecret = \"{S}\" trailing\n",
			markSecret, 4, "expected a newline after the value", ""},
		{"error on the line before the secret", "[server]\naddress = \"{A}\"\nport = \nsecret = \"{S}\"\n",
			markAddr, 3, "unexpected character at start of value", ""},
		{"error on the line after the secret", "[server]\naddress = \"{A}\"\nsecret = \"{S}\"\nsni = \n",
			markSecret, 4, "unexpected character at start of value", ""},
		{"literal string", "[server]\naddress = \"{A}\"\nsecret = '{S}'\nsni = \n",
			markSecret, 4, "unexpected character at start of value", ""},
		{"multiline basic string", "[server]\naddress = \"{A}\"\nsecret = \"\"\"\n{S}\n\"\"\"\nsni = \n",
			markSecret, 6, "unexpected character at start of value", ""},
		{"multiline literal string", "[server]\naddress = \"{A}\"\nsecret = '''\n{S}\n'''\nsni = \n",
			markSecret, 6, "unexpected character at start of value", ""},
		{"inline table", "server = { address = \"{A}\", secret = \"{S}\", port = }\n",
			markSecret, 1, "unexpected character at start of value", ""},
		{"array of servers", "[[servers]]\naddress = \"{A}\"\nsecret = \"{S}\"\n[[servers]]\naddress = \"{A}\"\nsecret = \"{S}\"\nport = 9x\n",
			markSecret, 7, "strings must be quoted", ""},
		{"unknown field next to the secret", "[server]\naddress = \"{A}\"\nsecret = \"{S}\"\nbogus = 1\n",
			markSecret, 4, "unknown field", "server.bogus"},
		{"unknown field in a servers entry", "[[servers]]\naddress = \"{A}\"\nsecret = \"{S}\"\nbogus = 1\n",
			markSecret, 4, "unknown field", "servers.bogus"},
		{"quoted key holding a value", "[server]\naddress = \"{A}\"\n\"{S}\" = 1\n",
			markSecret, 3, "unknown field", "server.<unknown>"},
		{"hex secret written as a key", "[server]\naddress = \"{A}\"\n" + hexKey + " = 1\n",
			hexKey, 3, "unknown field", "server.<unknown>"},
		{"address written as a key", "[server]\n\"{A}\" = 1\n",
			markAddr, 2, "unknown field", "server.<unknown>"},
		{"secret of integer type", "[server]\naddress = \"{A}\"\nsecret = {N}\n",
			markNum, 3, "cannot decode TOML integer into struct field toml.ClientServer.Secret of type string", "server.secret"},
		{"secret of array type", "[server]\naddress = \"{A}\"\nsecret = [\"{S}\"]\n",
			markSecret, 3, "cannot decode TOML array into struct field toml.ClientServer.Secret of type string", "server.secret"},
		{"secret used as a table", "[server]\naddress = \"{A}\"\nsecret.x = \"{S}\"\n",
			markSecret, 3, "cannot decode TOML table into struct field toml.ClientServer.Secret of type string", "server.secret.x"},
		{"unterminated secret", "[server]\naddress = \"{A}\"\nsecret = \"{S}\nport = 1\n",
			markSecret, 3, "basic strings cannot have new lines", ""},
		{"unterminated secret at end of file", "[server]\naddress = \"{A}\"\nsecret = \"{S}",
			markSecret, 3, "unterminated basic string", ""},
		{"unterminated multiline secret", "[server]\naddress = \"{A}\"\nsecret = \"\"\"{S}\n",
			markSecret, 3, "multiline basic string not terminated", ""},
		{"invalid escape in the secret", "[server]\naddress = \"{A}\"\nsecret = \"{S}\\q\"\n",
			markSecret, 3, "invalid escape character", ""},
		{"unquoted secret", "[server]\naddress = \"{A}\"\nsecret = {S}\n",
			markSecret, 3, "unexpected character at start of value", ""},
		{"secret defined twice", "[server]\naddress = \"{A}\"\nsecret = \"{S}\"\nsecret = \"{S}\"\n",
			markSecret, 4, "key defined more than once", "secret"},
		{"keyword typo next to the secret", "[server]\nsecret = \"{S}\"\nweight = tru\n",
			markSecret, 3, "expected a keyword", ""},
		{"float out of range next to the secret", "[server]\nsecret = \"{S}\"\nweight = 1e999\n",
			markSecret, 3, "invalid float", "server.weight"},
		{"number too large next to the secret", "[server]\nsecret = \"{S}\"\nport = 99999999999999999999\n",
			markSecret, 3, "decimal number is too large to fit in a 64-bit signed integer", "server.port"},
		{"bad key next to the secret", "[server]\nsecret = \"{S}\"\n@bad = 1\n",
			markSecret, 3, "invalid character at start of key", ""},
		{"table defined twice", "[server]\nsecret = \"{S}\"\n[server]\nport = 1\n",
			markSecret, 3, "table defined more than once", "server"},
		{"value redefined as a table", "[server]\nsecret = \"{S}\"\nport = 1\n[server.port]\nx = 1\n",
			markSecret, 4, "key defined as a value and as a table", "server.port"},
		{"empty array element next to the secret", "[server]\nsecret = \"{S}\"\n[tun]\nipv6_allow = [\"a\",,\"b\"]\n",
			markSecret, 4, "expected a value", ""},
		{"sign without digits next to the secret", "[server]\nsecret = \"{S}\"\nweight = +\n",
			markSecret, 3, "expected a digit", ""},
		{"array of tables over an inline array", "servers = [{address = \"{A}\", secret = \"{S}\"}]\n[[servers]]\naddress = \"{A}\"\n",
			markSecret, 2, "key defined as a value and as an array of tables", "servers"},
		{"nesting too deep next to the secret", "[server]\nsecret = \"{S}\"\nweight = " + strings.Repeat("[", 10001) + "\n",
			markSecret, 3, "arrays and inline tables are nested too deep", ""},
		{"array table into a struct", "[[server]]\nsecret = \"{S}\"\n",
			"", 1, "cannot store an array table in a struct", "server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.leak != "" && !strings.Contains(rawGoTOMLText(t, tc.body), tc.leak) {
				t.Fatalf("positive control: go-toml's own text does not quote %q, the fixture proves nothing", tc.leak)
			}
			p := writeConfig(t, tc.body)
			_, err := LoadClient(p)
			if err == nil {
				t.Fatal("LoadClient accepted the fixture")
			}
			msg := err.Error()
			assertNoFileValues(t, msg)
			want := regexp.MustCompile(fmt.Sprintf(`^%s: line %d, column [1-9]\d*: %s`,
				regexp.QuoteMeta(p), tc.line, regexp.QuoteMeta(tc.kind)))
			if !want.MatchString(msg) {
				t.Errorf("want %q, got %s", want, msg)
			}
			if tc.key != "" && !strings.HasSuffix(msg, " (key "+tc.key+")") {
				t.Errorf("want key %q in %s", tc.key, msg)
			}
		})
	}
}

// TestDecodeErrorExactPosition pins line and column on one fixture: the
// newline-expected error points right after the closing quote.
func TestDecodeErrorExactPosition(t *testing.T) {
	p := writeConfig(t, "[server]\nsecret = \"x\" y\n")
	_, err := LoadClient(p)
	if err == nil || err.Error() != p+": line 2, column 14: expected a newline after the value" {
		t.Fatalf("got %v", err)
	}
}

// TestDecodeErrorStrictListsEveryField: all unknown fields are reported, each
// with its position and key, on one line.
func TestDecodeErrorStrictListsEveryField(t *testing.T) {
	p := writeConfig(t, "[server]\naddress = \"{A}\"\nfoo = \"{S}\"\nsecret = \"{S}\"\nbar = \"{S}\"\n")
	_, err := LoadClient(p)
	if err == nil {
		t.Fatal("accepted")
	}
	assertNoFileValues(t, err.Error())
	want := p + ": line 3, column 1: unknown field (key server.foo); line 5, column 1: unknown field (key server.bar)"
	if err.Error() != want {
		t.Fatalf("got  %s\nwant %s", err, want)
	}
}

// narrowTarget reaches the go-toml messages that print a number from the
// document, which the client schema (int, float64) cannot trigger.
type narrowTarget struct {
	Small int8    `toml:"small"`
	F     float32 `toml:"f"`
	Tbl   string  `toml:"tbl"`
	Tbls  [1]struct {
		A int `toml:"a"`
	} `toml:"tbls"`
}

func TestDecodeErrorNumbersFromTheDocument(t *testing.T) {
	for _, tc := range []struct {
		body, kind, key string
		leaks           []string
	}{
		{"small = {N}\n", "integer value out of range for int8", "small", []string{markNum}},
		{"small = -{N}\n", "integer value out of range for int8", "small", []string{markNum}},
		{"f = 3.4e39\n", "float value out of range for float32", "f", []string{"339999"}},
		{"[tbl]\nx = 1\n", "cannot store a table in a string", "tbl", nil},
		{"[[tbls]]\na = 1\n[[tbls]]\na = 2\n", "array too small for this array table", "tbls", nil},
	} {
		p := writeConfig(t, tc.body)
		err := decodeStrict(p, &narrowTarget{})
		if err == nil {
			t.Fatalf("%q accepted", tc.body)
		}
		raw := gotoml.NewDecoder(strings.NewReader(fixture(tc.body))).Decode(&narrowTarget{})
		for _, l := range tc.leaks {
			if !strings.Contains(raw.Error(), l) {
				t.Fatalf("positive control: go-toml's message %q does not hold %q", raw, l)
			}
			if strings.Contains(err.Error(), l) {
				t.Errorf("error holds %q: %s", l, err)
			}
		}
		if !strings.Contains(err.Error(), ": "+tc.kind+" (key "+tc.key+")") {
			t.Errorf("%q: got %s, want kind %q key %q", tc.body, err, tc.kind, tc.key)
		}
	}
}

// TestDecodeErrorOtherFailures: a read error keeps its text (path and
// operation only); any other go-toml error is not passed on at all.
func TestDecodeErrorOtherFailures(t *testing.T) {
	dir := t.TempDir()
	err := decodeStrict(dir, &ClientConfig{})
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("read error lost: %v", err)
	}

	p := writeConfig(t, "[server]\nsecret = \"{S}\"\n")
	err = decodeStrict(p, ClientConfig{}) // not a pointer: go-toml's own error
	if err == nil || err.Error() != p+": cannot decode the file" {
		t.Fatalf("got %v", err)
	}
}

// TestDecodeErrorUnknownMessage: a message that is neither static nor a known
// form is not printed, whatever it holds.
func TestDecodeErrorUnknownMessage(t *testing.T) {
	cases := []string{
		"some future message quoting " + markSecret,
		"unexpected character U+0041 'A' somewhere new",
	}
	for _, msg := range cases {
		if got := decodeErrorKind(msg); got != "invalid TOML" {
			t.Errorf("%q -> %q, want invalid TOML", msg, got)
		}
	}
}

// TestValidationErrorsCarryNoValues: errors from the checks after decoding
// name the field and the rule, not the value that broke it.
func TestValidationErrorsCarryNoValues(t *testing.T) {
	const srv = "[server]\naddress = \"{A}\"\nport = 995\nsecret = \"{S}\"\n"
	for _, tc := range []struct {
		name, body, want string
		leak             string // a value as the old message printed it, when it differs from the file
	}{
		{"ipv6_allow comma", srv + "[tun]\nipv6_allow = [\"he6,{S}\"]\n", "tun.ipv6_allow[0] contains a comma", ""},
		{"routes6 comma", srv + "[tun]\nroutes6 = [\"2001:db8::/32,{S}\"]\n", "tun.routes6[0] contains a comma", ""},
		{"selection.policy", srv + "[selection]\npolicy = \"{S}\"\n", "selection.policy: unknown value", ""},
		{"selection.family", srv + "[selection]\nfamily = \"{S}\"\n", "selection.family: unknown value", ""},
		{"selection.health_check", srv + "[selection]\nhealth_check = \"{S}\"\n", "selection.health_check: unknown value", ""},
		{"selection.failure_threshold", srv + "[selection]\nfailure_threshold = -{N}\n", "selection.failure_threshold must be >= 0", ""},
		{"selection duration", srv + "[selection]\ncooldown = \"{S}\"\n", "selection.cooldown: invalid duration", ""},
		{"selection negative duration", srv + "[selection]\nmin_dwell = \"-{N}s\"\n", "selection.min_dwell must not be negative", "1252h54m11s"},
		{"selection cooldown order", srv + "[selection]\ncooldown = \"1h\"\nmax_cooldown = \"30m\"\n", "selection.max_cooldown is shorter than selection.cooldown", "30m0s"},
		{"duplicate server name", "[[servers]]\nname = \"{NAME}\"\naddress = \"{A}\"\n[[servers]]\nname = \"{NAME}\"\naddress = \"{A}\"\n", "duplicate server name (entries 0 and 1)", ""},
		{"port out of range", "[[servers]]\nname = \"{NAME}\"\naddress = \"{A}\"\nport = {N}\n", "servers[0].port must be in 1..65535", ""},
		{"shaper randomization_range", srv + "[shaper]\npreset = \"chrome_browsing\"\nrandomization_range = 1.{N}\n", "shaper.randomization_range must be in [0, 1)", ""},
		{"shaper distribution type", srv + "[shaper.custom.packet_size]\ntype = \"{S}\"\n", "shaper.custom.packet_size: unknown distribution type", ""},
		{"lognormal sigma", srv + "[shaper.custom.packet_size]\ntype = \"lognormal\"\n[shaper.custom.packet_size.lognormal]\nmu = 1.0\nsigma = -0.{N}\n", "lognormal.sigma must be non-negative", ""},
		{"pareto xm", srv + "[shaper.custom.packet_size]\ntype = \"pareto\"\n[shaper.custom.packet_size.pareto]\nxm = -{N}.0\nalpha = 1.0\n", "pareto.xm must be > 0", "4.510451e+06"},
		{"pareto alpha", srv + "[shaper.custom.packet_size]\ntype = \"pareto\"\n[shaper.custom.packet_size.pareto]\nxm = 1.0\nalpha = -{N}.0\n", "pareto.alpha must be > 0", "4.510451e+06"},
		{"markov sum", srv + "[shaper.custom.packet_size]\ntype = \"markov\"\n[shaper.custom.packet_size.markov]\nstates = [{name = \"a\", value = 1.0}]\ntransitions = [[0.{N}]]\n", "markov.transitions[0] must sum to 1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadClient(writeConfig(t, tc.body))
			if err == nil {
				t.Fatal("LoadClient accepted the fixture")
			}
			assertNoFileValues(t, err.Error())
			if tc.leak != "" && strings.Contains(err.Error(), tc.leak) {
				t.Errorf("error holds the value %q: %s", tc.leak, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want %q in %s", tc.want, err)
			}
		})
	}
}

func TestServerValidationErrorCarriesNoValue(t *testing.T) {
	p := writeConfig(t, "[listen]\naddress = \"{A}\"\nport = {N}\n[strategy]\nmode = \"reality\"\n[tls]\ncert_file = \"c\"\nkey_file = \"k\"\n[auth]\nmode = \"token\"\n")
	_, err := LoadServer(p)
	if err == nil {
		t.Fatal("accepted")
	}
	assertNoFileValues(t, err.Error())
	if !strings.Contains(err.Error(), "listen.port must be in 1..65535") {
		t.Errorf("got %s", err)
	}
}

// TestResolveCarriesNoValues: ResolveClient and ResolveServer, the paths the
// binaries use, go through the same decoder and validation.
func TestResolveCarriesNoValues(t *testing.T) {
	p := writeConfig(t, "[server]\naddress = \"{A}\"\nsecret = \"{S}\" x\n")
	if _, err := ResolveClient(p, nil); err == nil || !strings.Contains(err.Error(), "line 3, column") {
		t.Fatalf("ResolveClient: %v", err)
	} else {
		assertNoFileValues(t, err.Error())
	}
	if _, err := ResolveServer(p, nil); err == nil || !strings.Contains(err.Error(), "line 3, column") {
		t.Fatalf("ResolveServer: %v", err)
	} else {
		assertNoFileValues(t, err.Error())
	}
	v := writeConfig(t, "[server]\naddress = \"{A}\"\nport = {N}\n")
	if _, err := ResolveClient(v, nil); err == nil || !strings.Contains(err.Error(), "server.port must be in 1..65535") {
		t.Fatalf("ResolveClient validation: %v", err)
	} else {
		assertNoFileValues(t, err.Error())
	}
}

// TestSchemaKeysHaveIdentifierShape: error texts print a key only when it has
// the shape every schema key has. A new field outside that shape would be
// reported as "<unknown>" in its own errors; widen identifierKey with care.
func TestSchemaKeysHaveIdentifierShape(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Array || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for f := range rt.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
			if name == "" || name == "-" {
				continue
			}
			if !identifierKey.MatchString(name) {
				t.Errorf("%s.%s: key %q does not match %s", rt, f.Name, name, identifierKey)
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeFor[ClientConfig]())
	walk(reflect.TypeFor[ServerConfig]())
	if len(seen) < 5 {
		t.Fatalf("walked only %d structs, the check saw nothing", len(seen))
	}
}

// TestDecodeKindsAreJSONSafe: the Android error state is built as
// {"error":"<text>"} without escaping, so no kind text may hold a double quote
// or a backslash.
func TestDecodeKindsAreJSONSafe(t *testing.T) {
	kinds := []string{}
	for _, k := range staticDecodeMessages {
		kinds = append(kinds, k)
	}
	for _, k := range decodeKinds {
		kinds = append(kinds, k.kind)
	}
	if len(kinds) < 60 {
		t.Fatalf("only %d kinds seen", len(kinds))
	}
	for _, k := range kinds {
		if strings.ContainsAny(k, `"\`) {
			t.Errorf("kind %q holds a double quote or a backslash", k)
		}
	}
}
