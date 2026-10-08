package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

const redactTestSecret = "s3cr3t-value-0451"

// TestJNIStartLogLineHidesSecret is the line startClient logs, for the argv the
// app builds (TiredVpnService.kt). The secret must not be in it; every other
// token must be, they are what one reads when debugging a connection.
func TestJNIStartLogLineHidesSecret(t *testing.T) {
	argv := []string{
		"-server", "203.0.113.10:995",
		"-secret", redactTestSecret,
		"-strategy", "reality",
		"-cover", "cdn.example.org",
		"-server-v6", "[2001:db8::10]:995",
		"-tun",
	}
	orig := slices.Clone(argv)
	line := jniStartLogLine(argv)

	if strings.Contains(line, redactTestSecret) {
		t.Errorf("start line still has the secret: %s", line)
	}
	for _, want := range []string{
		"Starting client with 11 args: ",
		"-secret ***",
		"-server 203.0.113.10:995", "-strategy reality", "-cover cdn.example.org",
		"-server-v6 [2001:db8::10]:995", "-tun",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("start line lost %q: %s", want, line)
		}
	}
	if !slices.Equal(argv, orig) {
		t.Fatalf("redaction modified the argv the parser reads: %q", argv)
	}
}

// TestRedactArgsSpellings: every spelling of the flag the Go flag package
// accepts is redacted, and the flag name stays readable.
func TestRedactArgsSpellings(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"-secret", redactTestSecret}, "-secret ***"},
		{[]string{"-gost-tls13-pin", redactTestSecret}, "-gost-tls13-pin ***"},
		{[]string{"--gost-tls13-pin=" + redactTestSecret}, "--gost-tls13-pin=***"},
		{[]string{"-secret=" + redactTestSecret}, "-secret=***"},
		{[]string{"--secret", redactTestSecret}, "--secret ***"},
		{[]string{"--secret=" + redactTestSecret}, "--secret=***"},
		{[]string{"-secret", "-secret", redactTestSecret}, "-secret *** ***"},
		{[]string{"-secret"}, "-secret"}, // no value: nothing to hide, no panic
		{[]string{"-secrets", "x", "secret", "y"}, "-secrets x secret y"},
	} {
		if got := strings.Join(redactArgs(tc.in), " "); got != tc.want {
			t.Errorf("redactArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseClientArgsWarningsHideSecret: the parser echoes tokens it does not
// know and values it cannot parse. A sensitive token lands there when the app
// spells the flag in a form the parser lacks, or when a value is missing and
// the next flag is read as the value. Each warning branch is hit once.
func TestParseClientArgsWarningsHideSecret(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	inline := "-secret=" + redactTestSecret
	cfg, err := parseClientArgs([]string{
		"-server", "203.0.113.10:995",
		"-secret", "the-real-one",
		"--secret", redactTestSecret, // unknown flag, then unknown value token
		inline, // unknown flag
		"-quic-port", inline,
		"-shaper-seed", inline,
		"-prefer-ipv6", inline,
		"-fallback-v4", inline,
	})
	if err != nil {
		t.Fatalf("parseClientArgs: %v", err)
	}
	// The parser still reads the unredacted argv.
	if cfg.Secret != "the-real-one" || cfg.ServerAddr != "203.0.113.10:995" {
		t.Fatalf("parsed config changed: secret=%q server=%q", cfg.Secret, cfg.ServerAddr)
	}

	logged := buf.String()
	// Positive control: every branch must have logged, or the absence check
	// below would pass on a log that never saw the token.
	for _, want := range []string{
		`ignoring unknown flag "--secret"`,
		`ignoring unknown flag "***"`,
		`ignoring unknown flag "-secret=***"`,
		`invalid -quic-port value "-secret=***": invalid syntax`,
		`invalid -shaper-seed value "-secret=***": invalid syntax`,
		`invalid -prefer-ipv6 value "-secret=***": invalid syntax`,
		`invalid -fallback-v4 value "-secret=***": invalid syntax`,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log lacks %q:\n%s", want, logged)
		}
	}
	if strings.Contains(logged, redactTestSecret) {
		t.Errorf("parser log has the secret:\n%s", logged)
	}
}

// TestParseClientArgsErrorsHideSecret: parser errors reach the app's log and
// its error state. A sensitive token read as another flag's value comes back
// inside that flag's error; the %q spelling of the value is hidden too.
func TestParseClientArgsErrorsHideSecret(t *testing.T) {
	quoted := `qu"ot\ed-` + redactTestSecret
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"shaper", []string{"-server", "203.0.113.10:995", "-shaper", "-secret=" + redactTestSecret}, "shaper"},
		{"shaper-quoted", []string{"-server", "203.0.113.10:995", "-shaper", "-secret=" + quoted}, "shaper"},
		{"shaper-separate", []string{"-server", "203.0.113.10:995", "-secret", redactTestSecret, "-shaper", redactTestSecret}, "shaper"},
		{"config", []string{"-config", "-secret=" + redactTestSecret, "-server", "203.0.113.10:995"}, "config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseClientArgs(tc.args)
			if err == nil {
				t.Fatal("parseClientArgs accepted the argv, want an error")
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) || !strings.Contains(msg, redactedValue) {
				t.Fatalf("not the expected error, the check would prove nothing: %s", msg)
			}
			if strings.Contains(msg, redactTestSecret) {
				t.Errorf("error has the secret: %s", msg)
			}
		})
	}
}

// rawArgvNames are the identifiers that hold the unredacted argv in the JNI
// files.
var rawArgvNames = []string{"args", "argv", "argvSlice", "argsString"}

// argvSanitizers return something safe to print given the raw argv.
// parseClientArgs and runClientWithContext are here because their errors pass
// through redactArgError (TestParseClientArgsErrorsHideSecret); strconvReason
// because it drops the echoed input (TestParseClientArgsWarningsHideSecret).
var argvSanitizers = []string{
	"redactArgs", "jniStartLogLine", "redactArgError", "strconvReason",
	"parseClientArgs", "runClientWithContext", "len",
}

// isLogSink reports whether call prints its arguments somewhere a user can read
// them: the JNI log and state callbacks, the log package, error constructors and
// fmt's printers.
func isLogSink(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "logMessage" || fn.Name == "sendStateChange"
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		if !ok {
			return false
		}
		switch pkg.Name {
		case "log":
			return true
		case "errors":
			return fn.Sel.Name == "New"
		case "fmt":
			return fn.Sel.Name == "Errorf" || strings.HasPrefix(fn.Sel.Name, "Print") || strings.HasPrefix(fn.Sel.Name, "Fprint")
		}
	}
	return false
}

// argvLeaks finds log sinks in file whose arguments reach the raw argv, either
// directly or through a local variable assigned from it. Taint is tracked by
// name within each function, so it over-approximates. It returns the leaks and
// the number of sinks seen.
func argvLeaks(fset *token.FileSet, file *ast.File) (leaks []string, sinks int) {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		l, s := funcArgvLeaks(fset, fd.Body)
		leaks = append(leaks, l...)
		sinks += s
	}
	return leaks, sinks
}

func funcArgvLeaks(fset *token.FileSet, body *ast.BlockStmt) (leaks []string, sinks int) {
	tainted := slices.Clone(rawArgvNames)
	refersRaw := func(e ast.Node) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			if found {
				return false
			}
			switch n := n.(type) {
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && slices.Contains(argvSanitizers, id.Name) {
					return false
				}
			case *ast.Ident:
				found = slices.Contains(tainted, n.Name)
			}
			return !found
		})
		return found
	}
	taint := func(lhs []ast.Expr, rhs []ast.Expr) bool {
		if !slices.ContainsFunc(rhs, func(e ast.Expr) bool { return refersRaw(e) }) {
			return false
		}
		grew := false
		for _, l := range lhs {
			if id, ok := l.(*ast.Ident); ok && id.Name != "_" && !slices.Contains(tainted, id.Name) {
				tainted = append(tainted, id.Name)
				grew = true
			}
		}
		return grew
	}
	for grew := true; grew; {
		grew = false
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				grew = taint(n.Lhs, n.Rhs) || grew
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, len(n.Names))
				for i, id := range n.Names {
					lhs[i] = id
				}
				grew = taint(lhs, n.Values) || grew
			}
			return true
		})
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isLogSink(call) {
			return true
		}
		sinks++
		for _, a := range call.Args {
			if refersRaw(a) {
				leaks = append(leaks, fset.Position(call.Pos()).String())
				break
			}
		}
		return true
	})
	return leaks, sinks
}

// TestArgvLeakCheckerSeesLeaks is the positive control for the call-site test
// below: the checker must flag each way a raw argv can reach a sink.
func TestArgvLeakCheckerSeesLeaks(t *testing.T) {
	for _, tc := range []struct {
		body string
		leak bool
	}{
		{`logMessage(strings.Join(args, " "))`, true},
		{`logMessage(fmt.Sprintf("%d: %s", len(args), strings.Join(args, " ")))`, true},
		{`line := strings.Join(args, " "); logMessage(line)`, true},
		{`log.Warn("unknown %q", args[i])`, true},
		{`v, err := strconv.Atoi(args[1]); _ = v; log.Warn("bad: %v", err)`, true},
		{`if err := run(args); err != nil { sendStateChange("error", err.Error()) }`, true},
		{`logMessage(jniStartLogLine(args))`, false},
		{`logArgs := redactArgs(args); log.Warn("unknown %q", logArgs[i])`, false},
		{`v, err := strconv.Atoi(args[1]); _ = v; log.Warn("bad: %v", strconvReason(err))`, false},
		{`logMessage(fmt.Sprintf("%d args", len(args)))`, false},
	} {
		src := "package main\nfunc f(args []string, i int) {\n" + tc.body + "\n}\n"
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "snippet.go", src, 0)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.body, err)
		}
		leaks, sinks := argvLeaks(fset, file)
		if sinks == 0 {
			t.Errorf("%q: no sink seen", tc.body)
		}
		if got := len(leaks) > 0; got != tc.leak {
			t.Errorf("%q: leak=%v, want %v", tc.body, got, tc.leak)
		}
	}
}

// TestJNIFilesLogNoRawArgv guards the call sites. jni_android.go and jni.go need
// GOOS=android with cgo and never compile in the Linux CI, so a test of the
// helpers alone would stay green if startClient went back to printing argv.
// go/parser does not apply build tags, so their source is checked here.
func TestJNIFilesLogNoRawArgv(t *testing.T) {
	totalSinks := 0
	for _, name := range []string{"jni_android.go", "jni.go", "jni_args.go"} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		leaks, sinks := argvLeaks(fset, file)
		totalSinks += sinks
		for _, l := range leaks {
			t.Errorf("raw argv reaches a log or an error at %s", l)
		}
	}
	// jni_android.go alone has more than a dozen logMessage calls; far fewer
	// means the checker stopped seeing them.
	if totalSinks < 15 {
		t.Fatalf("only %d log sinks found, the checker is blind", totalSinks)
	}

	src, err := os.ReadFile("jni_android.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "logMessage(jniStartLogLine(args))") {
		t.Error("startClient no longer logs its argv through jniStartLogLine")
	}
}
