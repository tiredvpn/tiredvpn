package main

import (
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"strings"
	"testing"
)

// TestConnectionStringQUICPort: the admin commands used to write quicPort=8443
// into every connection string by default, a port no server listens on. The
// Android app passes it straight back as -quic-port. It is now written only
// when the operator sets one.
func TestConnectionStringQUICPort(t *testing.T) {
	query := func(s string) url.Values {
		t.Helper()
		_, q, ok := strings.Cut(s, "?")
		if !ok {
			t.Fatalf("no query in %q", s)
		}
		v, err := url.ParseQuery(q)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return v
	}

	if q := query(buildConnectionString("vpn.example.com:995", "s", true, 0, "auto", "c", nil)); q.Has("quicPort") {
		t.Errorf("unset -quic-port wrote quicPort=%s", q.Get("quicPort"))
	}
	if got := query(buildConnectionString("vpn.example.com:995", "s", true, 995, "auto", "c", nil)).Get("quicPort"); got != "995" {
		t.Errorf("explicit -quic-port 995 wrote quicPort=%q", got)
	}
}

// TestAdminQUICPortDefault: admin add and admin qr used to default -quic-port
// to 8443 and write it into every connection string. Both now take their
// connection flags from registerAdminConnFlags; parsed with no arguments the
// string carries no quicPort. The AST check pins the call sites: a command
// defining its own -quic-port again would bring its own default back.
func TestAdminQUICPortDefault(t *testing.T) {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	conn := registerAdminConnFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if s := conn.connectionString("vpn.example.com:995", "s"); strings.Contains(s, "quicPort") {
		t.Errorf("default admin flags wrote %s", s)
	}

	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"adminAdd", "adminQR"} {
		var decl *ast.FuncDecl
		for _, d := range file.Decls {
			if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == fn {
				decl = f
			}
		}
		if decl == nil {
			t.Fatalf("%s not found", fn)
		}
		usesHelper, ownFlag := false, false
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "registerAdminConnFlags" {
				usesHelper = true
			}
			if len(call.Args) > 0 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == `"quic-port"` {
					ownFlag = true
				}
			}
			return true
		})
		if !usesHelper || ownFlag {
			t.Errorf("%s: registerAdminConnFlags used=%v, own -quic-port flag=%v", fn, usesHelper, ownFlag)
		}
	}
}
