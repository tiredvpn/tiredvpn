package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// -protect-proto has to reach the protect package before the first dial.
func TestInitProtectorAppliesProtocol(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		t.Skip("protector only exists on linux/android")
	}
	sock := filepath.Join(t.TempDir(), "protect.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { protect.SetProtocol(protect.ProtoV1) })

	initProtector(&Config{ProtectPath: sock, ProtectProto: 2})
	if got := protect.Protocol(); got != protect.ProtoV2 {
		t.Fatalf("protocol after -protect-proto 2 = %d, want 2", got)
	}
	initProtector(&Config{ProtectPath: sock})
	if got := protect.Protocol(); got != protect.ProtoV1 {
		t.Fatalf("protocol without -protect-proto = %d, want 1", got)
	}
}

// The function is only half of it: the Android path (runControlSocketMode)
// and the TUN path must actually apply the protocol. Checked on the source,
// since neither mode can be started in a unit test.
func TestProtectProtocolCallSites(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "client.go", nil, 0)
	if err != nil {
		t.Fatalf("parse client.go: %v", err)
	}
	want := map[string]string{
		"runControlSocketMode": "initProtector",
		"runTUNMode":           "SetProtocol",
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || want[fn.Name.Name] == "" {
			continue
		}
		callee := want[fn.Name.Name]
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				found = found || fun.Name == callee
			case *ast.SelectorExpr:
				found = found || fun.Sel.Name == callee
			}
			return true
		})
		if !found {
			t.Errorf("%s does not call %s", fn.Name.Name, callee)
		}
		delete(want, fn.Name.Name)
	}
	for name := range want {
		t.Errorf("function %s not found in client.go", name)
	}
}
