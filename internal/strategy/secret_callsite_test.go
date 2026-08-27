package strategy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A strategy keeps the secret it was built with only as a fallback, for the
// single-server case and for tests. Every dial resolves the key in force once,
// at the top of Connect, and passes it down by hand.
//
// The failure this guards against is not a missing feature but a reverted call
// site: `donorsFor(secret)` written as `donorsFor(r.secret)`, or
// `NewHTTP2StegoConn(conn, secret, ...)` as `NewHTTP2StegoConn(conn, s.secret,
// ...)`. Each compiles, each looks right in review, and each puts one
// endpoint's key into a handshake aimed at another. A behavioural test catches
// this only where there is a server to reject the wrong key; most of these
// strategies have no such test, and building one for every transport (raw ICMP,
// QUIC, five different TLS dialects) is not a thing this repository has.
//
// So this is a coverage floor rather than a substitute: it says the
// construction-time field is read in exactly the places it is allowed to be
// read, which is the whole of this mistake's shape. What it does NOT catch is a
// call site handed some third wrong value - for that, see the wire-level tests
// in per_endpoint_secret_test.go and secret_wire_test.go.
//
// allowedConstructionSecretReads names the functions that may read the field,
// with the reason each needs to.
var allowedConstructionSecretReads = map[string]string{
	// The fallback argument itself: dialSecret(ctx, r.secret).
	"": "",
	// donorsFor compares the asked-for secret against the construction one to
	// decide whether the set derived at construction is the right answer.
	"donorsFor": "compares against the construction secret by design",
}

// secretFieldNames are the construction-time secret fields on strategy types.
var secretFieldNames = map[string]bool{"secret": true, "knockSecret": true}

func TestConstructionSecretIsOnlyEverAFallback(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string
	checked := 0

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			recvName, recvType := receiverOf(fn)
			if recvName == "" || !strings.HasSuffix(recvType, "Strategy") {
				continue
			}
			checked++
			if _, allowed := allowedConstructionSecretReads[fn.Name.Name]; allowed {
				continue
			}
			for _, pos := range constructionSecretReads(fn.Body, recvName) {
				offenders = append(offenders,
					fset.Position(pos).String()+" in "+recvType+"."+fn.Name.Name)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no strategy methods were examined; the scan is not looking at anything")
	}
	if len(offenders) > 0 {
		t.Fatalf("a strategy method reads its construction-time secret outside dialSecret's fallback:\n  %s\n"+
			"the key in force comes from dialSecret(ctx, <field>), resolved once at the top of Connect; "+
			"reading the field again dials one endpoint with another endpoint's key",
			strings.Join(offenders, "\n  "))
	}
}

// receiverOf returns the receiver's variable name and bare type name, or empty
// strings for a receiver this scan cannot reason about (unnamed, or not a
// pointer/value to a plain identifier).
func receiverOf(fn *ast.FuncDecl) (name, typ string) {
	if len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return "", ""
	}
	name = fn.Recv.List[0].Names[0].Name
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	id, ok := expr.(*ast.Ident)
	if !ok {
		return "", ""
	}
	return name, id.Name
}

// constructionSecretReads returns the positions where body reads
// recv.secret / recv.knockSecret somewhere other than as dialSecret's fallback
// argument.
func constructionSecretReads(body *ast.BlockStmt, recv string) []token.Pos {
	// Positions of the reads that ARE the fallback argument, so they can be
	// subtracted from the total rather than matched structurally twice.
	allowed := map[token.Pos]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "dialSecret" || len(call.Args) != 2 {
			return true
		}
		if sel, ok := call.Args[1].(*ast.SelectorExpr); ok {
			allowed[sel.Pos()] = true
		}
		return true
	})

	var found []token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !secretFieldNames[sel.Sel.Name] {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != recv {
			return true
		}
		if allowed[sel.Pos()] {
			return true
		}
		found = append(found, sel.Pos())
		return true
	})
	return found
}
