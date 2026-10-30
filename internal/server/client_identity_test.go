package server

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/padding"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// Every transport's authentication, given a registry client's secret, must
// yield an identity whose connections and traffic land on that client. Up to
// this test REALITY - the strategy clients try first - did not: it threw the
// registry match away and returned a shared "reality:<hmac>" identity, so its
// sessions recorded nothing.
//
// The boundaries, enumerated (TestIdentitySourcesAreKnown pins the list):
//
//	function    REALITY, REALITY-B1, IMAP, SSH, anti-probe, QUIC (below)
//	inline      HTTP polling (below, through processHTTPPollingRequest);
//	            WebSocket (TestWebSocketTrafficThroughAuth); morph, confusion
//	            and H2 stego (the traffic tests, which authenticate for real)

// realityIdentityString adapts realityIdentityFor (shared with
// failover_lease_test) to the string-secret signature the auth table uses.
func realityIdentityString(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
	t.Helper()
	return realityIdentityFor(t, srvCtx, []byte(secret))
}

func TestRegistrySecretIsAccounted(t *testing.T) {
	const global = "traffic-test-the-global-secret!!"
	ctxWith := func(t *testing.T) *serverContext {
		srvCtx := newTestServerContext(t)
		srvCtx.cfg.Secret = []byte(global)
		srvCtx.registry = trafficRegistry(t)
		return srvCtx
	}

	for _, tc := range []struct {
		name string
		auth func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity
	}{
		{"reality", realityIdentityString},
		{"reality-b1", func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
			var idx shortIDIndex
			idx.Rebuild(srvCtx.registry.ListClients(), srvCtx.cfg.Secret)
			e, ok := idx.Lookup(customtls.ShortIDFor([]byte(secret)))
			if !ok {
				t.Fatal("no short-ID entry")
			}
			return e.clientID
		}},
		{"imap", func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
			challenge, binding := "challenge-1", bytes.Repeat([]byte{0x42}, 32)
			id, _, ok := verifyIMAPAuth(strategy.IMAPAuthResponse([]byte(secret), challenge, binding), challenge, binding, srvCtx)
			if !ok {
				t.Fatal("IMAP did not authenticate the secret")
			}
			return id
		}},
		{"ssh", func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
			sid := []byte("exchange-hash")
			id, _, ok := verifySSHAuth(strategy.SSHAuthToken([]byte(secret), sid, strategy.SSHAuthClientToServer), sid, srvCtx)
			if !ok {
				t.Fatal("SSH did not authenticate the secret")
			}
			return id
		}},
		{"anti-probe", func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
			nonce := make([]byte, strategy.KnockNonceLen)
			rand.Read(nonce)
			bucket := strategy.KnockBucketNow()
			knock := []byte{0x00}
			knock = binary.BigEndian.AppendUint64(knock, uint64(bucket))
			knock = append(knock, nonce...)
			knock = append(knock, strategy.KnockTag([]byte(secret), nonce, bucket)...)
			ok, _, id := detectTimingKnockWithRegistry(knock, srvCtx)
			if !ok {
				t.Fatal("the knock did not match")
			}
			return id
		}},
		{"polling", func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
			sessionID := "fxacct-" + strings.ReplaceAll(t.Name(), "/", "-")
			ekm := bytes.Repeat([]byte{0x7e}, 32)
			pollingRawExchange(t, srvCtx, pollingHead(sessionID, pollingTokenFor(sessionID, []byte(secret), ekm), 0, 0), bytes.NewReader(nil))
			sess := pollingManager.Get(sessionID)
			if sess == nil {
				t.Fatal("no session was created")
			}
			defer pollingManager.removeSession(sess)
			return sess.ClientID
		}},
		{"quic", func(t *testing.T, srvCtx *serverContext, secret string) clientIdentity {
			// The QUIC listener matches the secret itself (strategy) and hands
			// over the client's id; this is where it becomes an identity.
			qc := &strategy.QUICServerConn{ClientIDFromRegistry: secret != global, ClientID: trafficClient}
			if secret == global {
				qc.ClientID = globalClientID
			}
			return quicClientIdentity(qc)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvCtx := ctxWith(t)
			id := tc.auth(t, srvCtx, trafficSecret)
			if !id.perClient || id.leaseID() != trafficClient || srvCtx.trafficOf(id) == nil {
				t.Fatalf("registry secret: identity %q accounted to %q, want %q with counters", id.id, id.leaseID(), trafficClient)
			}
			if g := tc.auth(t, srvCtx, global); g.perClient || srvCtx.trafficOf(g) != nil {
				t.Fatalf("global secret: identity %q is accounted to %q", g.id, g.leaseID())
			}
		})
	}
}

// TestREALITYKeepsItsLeaseSpelling: accounting the session to the registry
// client must not change the key its tunnel address is leased under.
func TestREALITYKeepsItsLeaseSpelling(t *testing.T) {
	srvCtx := newTestServerContext(t)
	srvCtx.registry = trafficRegistry(t)
	id := realityIdentityFor(t, srvCtx, []byte(trafficSecret))
	if want := realityClientIdentity([]byte(trafficSecret), registryIdentity(trafficClient)); id.id != want.id || id.perClient != want.perClient {
		t.Fatalf("lease identity %q/%v, want %q/%v", id.id, id.perClient, want.id, want.perClient)
	}
	// A registry REALITY client leases under its credential (leaseID), the same
	// key every other transport uses for it, not under the "reality:<hmac>"
	// spelling or a per-origin qualification: accounting it to the registry
	// client leaves the lease key alone.
	if got := allocationKey(id, "203.0.113.5", ""); got != trafficClient {
		t.Fatalf("REALITY lease key %q, want the registry client %q", got, trafficClient)
	}
}

// TestWebSocketTrafficThroughAuth authenticates a WebSocket client with a
// registry secret through the real TLS entry and proxies through it.
func TestWebSocketTrafficThroughAuth(t *testing.T) {
	const upN, downN = 30001, 50002
	srvCtx := newTestServerContext(t)
	reg := trafficRegistry(t)
	srvCtx.registry = reg
	target := proxyTarget(t, upN, downN)
	client, done := runTLSDispatch(t, srvCtx)

	token := computeMorphAuthForTest(t, []byte(trafficSecret), clientExporter(t, client))
	req := "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"X-Auth-Token: " + hex.EncodeToString(token) + "\r\n\r\n"
	client.Write(append([]byte{protocol.TypeWS}, req...))
	br := bufio.NewReader(client)
	if status := readStatusLine(t, br); !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("status %q", status)
	}
	tunnel := strategy.NewSalamanderConn(client, padding.NewSalamanderPadder([]byte(trafficSecret), padding.Balanced), true)
	tunnel.Write(targetPacket(target))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(tunnel, ack); err != nil || ack[0] != 0 {
		t.Fatalf("ack %x, err %v", ack, err)
	}
	tunnel.Write(bytes.Repeat([]byte{1}, upN))
	readDown(t, tunnel, downN)
	client.Close()
	waitHandler(t, done)
	waitTraffic(t, reg, trafficClient, upN, downN)
	if c := reg.GetStats(trafficClient).TotalConns; c != 1 {
		t.Fatalf("total_conns = %d, want 1", c)
	}
}

// funcCalls walks every function of the package's non-test files and hands
// visit each call with the name of the function it is in.
func funcCalls(t *testing.T, visit func(caller string, call *ast.CallExpr)) {
	t.Helper()
	funcNodes(t, func(caller string, n ast.Node) {
		if call, ok := n.(*ast.CallExpr); ok {
			visit(caller, call)
		}
	})
}

// funcNodes is funcCalls for every node.
func funcNodes(t *testing.T, visit func(caller string, n ast.Node)) {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			caller := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				recv := fn.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				if id, ok := recv.(*ast.Ident); ok {
					caller = id.Name + "." + caller
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n != nil {
					visit(caller, n)
				}
				return true
			})
		}
	}
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func checkKnown(t *testing.T, what string, got, want []string) {
	t.Helper()
	slices.Sort(got)
	got = slices.Compact(got)
	if !slices.Equal(got, want) {
		t.Fatalf("%s changed.\ngot:\n  %s\nwant:\n  %s", what, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// knownTrafficSinkCalls is every call that sets up a TUN session's data path,
// with the counters it passes - found by what it is (a trafficOf call), not by
// argument position. Each line is driven by TestTUNTrafficCountsIPBytes.
var knownTrafficSinkCalls = []string{
	"RegisterClientGated <- handleConfusionTUNMode: srvCtx.trafficOf(clientID)",  // confusion/exit
	"RegisterClientGated <- handleMorphTUNMode: srvCtx.trafficOf(clientID)",      // morph/exit
	"RegisterClientGated <- handleTUNModeCore: srvCtx.trafficOf(clientID)",       // native/exit
	"RegisterClientGated <- runPollingTUNMode: srvCtx.trafficOf(clientID)",       // polling/exit
	"RegisterClientGated <- setupH2TUNTunnel: srvCtx.trafficOf(tunnel.clientID)", // h2/exit
	"dialRelayTUN <- handleConfusionTUNMode: srvCtx.trafficOf(clientID)",         // confusion/relay
	"dialRelayTUN <- handleMorphTUNMode: srvCtx.trafficOf(clientID)",             // morph/relay
	"dialRelayTUN <- runPollingTUNMode: srvCtx.trafficOf(clientID)",              // polling/relay
	"dialRelayTUN <- setupH2TUNTunnel: srvCtx.trafficOf(tunnel.clientID)",        // h2/relay
	"relayTUNToUpstream <- handleTUNModeCore: srvCtx.trafficOf(clientID)",        // native/relay
}

func TestTrafficSinkCallsAreKnown(t *testing.T) {
	var got []string
	funcCalls(t, func(caller string, call *ast.CallExpr) {
		callee := calleeName(call)
		if callee != "RegisterClientGated" && callee != "dialRelayTUN" && callee != "relayTUNToUpstream" {
			return
		}
		counters := "<no counters>"
		for _, arg := range call.Args {
			if c, ok := arg.(*ast.CallExpr); ok && calleeName(c) == "trafficOf" {
				counters = types.ExprString(arg)
			}
		}
		got = append(got, callee+" <- "+caller+": "+counters)
	})
	checkKnown(t, "TUN sessions and the counters they pass", got, knownTrafficSinkCalls)
}

// knownProxyDials is every function that dials a proxy target for a client,
// with how its bytes are counted. A new one without counting fails here.
var knownProxyDials = []string{
	"MuxHandler.handleStream: counted at stream end", // no caller
	"handleMorphConnection: counted",                 // proxy/morph
	"handleProtocolConfusion: counted",               // proxy/confusion
	"handleQUICConnection: counted",                  // no harness: needs a live QUIC session
	"handleRawTunnel: counted",                       // proxy/raw, and WebSocket
	"runPollingSessionRelay: counted",                // proxy/polling
	"setupH2Tunnel: counted",                         // proxy/h2
}

func TestProxyDialsAreCounted(t *testing.T) {
	dials := map[string]bool{}
	counts := map[string]string{}
	funcCalls(t, func(caller string, call *ast.CallExpr) {
		switch calleeName(call) {
		case "optimizedDial":
			dials[caller] = true
		case "Dial":
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && strings.HasSuffix(types.ExprString(sel.X), "upstreamDialer") {
				dials[caller] = true
			}
		case "trafficOf", "addUp", "addDown":
			counts[caller] = "counted"
		case "AddBytes":
			if counts[caller] == "" {
				counts[caller] = "counted at stream end"
			}
		}
	})
	var got []string
	for caller := range dials {
		how := cmp.Or(counts[caller], "NOT COUNTED")
		got = append(got, caller+": "+how)
	}
	checkKnown(t, "proxy dial sites", got, knownProxyDials)
}

// TestOnlyTheSinkWritesTheTUNDevice: an uplink packet is counted where it is
// written to the device, so nothing else may write it.
func TestOnlyTheSinkWritesTheTUNDevice(t *testing.T) {
	var got []string
	funcCalls(t, func(caller string, call *ast.CallExpr) {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Write" {
			if inner, ok := sel.X.(*ast.CallExpr); ok && calleeName(inner) == "TUNDevice" {
				got = append(got, caller)
			}
		}
	})
	checkKnown(t, "writers of the shared TUN device", got, []string{"localTUNSink.WritePacket"})
}

// knownIdentitySources is every place an identity is made, with what from.
// registryIdentity (and realityClientIdentity carrying a registry cred) is how
// an identity gets attributed to a registry client; a new authentication path
// has to appear here, and its test in TestRegistrySecretIsAccounted with it.
var knownIdentitySources = []string{
	"literal <- clientIdentity.prefixed: clientIdentity{…}",
	"literal <- realityClientIdentity: clientIdentity{…}",
	"literal <- registryIdentity: clientIdentity{…}",
	"literal <- sharedIdentity: clientIdentity{…}",
	"realityClientIdentity <- authenticateREALITYClient: secret, registryIdentity(client.ID)",
	"realityClientIdentity <- authenticateREALITYClient: srvCtx.cfg.Secret, sharedIdentity(globalClientID)",
	"realityClientIdentity <- legacyAllocationKeys: secret, clientIdentity{}",
	"registryIdentity <- authenticateREALITYClient: client.ID",
	"registryIdentity <- detectTimingKnockWithRegistry: client.ID",
	"registryIdentity <- handleMorphConnection: client.ID",
	"registryIdentity <- handleWebSocketPadded: client.ID",
	"registryIdentity <- matchConfusionSecret: client.ID",
	"registryIdentity <- processHTTPPollingRequest: c.ID",
	"registryIdentity <- quicClientIdentity: qc.ClientID",
	"registryIdentity <- shortIDIndex.Rebuild: c.ID",
	"registryIdentity <- verifyH2AuthMulti: client.ID",
	"registryIdentity <- verifyIMAPAuth: client.ID",
	"registryIdentity <- verifySSHAuth: client.ID",
	"sharedIdentity <- authenticateREALITYClient: globalClientID",
	"sharedIdentity <- detectTimingKnockWithRegistry: globalClientID",
	"sharedIdentity <- handleMorphConnection: globalClientID",
	"sharedIdentity <- handleTUNModeCore: fmt.Sprintf(\"tun:%s\", conn.RemoteAddr().String())",
	"sharedIdentity <- handleWebSocketPadded: globalClientID",
	"sharedIdentity <- matchConfusionSecret: globalClientID",
	"sharedIdentity <- processHTTPPollingRequest: globalClientID",
	"sharedIdentity <- quicClientIdentity: qc.ClientID",
	"sharedIdentity <- shortIDIndex.Rebuild: globalClientID",
	"sharedIdentity <- verifyH2AuthMulti: globalClientID",
	"sharedIdentity <- verifyIMAPAuth: globalClientID",
	"sharedIdentity <- verifySSHAuth: globalClientID",
}

func TestIdentitySourcesAreKnown(t *testing.T) {
	var got []string
	funcNodes(t, func(caller string, n ast.Node) {
		// A literal that sets a field builds an identity past the
		// constructors; only the constructors themselves may.
		if lit, ok := n.(*ast.CompositeLit); ok && types.ExprString(lit.Type) == "clientIdentity" && len(lit.Elts) > 0 {
			got = append(got, "literal <- "+caller+": "+types.ExprString(lit))
		}
	})
	funcCalls(t, func(caller string, call *ast.CallExpr) {
		switch callee := calleeName(call); callee {
		case "registryIdentity", "sharedIdentity", "realityClientIdentity":
			args := make([]string, len(call.Args))
			for i, a := range call.Args {
				args[i] = types.ExprString(a)
			}
			got = append(got, callee+" <- "+caller+": "+strings.Join(args, ", "))
		}
	})
	checkKnown(t, "identity sources", got, knownIdentitySources)
}
