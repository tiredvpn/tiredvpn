package server

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/padding"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// handleRawTunnel authenticates nobody: it trusts its caller to have done it.
// These tests drive the real post-handshake entry point, handleTLSConnection,
// with every input that used to reach the tunnel funnel with no credential at
// all, and check that none of them gets a relay or a TUN reply any more.
//
// The paths, enumerated (rule 7):
//   - dispatch byte TypeRaw, then a SOCKS-style target;
//   - dispatch byte TypeRaw, then the TUN mode byte and a TUN handshake;
//   - an HTTP/1 request carrying "Upgrade: websocket" but no X-Auth-Token,
//     which the legacy detector handed to an unauthenticated WebSocket relay;
//   - an HTTP/1 request with the literal "TIRED" anywhere past its first
//     byte, which the legacy detector answered with "TIRED" and a raw tunnel.
//
// All other callers of handleRawTunnel sit behind their transport's own
// authentication; TestRawTunnelCallersAreKnown pins that list.

const rawAuthTestSecret = "raw-tunnel-auth-test-secret-32b!"

// unassignedDispatch is a discriminator no client sends. Whatever the server
// does with it is, by definition, what a prober gets for "not ours".
const unassignedDispatch = byte(0xfe)

func rawAuthCtx(t *testing.T) *serverContext {
	t.Helper()
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte(rawAuthTestSecret)
	return srvCtx
}

// tunHandshakeProbe is a TUN request ([mode 0x02][ip:4][mtu:2][ver:1]) padded
// past the legacy detector's 24-byte peek with what a client would send next.
func tunHandshakeProbe() []byte {
	p := []byte{0x02, 0, 0, 0, 0, 0x05, 0x78, 0x03}
	return append(p, bytes.Repeat([]byte{0x45}, 24)...)
}

// proxyProbe is a raw-tunnel target request followed by a first payload, so
// that the bytes after the dispatch byte also fill the legacy 24-byte peek.
func proxyProbe(target string) []byte {
	return append(targetPacket(target), []byte("unauthenticated-ping-0123456789")...)
}

// drainAnswer reads what the server sends within window and stops at EOF.
func drainAnswer(t *testing.T, c net.Conn, window time.Duration) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(window)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, c)
	return buf.Bytes()
}

// targetHit reports whether the server dialled the target, closing that
// connection so a relay the server did open can wind down.
func targetHit(hits chan net.Conn) bool {
	select {
	case c := <-hits:
		c.Close()
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}

// dispatchAnswer runs one TLS session through handleTLSConnection, writes
// disp followed by body, and returns everything the server sent back and
// whether it dialled the target.
func dispatchAnswer(t *testing.T, srvCtx *serverContext, hits chan net.Conn, disp byte, body []byte) ([]byte, bool) {
	t.Helper()
	client, done := runTLSDispatch(t, srvCtx)
	if _, err := client.Write(append([]byte{disp}, body...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	answer := drainAnswer(t, client, time.Second)
	hit := targetHit(hits)
	client.Close()
	waitHandler(t, done)
	return answer, hit
}

func TestRawDispatchUnauthenticatedGetsNoTunnel(t *testing.T) {
	longTest(t)
	for _, tc := range []struct {
		name string
		body func(target string) []byte
	}{
		{"proxy target", proxyProbe},
		{"TUN handshake", func(string) []byte { return tunHandshakeProbe() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvCtx := rawAuthCtx(t)
			target, hits := deadTarget(t)

			got, hit := dispatchAnswer(t, srvCtx, hits, protocol.TypeRaw, tc.body(target))
			if hit {
				t.Fatal("the server opened a connection to the target for an unauthenticated peer")
			}
			if len(got) != 0 {
				t.Fatalf("server answered %d bytes (%x) to an unauthenticated TypeRaw session", len(got), got)
			}

			// Rule 8: the fix must not leave TypeRaw distinguishable from a
			// discriminator nobody uses. Same tail, unassigned byte, same answer.
			control, _ := dispatchAnswer(t, srvCtx, hits, unassignedDispatch, tc.body(target))
			if !bytes.Equal(got, control) {
				t.Fatalf("TypeRaw answer %x differs from an unassigned dispatch byte's %x", got, control)
			}
		})
	}
}

// readStatusLine reads the first response line and the headers behind it.
func readStatusLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	status, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	return strings.TrimSpace(status)
}

// http1Answer sends req over a fresh TLS session with no dispatch byte (the
// legacy path), then follow-up, and returns the status line plus whatever
// raw bytes followed it.
func http1Answer(t *testing.T, srvCtx *serverContext, hits chan net.Conn, req string, followUp []byte) (status string, rest []byte, hit bool) {
	t.Helper()
	client, done := runTLSDispatch(t, srvCtx)
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	br := bufio.NewReader(client)
	if strings.Contains(req, "TIRED") {
		// The old literal answer is five bytes with no status line.
		head := make([]byte, 5)
		n, _ := io.ReadFull(br, head)
		if string(head[:n]) == "TIRED" {
			status = "TIRED"
		} else {
			br = bufio.NewReader(io.MultiReader(bytes.NewReader(head[:n]), br))
		}
	}
	if status == "" {
		status = readStatusLine(t, br)
	}
	if followUp != nil {
		_, _ = client.Write(followUp)
	}
	rest = drainAnswer(t, &readerConn{Conn: client, r: br}, time.Second)
	hit = targetHit(hits)
	client.Close()
	waitHandler(t, done)
	return status, rest, hit
}

// readerConn reads through a bufio.Reader that may already hold bytes.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// wsFrame builds an unmasked binary WebSocket frame, the shape the old
// unauthenticated relay unwrapped before handing the payload to the tunnel.
func wsFrame(payload []byte) []byte {
	return append([]byte{0x82, byte(len(payload))}, payload...)
}

func TestHTTP1UnauthenticatedGetsNoTunnel(t *testing.T) {
	longTest(t)
	for _, tc := range []struct {
		name    string
		req     string
		control string
		frame   func(target string) []byte
	}{
		{
			name: "WebSocket upgrade without token",
			req: "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n" +
				"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
			control: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			frame:   func(target string) []byte { return wsFrame(proxyProbe(target)) },
		},
		{
			name:    "TIRED literal",
			req:     "GET /TIRED HTTP/1.1\r\nHost: example.com\r\n\r\n",
			control: "GET /TIRxD HTTP/1.1\r\nHost: example.com\r\n\r\n",
			frame:   proxyProbe,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvCtx := rawAuthCtx(t)
			target, hits := deadTarget(t)

			status, rest, hit := http1Answer(t, srvCtx, hits, tc.req, tc.frame(target))
			if hit {
				t.Fatal("the server opened a connection to the target for an unauthenticated peer")
			}
			if !strings.HasPrefix(status, "HTTP/1.1 ") || strings.HasPrefix(status, "HTTP/1.1 101") {
				t.Fatalf("unauthenticated request was taken into a tunnel (answer %q)", status)
			}
			if len(rest) > 0 && rest[0] == 0x00 {
				t.Fatalf("server sent a tunnel success ack after %q", status)
			}

			// The answer must be the fake site's answer to the same request
			// without the trigger, so the trigger itself is not a probe.
			controlStatus, _, _ := http1Answer(t, srvCtx, hits, tc.control, nil)
			if status != controlStatus {
				t.Fatalf("status %q differs from the plain request's %q", status, controlStatus)
			}
		})
	}
}

// TestAuthenticatedTunnelThroughTLSDispatch is the positive control for the
// harness above: an authenticated WebSocket Padded client on the same entry
// point does reach handleRawTunnel, gets the ack and an echo. Without it, the
// "no target hit" results would be compatible with a harness that cannot see
// a tunnel at all.
func TestAuthenticatedTunnelThroughTLSDispatch(t *testing.T) {
	srvCtx := rawAuthCtx(t)
	target, hits := deadTarget(t)
	client, _ := runTLSDispatch(t, srvCtx)

	token := computeMorphAuthForTest(t, srvCtx.cfg.Secret, clientExporter(t, client))
	req := "GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"X-Auth-Token: " + hex.EncodeToString(token) + "\r\n\r\n"
	if _, err := client.Write(append([]byte{protocol.TypeWS}, req...)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(client)
	if status := readStatusLine(t, br); !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("status %q, want 101", status)
	}
	if br.Buffered() != 0 {
		t.Fatalf("%d unexpected bytes after the upgrade response", br.Buffered())
	}

	padder := padding.NewSalamanderPadder([]byte(rawAuthTestSecret), padding.Balanced)
	tunnel := strategy.NewSalamanderConn(client, padder, true)
	if _, err := tunnel.Write(targetPacket(target)); err != nil {
		t.Fatalf("write target: %v", err)
	}

	select {
	case c := <-hits:
		defer c.Close()
		go func() { _, _ = io.Copy(c, c) }()
	case <-time.After(3 * time.Second):
		t.Fatal("authenticated client never reached the target")
	}

	ack := make([]byte, 1)
	if _, err := io.ReadFull(tunnel, ack); err != nil || ack[0] != 0x00 {
		t.Fatalf("ack %x, err %v; want 0x00", ack, err)
	}
	msg := []byte("authenticated-echo")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(tunnel, echo); err != nil || !bytes.Equal(echo, msg) {
		t.Fatalf("echo %q, err %v", echo, err)
	}
}

// tunnelFunnels are the functions that open a relay or hand out a TUN address
// and authenticate nobody themselves.
var tunnelFunnels = []string{"handleRawTunnel", "handleTUNModeWithHandshake", "handleTUNModeCore"}

// knownFunnelCallers is every "callee <- caller" in the package. Each caller
// authenticates its peer before the call (or is itself a funnel). Adding a
// line here is a claim that the new caller does too.
var knownFunnelCallers = []string{
	"handleRawTunnel <- (*ICMPServer).getOrCreateSession", // AEAD under the master key per packet
	"handleRawTunnel <- handleAntiProbeAuth",
	"handleRawTunnel <- handleIMAPCamouflage",
	"handleRawTunnel <- handleREALITYB1",
	"handleRawTunnel <- handleREALITYSession",
	"handleRawTunnel <- handleSSHCamouflage",
	"handleRawTunnel <- handleWebSocketPadded",
	"handleTUNModeCore <- handleTUNModeWithHandshake",
	"handleTUNModeWithHandshake <- handleQUICConnection", // QUIC listener authenticates the session
	"handleTUNModeWithHandshake <- handleRawTunnel",
}

// TestRawTunnelCallersAreKnown fails when a call into an unauthenticated
// funnel appears or disappears, so the next one is looked at instead of
// inherited - the failure rule 7 is about.
func TestRawTunnelCallersAreKnown(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
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
				if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok {
						caller = "(*" + id.Name + ")." + caller
					}
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && slices.Contains(tunnelFunnels, id.Name) {
					got = append(got, id.Name+" <- "+caller)
				}
				return true
			})
		}
	}
	slices.Sort(got)
	got = slices.Compact(got)
	if !slices.Equal(got, knownFunnelCallers) {
		t.Fatalf("callers of the unauthenticated funnels changed.\ngot:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(knownFunnelCallers, "\n  "))
	}
}
