package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// tlsLoopbackPair returns both ends of a completed TLS handshake over a real
// loopback TCP connection.
func tlsLoopbackPair(t *testing.T) (client, server *tls.Conn) {
	t.Helper()
	rawClient, rawServer := tcpPair(t)

	server = tls.Server(rawServer, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCertForTest(t)},
		MinVersion:   tls.VersionTLS13,
	})
	client = tls.Client(rawClient, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})

	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return client, server
}

// wrapBuffered stacks n bufferedConns on conn, the way the dispatcher does.
func wrapBuffered(conn net.Conn, n int) net.Conn {
	for range n {
		conn = &bufferedConn{Conn: conn, reader: conn}
	}
	return conn
}

func clientExporter(t *testing.T, c *tls.Conn) []byte {
	t.Helper()
	state := c.ConnectionState()
	ekm, err := customtls.ExportBindingKey(&state)
	if err != nil {
		t.Fatalf("client exporter: %v", err)
	}
	return ekm
}

// The legacy TLS path stacks two bufferedConns on the *tls.Conn: the replayed
// dispatch byte in handleTLSConnection, then the protocol peek in
// handleTLSConnectionLegacy. exporterBindingKey must see through all of them
// and return the exporter of this very session.
func TestExporterBindingKeyThroughNestedBufferedConns(t *testing.T) {
	client, server := tlsLoopbackPair(t)
	want := clientExporter(t, client)

	for depth := range 4 {
		got, err := exporterBindingKey(wrapBuffered(server, depth))
		if err != nil {
			t.Fatalf("depth %d: exporterBindingKey: %v", depth, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("depth %d: exporter differs from the client's side of the session", depth)
		}
	}
}

// Unwrapping all the way down must not invent a TLS session: with no *tls.Conn
// at the bottom it is still an error, at any depth.
func TestExporterBindingKeyPlaintextStillFails(t *testing.T) {
	_, rawServer := tcpPair(t)
	for depth := range 4 {
		if _, err := exporterBindingKey(wrapBuffered(rawServer, depth)); err == nil {
			t.Fatalf("depth %d: exporter returned for a plaintext connection", depth)
		}
	}
	if _, err := exporterBindingKey(&bufferedConn{}); err == nil {
		t.Fatal("exporter returned for a bufferedConn with nothing underneath")
	}
}

// runTLSDispatch starts handleTLSConnection on the server side of a TLS pair,
// the real entry point after the handshake, and returns the client side.
func runTLSDispatch(t *testing.T, srvCtx *serverContext) (*tls.Conn, <-chan struct{}) {
	t.Helper()
	client, server := tlsLoopbackPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleTLSConnection(server, srvCtx, 1)
	}()
	t.Cleanup(func() {
		client.Close()
		<-done
	})
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return client, done
}

// A client that writes an HTTP upgrade straight after the handshake, with no
// dispatch byte (the geneva strategies do exactly this), goes default ->
// handleTLSConnectionLegacy -> handleWebSocketPadded behind two bufferedConns.
// Its session-bound X-Auth-Token must verify there.
func TestLegacyTLSPath_WebSocketPaddedAuthenticates(t *testing.T) {
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte("legacy-exporter-test-secret-32b!")
	client, _ := runTLSDispatch(t, srvCtx)

	token := computeMorphAuthForTest(t, srvCtx.cfg.Secret, clientExporter(t, client))
	req := "GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"X-Auth-Token: " + hex.EncodeToString(token) + "\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	status, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("no answer to a correctly bound upgrade (exporter lost on the legacy path?): %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("status line %q, want 101", status)
	}
}

// Same path with a token that is not bound to this session: the answer must
// be what it always was - the connection closes with no bytes. Finding the
// exporter must not turn a failed token into a different reply.
func TestLegacyTLSPath_WebSocketPaddedBadTokenClosesSilently(t *testing.T) {
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte("legacy-exporter-test-secret-32b!")
	client, _ := runTLSDispatch(t, srvCtx)

	unbound := computeMorphAuthForTest(t, srvCtx.cfg.Secret, nil)
	req := "GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"X-Auth-Token: " + hex.EncodeToString(unbound) + "\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	got, err := io.ReadAll(client)
	if len(got) != 0 {
		t.Fatalf("server answered %d bytes to an unbound token: %q", len(got), got)
	}
	if err != nil {
		t.Fatalf("want a clean close, got %v", err)
	}
}

// A morph client without the dispatch byte lands in handleMorphConnection
// behind the same two wrappers; its bound token must verify and draw the ack.
func TestLegacyTLSPath_MorphAuthenticates(t *testing.T) {
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte("legacy-exporter-test-secret-32b!")
	client, _ := runTLSDispatch(t, srvCtx)

	name := []byte("test")
	hs := append([]byte("MRPH"), byte(len(name)))
	hs = append(hs, name...)
	hs = append(hs, computeMorphAuthForTest(t, srvCtx.cfg.Secret, clientExporter(t, client))...)
	// The legacy peek wants at least 24 bytes before it classifies; a real
	// client follows the header with its first frame straight away.
	hs = append(hs, make([]byte, 16)...)
	if _, err := client.Write(hs); err != nil {
		t.Fatalf("write morph handshake: %v", err)
	}

	ack := make([]byte, 1)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("no morph ack (exporter lost on the legacy path?): %v", err)
	}
	if ack[0] != 0x00 {
		t.Fatalf("ack 0x%02x, want 0x00", ack[0])
	}
}
