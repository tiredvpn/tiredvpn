package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The plaintext entry path (handleConnection) routes a bare "MRPH" or HTTP/2
// preface into the morph and h2 handlers with no TLS session behind them, so
// there is no exporter to bind the auth token to. The handlers used to carry on
// with ekm == nil, which h.Write(nil) turns into the unbound pre-S22 token: one
// value per secret per minute, sent in the clear and replayable for the whole
// skew window. These tests drive the production dispatcher, not the verifier
// alone, and pair each plaintext refusal with a TLS acceptance on the same
// dispatcher so a refusal cannot come from a broken harness.

const replayTestSecret = "plaintext-replay-secret-0123456789"

// serveOne runs handleConnection for exactly one accepted loopback connection.
func serveOne(t *testing.T, srvCtx *serverContext) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConnection(conn, srvCtx, 1)
	}()
	return ln.Addr().String()
}

func replayTestServer(t *testing.T) *serverContext {
	t.Helper()
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte(replayTestSecret)
	srvCtx.tlsConfig = &tls.Config{Certificates: []tls.Certificate{selfSignedCertForTest(t)}}
	return srvCtx
}

func morphHello(token []byte) []byte {
	hs := []byte("MRPH")
	hs = append(hs, 0) // empty profile name
	hs = append(hs, token...)
	return append(hs, 0) // shaper ID
}

func readMorphAck(t *testing.T, conn net.Conn) byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil {
		t.Fatalf("read morph ack: %v", err)
	}
	return ack[0]
}

// morphPlaintextAck sends one morph hello over a bare TCP connection.
func morphPlaintextAck(t *testing.T, token []byte) byte {
	t.Helper()
	conn, err := net.Dial("tcp", serveOne(t, replayTestServer(t)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(morphHello(token)); err != nil {
		t.Fatalf("write: %v", err)
	}
	return readMorphAck(t, conn)
}

func TestPlaintextMorphRefusesUnboundToken(t *testing.T) {
	// A wrong token first: the answer an unbound token must now share.
	if got := morphPlaintextAck(t, make([]byte, 32)); got != 0x01 {
		t.Fatalf("wrong token: ack 0x%02x, want 0x01", got)
	}
	unbound := mintBoundMorphToken([]byte(replayTestSecret), nil)
	for i := range 2 { // the second send is the replay of captured bytes
		if got := morphPlaintextAck(t, unbound); got != 0x01 {
			t.Fatalf("unbound token, connection %d: ack 0x%02x, want 0x01 (plaintext token accepted)", i+1, got)
		}
	}
}

func TestTLSMorphAcceptsBoundToken(t *testing.T) {
	raw, err := net.Dial("tcp", serveOne(t, replayTestServer(t)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "www.example.com"})
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	if err := protocol.WriteDispatch(conn, protocol.TypeMorph); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	ekm, err := exporterBindingKey(conn)
	if err != nil {
		t.Fatalf("exporter: %v", err)
	}
	if _, err := conn.Write(morphHello(mintBoundMorphToken([]byte(replayTestSecret), ekm))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readMorphAck(t, conn); got != 0x00 {
		t.Fatalf("session-bound token over TLS: ack 0x%02x, want 0x00", got)
	}
}

// h2Handshake runs the real stego client handshake and reports its error.
func h2Handshake(t *testing.T, conn net.Conn, ekm []byte) error {
	t.Helper()
	sc := strategy.NewHTTP2StegoConn(conn, []byte(replayTestSecret), true, strategy.NaivePaddingMinimal, ekm)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	return sc.HandshakeContext(ctx)
}

// h2PlaintextAuth sends the stego auth HEADERS over bare TCP and reports whether
// the server answered them with its auth ack (a HEADERS frame). The preface goes
// out alone first: the plaintext dispatcher recognises h2 only when its first
// read is exactly the preface, so letting it coalesce with SETTINGS would send
// the connection to the decoy and pass for the wrong reason. Seeing the server's
// SETTINGS proves the h2 handler, not the decoy, is the one answering.
func h2PlaintextAuth(t *testing.T, apiKey, requestID string) bool {
	t.Helper()
	conn, err := net.Dial("tcp", serveOne(t, replayTestServer(t)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/grpc.health.v1.Health/Check"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "x-goog-api-key", Value: apiKey},
		{Name: "x-goog-request-id", Value: requestID},
	} {
		enc.WriteField(f)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hbuf.Bytes(), EndHeaders: true}); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	sawSettings := false
	conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			break // deadline: no ack arrived
		}
		switch f.(type) {
		case *http2.SettingsFrame:
			sawSettings = true
		case *http2.HeadersFrame:
			return true
		}
	}
	if !sawSettings {
		t.Fatal("no server SETTINGS: the connection never reached the h2 handler")
	}
	return false
}

func TestPlaintextH2RefusesUnboundToken(t *testing.T) {
	if h2PlaintextAuth(t, strings.Repeat("00", 16), strings.Repeat("00", 16)) {
		t.Fatal("wrong token authenticated")
	}
	apiKey, requestID := mintBoundH2Token([]byte(replayTestSecret), nil)
	for i := range 2 { // the second connection replays the captured headers
		if h2PlaintextAuth(t, apiKey, requestID) {
			t.Fatalf("connection %d: unbound h2 token authenticated over plaintext", i+1)
		}
	}
}

func TestTLSH2AcceptsBoundToken(t *testing.T) {
	raw, err := net.Dial("tcp", serveOne(t, replayTestServer(t)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "www.example.com", NextProtos: []string{"h2"}})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	if err := protocol.WriteDispatch(conn, protocol.TypeStego); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	ekm, err := exporterBindingKey(conn)
	if err != nil {
		t.Fatalf("exporter: %v", err)
	}
	if err := h2Handshake(t, conn, ekm); err != nil {
		t.Fatalf("session-bound h2 handshake over TLS failed: %v", err)
	}
}

// HTTP polling has no plaintext entry path, but its verifier takes the same
// exporter and must refuse the same way if one ever arrives without it.
func TestVerifyPollingAuthRefusesUnboundToken(t *testing.T) {
	secret := []byte(replayTestSecret)
	sessionID := "sess-unbound-0123456789"
	if verifyPollingAuth(mintBoundPollingToken(secret, nil, sessionID), sessionID, secret, nil) {
		t.Fatal("unbound polling token accepted with no exporter")
	}
	ekm := []byte("polling-exporter-0123456789abcdef")
	if !verifyPollingAuth(mintBoundPollingToken(secret, ekm, sessionID), sessionID, secret, ekm) {
		t.Fatal("session-bound polling token rejected")
	}
}
