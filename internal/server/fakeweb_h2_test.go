package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// We advertise h2 in ALPN on every TLS path that can end at the decoy. These
// tests hold the decoy to that advertisement: a peer that settled on h2 gets
// HTTP/2, a peer that settled on http/1.1 keeps the byte-exact nginx bytes,
// and the ALPN is still found when the dispatcher has stacked its replay
// buffers on top of the *tls.Conn - which it always has by the time an
// unrecognised connection reaches serveFakeWebsite.

// fakeDecoyServer runs serveFakeWebsite behind a real TLS handshake on a real
// socket and returns the address to dial. wrap is applied to the handshaked
// connection, standing in for the dispatcher's buffering layers.
func fakeDecoyServer(t *testing.T, alpn []string, wrap func(net.Conn) net.Conn) string {
	t.Helper()

	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCertForTest(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   alpn,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				tc := tls.Server(raw, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				conn := net.Conn(tc)
				if wrap != nil {
					conn = wrap(conn)
				}
				serveFakeWebsite(conn, &Config{}, testLogger(t))
			}()
		}
	}()

	return ln.Addr().String()
}

// h2Get fetches path over HTTP/2 only. http2.Transport never falls back to
// HTTP/1.1, so a passing request proves the server really spoke h2 rather than
// the client having quietly downgraded.
func h2Get(t *testing.T, addr, path, method string) *http.Response {
	t.Helper()

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed leaf minted for this test
			NextProtos:         []string{"h2"},
			MinVersion:         tls.VersionTLS12,
		},
	}
	t.Cleanup(tr.CloseIdleConnections)

	req, err := http.NewRequest(method, "https://"+addr+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2 %s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestFakeWebsite_H2ServesPage is the regression this file exists for. Before
// the fix a client that agreed on h2 got "HTTP/1.1 200 OK" written into a
// connection waiting for a SETTINGS frame, and reported a protocol error
// instead of rendering anything: the decoy did not work for any browser.
//
// It checks the whole exchange down to the body, not that the request returned
// without an error - a 200 with no page would be the same failure wearing a
// success code.
func TestFakeWebsite_H2ServesPage(t *testing.T) {
	t.Parallel()

	addr := fakeDecoyServer(t, []string{"h2", "http/1.1"}, nil)
	resp := h2Get(t, addr, "/", http.MethodGet)

	if resp.ProtoMajor != 2 {
		t.Fatalf("served HTTP/%d.%d, want HTTP/2", resp.ProtoMajor, resp.ProtoMinor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != nginxIndexHTML {
		t.Fatalf("body is not the nginx welcome page (%d bytes, want %d)", len(body), len(nginxIndexHTML))
	}

	// The same header set the HTTP/1.1 path sends. Order is not checked
	// because HPACK has none to check.
	for _, h := range []struct{ name, want string }{
		{"Server", nginxServerHeader},
		{"Content-Type", "text/html"},
		{"Content-Length", strconv.Itoa(len(nginxIndexHTML))},
		{"Accept-Ranges", "bytes"},
	} {
		if got := resp.Header.Get(h.name); got != h.want {
			t.Errorf("%s = %q, want %q", h.name, got, h.want)
		}
	}
	for _, name := range []string{"Date", "Last-Modified", "ETag"} {
		if resp.Header.Get(name) == "" {
			t.Errorf("missing %s header", name)
		}
	}
}

// TestFakeWebsite_H2ThroughBufferedConn covers the shape the dispatcher
// actually produces: the h2 preface was peeked and is replayed through two
// bufferedConns before anything reaches the decoy. If the ALPN cannot be read
// through those wrappers the connection falls back to HTTP/1.1 bytes, which is
// the original bug with an extra layer on top.
func TestFakeWebsite_H2ThroughBufferedConn(t *testing.T) {
	t.Parallel()

	addr := fakeDecoyServer(t, []string{"h2", "http/1.1"}, func(c net.Conn) net.Conn {
		return &bufferedConn{Conn: &bufferedConn{Conn: c, reader: c}, reader: c}
	})

	resp := h2Get(t, addr, "/", http.MethodGet)
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/%d.%d status %d, want HTTP/2 200", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != nginxIndexHTML {
		t.Fatalf("body is not the nginx welcome page (%d bytes)", len(body))
	}
}

func TestFakeWebsite_H2UnknownPath404(t *testing.T) {
	t.Parallel()

	addr := fakeDecoyServer(t, []string{"h2", "http/1.1"}, nil)
	resp := h2Get(t, addr, "/nope.php", http.MethodGet)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != nginx404Body {
		t.Errorf("404 body is not the nginx page")
	}
}

func TestFakeWebsite_H2HeadHasNoBody(t *testing.T) {
	t.Parallel()

	addr := fakeDecoyServer(t, []string{"h2", "http/1.1"}, nil)
	resp := h2Get(t, addr, "/", http.MethodHead)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("HEAD returned %d body bytes, want none", len(body))
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(nginxIndexHTML)) {
		t.Errorf("HEAD Content-Length = %q, want %d", got, len(nginxIndexHTML))
	}
}

// TestFakeWebsite_HTTP11ALPNKeepsNginxBytes is the other half of the branch.
// The HTTP/1.1 path writes nginx's exact header block in nginx's order, and a
// change that sent every TLS connection through the h2 server would destroy
// that without any h2 test noticing.
func TestFakeWebsite_HTTP11ALPNKeepsNginxBytes(t *testing.T) {
	t.Parallel()

	addr := fakeDecoyServer(t, []string{"http/1.1"}, nil)

	raw, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed leaf minted for this test
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	if got := raw.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", got)
	}

	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := raw.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	got, err := io.ReadAll(raw)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 200 OK\r\nServer: "+nginxServerHeader+"\r\n")) {
		t.Fatalf("not the byte-exact nginx status line and Server header: %.60q", got)
	}
	if !bytes.Contains(got, []byte(nginxIndexHTML)) {
		t.Fatal("welcome page missing from the HTTP/1.1 response")
	}
}

// TestNegotiatedALPN_PlaintextConnection pins the answer for connections that
// never did a TLS handshake. imap and ssh camouflage and the unknown-protocol
// fallback on the bare socket all reach the decoy this way, and sending any of
// them to the h2 server would hang them.
func TestNegotiatedALPN_PlaintextConnection(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	if got := negotiatedALPN(server); got != "" {
		t.Errorf("plain socket: ALPN = %q, want empty", got)
	}
	wrapped := &bufferedConn{Conn: server, reader: server}
	if got := negotiatedALPN(wrapped); got != "" {
		t.Errorf("buffered plain socket: ALPN = %q, want empty", got)
	}
}
