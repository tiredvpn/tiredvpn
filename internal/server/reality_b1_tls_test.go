package server

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// b1TLSPair runs our server-side TLS config against a crypto/tls client over a
// loopback connection, and hands both completed sides back.
// testB1AuthKey stands in for the key the gate derives per connection.
var testB1AuthKey = []byte("test-connection-auth-key-32bytes")

func b1TLSPair(t *testing.T, serverCfg *tls.Config, clientCfg *tls.Config) (client, server *tls.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		conn *tls.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		// Wrap the way handleREALITYB1 does: the certificate's signature field
		// carries a MAC keyed with the connection's auth key, so a connection
		// that never passed the gate gets no certificate at all.
		sc := tls.Server(customtls.NewAuthConn(raw, testB1AuthKey), serverCfg)
		accepted <- result{conn: sc, err: sc.Handshake()}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc := tls.Client(raw, clientCfg)
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	res := <-accepted
	if res.err != nil {
		t.Fatalf("server handshake: %v", res.err)
	}

	t.Cleanup(func() { _ = cc.Close(); _ = res.conn.Close() })
	return cc, res.conn
}

func b1ClientConfig(sni string, curves []tls.CurveID) *tls.Config {
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // the leaf is self-signed by design; trust comes from the binding
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   curves,
	}
}

// TestB1TLSNegotiation pins what the B1 handshake settles on: TLS 1.3, h2, and
// the key exchange the donor being imitated uses.
//
// This deliberately contradicts the group named in the task 006 acceptance
// criteria, which predate the donor measurements. Eleven of thirteen donors
// answer with classic X25519 in a 133-byte plaintext ServerHello, against 1221
// when the hybrid is chosen, and B1 presents itself under a donor's SNI - so
// the 1088 extra bytes would ride in every real connection. The group comes
// from the same donor table the shared listener uses, so the two paths cannot
// answer differently on one port.
func TestB1TLSNegotiation(t *testing.T) {
	t.Parallel()

	serverCfg := b1TLSConfig(newCertMinter(), "www.microsoft.com")

	// The client offers the hybrid first, exactly as a current browser does.
	// What we answer is decided by the donor, not by what was offered.
	clientCurves := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}

	t.Run("classic donor", func(t *testing.T) {
		client, server := b1TLSPair(t, serverCfg, b1ClientConfig("yandex.ru", clientCurves))
		for name, st := range map[string]tls.ConnectionState{"client": client.ConnectionState(), "server": server.ConnectionState()} {
			if st.CurveID != tls.X25519 {
				t.Fatalf("%s: negotiated %v under a classic donor, want X25519", name, st.CurveID)
			}
			if st.Version != tls.VersionTLS13 {
				t.Fatalf("%s: version = %x, want TLS 1.3", name, st.Version)
			}
			if st.NegotiatedProtocol != "h2" {
				t.Fatalf("%s: ALPN = %q, want h2", name, st.NegotiatedProtocol)
			}
		}
	})

	t.Run("hybrid donor", func(t *testing.T) {
		// raw.githubusercontent.com really does negotiate ML-KEM, so under its
		// name we do too - reproducing a measured difference, not inventing one.
		client, _ := b1TLSPair(t, serverCfg, b1ClientConfig("raw.githubusercontent.com", clientCurves))
		if got := client.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
			t.Fatalf("negotiated %v under a hybrid donor, want X25519MLKEM768", got)
		}
	})
}

// TestB1TLSCertificateMatchesSNI covers the criterion across several names from
// the donor pool: whatever the client asked for is the name it gets back.
func TestB1TLSCertificateMatchesSNI(t *testing.T) {
	t.Parallel()

	serverCfg := b1TLSConfig(newCertMinter(), "www.microsoft.com")

	for _, sni := range []string{"yandex.ru", "www.vk.com", "github.com"} {
		t.Run(sni, func(t *testing.T) {
			client, _ := b1TLSPair(t, serverCfg, b1ClientConfig(sni, nil))

			certs := client.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				t.Fatal("server sent no certificate")
			}
			if cn := certs[0].Subject.CommonName; cn != sni {
				t.Fatalf("CN = %q, want the requested %q", cn, sni)
			}
		})
	}
}

// TestB1BindingFlow walks the post-handshake exchange both ways: a client that
// proves it holds the secret gets the tunnel, and one that does not gets a web
// page rather than a reset.
func TestB1BindingFlow(t *testing.T) {
	secret := []byte("shared-secret")

	t.Run("valid proof is answered", func(t *testing.T) {
		serverCfg := b1TLSConfig(newCertMinter(), "")
		client, server := b1TLSPair(t, serverCfg, b1ClientConfig("yandex.ru", nil))

		serverState := server.ConnectionState()
		serverEKM, err := customtls.ExportBindingKey(&serverState)
		if err != nil {
			t.Fatal(err)
		}
		clientState := client.ConnectionState()
		clientEKM, err := customtls.ExportBindingKey(&clientState)
		if err != nil {
			t.Fatal(err)
		}
		if string(serverEKM) != string(clientEKM) {
			t.Fatal("the two sides exported different keying material")
		}

		go func() {
			_ = customtls.WriteClientBinding(client, secret, clientEKM, protocol.TypeMux)
		}()

		dispatch, err := customtls.ReadClientBinding(server, secret, serverEKM)
		if err != nil {
			t.Fatalf("valid binding was rejected: %v", err)
		}
		if dispatch != protocol.TypeMux {
			t.Fatalf("dispatch = %d, want TypeMux", dispatch)
		}

		// The server's answer is one-way now: no proof, and the client does not
		// block on it. Proving the server happens inside the handshake through
		// the certificate MAC.
		want := time.Now().Truncate(time.Second)
		go func() {
			_ = customtls.WriteServerTime(server, want)
		}()
		got, err := customtls.ReadServerTime(client)
		if err != nil {
			t.Fatalf("client could not read the server time: %v", err)
		}
		if !got.Equal(want) {
			t.Fatalf("server time = %v, want %v", got, want)
		}
	})

	t.Run("wrong secret is a mismatch, not a parse error", func(t *testing.T) {
		serverCfg := b1TLSConfig(newCertMinter(), "")
		client, server := b1TLSPair(t, serverCfg, b1ClientConfig("yandex.ru", nil))

		serverState := server.ConnectionState()
		serverEKM, _ := customtls.ExportBindingKey(&serverState)
		clientState := client.ConnectionState()
		clientEKM, _ := customtls.ExportBindingKey(&clientState)

		go func() {
			_ = customtls.WriteClientBinding(client, []byte("the wrong secret"), clientEKM, protocol.TypeMux)
		}()

		_, err := customtls.ReadClientBinding(server, secret, serverEKM)
		if !errors.Is(err, customtls.ErrBindingMismatch) {
			t.Fatalf("err = %v, want ErrBindingMismatch - the server has to be able to tell "+
				"a bad proof from a broken connection, or it cannot serve the fake site", err)
		}
	})
}

// TestB1BadBindingGetsAWebsite is the criterion that a client failing the
// binding sees an HTTP response rather than a reset or an alert: it
// authenticated its session_id, so from its point of view it is talking to a
// web server, and a web server answers.
func TestB1BadBindingGetsAWebsite(t *testing.T) {
	dir := t.TempDir()
	if err := writeTestIndex(dir); err != nil {
		t.Fatal(err)
	}
	srvCtx := &serverContext{cfg: &Config{FakeWebRoot: dir}}

	serverCfg := b1TLSConfig(newCertMinter(), "")
	client, server := b1TLSPair(t, serverCfg, b1ClientConfig("yandex.ru", nil))

	clientState := client.ConnectionState()
	clientEKM, _ := customtls.ExportBindingKey(&clientState)

	// The client sends a proof under a secret the server does not know, then
	// behaves like a browser.
	go func() {
		_ = customtls.WriteClientBinding(client, []byte("stolen-session-id-holder"), clientEKM, protocol.TypeMux)
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: yandex.ru\r\n\r\n"))
	}()

	serverState := server.ConnectionState()
	serverEKM, _ := customtls.ExportBindingKey(&serverState)
	logger := log.WithPrefix("test")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := customtls.ReadClientBinding(server, []byte("real-secret"), serverEKM); errors.Is(err, customtls.ErrBindingMismatch) {
			serveFakeWebsite(server, srvCtx.cfg, logger)
		}
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client got no reply at all: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		t.Fatalf("client got %q, want an HTTP response", buf[:n])
	}

	// The reply is what this test is about. serveFakeWebsite then keeps the
	// connection alive the way a web server does, so hang up rather than wait
	// out its idle timeout.
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the fake website handler did not return after the client hung up")
	}
}

func writeTestIndex(dir string) error {
	return os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html><body>hello</body></html>"), 0o600)
}
