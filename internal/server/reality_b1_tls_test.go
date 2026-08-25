package server

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// deadlineRecorder records the deadlines set on a connection, so a test can
// assert the handshake is bounded and the tunnel is not.
type deadlineRecorder struct {
	net.Conn
	mu    sync.Mutex
	calls []time.Time
}

func (d *deadlineRecorder) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.calls = append(d.calls, t)
	d.mu.Unlock()
	return d.Conn.SetDeadline(t)
}

func (d *deadlineRecorder) seen() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.calls...)
}

// TestB1HandshakeIsBoundedAndTheTunnelIsNot covers both halves of the same
// mistake.
//
// A handshake with no deadline of its own is a handshake an authenticated
// client can hold open: crypto/tls resets its useless-record counter on any
// record that advances things, so alternating ChangeCipherSpec with encrypted
// fragments never trips it. And a deadline that survives into the tunnel is
// worse than none, because it would cut every real connection at whatever
// absolute time the peek loop happened to pick.
func TestB1HandshakeIsBoundedAndTheTunnelIsNot(t *testing.T) {
	secret := []byte("shared-secret")
	dir := t.TempDir()
	if err := writeTestIndex(dir); err != nil {
		t.Fatal(err)
	}
	srvCtx := &serverContext{cfg: &Config{FakeWebRoot: dir}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A real peek buffer: the certificate HMAC derives this connection's auth
	// key from the ClientHello's key share, so nil no longer gets past the door.
	f := newB1Fixture(t, 0)
	hello := f.buildB1Hello(t, f.payload(t, time.Now()))
	peek := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

	recorded := make(chan []time.Time, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			recorded <- nil
			return
		}
		rec := &deadlineRecorder{Conn: raw}
		handleREALITYB1(rec, peek, "test-client", secret, customtls.AuthFlagExporterBinding, srvCtx, log.WithPrefix("test"))
		recorded <- rec.seen()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, b1ClientConfig("yandex.ru", nil))
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	state := client.ConnectionState()
	ekm, err := customtls.ExportBindingKey(&state)
	if err != nil {
		t.Fatal(err)
	}
	if err := customtls.WriteClientBinding(client, secret, ekm, protocol.TypeMux); err != nil {
		t.Fatal(err)
	}
	// The server answers with its own clock, one-way: proof_s was dropped once
	// cert-HMAC took over authenticating the server inside the handshake.
	if _, err := customtls.ReadServerTime(client); err != nil {
		t.Fatalf("server time record: %v", err)
	}
	_ = client.Close()

	var calls []time.Time
	select {
	case calls = <-recorded:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never finished with the connection")
	}

	if len(calls) < 2 {
		t.Fatalf("saw %d deadline calls, want a bound before the handshake and a clear after", len(calls))
	}
	if calls[0].IsZero() {
		t.Fatal("the handshake ran with no deadline of its own")
	}
	if within := time.Until(calls[0]); within > b1HandshakeTimeout+time.Second {
		t.Fatalf("handshake deadline is %v out, want about %v", within, b1HandshakeTimeout)
	}
	if !calls[len(calls)-1].IsZero() {
		t.Fatal("the tunnel inherited the handshake deadline, so it would die when the handshake would have")
	}
}

// TestB1SafetyPolicyIsNotADonorNumber states the distinction the limit exists
// for: donor tolerances make a prober see the site we claim to be, and a client
// past the gate is no longer someone to convince.
func TestB1SafetyPolicyIsNotADonorNumber(t *testing.T) {
	t.Parallel()

	if b1HandshakeSafetyPolicy.Mechanism != ccsCount {
		t.Fatal("the safety bound must be a count, not a donor mechanism")
	}
	if b1HandshakeSafetyPolicy.Limit < 2 {
		t.Fatal("a real client sends one ChangeCipherSpec; the bound must leave room for it")
	}
	if b1HandshakeSafetyPolicy.Limit > 16 {
		t.Fatalf("bound is %d: above crypto/tls's own 16 it never governs anything",
			b1HandshakeSafetyPolicy.Limit)
	}

	// Deliberately not compared against the donor table. The two limits never
	// meet: donor tolerances govern the shared listener, where a prober is
	// being shown a site, and this one governs the B1 path, where the client
	// has already authenticated and there is nobody left to convince.

	// And it closes when spent.
	stream := repeat(ccsRecord, b1HandshakeSafetyPolicy.Limit+4)
	g := newCCSGuardWithPolicy(&scriptConn{data: stream}, b1HandshakeSafetyPolicy)
	if _, err := feedGuard(t, g, stream, 64); !errors.Is(err, errCCSFlood) {
		t.Fatalf("err = %v, want the flood to be cut off", err)
	}
}
