package wiretest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/server"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
	"github.com/tiredvpn/tiredvpn/internal/wiretest"
)

// testSecret is the shared key every fixture uses. Fixed, because two of the
// detectors are about what a key-derived value looks like across connections.
var testSecret = []byte("wiretest-shared-secret-0123456789")

// managerAt builds a strategy Manager pinned to one loopback address, which is
// the only thing the strategies need from it here.
func managerAt(t *testing.T, addr net.Addr) *strategy.Manager {
	t.Helper()
	m := strategy.NewManager()
	err := m.SetEndpoints([]endpoint.Endpoint{{Name: "wiretest", V4: addr.String()}}, endpoint.V4Only)
	if err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	if got := m.GetServerAddr(t.Context()); got != addr.String() {
		t.Fatalf("manager points at %q, want %q", got, addr.String())
	}
	return m
}

// testCert mints a throwaway self-signed certificate. Every client in this
// package dials with InsecureSkipVerify, so only the handshake has to succeed.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"wiretest"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// session ties the two observation points of one connection together: the raw
// TCP stream and, where the fixture terminates TLS, the plaintext behind it.
type session struct {
	Wire  *wiretest.Dump
	Plain *wiretest.Dump
}

// serveTLS accepts one connection, terminates TLS on it, and hands the
// plaintext side to handle. The returned channel carries the session once the
// handler is done with it.
//
// Two dumps come out: Wire is the TCP stream (TLS records — what a passive box
// sees) and Plain is the application stream behind the handshake (what a box
// holding the session key sees). Keeping them apart is the point; a marker
// found only in Plain is a different finding from one found in Wire.
func serveTLS(t *testing.T, ln *wiretest.Listener, handle func(net.Conn)) <-chan session {
	t.Helper()
	cert := testCert(t)
	out := make(chan session, 4)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				wire := raw.(*wiretest.Conn).Dump()
				tlsConn := tls.Server(raw, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{"h2", "http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				plain := wiretest.NewDump(wire.Name+"-plain", wiretest.LayerTLSPlaintext)
				rec := wiretest.NewConn(tlsConn, plain, true)
				handle(rec)
				out <- session{Wire: wire, Plain: plain}
			}(raw)
		}
	}()
	return out
}

// readHTTPHeaders drains one HTTP/1.1 request head, byte by byte, so nothing
// past \r\n\r\n is consumed.
func readHTTPHeaders(c net.Conn) ([]byte, error) {
	var buf bytes.Buffer
	one := make([]byte, 1)
	for buf.Len() < 8192 {
		if _, err := io.ReadFull(c, one); err != nil {
			return buf.Bytes(), err
		}
		buf.Write(one)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			return buf.Bytes(), nil
		}
	}
	return buf.Bytes(), io.ErrUnexpectedEOF
}

const wsUpgradeResponse = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
	"\r\n"

// fakeREALITYServer answers one REALITY ClientHello well enough that the real
// client accepts the ServerHello and moves on to the next step.
//
// This is a reconstruction of the server, not the server (internal/server's
// REALITY handler hangs off an unexported serverContext). It is honest about
// what it proves: the CLIENT is the real artifact here, and the bytes the
// detectors look at are the ones the shipped client emits. The fake only has to
// be convincing enough to get the client past validateServerHello — it proves
// nothing about the server's own wire behaviour.
func fakeREALITYServer(t *testing.T, ln *wiretest.Listener, secret []byte) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

				hello, err := readTLSRecord(conn)
				if err != nil {
					return
				}
				clientExt, err := server.ExtractREALITYExtensionFromClientHello(hello)
				if err != nil {
					return
				}

				serverPriv, _, err := customtls.GenerateX25519KeyPair()
				if err != nil {
					return
				}

				// Answer data-layer v2, which is what the shipped binary
				// requires (requireDataV2 defaults true there; the constructor
				// alone leaves it false). Answering v1 would have the client
				// fall back to a path nobody ships, and every shape assertion
				// below would then be about the wrong data layer - rule 9.
				clientSalt, ok := customtls.ParseClientDataV2(secret, clientExt.PubKey, clientExt.Extra)
				if !ok {
					t.Errorf("fake reality server: client did not offer data-layer v2")
					return
				}
				var serverSalt [32]byte
				if _, err := rand.Read(serverSalt[:]); err != nil {
					return
				}
				serverExt, err := customtls.NewServerREALITYExtensionDataV2(
					secret, serverPriv, clientExt.PubKey, clientSalt, serverSalt)
				if err != nil {
					return
				}
				if _, err := conn.Write(fakeServerHello(serverExt)); err != nil {
					return
				}

				// Everything after this point is the client's post-handshake
				// traffic: the encrypted dispatch record, then whatever smux
				// says. Drain it with a large buffer so the recorded boundaries
				// are the ones the kernel delivered, not ones this reader
				// invented.
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

// realityHandshakes runs n REALITY connections against the fake server and
// returns the captures that got past the ServerHello.
//
// requireDataV2 is turned on here because the shipped binary turns it on and
// the constructor does not: without it the client would silently take the v1
// data layer, and every shape assertion about the encrypted records would be
// about a path nobody deploys.
//
// More than one connection is taken on purpose. The observations downstream are
// segment-boundary-sensitive and read() may merge two writes, so a single noisy
// sample is not enough to conclude from.
func realityHandshakes(t *testing.T, n int) []*wiretest.Dump {
	t.Helper()
	ln := wiretest.Listen(t, "reality", wiretest.LayerTCP)
	fakeREALITYServer(t, ln, testSecret)

	m := managerAt(t, ln.Addr())
	s := strategy.NewREALITYStrategy(m, testSecret)
	s.SetRequireDataV2(true)

	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		conn, err := s.Connect(ctx, "wiretest")
		if err == nil {
			conn.Close()
		}
		cancel()
	}

	var out []*wiretest.Dump
	for _, d := range ln.Dumps() {
		c2s := d.Bytes(wiretest.C2S)
		if h := reassembledHelloLen(c2s); h > 0 && len(c2s) > h {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		t.Fatal("no REALITY handshake got past the ServerHello — the harness, not the code, is broken")
	}
	return out
}

// fakeIMAPServer answers the client side of the IMAP camouflage handshake using
// only exported strategy helpers, then drains the TLS session so the recorder
// keeps seeing bytes.
//
// Like the REALITY fixture this is a reconstruction of the server; the client is
// the shipped artifact and the assertions are about its bytes. What the fixture
// does contribute is the TLS upgrade, which is what the absence assertions lean
// on - and that part is the standard library, not our code.
func fakeIMAPServer(t *testing.T, ln *wiretest.Listener, secret []byte) {
	t.Helper()
	cert := testCert(t)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
				if err := imapServerHandshake(raw, cert, secret); err != nil {
					t.Errorf("fake imap server: %v", err)
				}
			}(raw)
		}
	}()
}

func imapServerHandshake(raw net.Conn, cert tls.Certificate, secret []byte) error {
	br := bufio.NewReader(raw)
	line := func() (string, error) { return br.ReadString('\n') }
	tagOf := func(s string) string { return strings.Fields(s)[0] }

	greeting, err := line()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return fmt.Errorf("not an IMAP greeting: %q", greeting)
	}

	capLine, err := line()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(raw, "%s%s OK Pre-login capabilities listed.\r\n",
		strategy.IMAPPreLoginCaps(), tagOf(capLine)); err != nil {
		return err
	}

	tlsLine, err := line()
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToUpper(tlsLine), "STARTTLS") {
		return fmt.Errorf("expected STARTTLS, got %q", tlsLine)
	}
	if _, err := fmt.Fprintf(raw, "%s OK Begin TLS negotiation now.\r\n", tagOf(tlsLine)); err != nil {
		return err
	}

	tlsConn := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	binding, err := strategy.IMAPChannelBinding(tlsConn.ConnectionState())
	if err != nil {
		return err
	}
	br = bufio.NewReader(tlsConn)

	capLine, err = line()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tlsConn, "%s%s OK Capabilities listed.\r\n",
		strategy.IMAPPostSTARTTLSCaps(), tagOf(capLine)); err != nil {
		return err
	}

	authLine, err := line()
	if err != nil {
		return err
	}
	challenge, err := strategy.NewIMAPAuthChallenge()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tlsConn, "+ %s\r\n",
		base64.StdEncoding.EncodeToString([]byte(challenge))); err != nil {
		return err
	}
	respLine, err := line()
	if err != nil {
		return err
	}
	rawResp, err := base64.StdEncoding.DecodeString(strings.TrimSpace(respLine))
	if err != nil {
		return err
	}
	_, digest, err := strategy.ParseIMAPAuthResponse(rawResp)
	if err != nil {
		return err
	}
	if !strategy.VerifyIMAPAuthResponse(digest, secret, challenge, binding) {
		return fmt.Errorf("client digest did not verify")
	}
	if _, err := fmt.Fprintf(tlsConn, "%s%s OK [CAPABILITY %s] Logged in\r\n",
		strategy.IMAPPostLoginCaps(), tagOf(authLine), strategy.IMAPCapsInline()); err != nil {
		return err
	}

	selectLine, err := line()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tlsConn, "* 1234 EXISTS\r\n* 0 RECENT\r\n"+
		"* OK [UIDVALIDITY 1234567890] UIDs valid\r\n"+
		"%s OK [READ-WRITE] Select completed.\r\n", tagOf(selectLine)); err != nil {
		return err
	}

	// Keep pulling TLS records so the tunnel bytes the client writes actually
	// cross the recorded socket instead of sitting in a send buffer.
	_, _ = io.Copy(io.Discard, tlsConn)
	return nil
}

// readTLSRecord reads one complete TLS record (5-byte header + body).
//
// Deliberately NOT io.ReadFull(conn, header[:5]): a short fixed-size read forces
// a chunk boundary the client never wrote, and the fragment-shape detector then
// measures the fixture instead of the client. Reading into a large buffer keeps
// every recorded boundary one the kernel actually delivered.
func readTLSRecord(c net.Conn) ([]byte, error) {
	var buf []byte
	chunk := make([]byte, 4096)
	for {
		n, err := c.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if len(buf) >= 5 {
			want := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
			if len(buf) >= want {
				return buf[:want], nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

// fakeServerHello wraps a REALITY extension in a ServerHello record shaped the
// way the client's validateServerHello scans for it: a padding extension
// (0x0015) whose body starts with [PubKey:32][AuthToken:32].
func fakeServerHello(ext *customtls.REALITYExtension) []byte {
	pad := ext.Marshal()

	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x15})
	_ = binary.Write(&exts, binary.BigEndian, uint16(len(pad)))
	exts.Write(pad)

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(serverHelloRandom())
	body.WriteByte(0x00)           // empty session id
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(0x00)           // null compression
	_ = binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	exts.WriteTo(&body) //nolint:errcheck // bytes.Buffer never fails

	var msg bytes.Buffer
	msg.WriteByte(0x02) // ServerHello
	msg.Write([]byte{byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())})
	body.WriteTo(&msg) //nolint:errcheck // bytes.Buffer never fails

	var rec bytes.Buffer
	rec.Write([]byte{0x16, 0x03, 0x03})
	_ = binary.Write(&rec, binary.BigEndian, uint16(msg.Len()))
	msg.WriteTo(&rec) //nolint:errcheck // bytes.Buffer never fails
	return rec.Bytes()
}

// serverHelloRandom returns 32 random bytes that do not contain the 0x00 0x15
// pair. The client scans the whole record for that pair and tries to parse a
// REALITY extension at every hit; a random hit would be rejected by the auth
// check anyway, but excluding it keeps the fixture deterministic.
func serverHelloRandom() []byte {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		if !bytes.Contains(b, []byte{0x00, 0x15}) {
			return b
		}
	}
}
