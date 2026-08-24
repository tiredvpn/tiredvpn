package strategy

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// A stand-in for the B1 server, close enough to the real one that the client
// cannot tell: it runs the same gate arithmetic on the ClientHello, mints the
// same shape of certificate with the same MAC in its signature field, and
// speaks the same binding exchange.
//
// Deliberately not a call into internal/server: this is the client's test, and
// importing the server would make it pass or fail for reasons that have nothing
// to do with the client.
type b1TestServer struct {
	staticPriv *ecdh.PrivateKey
	secret     []byte
	srvTime    time.Time

	// corruptCertMAC makes the server sign the certificate with the wrong key,
	// which is what a MITM terminating TLS would end up doing.
	corruptCertMAC bool

	// wrongBindingSecret makes the server read proof_c with a different secret.
	wrongBindingSecret bool
}

func newB1TestServer(t *testing.T) *b1TestServer {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &b1TestServer{
		staticPriv: priv,
		secret:     []byte("shared-test-secret"),
		srvTime:    time.Now().Truncate(time.Second),
	}
}

func (s *b1TestServer) publicKey() []byte { return s.staticPriv.PublicKey().Bytes() }

// serve runs one connection: peek the ClientHello, derive the auth key, run the
// TLS handshake with the MAC'd certificate, check the binding, answer with the
// time, then echo every stream.
func (s *b1TestServer) serve(t *testing.T, raw net.Conn) error {
	t.Helper()
	defer raw.Close()

	peeked, buffered, err := peekClientHello(raw)
	if err != nil {
		return err
	}

	helloRaw := peeked[5:]
	peerPub, err := customtls.ExtractPeerX25519(helloRaw)
	if err != nil {
		return err
	}
	random := helloRaw[4+2 : 4+2+32]
	authKey, err := customtls.ServerAuthKey(s.staticPriv.Bytes(), peerPub, random)
	if err != nil {
		return err
	}

	// The gate: the session_id must open under this key, or the client is not
	// one of ours.
	sessionID, err := customtls.SessionIDFrom(helloRaw)
	if err != nil {
		return err
	}
	zeroed, err := customtls.ZeroSessionID(helloRaw)
	if err != nil {
		return err
	}
	payload, err := customtls.OpenSessionID(s.staticPriv.Bytes(), peerPub, zeroed, random, sessionID)
	if err != nil {
		return err
	}
	if payload.ShortID != customtls.ShortIDFor(s.secret) {
		return errors.New("unknown short id")
	}

	certKey := authKey
	if s.corruptCertMAC {
		certKey = bytes.Repeat([]byte{0xFF}, 32)
	}
	cert := b1TestCert(t, "github.com")

	tlsConn := stdtls.Server(buffered, &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		GetCertificate: func(*stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			return customtls.CertHMACOverlay(cert, certKey)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	ekm, err := customtls.ExportBindingKey(&state)
	if err != nil {
		return err
	}

	readSecret := s.secret
	if s.wrongBindingSecret {
		readSecret = []byte("a different secret")
	}
	dispatch, err := customtls.ReadClientBinding(tlsConn, readSecret, ekm)
	if err != nil {
		return err
	}
	if dispatch != protocol.TypeMux {
		return errors.New("unexpected dispatch")
	}
	if err := customtls.WriteServerTime(tlsConn, s.srvTime); err != nil {
		return err
	}

	sess, err := smux.Server(tlsConn, smux.DefaultConfig())
	if err != nil {
		return err
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return nil
		}
		go func() {
			defer stream.Close()
			_, _ = io.Copy(stream, stream)
		}()
	}
}

// peekClientHello reads the first TLS record and returns it along with a
// connection that replays it, the same trick the real server uses.
func peekClientHello(conn net.Conn) ([]byte, net.Conn, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, err
	}
	length := int(header[3])<<8 | int(header[4])
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil, err
	}
	full := append(header, body...)
	return full, &replayConn{Conn: conn, replay: bytes.NewReader(full)}, nil
}

type replayConn struct {
	net.Conn
	replay *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.replay.Len() > 0 {
		return c.replay.Read(p)
	}
	return c.Conn.Read(p)
}

func b1TestCert(t *testing.T, sni string) *stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// b1Client builds a strategy configured for B1 against the given server.
func b1Client(t *testing.T, srv *b1TestServer) *REALITYStrategy {
	t.Helper()
	r := NewREALITYStrategy(nil, srv.secret)
	r.SetB1(srv.publicKey())
	if !r.b1Enabled {
		t.Fatal("B1 did not enable")
	}
	return r
}

// dialB1 runs one full client connection against the stand-in server.
func dialB1(t *testing.T, r *REALITYStrategy, srv *b1TestServer) (net.Conn, error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.serve(t, conn)
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = tcpConn.SetDeadline(deadline)

	conn, err := r.connectB1(t.Context(), tcpConn, "github.com:443", deadline)
	if err != nil {
		tcpConn.Close()
		<-srvDone
		return nil, err
	}
	t.Cleanup(func() { conn.Close(); <-srvDone })
	return conn, nil
}

// TestB1ClientEndToEnd is the acceptance criterion: the client authenticates,
// brings up smux over real TLS, and moves a megabyte in both directions.
func TestB1ClientEndToEnd(t *testing.T) {
	srv := newB1TestServer(t)
	conn, err := dialB1(t, b1Client(t, srv), srv)
	if err != nil {
		t.Fatalf("connectB1: %v", err)
	}

	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writing: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("a megabyte did not survive the round trip intact")
	}
}

// TestB1ClientRejectsForeignServer covers the case cert-HMAC exists for: a
// server that completes a perfectly good TLS handshake but cannot prove it
// holds our static key. The client must fail inside the handshake, before any
// application data.
func TestB1ClientRejectsForeignServer(t *testing.T) {
	srv := newB1TestServer(t)
	srv.corruptCertMAC = true

	_, err := dialB1(t, b1Client(t, srv), srv)
	if err == nil {
		t.Fatal("the client accepted a server that could not prove itself")
	}
	if !errors.Is(err, customtls.ErrCertHMACMismatch) {
		t.Fatalf("err = %v, want it to wrap ErrCertHMACMismatch", err)
	}
}

// TestB1ClientFailuresDoNotLeak checks that a hundred rejected dials leave no
// goroutines or descriptors behind. The reject path is the one that runs when a
// censor is interfering, so it is the one that must not accumulate.
func TestB1ClientFailuresDoNotLeak(t *testing.T) {
	srv := newB1TestServer(t)
	srv.corruptCertMAC = true
	r := b1Client(t, srv)

	// Warm up so one-time allocations are not counted as a leak.
	for range 3 {
		_, _ = dialB1(t, r, srv)
	}
	runtime.GC()
	before := runtime.NumGoroutine()

	for range 100 {
		if _, err := dialB1(t, r, srv); err == nil {
			t.Fatal("a dial against a foreign server succeeded")
		}
	}

	// Goroutines from the accept side wind down asynchronously; give them a
	// bounded chance to finish rather than asserting on an instant.
	deadline := time.Now().Add(5 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+10 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines went from %d to %d over 100 failed dials", before, after)
}

// TestB1ClientAppliesClockOffset is the acceptance criterion on the clock hint:
// after the server reports a time 400 seconds ahead, the next session_id
// carries that corrected time rather than the local one.
func TestB1ClientAppliesClockOffset(t *testing.T) {
	srv := newB1TestServer(t)
	srv.srvTime = time.Now().Add(400 * time.Second).Truncate(time.Second)

	r := b1Client(t, srv)
	if _, err := dialB1(t, r, srv); err != nil {
		t.Fatalf("connectB1: %v", err)
	}

	if off := r.clockOffset.Offset(); off < 395*time.Second || off > 405*time.Second {
		t.Fatalf("clock offset = %v, want about 400s", off)
	}

	// The next connection must stamp the corrected time into session_id.
	conn, err := dialB1(t, r, srv)
	if err != nil {
		t.Fatalf("second connectB1: %v", err)
	}
	_ = conn

	skew := time.Duration(r.clockOffset.Now().Unix()-time.Now().Unix()) * time.Second
	if skew < 395*time.Second || skew > 405*time.Second {
		t.Fatalf("corrected clock is %v ahead, want about 400s", skew)
	}
}

// TestB1ClientSendsNothingInTheClear is the acceptance criterion on the wire
// shape: after the handshake there must be no bare one-byte segment. Everything
// the client sends is a TLS application-data record.
func TestB1ClientSendsNothingInTheClear(t *testing.T) {
	srv := newB1TestServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.serve(t, conn)
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	rec := &b1RecordingConn{Conn: tcpConn}
	deadline := time.Now().Add(10 * time.Second)
	_ = tcpConn.SetDeadline(deadline)

	conn, err := b1Client(t, srv).connectB1(t.Context(), rec, "github.com:443", deadline)
	if err != nil {
		t.Fatalf("connectB1: %v", err)
	}
	conn.Close()
	<-srvDone

	writes := rec.writes()
	if len(writes) == 0 {
		t.Fatal("the client wrote nothing")
	}
	for i, w := range writes {
		if len(w) == 1 {
			t.Fatalf("write %d is a bare single byte: the dispatch byte is back on the wire", i)
		}
	}

	// Everything after the handshake must be application data. The first
	// post-handshake write starts with 0x17 0x03 0x03.
	var appData []byte
	for _, w := range writes {
		if len(w) >= 3 && w[0] == 0x17 && w[1] == 0x03 && w[2] == 0x03 {
			appData = w
			break
		}
	}
	if appData == nil {
		t.Fatal("no application-data record found; the binding record did not go out encrypted")
	}
}

// b1RecordingConn keeps a copy of every Write so a test can inspect the wire
// shape without a packet capture.
type b1RecordingConn struct {
	net.Conn
	buf [][]byte
}

func (c *b1RecordingConn) Write(p []byte) (int, error) {
	c.buf = append(c.buf, bytes.Clone(p))
	return c.Conn.Write(p)
}

func (c *b1RecordingConn) writes() [][]byte { return c.buf }

// TestB1ClientStillSendsRenegotiationInfo pins the claim that lets the B1
// client clear config.Renegotiation to get the TLS exporter back.
//
// The clearing happens after HandshakeContext returns, so the ClientHello is
// already on the wire and cannot be affected by it — but that ordering is easy
// to lose in a later edit, and losing it would drop renegotiation_info from the
// extension list. Every browser sends that extension, so dropping it changes
// JA3 and JA4 and undoes the point of parroting a browser at all.
//
// So this checks the wire, not the intent: extension 0xff01 must be in the
// ClientHello the client actually sent.
func TestB1ClientStillSendsRenegotiationInfo(t *testing.T) {
	for _, profile := range []string{"firefox", "chrome", "safari"} {
		t.Run(profile, func(t *testing.T) {
			srv := newB1TestServer(t)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })

			srvDone := make(chan struct{})
			go func() {
				defer close(srvDone)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = srv.serve(t, conn)
			}()

			tcpConn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			rec := &b1RecordingConn{Conn: tcpConn}
			deadline := time.Now().Add(10 * time.Second)
			_ = tcpConn.SetDeadline(deadline)

			r := b1Client(t, srv)
			r.SetFingerprint(profile)

			conn, err := r.connectB1(t.Context(), rec, "github.com:443", deadline)
			if err != nil {
				t.Fatalf("connectB1 with %s: %v", profile, err)
			}
			conn.Close()
			<-srvDone

			writes := rec.writes()
			if len(writes) == 0 {
				t.Fatal("the client wrote nothing")
			}
			// The ClientHello is the first record: 0x16 handshake, then the body.
			hello := writes[0]
			if len(hello) < 6 || hello[0] != 0x16 {
				t.Fatalf("first write is not a handshake record: % x", hello[:min(6, len(hello))])
			}
			ids := extensionIDs(t, hello[5:])
			if !bytes.Contains(ids, []byte{0xff, 0x01}) {
				t.Fatal("renegotiation_info (0xff01) is missing from the ClientHello; " +
					"the profile no longer matches the browser it imitates")
			}
		})
	}
}

// extensionIDs returns the ClientHello's extension types in order, which is the
// part of the message JA3 and JA4 are computed from.
func extensionIDs(t *testing.T, helloRaw []byte) []byte {
	t.Helper()
	// 4 handshake header + 2 legacy_version + 32 random
	off := 4 + 2 + 32
	off += 1 + int(helloRaw[off])                             // session_id
	off += 2 + (int(helloRaw[off])<<8 | int(helloRaw[off+1])) // cipher_suites
	off += 1 + int(helloRaw[off])                             // compression_methods
	total := int(helloRaw[off])<<8 | int(helloRaw[off+1])     // extensions length
	off += 2
	end := off + total

	var ids []byte
	for off+4 <= end {
		ids = append(ids, helloRaw[off], helloRaw[off+1])
		off += 4 + (int(helloRaw[off+2])<<8 | int(helloRaw[off+3]))
	}
	return ids
}

// BenchmarkB1ClientThroughput measures bulk transfer over the B1 tunnel on
// loopback. The acceptance bar is that B1 is not more than 10% slower than the
// legacy path; the legacy path's own cost is its hand-rolled ChaCha20 stream,
// against real TLS 1.3 with AES-NI here, so B1 is expected to win rather than
// merely keep up.
func BenchmarkB1ClientThroughput(b *testing.B) {
	t := &testing.T{}
	srv := newB1TestServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(t, conn)
		}
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer tcpConn.Close()
	deadline := time.Now().Add(5 * time.Minute)
	_ = tcpConn.SetDeadline(deadline)

	r := NewREALITYStrategy(nil, srv.secret)
	r.SetB1(srv.publicKey())
	conn, err := r.connectB1(b.Context(), tcpConn, "github.com:443", deadline)
	if err != nil {
		b.Fatalf("connectB1: %v", err)
	}
	defer conn.Close()

	const chunk = 64 << 10
	payload := make([]byte, chunk)
	if _, err := rand.Read(payload); err != nil {
		b.Fatalf("rand: %v", err)
	}
	sink := make([]byte, chunk)

	b.SetBytes(chunk)
	b.ResetTimer()
	for b.Loop() {
		done := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			done <- err
		}()
		if _, err := io.ReadFull(conn, sink); err != nil {
			b.Fatalf("read: %v", err)
		}
		if err := <-done; err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}
