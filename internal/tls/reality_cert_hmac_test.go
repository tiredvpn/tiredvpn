package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// mintTestCert produces the kind of certificate the server's minter caches: a
// self-signed ECDSA P-256 leaf with Leaf populated.
func mintTestCert(t *testing.T, sni string) *stdtls.Certificate {
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

// mustOverlay is CertHMACOverlay with the test's error handling.
func mustOverlay(t *testing.T, cert *stdtls.Certificate, authKey []byte) []byte {
	t.Helper()
	out, err := CertHMACOverlay(cert, authKey)
	if err != nil {
		t.Fatalf("CertHMACOverlay: %v", err)
	}
	return out.Certificate[0]
}

func testAuthKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestCertHMACRoundTrip(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	authKey := testAuthKey(t)

	der := mustOverlay(t, cert, authKey)
	if err := VerifyCertHMAC([][]byte{der}, authKey); err != nil {
		t.Fatalf("VerifyCertHMAC on our own certificate: %v", err)
	}
}

// TestCertHMACRejectsForeignCertificate is the acceptance criterion: a
// well-formed certificate carrying a MAC under a different key must be refused,
// which aborts the handshake.
func TestCertHMACRejectsForeignCertificate(t *testing.T) {
	cert := mintTestCert(t, "github.com")

	ours := testAuthKey(t)
	theirs := testAuthKey(t)

	// A well-formed certificate, minted the same way, MAC'd with the wrong key.
	forged := mustOverlay(t, cert, theirs)
	if err := VerifyCertHMAC([][]byte{forged}, ours); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("err = %v, want ErrCertHMACMismatch", err)
	}

	// A one-bit change in the key must also fail.
	near := bytes.Clone(ours)
	near[0] ^= 0x01
	if err := VerifyCertHMAC([][]byte{mustOverlay(t, cert, ours)}, near); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("one-bit key change: err = %v, want ErrCertHMACMismatch", err)
	}

	// An entirely independent certificate — different key pair, different
	// issuer — must fail too, not merely differ.
	other := mintTestCert(t, "github.com")
	if err := VerifyCertHMAC([][]byte{mustOverlay(t, other, theirs)}, ours); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("independent certificate: err = %v, want ErrCertHMACMismatch", err)
	}
}

// TestCertHMACRejectsGenuineSignature guards the case that would silently break
// the scheme: an unmodified self-signed certificate, whose signature field still
// holds the real signature rather than our MAC.
func TestCertHMACRejectsGenuineSignature(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	if err := VerifyCertHMAC([][]byte{cert.Certificate[0]}, testAuthKey(t)); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("an unmodified certificate verified: err = %v", err)
	}
}

func TestVerifyCertHMACRejectsMalformed(t *testing.T) {
	authKey := testAuthKey(t)

	t.Run("no certificates", func(t *testing.T) {
		if err := VerifyCertHMAC(nil, authKey); !errors.Is(err, ErrCertNone) {
			t.Fatalf("err = %v, want ErrCertNone", err)
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		if err := VerifyCertHMAC([][]byte{{0x01, 0x02, 0x03}}, authKey); err == nil {
			t.Fatal("garbage parsed as a certificate")
		}
	})

	t.Run("someone else's certificate", func(t *testing.T) {
		// A well-formed certificate that is not ours at all — the shape a MITM
		// splicing in a real site's certificate would present.
		der := mintForeignCert(t)
		if err := VerifyCertHMAC([][]byte{der}, authKey); !errors.Is(err, ErrCertHMACMismatch) {
			t.Fatalf("err = %v, want ErrCertHMACMismatch", err)
		}
	})
}

// certMACStream reproduces the derivation at an arbitrary width, so a test can
// mint the certificate the hole allowed: the right bytes of the right stream,
// the wrong number of them.
//
// Spelled out rather than calling certMAC, which no longer takes a width — a
// test that asked the implementation for the expected bytes would agree with it
// whatever it did. HKDF output is prefix-consistent, so the n-byte expansion is
// the first n bytes of the 32-byte one, which is precisely why a width taken
// from the wire is exploitable.
func certMACStream(t *testing.T, authKey, spki []byte, n int) []byte {
	t.Helper()
	if n == 0 {
		return []byte{}
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(spki)
	out, err := hkdf.Expand(sha512.New, mac.Sum(nil), certMACInfo, n)
	if err != nil {
		t.Fatalf("hkdf.Expand(%d): %v", n, err)
	}
	return out
}

// certWithSignature re-encodes cert carrying sig in its signature field,
// producing the DER a peer would put on the wire.
func certWithSignature(t *testing.T, cert *stdtls.Certificate, sig []byte) []byte {
	t.Helper()
	der, err := replaceSignature(cert.Certificate[0], sig)
	if err != nil {
		t.Fatalf("replaceSignature(%d bytes): %v", len(sig), err)
	}
	return der
}

// TestVerifyCertHMACRejectsOtherSignatureLengths closes the hole where the peer
// chose how many bytes it had to get right.
//
// The verifier used to expand the MAC to len(cert.Signature) and compare. Since
// the expansion is prefix-consistent, a peer that truncated the field only had
// to produce that many bytes: one byte is a 1-in-256 guess per attempt, and a
// zero-length field needs no guess at all, because hmac.Equal of two empty
// slices is true.
//
// Each certificate here carries the genuine MAC stream at the wrong width, so
// nothing but the length check can refuse it. Restore the old
// certMAC(..., len(cert.Signature)) and every subtest below goes green — which
// is the point of writing them this way.
func TestVerifyCertHMACRejectsOtherSignatureLengths(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	authKey := testAuthKey(t)
	spki := cert.Leaf.RawSubjectPublicKeyInfo

	for _, n := range []int{0, 1, 31, 33} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			der := certWithSignature(t, cert, certMACStream(t, authKey, spki, n))
			if err := VerifyCertHMAC([][]byte{der}, authKey); !errors.Is(err, ErrCertHMACLen) {
				t.Fatalf("a %d-byte signature was accepted or refused for the wrong reason: err = %v", n, err)
			}
		})
	}

	// The positive control: the same construction at the right width must pass,
	// or the four above would prove only that the helper builds broken
	// certificates.
	t.Run("32 bytes", func(t *testing.T) {
		der := certWithSignature(t, cert, certMACStream(t, authKey, spki, certMACLen))
		if err := VerifyCertHMAC([][]byte{der}, authKey); err != nil {
			t.Fatalf("a correct %d-byte MAC was refused: %v", certMACLen, err)
		}
	})

	// A wrong-length field must not be treated as a mere mismatch by callers
	// that only ask whether the peer authenticated.
	if !errors.Is(ErrCertHMACLen, ErrCertHMACMismatch) {
		t.Fatal("ErrCertHMACLen does not read as an authentication failure")
	}
}

// TestCertsDifferOnlyInTheSignature is the observable property an inspector can
// check: two connections to one SNI get certificates that are byte-identical
// apart from the signature field.
func TestCertsDifferOnlyInTheSignature(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	blank := bytes.Clone(cert.Certificate[0])

	first := mustOverlay(t, cert, testAuthKey(t))
	second := mustOverlay(t, cert, testAuthKey(t))

	if len(first) != len(second) {
		t.Fatalf("certificate lengths differ: %d vs %d", len(first), len(second))
	}
	// Both MACs are certMACLen wide, so the signature field sits at the same
	// offset in both and everything ahead of it must match byte for byte.
	body := len(first) - certMACLen
	if !bytes.Equal(first[:body], second[:body]) {
		t.Fatal("certificates differ outside the signature field")
	}
	if bytes.Equal(first[body:], second[body:]) {
		t.Fatal("two connections got the same signature; the MAC is not per-connection")
	}

	// And the blank itself must be untouched, or the two would race. Compared
	// against a copy taken before the overlays rather than against a prefix of
	// the result: the overlay re-encodes, so the result is not a prefix match.
	if !bytes.Equal(blank, cert.Certificate[0]) {
		t.Fatal("the overlay mutated the cached certificate")
	}
}

// TestCertOverlayReplacesOnlyTheSignature pins what the overlay guarantees
// about the bytes it produces: the signed body goes through untouched and the
// only field that moves is signatureValue, now a fixed-width MAC rather than
// the variable-length ECDSA signature it replaces.
//
// The previous version of this test pinned the opposite — that the signature
// keeps its original length and can be painted over the DER tail in place. That
// is what let the peer choose the width of the comparison; see certMACLen.
func TestCertOverlayReplacesOnlyTheSignature(t *testing.T) {
	cert := mintTestCert(t, "api.github.com")
	parsed := cert.Leaf
	if len(parsed.Signature) == 0 {
		t.Fatal("certificate has no signature")
	}

	withMAC, err := x509.ParseCertificate(mustOverlay(t, cert, testAuthKey(t)))
	if err != nil {
		t.Fatalf("ParseCertificate after overlay: %v", err)
	}
	if len(withMAC.Signature) != certMACLen {
		t.Fatalf("signature is %d bytes after the overlay, want %d", len(withMAC.Signature), certMACLen)
	}
	if bytes.Equal(withMAC.Signature, parsed.Signature) {
		t.Fatal("the overlay did not change the signature field x509 reads")
	}
	// The MAC is computed over the SPKI and CertificateVerify is checked against
	// it, so nothing in the signed body may shift.
	if !bytes.Equal(withMAC.RawTBSCertificate, parsed.RawTBSCertificate) {
		t.Fatal("the overlay disturbed the signed body of the certificate")
	}
	if !bytes.Equal(withMAC.RawSubjectPublicKeyInfo, parsed.RawSubjectPublicKeyInfo) {
		t.Fatal("the overlay disturbed the public key")
	}
	if withMAC.SignatureAlgorithm != parsed.SignatureAlgorithm {
		t.Fatalf("signature algorithm changed from %v to %v", parsed.SignatureAlgorithm, withMAC.SignatureAlgorithm)
	}
}

// certHMACServer returns a stdlib TLS 1.3 server config that hands out our
// MAC-bearing certificate.
func certHMACServer(t *testing.T, cert *stdtls.Certificate, authKey []byte) *stdtls.Config {
	t.Helper()
	return &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		GetCertificate: func(*stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			return CertHMACOverlay(cert, authKey)
		},
	}
}

// connPair returns a connected pair over loopback TCP.
//
// Not net.Pipe: a pipe is synchronous and unbuffered, so when the client
// rejects the certificate its alert has nobody to read it and the write blocks
// until the deadline. Loopback has kernel buffers, so the failure path finishes
// as fast as the success path — and it is what production runs over anyway.
func connPair(t *testing.T) (client, server net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-accepted
	if server == nil {
		client.Close()
		t.Fatal("accept failed")
	}

	deadline := time.Now().Add(10 * time.Second)
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// TestCertHMACOverRealTLSHandshake is the claim the whole design rests on,
// checked by execution rather than by reading: the Go standard library serves a
// certificate whose signature field is a MAC, never noticing, and the client
// accepts it from VerifyPeerCertificate.
func TestCertHMACOverRealTLSHandshake(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	authKey := testAuthKey(t)
	serverCfg := certHMACServer(t, cert, authKey)

	run := func(t *testing.T, clientKey []byte) error {
		t.Helper()
		clientConn, serverConn := connPair(t)

		srvDone := make(chan struct{})
		go func() {
			defer close(srvDone)
			defer serverConn.Close()
			_ = stdtls.Server(serverConn, serverCfg).HandshakeContext(t.Context())
		}()

		err := stdtls.Client(clientConn, &stdtls.Config{
			ServerName:         "github.com",
			MinVersion:         stdtls.VersionTLS13,
			InsecureSkipVerify: true, // chain validation is replaced by cert-HMAC
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return VerifyCertHMAC(rawCerts, clientKey)
			},
		}).HandshakeContext(t.Context())

		// Close both ends before waiting: the client returning does not
		// unblock a server still reading, and the deadline would otherwise be
		// what ends the negative cases.
		clientConn.Close()
		serverConn.Close()
		<-srvDone
		return err
	}

	t.Run("matching key completes the handshake", func(t *testing.T) {
		if err := run(t, authKey); err != nil {
			t.Fatalf("handshake failed with the right key: %v", err)
		}
	})

	t.Run("wrong key aborts the handshake", func(t *testing.T) {
		err := run(t, testAuthKey(t))
		if !errors.Is(err, ErrCertHMACMismatch) {
			t.Fatalf("err = %v, want it to wrap ErrCertHMACMismatch", err)
		}
	})
}

// TestCertHMACOverUTLSHandshake repeats the check against the stack production
// actually uses: a uTLS client with a browser profile against our stdlib
// server. uTLS is a fork of crypto/tls, so its VerifyPeerCertificate ought to
// behave identically — but the whole design rests on that, and "ought to" is
// not verification.
//
// It also covers the reason this file uses ECDSA rather than the reference
// implementation's Ed25519: a browser profile does not advertise Ed25519, so an
// Ed25519 certificate makes the server fail to pick a signature scheme and send
// handshake_failure. That failure is invisible to the unit tests above, which
// never run a handshake.
func TestCertHMACOverUTLSHandshake(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	authKey := testAuthKey(t)
	serverCfg := certHMACServer(t, cert, authKey)

	run := func(t *testing.T, profile string, clientKey []byte) error {
		t.Helper()
		clientConn, serverConn := connPair(t)

		srvDone := make(chan struct{})
		go func() {
			defer close(srvDone)
			defer serverConn.Close()
			_ = stdtls.Server(serverConn, serverCfg).HandshakeContext(t.Context())
		}()

		fp, ok := LookupFingerprint(profile)
		if !ok {
			t.Fatalf("profile %q does not resolve", profile)
		}
		uconn, err := NewUConn(clientConn, &utls.Config{
			ServerName:         "github.com",
			InsecureSkipVerify: true, // chain validation is replaced by cert-HMAC
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return VerifyCertHMAC(rawCerts, clientKey)
			},
		}, fp, 0)
		if err != nil {
			t.Fatalf("NewUConn: %v", err)
		}
		hsErr := uconn.HandshakeContext(t.Context())

		clientConn.Close()
		serverConn.Close()
		<-srvDone
		return hsErr
	}

	for _, profile := range []string{"firefox", "chrome", "safari"} {
		t.Run(profile+"/matching key", func(t *testing.T) {
			if err := run(t, profile, authKey); err != nil {
				t.Fatalf("uTLS %s handshake failed with the right key: %v", profile, err)
			}
		})
		t.Run(profile+"/wrong key", func(t *testing.T) {
			err := run(t, profile, testAuthKey(t))
			if !errors.Is(err, ErrCertHMACMismatch) {
				t.Fatalf("err = %v, want it to wrap ErrCertHMACMismatch", err)
			}
		})
	}
}

// TestEd25519CertificateIsRejectedByBrowserProfiles pins the finding that made
// this file use ECDSA instead of copying the reference implementation.
//
// No browser advertises Ed25519 in signature_algorithms, so a standard-library
// server holding an Ed25519 certificate cannot pick a scheme for
// CertificateVerify and sends handshake_failure — before the certificate is
// even examined, which is why no amount of certificate-level testing would have
// caught it. XTLS avoids this only by forking crypto/tls and assigning
// hs.sigAlg = Ed25519 directly.
//
// If this test ever starts failing because browsers began advertising Ed25519,
// switching back is worth reconsidering: the fixed 64-byte signature would make
// the overlay simpler.
func TestEd25519CertificateIsRejectedByBrowserProfiles(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "github.com"},
		DNSNames:     []string{"github.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	serverCfg := &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		GetCertificate: func(*stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			return &stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
		},
	}

	clientConn, serverConn := connPair(t)
	srvDone := make(chan error, 1)
	go func() {
		srvDone <- stdtls.Server(serverConn, serverCfg).HandshakeContext(t.Context())
	}()

	fp, ok := LookupFingerprint(DefaultFingerprintName)
	if !ok {
		t.Fatal("default fingerprint does not resolve")
	}
	uconn, err := NewUConn(clientConn, &utls.Config{
		ServerName:         "github.com",
		InsecureSkipVerify: true,
	}, fp, 0)
	if err != nil {
		t.Fatalf("NewUConn: %v", err)
	}
	clientErr := uconn.HandshakeContext(t.Context())

	clientConn.Close()
	serverConn.Close()
	serverErr := <-srvDone

	if clientErr == nil {
		t.Fatal("a browser profile completed a handshake against an Ed25519 certificate; " +
			"the reason this file uses ECDSA no longer holds")
	}
	if serverErr == nil {
		t.Fatal("the server accepted an Ed25519 certificate it had no signature scheme for")
	}
}

// TestCertHMACKeyMatchesSessionIDAuthKey ties the two halves of the design
// together: the HMAC key is the same authKey the session_id authentication
// derives, so both sides already hold it and neither needs an extra exchange.
func TestCertHMACKeyMatchesSessionIDAuthKey(t *testing.T) {
	clientEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serverStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	random := make([]byte, helloRandomLen)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand: %v", err)
	}

	clientKey, err := ClientAuthKey(clientEph, serverStatic.PublicKey().Bytes(), random)
	if err != nil {
		t.Fatalf("ClientAuthKey: %v", err)
	}
	serverKey, err := ServerAuthKey(serverStatic.Bytes(), clientEph.PublicKey().Bytes(), random)
	if err != nil {
		t.Fatalf("ServerAuthKey: %v", err)
	}
	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("client and server derived different auth keys")
	}

	// And that key works end to end for the certificate.
	cert := mintTestCert(t, "github.com")
	if err := VerifyCertHMAC([][]byte{mustOverlay(t, cert, serverKey)}, clientKey); err != nil {
		t.Fatalf("cert-HMAC under the session_id auth key: %v", err)
	}
}

// mintForeignCert produces a well-formed certificate that is not ours, so the
// negative path gets a plausible certificate rather than garbage. It is the
// shape a real web server would present, which is what a MITM splicing in
// someone else's certificate would look like.
func mintForeignCert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "github.com"},
		DNSNames:     []string{"github.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}
