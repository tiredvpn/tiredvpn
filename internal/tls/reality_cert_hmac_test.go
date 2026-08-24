package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// mustCert is WithAuthHMAC with the test's error handling.
func mustCert(t *testing.T, b *CertBlank, authKey []byte) []byte {
	t.Helper()
	der, err := b.WithAuthHMAC(authKey)
	if err != nil {
		t.Fatalf("WithAuthHMAC: %v", err)
	}
	return der
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
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	authKey := testAuthKey(t)

	der := mustCert(t, blank, authKey)
	if err := VerifyCertHMAC([][]byte{der}, authKey); err != nil {
		t.Fatalf("VerifyCertHMAC on our own certificate: %v", err)
	}
}

// TestCertHMACRejectsForeignCertificate is the acceptance criterion: a
// well-formed certificate carrying a MAC under a different key must be refused,
// which aborts the handshake.
func TestCertHMACRejectsForeignCertificate(t *testing.T) {
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}

	ours := testAuthKey(t)
	theirs := testAuthKey(t)

	// A well-formed certificate, minted the same way, MAC'd with the wrong key.
	forged := mustCert(t, blank, theirs)
	if err := VerifyCertHMAC([][]byte{forged}, ours); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("err = %v, want ErrCertHMACMismatch", err)
	}

	// A one-bit change in the key must also fail.
	near := bytes.Clone(ours)
	near[0] ^= 0x01
	if err := VerifyCertHMAC([][]byte{mustCert(t, blank, ours)}, near); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("one-bit key change: err = %v, want ErrCertHMACMismatch", err)
	}

	// An entirely independent certificate — different key pair, different
	// issuer — must fail too, not merely differ.
	other, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	if err := VerifyCertHMAC([][]byte{mustCert(t, other, theirs)}, ours); !errors.Is(err, ErrCertHMACMismatch) {
		t.Fatalf("independent certificate: err = %v, want ErrCertHMACMismatch", err)
	}
}

// TestCertHMACRejectsGenuineSignature guards the case that would silently break
// the scheme: an unmodified self-signed certificate, whose signature field still
// holds the real signature rather than our MAC.
func TestCertHMACRejectsGenuineSignature(t *testing.T) {
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	if err := VerifyCertHMAC([][]byte{blank.der}, testAuthKey(t)); !errors.Is(err, ErrCertHMACMismatch) {
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

// TestCertsDifferOnlyInTheSignature is the observable property an inspector can
// check: two connections to one SNI get certificates that are byte-identical
// apart from the signature field.
func TestCertsDifferOnlyInTheSignature(t *testing.T) {
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}

	first := mustCert(t, blank, testAuthKey(t))
	second := mustCert(t, blank, testAuthKey(t))

	if len(first) != len(second) {
		t.Fatalf("certificate lengths differ: %d vs %d", len(first), len(second))
	}
	body := len(first) - blank.sigLen
	if !bytes.Equal(first[:body], second[:body]) {
		t.Fatal("certificates differ outside the signature field")
	}
	if bytes.Equal(first[body:], second[body:]) {
		t.Fatal("two connections got the same signature; the MAC is not per-connection")
	}

	// And the blank itself must be untouched, or the two would race.
	if !bytes.Equal(blank.der[:body], first[:body]) {
		t.Fatal("WithAuthHMAC mutated the cached blank")
	}
}

// TestCertBlankSignatureIsTheDERTail pins the layout assumption the overlay
// rests on: signatureValue is the last field of the certificate, so it is the
// tail of the DER and can be replaced in place. ECDSA makes its length vary,
// which is why the blank records the length instead of assuming one.
func TestCertBlankSignatureIsTheDERTail(t *testing.T) {
	blank, err := NewCertBlank("api.github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	parsed, err := x509.ParseCertificate(blank.der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if len(parsed.Signature) != blank.sigLen {
		t.Fatalf("blank recorded signature length %d, certificate has %d", blank.sigLen, len(parsed.Signature))
	}
	if !bytes.Equal(parsed.Signature, blank.der[len(blank.der)-blank.sigLen:]) {
		t.Fatal("signature is not the DER tail")
	}

	// After the overlay, the parsed signature must be our MAC — i.e. the
	// certificate still parses and the field we replaced is the one x509 reads.
	authKey := testAuthKey(t)
	withMAC, err := x509.ParseCertificate(mustCert(t, blank, authKey))
	if err != nil {
		t.Fatalf("ParseCertificate after overlay: %v", err)
	}
	if bytes.Equal(withMAC.Signature, parsed.Signature) {
		t.Fatal("the overlay did not change the signature field x509 reads")
	}
	if !bytes.Equal(withMAC.RawSubjectPublicKeyInfo, blank.spki) {
		t.Fatal("the overlay disturbed the public key")
	}
	if len(withMAC.Signature) != blank.sigLen {
		t.Fatalf("the overlay changed the signature length to %d", len(withMAC.Signature))
	}
}

// TestCertBlankCacheMintsPerSNI is the acceptance criterion on cost: 100
// connections across 5 SNIs must mint 5 times.
func TestCertBlankCacheMintsPerSNI(t *testing.T) {
	cache := NewCertBlankCache()
	snis := []string{"github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com"}

	for i := range 100 {
		sni := snis[i%len(snis)]
		blank, err := cache.Get(sni)
		if err != nil {
			t.Fatalf("Get(%s): %v", sni, err)
		}
		if got := mustCert(t, blank, testAuthKey(t)); len(got) == 0 {
			t.Fatal("empty certificate")
		}
	}

	if got := cache.Mints(); got != int64(len(snis)) {
		t.Fatalf("minted %d times for %d SNIs over 100 connections, want %d", got, len(snis), len(snis))
	}
}

func TestCertBlankCacheIsConcurrencySafe(t *testing.T) {
	cache := NewCertBlankCache()
	snis := []string{"github.com", "api.github.com", "raw.githubusercontent.com"}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for i := range 50 {
				sni := snis[i%len(snis)]
				blank, err := cache.Get(sni)
				if err != nil {
					t.Errorf("Get(%s): %v", sni, err)
					return
				}
				_ = mustCert(t, blank, testAuthKey(t))
			}
		})
	}
	wg.Wait()

	// Every goroutine must have seen the same blank per SNI, or certificates
	// for one SNI would differ in more than the signature.
	if got := cache.Mints(); got != int64(len(snis)) {
		t.Fatalf("minted %d times, want %d; concurrent first connections raced", got, len(snis))
	}
}

func TestCertBlankCacheRemintsAfterTTL(t *testing.T) {
	cache := NewCertBlankCache()
	cache.ttl = int64(10 * time.Millisecond)

	first, err := cache.Get("github.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := cache.Get("github.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if first == second {
		t.Fatal("blank was reused past its TTL")
	}
	if cache.Mints() != 2 {
		t.Fatalf("minted %d times, want 2", cache.Mints())
	}
}

func TestCertBlankCacheIsBounded(t *testing.T) {
	cache := NewCertBlankCache()
	for i := range certBlankCacheMax + 20 {
		if _, err := cache.Get(string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	cache.mu.Lock()
	size := len(cache.blanks)
	cache.mu.Unlock()
	if size > certBlankCacheMax {
		t.Fatalf("cache holds %d entries, cap is %d", size, certBlankCacheMax)
	}
}

// certHMACServer returns a stdlib TLS 1.3 server config that hands out our
// MAC-bearing certificate.
func certHMACServer(t *testing.T, blank *CertBlank, authKey []byte) *stdtls.Config {
	t.Helper()
	return &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		GetCertificate: func(*stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			der, err := blank.WithAuthHMAC(authKey)
			if err != nil {
				return nil, err
			}
			return &stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: blank.PrivateKey()}, nil
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
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	authKey := testAuthKey(t)
	serverCfg := certHMACServer(t, blank, authKey)

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
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	authKey := testAuthKey(t)
	serverCfg := certHMACServer(t, blank, authKey)

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
	blank, err := NewCertBlank("github.com")
	if err != nil {
		t.Fatalf("NewCertBlank: %v", err)
	}
	if err := VerifyCertHMAC([][]byte{mustCert(t, blank, serverKey)}, clientKey); err != nil {
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
