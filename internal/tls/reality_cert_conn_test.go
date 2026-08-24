package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
)

// wrapperConn stands in for the layers a server puts around a connection
// between the gate and the TLS handshake: buffering the peeked ClientHello,
// accounting, deadlines.
type wrapperConn struct {
	net.Conn
}

func (w wrapperConn) Unwrap() net.Conn { return w.Conn }

// opaqueConn is a wrapper that does NOT expose Unwrap, which is what breaks the
// chain.
type opaqueConn struct {
	net.Conn
}

func TestAuthKeyFromConn(t *testing.T) {
	base, other := net.Pipe()
	defer base.Close()
	defer other.Close()

	key := testAuthKey(t)
	authConn := NewAuthConn(base, key)

	t.Run("direct", func(t *testing.T) {
		got, err := AuthKeyFromConn(authConn)
		if err != nil {
			t.Fatalf("AuthKeyFromConn: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("recovered the wrong key")
		}
	})

	t.Run("through wrappers", func(t *testing.T) {
		// The realistic case: by the time GetCertificate runs, the AuthConn is
		// no longer the outermost layer.
		wrapped := net.Conn(wrapperConn{wrapperConn{authConn}})
		got, err := AuthKeyFromConn(wrapped)
		if err != nil {
			t.Fatalf("AuthKeyFromConn through wrappers: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("recovered the wrong key")
		}
	})

	t.Run("no auth conn in the chain", func(t *testing.T) {
		if _, err := AuthKeyFromConn(wrapperConn{base}); !errors.Is(err, ErrNoConnAuthKey) {
			t.Fatalf("err = %v, want ErrNoConnAuthKey", err)
		}
	})

	t.Run("chain broken by an opaque wrapper", func(t *testing.T) {
		// A wrapper without Unwrap hides everything below it. Better to fail
		// loudly here than to mint a certificate with the wrong key.
		if _, err := AuthKeyFromConn(opaqueConn{authConn}); !errors.Is(err, ErrNoConnAuthKey) {
			t.Fatalf("err = %v, want ErrNoConnAuthKey", err)
		}
	})

	t.Run("nil", func(t *testing.T) {
		if _, err := AuthKeyFromConn(nil); !errors.Is(err, ErrNoConnAuthKey) {
			t.Fatalf("err = %v, want ErrNoConnAuthKey", err)
		}
	})
}

// TestAuthKeyFromConnTerminatesOnCycle guards the bound on the walk: a wrapper
// chain that loops must not hang an accept loop.
func TestAuthKeyFromConnTerminatesOnCycle(t *testing.T) {
	c := &cyclicConn{}
	c.next = c
	done := make(chan error, 1)
	go func() {
		_, err := AuthKeyFromConn(c)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoConnAuthKey) {
			t.Fatalf("err = %v, want ErrNoConnAuthKey", err)
		}
	case <-t.Context().Done():
		t.Fatal("AuthKeyFromConn did not terminate on a cyclic wrapper chain")
	}
}

type cyclicConn struct {
	net.Conn
	next net.Conn
}

func (c *cyclicConn) Unwrap() net.Conn { return c.next }

// TestCertificateForHelloEndToEnd runs the server side the way task 006 wires
// it: the gate wraps the connection with the authKey, GetCertificate recovers
// it and applies the MAC to a cached certificate, and a client verifies it.
func TestCertificateForHelloEndToEnd(t *testing.T) {
	authKey := testAuthKey(t)
	cert := mintTestCert(t, "github.com")

	// Stands in for the server's per-SNI cache: minting happens once, the
	// overlay happens per connection.
	mints := 0
	mint := func(string) (*stdtls.Certificate, error) {
		mints++
		return cert, nil
	}

	clientConn, serverConn := connPair(t)

	// The gate would do this after opening the session_id.
	gated := NewAuthConn(serverConn, authKey)

	serverCfg := &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		GetCertificate: func(chi *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			return CertificateForHello(chi, chi.ServerName, mint)
		},
	}

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- stdtls.Server(gated, serverCfg).HandshakeContext(t.Context())
	}()

	err := stdtls.Client(clientConn, &stdtls.Config{
		ServerName:         "github.com",
		MinVersion:         stdtls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return VerifyCertHMAC(rawCerts, authKey)
		},
	}).HandshakeContext(t.Context())

	clientConn.Close()
	serverConn.Close()
	<-srvDone

	if err != nil {
		t.Fatalf("handshake through the conn-carried auth key: %v", err)
	}
	if mints != 1 {
		t.Fatalf("minted %d times for one connection, want 1", mints)
	}
}

// TestCertificateForHelloRefusesUngatedConnection is the property worth having:
// a connection that never passed the session_id gate must not get a certificate
// at all, rather than one minted under some default key.
func TestCertificateForHelloRefusesUngatedConnection(t *testing.T) {
	base, other := net.Pipe()
	defer base.Close()
	defer other.Close()

	minted := false
	mint := func(string) (*stdtls.Certificate, error) {
		minted = true
		return mintTestCert(t, "github.com"), nil
	}

	_, err := CertificateForHello(&stdtls.ClientHelloInfo{Conn: base}, "github.com", mint)
	if !errors.Is(err, ErrNoConnAuthKey) {
		t.Fatalf("err = %v, want ErrNoConnAuthKey", err)
	}
	if minted {
		t.Fatal("minted a certificate for a connection that never authenticated")
	}
}

// TestCertHMACOverlayKeepsThePrivateKey guards the mistake that would look fine
// and then fail at CertificateVerify: dropping the key while replacing the DER.
func TestCertHMACOverlayKeepsThePrivateKey(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	out, err := CertHMACOverlay(cert, testAuthKey(t))
	if err != nil {
		t.Fatalf("CertHMACOverlay: %v", err)
	}
	if out.PrivateKey == nil {
		t.Fatal("private key dropped; the handshake would die at CertificateVerify")
	}

	signer, ok := out.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("private key is not a crypto.Signer: %T", out.PrivateKey)
	}
	parsed, err := x509.ParseCertificate(out.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	certPub, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want *ecdsa.PublicKey", parsed.PublicKey)
	}
	if !certPub.Equal(signer.Public()) {
		t.Fatal("private key does not match the certificate after the overlay")
	}
}

func TestCertHMACOverlayRequiresLeaf(t *testing.T) {
	cert := mintTestCert(t, "github.com")
	cert.Leaf = nil
	if _, err := CertHMACOverlay(cert, testAuthKey(t)); !errors.Is(err, ErrCertNoLeaf) {
		t.Fatalf("err = %v, want ErrCertNoLeaf", err)
	}
}
