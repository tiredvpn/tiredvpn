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

// TestCertificateForHelloEndToEnd runs the server side the way task 006 will
// wire it: the gate wraps the connection with the authKey, GetCertificate
// recovers it, and a client verifies the resulting certificate.
func TestCertificateForHelloEndToEnd(t *testing.T) {
	cache := NewCertBlankCache()
	authKey := testAuthKey(t)

	clientConn, serverConn := connPair(t)

	// The gate would do this after opening the session_id.
	gated := NewAuthConn(serverConn, authKey)

	serverCfg := &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		GetCertificate: func(chi *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			return CertificateForHello(cache, chi, chi.ServerName)
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
	if cache.Mints() != 1 {
		t.Fatalf("minted %d certificates for one SNI, want 1", cache.Mints())
	}
}

// TestCertificateForHelloRefusesUngatedConnection is the property worth having:
// a connection that never passed the session_id gate must not get a
// certificate at all, rather than one minted under some default key.
func TestCertificateForHelloRefusesUngatedConnection(t *testing.T) {
	cache := NewCertBlankCache()
	base, other := net.Pipe()
	defer base.Close()
	defer other.Close()

	_, err := CertificateForHello(cache, &stdtls.ClientHelloInfo{Conn: base}, "github.com")
	if !errors.Is(err, ErrNoConnAuthKey) {
		t.Fatalf("err = %v, want ErrNoConnAuthKey", err)
	}
	if cache.Mints() != 0 {
		t.Fatal("minted a certificate for a connection that never authenticated")
	}
}

func TestCertificateForSetsBothFields(t *testing.T) {
	cache := NewCertBlankCache()
	cert, err := CertificateFor(cache, "github.com", testAuthKey(t))
	if err != nil {
		t.Fatalf("CertificateFor: %v", err)
	}
	if len(cert.Certificate) != 1 || len(cert.Certificate[0]) == 0 {
		t.Fatal("certificate DER missing")
	}
	if cert.PrivateKey == nil {
		t.Fatal("private key missing; CertificateVerify would fail and the handshake with it")
	}

	// The private key must match the certificate, or the client's
	// CertificateVerify check fails and takes the handshake with it.
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("private key is not a crypto.Signer: %T", cert.PrivateKey)
	}
	certPub, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want *ecdsa.PublicKey", parsed.PublicKey)
	}
	if !certPub.Equal(signer.Public()) {
		t.Fatal("private key does not match the certificate")
	}
}
