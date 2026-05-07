package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// selfSignedCertForTest generates a self-signed RSA-2048 certificate for
// "localhost" valid for 1 hour. Test-only helper — t.Fatalf on any failure
// so callers can use it as a one-liner.
func selfSignedCertForTest(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"TiredVPN Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// newTestServerContext returns a minimal serverContext usable by handlers
// that don't depend on the registry / store / upstream / metrics / IP pool
// / TUN device. Tests that DO depend on those fields should populate them
// explicitly after this call.
func newTestServerContext(t *testing.T) *serverContext {
	t.Helper()
	return &serverContext{
		cfg: &Config{},
	}
}

// testLogger returns the project logger prefixed with the current test name.
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.WithPrefix(t.Name())
}
