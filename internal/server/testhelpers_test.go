package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
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

// tlsDonor is a donor site on loopback for the REALITY paths that borrow a
// real server's handshake: a crypto/tls server with a self-signed
// certificate. It returns the dial a serverContext's donorDialer takes, so a
// test never reaches the SNI host on the internet - which failed whenever
// that host did not answer from the test machine.
func tlsDonor(t *testing.T) func(string) (net.Conn, error) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCertForTest(t)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return func(string) (net.Conn, error) {
		return net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	}
}

// testDonorFor is the donor dial for a test server with cfg: a tlsDonor when
// the legacy REALITY transport is on, which borrows the SNI host's
// handshake, and the production dial otherwise.
func testDonorFor(t *testing.T, cfg *Config) func(string) (net.Conn, error) {
	t.Helper()
	if !cfg.REALITYLegacyEnabled {
		return nil
	}
	return tlsDonor(t)
}
