package server

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

func TestMintLeafCertificateShape(t *testing.T) {
	t.Parallel()

	cert, err := mintLeafCertificate(defaultCertParams("www.yandex.ru"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf

	if leaf.Subject.CommonName != "www.yandex.ru" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if !slices.Contains(leaf.DNSNames, "www.yandex.ru") || !slices.Contains(leaf.DNSNames, "*.yandex.ru") {
		t.Fatalf("SANs = %v, want the name and its wildcard", leaf.DNSNames)
	}

	now := time.Now()
	if !leaf.NotBefore.Before(now) || !leaf.NotAfter.After(now) {
		t.Fatalf("validity %v..%v does not cover now", leaf.NotBefore, leaf.NotAfter)
	}
	// Backdated, so a client with a slow clock still accepts it.
	if leaf.NotBefore.After(now.Add(-24 * time.Hour)) {
		t.Fatal("certificate is not backdated enough to survive client clock skew")
	}
}

// TestCertParamsAreParameterised is the constraint the task calls out
// explicitly: the certificate has to be able to get both bigger and smaller
// without editing the mint. Go does not implement compress_certificate while
// real sites do, so our Certificate message is already the wrong size, and
// padding alone can only push it up.
func TestCertParamsAreParameterised(t *testing.T) {
	t.Parallel()

	baseline, err := mintLeafCertificate(defaultCertParams("www.yandex.ru"))
	if err != nil {
		t.Fatal(err)
	}
	base := len(baseline.Certificate[0])

	t.Run("padding grows it", func(t *testing.T) {
		p := defaultCertParams("www.yandex.ru")
		p.PadBytes = 512
		grown, err := mintLeafCertificate(p)
		if err != nil {
			t.Fatal(err)
		}
		if delta := len(grown.Certificate[0]) - base; delta < 512 {
			t.Fatalf("512 bytes of padding grew the leaf by %d", delta)
		}
	})

	t.Run("one SAN shrinks it", func(t *testing.T) {
		p := certMintParams{CommonName: "www.yandex.ru", SANs: []string{"www.yandex.ru"}}
		lean, err := mintLeafCertificate(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(lean.Certificate[0]) >= base {
			t.Fatal("dropping the wildcard SAN did not make the leaf smaller")
		}
	})

	// Where task 011 puts the certificate HMAC. Asserting the extension
	// survives into the DER means that task adds a signer, not a rewrite.
	t.Run("extra extensions reach the leaf", func(t *testing.T) {
		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 9, 9}
		p := defaultCertParams("www.yandex.ru")
		p.ExtraExtensions = []pkix.Extension{{Id: oid, Value: []byte("proof-goes-here")}}

		cert, err := mintLeafCertificate(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, ext := range cert.Leaf.Extensions {
			if ext.Id.Equal(oid) {
				if string(ext.Value) != "proof-goes-here" {
					t.Fatalf("extension value = %q", ext.Value)
				}
				return
			}
		}
		t.Fatal("the extra extension did not reach the certificate")
	})
}

func TestWildcardFor(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"www.yandex.ru":             "*.yandex.ru",
		"raw.githubusercontent.com": "*.githubusercontent.com",
		"yandex.ru":                 "",
		"localhost":                 "",
		"a.b.c.example.com":         "*.b.c.example.com",
	}
	for in, want := range tests {
		if got := wildcardFor(in); got != want {
			t.Fatalf("wildcardFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCertMinterCachesPerSNI is the acceptance criterion: many connections
// across a few names must not mean many mints. Minting is a P-256 keygen plus a
// signature, so without the cache an attacker rotating SNI turns every
// connection into that work.
func TestCertMinterCachesPerSNI(t *testing.T) {
	t.Parallel()

	m := newCertMinter()
	names := []string{"yandex.ru", "vk.com", "github.com", "sberbank.ru", "gosuslugi.ru"}

	for i := range 100 {
		if _, err := m.certForSNI(names[i%len(names)]); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.mintCount(); got != len(names) {
		t.Fatalf("%d mints for %d names over 100 connections, want %d", got, len(names), len(names))
	}
}

// TestCertMinterEvictsOldest keeps the cache from being a memory lever: a peer
// that rotates SNI endlessly must not make us remember every name it invented.
func TestCertMinterEvictsOldest(t *testing.T) {
	t.Parallel()

	m := newCertMinter()
	for i := range certCacheSize + 10 {
		if _, err := m.certForSNI(fmt.Sprintf("host-%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}

	m.mu.Lock()
	size := m.order.Len()
	m.mu.Unlock()
	if size != certCacheSize {
		t.Fatalf("cache holds %d entries, want the %d-entry cap", size, certCacheSize)
	}

	// The first name is gone, so asking for it mints again.
	before := m.mintCount()
	if _, err := m.certForSNI("host-0.example.com"); err != nil {
		t.Fatal(err)
	}
	if m.mintCount() != before+1 {
		t.Fatal("the oldest entry was not evicted")
	}
}

// gatedHello builds a ClientHelloInfo whose connection carries an auth key, the
// way handleREALITYB1 does. Without one the certificate has no MAC key and
// GetCertificate refuses — which is the point: only a client that passed the
// gate gets a certificate.
func gatedHello(t *testing.T, sni string) *tls.ClientHelloInfo {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
	return &tls.ClientHelloInfo{
		ServerName: sni,
		Conn:       customtls.NewAuthConn(local, testB1AuthKey),
	}
}

func TestCertForSNIFallsBackToCoverDomain(t *testing.T) {
	t.Parallel()

	m := newCertMinter()
	cfg := b1TLSConfig(m, "www.microsoft.com")

	cert, err := cfg.GetCertificate(gatedHello(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cn := cert.Leaf.Subject.CommonName; cn != "www.microsoft.com" {
		t.Fatalf("CN for a client without SNI = %q, want the cover domain", cn)
	}

	// With no cover domain configured we still have to answer with something:
	// failing the handshake would itself be a behaviour worth noticing.
	cert, err = b1TLSConfig(newCertMinter(), "").GetCertificate(gatedHello(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.Subject.CommonName != defaultCertName {
		t.Fatalf("CN = %q, want %q", cert.Leaf.Subject.CommonName, defaultCertName)
	}
}
