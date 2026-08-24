package server

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"crypto/tls"
)

// Certificate minting for the B1 transport.
//
// The leaf is self-signed, and that is sound here rather than a shortcut: only
// a client that already authenticated in session_id reaches our TLS stack, and
// it does not validate the chain - trust comes from the exporter binding that
// follows the handshake. A prober that did not authenticate never gets here at
// all; it is proxied to the real donor (see realityDonorFallback) and sees that
// site's real certificate.
//
// What the leaf must do is look ordinary. Its size lands in the encrypted flight
// and shifts the record lengths an observer measures, which is why the shape is
// parameterised rather than hardcoded - see certMintParams.

const (
	// certCacheSize bounds the cache. Minting is ECDSA P-256 key generation
	// plus a signature, so an attacker rotating SNI through a big pool could
	// otherwise turn every connection into that work.
	certCacheSize = 64

	// certNotBefore/certNotAfter place the validity window around now. Backdating
	// covers client clock skew; the forward window is short like a real
	// automated issuance.
	certNotBefore = -30 * 24 * time.Hour
	certNotAfter  = 60 * 24 * time.Hour
)

// certMintParams describes the certificate to mint.
//
// Every field here exists because measurements may need to move it. Task 013
// found our whole flight is lighter than the lightest donor's (chain 1305 bytes
// against 2718-5364), and Go does not implement compress_certificate (RFC 8879)
// while real sites do, so our Certificate message is both smaller in content and
// larger on the wire than the sites we imitate. Padding can only add; getting
// smaller means fewer SANs and fewer extensions. Both directions have to be
// reachable without touching this file again.
type certMintParams struct {
	// CommonName and SANs are what the client sees. Defaults to the SNI plus
	// the wildcard for its second-level domain, which is what a real site
	// serves, but a measurement campaign may want exactly one name.
	CommonName string
	SANs       []string

	// PadBytes adds an inert extension of this size to move the record length.
	// 0 disables it.
	PadBytes int

	// ExtraExtensions are appended to the leaf verbatim.
	//
	// This is where the certificate HMAC from task 011 goes: it authenticates
	// the server to the client without a CA and without an extra round trip,
	// because the client can check it inside VerifyPeerCertificate. Keeping it
	// as a parameter means that task adds a signer, not a rewrite of the mint.
	ExtraExtensions []pkix.Extension
}

// certPadOID is a private-enterprise arc used for the inert padding extension.
// Non-critical, so any implementation ignores it.
var certPadOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

// certMinter mints and caches leaf certificates per SNI.
type certMinter struct {
	mu    sync.Mutex
	cache map[string]*list.Element
	order *list.List // front = most recently used

	// mints counts minting operations, for the test that proves the cache
	// works. Guarded by mu.
	mints int

	// params, when non-nil, overrides the derived parameters. Used by tests and
	// by the measurement work that has to move certificate sizes.
	params func(sni string) certMintParams
}

type certCacheEntry struct {
	sni  string
	cert *tls.Certificate
}

func newCertMinter() *certMinter {
	return &certMinter{
		cache: make(map[string]*list.Element),
		order: list.New(),
	}
}

// certForSNI returns the certificate for a ClientHello, minting on a miss.
func (m *certMinter) certForSNI(sni string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if el, ok := m.cache[sni]; ok {
		m.order.MoveToFront(el)
		return el.Value.(*certCacheEntry).cert, nil
	}

	params := defaultCertParams(sni)
	if m.params != nil {
		params = m.params(sni)
	}
	cert, err := mintLeafCertificate(params)
	if err != nil {
		return nil, err
	}
	m.mints++

	el := m.order.PushFront(&certCacheEntry{sni: sni, cert: cert})
	m.cache[sni] = el
	for m.order.Len() > certCacheSize {
		oldest := m.order.Back()
		m.order.Remove(oldest)
		delete(m.cache, oldest.Value.(*certCacheEntry).sni)
	}
	return cert, nil
}

// mintCount reports how many certificates have actually been generated.
func (m *certMinter) mintCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mints
}

// defaultCertParams derives the ordinary shape: the requested name plus the
// wildcard for its second-level domain, which is what most real sites serve.
func defaultCertParams(sni string) certMintParams {
	sans := []string{sni}
	if w := wildcardFor(sni); w != "" {
		sans = append(sans, w)
	}
	return certMintParams{CommonName: sni, SANs: sans}
}

// wildcardFor returns "*.example.com" for "www.example.com", and "" when the
// name is already a bare second-level domain or is not a domain at all.
func wildcardFor(sni string) string {
	labels := strings.Split(sni, ".")
	if len(labels) < 3 {
		return ""
	}
	return "*." + strings.Join(labels[1:], ".")
}

// mintLeafCertificate generates a self-signed ECDSA P-256 leaf.
func mintLeafCertificate(p certMintParams) (*tls.Certificate, error) {
	if p.CommonName == "" && len(p.SANs) == 0 {
		return nil, fmt.Errorf("reality cert: no name to mint for")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("reality cert: key generation: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("reality cert: serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: p.CommonName},
		DNSNames:              p.SANs,
		NotBefore:             now.Add(certNotBefore),
		NotAfter:              now.Add(certNotAfter),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       p.ExtraExtensions,
	}

	if p.PadBytes > 0 {
		pad := make([]byte, p.PadBytes)
		if _, err := rand.Read(pad); err != nil {
			return nil, fmt.Errorf("reality cert: padding: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       certPadOID,
			Critical: false,
			Value:    pad,
		})
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("reality cert: create: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("reality cert: parse back: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
