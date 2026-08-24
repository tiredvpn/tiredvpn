package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// cert-HMAC: proving the server to the client for zero extra packets.
//
// Our certificate is self-signed and no client builds a chain for it, so the
// signature field is dead weight — nobody reads it. We put a MAC there instead,
// keyed with the connection's authKey, which only the holder of the server's
// static X25519 key can derive. The client checks it inside
// VerifyPeerCertificate, during the handshake, before Handshake() returns.
//
// Why this replaces a synchronous proof: the alternative was the server
// answering the client's proof_c with a proof_s the client had to wait for
// before passing user traffic. That is a full round trip on every CONNECT,
// because the connection pool does not reuse connections and the path runs
// through a relay chain. cert-HMAC costs nothing on the wire.
//
// Why it works without forking crypto/tls — verified against the Go 1.26
// standard library, not only against the XTLS fork:
//
//   - Config.getCertificate (crypto/tls/common.go:1317) returns whatever the
//     GetCertificate callback hands back, with no parsing and no validation.
//   - sendServerCertificate (handshake_server_tls13.go:848) assigns
//     certMsg.certificate = *hs.cert and writes it, so the DER goes out byte for
//     byte.
//   - Nothing in the server path verifies a certificate's own signature. It
//     never has: verifying your own certificate proves nothing.
//
// CertificateVerify is still signed with the real private key and the client
// still checks it against the SPKI in the certificate, so the key pair has to be
// genuine. Only the signature field is ours to use.
//
// # Why ECDSA P-256 and not Ed25519
//
// The reference implementation uses Ed25519, and the obvious reason to copy it
// is that an Ed25519 signature is a fixed 64-byte tail, trivial to overwrite.
// It does not work here, and the reason is worth writing down because it is
// invisible until you run it.
//
// No browser advertises Ed25519 in signature_algorithms — not Chrome, not
// Firefox, not Safari, and so not any uTLS profile that parrots them. A
// standard-library TLS 1.3 server holding an Ed25519 certificate therefore has
// no signature scheme it may use for CertificateVerify: selectSignatureScheme
// fails and the server sends handshake_failure before the certificate is ever
// looked at. XTLS gets away with Ed25519 only because it forks crypto/tls and
// assigns hs.sigAlg = Ed25519 directly
// (.ref/REALITY/handshake_server_tls13.go:164), skipping the check.
//
// Making our client advertise Ed25519 would fix the handshake and break the
// point of the client: signature_algorithms is part of JA3 and JA4, so we would
// no longer match the browser we are imitating.
//
// ECDSA P-256 is advertised by every profile we ship. Its signature is
// variable-length DER rather than a fixed tail, which costs us nothing: the
// signature is still the last field of the certificate, so the blank records
// its length at mint time and the overlay writes exactly that many bytes.

const (
	// certMACInfo separates the certificate MAC from every other use of authKey.
	certMACInfo = "tiredvpn-reality-cert-v1"

	// certBlankTTL bounds how long a cached blank is reused. The certificate
	// carries validity dates, so a blank that lived for months would start
	// handing out a NotBefore far in the past — harmless for us, since nobody
	// validates the chain, but a needless oddity for anyone looking.
	certBlankTTL = 12 * time.Hour

	// certBlankCacheMax bounds the cache. The donor pool is a handful of
	// domains, so this is hygiene rather than a real limit: it keeps a peer that
	// can drive SNI variety from growing the map without bound.
	certBlankCacheMax = 64
)

var (
	// ErrCertNone reports an empty certificate list.
	ErrCertNone = errors.New("reality cert: peer sent no certificates")

	// ErrCertHMACMismatch reports a peer certificate whose signature field does
	// not carry our MAC. The peer does not hold the server's static key.
	ErrCertHMACMismatch = errors.New("reality cert: certificate HMAC mismatch")
)

// CertBlank is a minted certificate template for one SNI, reusable across
// connections. Everything in it is fixed except the signature field, which each
// connection overwrites with its own MAC.
//
// Minting costs a key generation and a DER encode, so blanks are cached; the
// per-connection work is one HMAC and one copy.
type CertBlank struct {
	// der holds the full certificate with its genuine signature. Connections
	// never see this copy.
	der []byte

	// spki is the certificate's SubjectPublicKeyInfo, the MAC message. Taken
	// from the parsed certificate rather than re-marshalled from the key, so
	// the server and the client are provably hashing the same bytes.
	spki []byte

	// sigLen is the length of the signature field, which for ECDSA varies.
	sigLen int

	// priv signs CertificateVerify during the handshake. This one has to be
	// genuine — the client checks it against the SPKI above.
	priv crypto.Signer

	mintedAt time.Time
}

// PrivateKey returns the key that signs CertificateVerify. It belongs in the
// tls.Certificate handed back from GetCertificate.
func (b *CertBlank) PrivateKey() crypto.Signer { return b.priv }

// NewCertBlank mints a self-signed ECDSA P-256 leaf for sni.
//
// The certificate is deliberately unremarkable: a leaf with the SNI as its
// common name and SAN, a random serial, and a validity window that looks like
// something an automated issuer would produce.
func NewCertBlank(sni string) (*CertBlank, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("reality cert: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("reality cert: serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("reality cert: create certificate: %w", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("reality cert: reparse minted certificate: %w", err)
	}

	// signatureValue is the last field of the Certificate SEQUENCE, so it is
	// the tail of the DER. Check it rather than assume it: if a future Go
	// changes the encoding, this fails at mint time instead of producing
	// certificates that silently fail to authenticate.
	sigLen := len(parsed.Signature)
	if sigLen == 0 || sigLen > len(der) {
		return nil, fmt.Errorf("reality cert: implausible signature length %d", sigLen)
	}
	if !hmac.Equal(parsed.Signature, der[len(der)-sigLen:]) {
		return nil, errors.New("reality cert: signature is not the DER tail, cannot overwrite in place")
	}

	return &CertBlank{
		der:      der,
		spki:     parsed.RawSubjectPublicKeyInfo,
		sigLen:   sigLen,
		priv:     priv,
		mintedAt: now,
	}, nil
}

// certMAC derives the bytes that go in the signature field: HMAC-SHA512 over
// the certificate's SubjectPublicKeyInfo, expanded to the signature's length.
//
// Expanded rather than truncated or padded so that the whole field varies per
// connection. Leaving a few trailing bytes of the original signature in place
// would be a constant across every connection to one SNI — small, but it is
// exactly the kind of fixed remnant this project keeps finding in its own
// traffic.
func certMAC(authKey, spki []byte, n int) ([]byte, error) {
	mac := hmac.New(sha512.New, authKey)
	mac.Write(spki)
	out, err := hkdf.Expand(sha512.New, mac.Sum(nil), certMACInfo, n)
	if err != nil {
		return nil, fmt.Errorf("reality cert: expand MAC: %w", err)
	}
	return out, nil
}

// WithAuthHMAC returns a fresh DER for one connection, with the signature field
// replaced by the connection's MAC.
//
// The blank is never mutated: two connections to the same SNI must get
// certificates that differ in the signature and match everywhere else, and a
// shared buffer would make them race instead.
func (b *CertBlank) WithAuthHMAC(authKey []byte) ([]byte, error) {
	mac, err := certMAC(authKey, b.spki, b.sigLen)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(b.der))
	copy(out, b.der)
	copy(out[len(out)-b.sigLen:], mac)
	return out, nil
}

// VerifyCertHMAC is the client's check, for use inside
// tls.Config.VerifyPeerCertificate.
//
// It takes rawCerts, the callback's first argument, rather than reaching into
// the connection's unexported peerCertificates through unsafe the way Xray does
// (.ref/Xray-core/transport/internet/reality/reality.go:82-83). The bytes are
// identical and this does not break when uTLS changes its struct layout.
//
// A failure must be returned from the callback as-is: the handshake aborts on
// its own, and there is nothing useful to do with a server that cannot prove
// itself.
func VerifyCertHMAC(rawCerts [][]byte, authKey []byte) error {
	if len(rawCerts) == 0 {
		return ErrCertNone
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("reality cert: parse peer certificate: %w", err)
	}

	want, err := certMAC(authKey, cert.RawSubjectPublicKeyInfo, len(cert.Signature))
	if err != nil {
		return err
	}
	// hmac.Equal, not bytes.Equal: this is a MAC comparison, and the upstream
	// implementation using bytes.Equal here is not a reason to copy it.
	if !hmac.Equal(want, cert.Signature) {
		return ErrCertHMACMismatch
	}
	return nil
}

// CertBlankCache hands out blanks by SNI, minting on miss.
//
// The certificate now depends on the connection's authKey, not only on the SNI,
// so a cache of finished certificates is no longer possible. What stays
// cacheable is the blank — the expensive part, a key generation plus a DER
// encode — while the per-connection work drops to one HMAC.
//
// Safe for concurrent use.
type CertBlankCache struct {
	ttl int64 // nanoseconds; 0 selects certBlankTTL

	mu     sync.Mutex
	blanks map[string]*CertBlank
	mints  int64
}

// NewCertBlankCache returns an empty cache.
func NewCertBlankCache() *CertBlankCache {
	return &CertBlankCache{blanks: make(map[string]*CertBlank)}
}

// Get returns the blank for sni, minting one if there is no live entry.
func (c *CertBlankCache) Get(sni string) (*CertBlank, error) {
	ttl := certBlankTTL
	if c.ttl > 0 {
		ttl = time.Duration(c.ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if b, ok := c.blanks[sni]; ok && time.Since(b.mintedAt) < ttl {
		return b, nil
	}

	// Minting happens under the lock. It costs a key generation, so two
	// concurrent first connections to one SNI would otherwise mint twice and
	// hand out certificates that differ in more than the signature — which is
	// exactly the property the client and any observer can check.
	b, err := NewCertBlank(sni)
	if err != nil {
		return nil, err
	}

	if len(c.blanks) >= certBlankCacheMax {
		c.evictOldestLocked()
	}
	c.blanks[sni] = b
	c.mints++
	return b, nil
}

// Mints reports how many certificates have been minted. Exposed for tests and
// for a metric: mints should track distinct SNIs, not connections.
func (c *CertBlankCache) Mints() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mints
}

// evictOldestLocked drops the least recently minted entry. Callers hold mu.
func (c *CertBlankCache) evictOldestLocked() {
	var (
		oldestKey string
		oldest    time.Time
	)
	for sni, b := range c.blanks {
		if oldestKey == "" || b.mintedAt.Before(oldest) {
			oldestKey, oldest = sni, b.mintedAt
		}
	}
	if oldestKey != "" {
		delete(c.blanks, oldestKey)
	}
}
