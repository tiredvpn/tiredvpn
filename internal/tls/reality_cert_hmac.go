package tls

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// cert-HMAC: proving the server to the client for zero extra packets.
//
// The certificate is self-signed and no client builds a chain for it, so the
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
// # Why the signature field and not an extension
//
// An X.509 extension carrying 64 opaque bytes under a private OID is a thing no
// real certificate has. It rides inside the encrypted flight so no passive
// observer sees it, but anything that terminates TLS does, and it costs bytes.
// The signature field costs nothing and is already 64-ish bytes of
// high-entropy data in every certificate ever issued.
//
// # Why ECDSA and not Ed25519
//
// The reference implementation uses Ed25519, and the obvious reason to copy it
// is that an Ed25519 signature is a fixed 64-byte tail, trivial to overwrite.
// It does not work here, and the reason is invisible until you run it.
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
// point of the client: signature_algorithms is part of JA3 and JA4.
//
// ECDSA P-256 is advertised by every profile we ship. Its signature is
// variable-length DER rather than a fixed tail, so the field cannot simply be
// painted over: the overlay re-encodes the certificate around a MAC of fixed
// width. The width has to be fixed rather than copied from the signature it
// replaces — see certMACLen.

// certMACInfo separates the certificate MAC from every other use of authKey.
const certMACInfo = "tiredvpn-reality-cert-v1"

// certMACLen is the width of the MAC, fixed and checked before anything is
// derived.
//
// It used to be whatever the peer's signature field happened to be, because the
// verifier expanded the MAC to len(cert.Signature) and then compared the two.
// That hands the security parameter to the attacker: a one-byte signature is
// guessed once in 256 tries, and a zero-length one always passes, since
// hmac.Equal of two empty slices is true. Deriving at a fixed width and
// rejecting every other width first closes both, and costs the certificate
// nothing that anyone reads.
const certMACLen = 32

var (
	// ErrCertNone reports an empty certificate list.
	ErrCertNone = errors.New("reality cert: peer sent no certificates")

	// ErrCertHMACMismatch reports a peer certificate whose signature field does
	// not carry our MAC. The peer does not hold the server's static key.
	ErrCertHMACMismatch = errors.New("reality cert: certificate HMAC mismatch")

	// ErrCertHMACLen reports a signature field that is not the MAC's width.
	//
	// It wraps ErrCertHMACMismatch because that is what it is — a certificate
	// that does not carry our MAC — and because every caller upstream only asks
	// whether the peer authenticated. The distinct sentinel exists so the log
	// line says which check refused it.
	ErrCertHMACLen = fmt.Errorf("%w: signature field is not %d bytes", ErrCertHMACMismatch, certMACLen)

	// ErrCertNoLeaf reports a certificate handed to the overlay without its
	// parsed leaf, which the overlay needs to locate the signature.
	ErrCertNoLeaf = errors.New("reality cert: certificate has no parsed leaf")
)

// certMAC derives the bytes that go in the signature field: HMAC-SHA512 over
// the certificate's SubjectPublicKeyInfo, expanded to certMACLen.
//
// The width is the constant, not an argument. HKDF output is prefix-consistent
// — the 31-byte expansion is the first 31 bytes of the 32-byte one — so a
// derivation whose length comes from the wire lets a peer pick how many bytes
// of the same stream it has to produce.
//
// The whole field is the MAC rather than a MAC padded into it: leaving trailing
// bytes of the original ECDSA signature in place would be a constant across
// every connection to one SNI — small, but it is exactly the kind of fixed
// remnant this project keeps finding in its own traffic.
func certMAC(authKey, spki []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, authKey)
	mac.Write(spki)
	out, err := hkdf.Expand(sha512.New, mac.Sum(nil), certMACInfo, certMACLen)
	if err != nil {
		return nil, fmt.Errorf("reality cert: expand MAC: %w", err)
	}
	return out, nil
}

// CertHMACOverlay returns a per-connection copy of cert with the signature
// field replaced by the connection's MAC.
//
// It takes a minted certificate rather than minting one, so the expensive part
// — key generation and DER encoding — stays cached per SNI by whoever owns the
// minting, and the per-connection cost is one HMAC and one re-encode.
//
// cert.Leaf must be set. The server's minter parses the certificate back after
// creating it anyway, so this costs nothing there, and it saves a parse on
// every single connection.
//
// The input is never mutated: two connections to one SNI share a cached
// certificate, and writing into it would both race and make their signatures
// identical.
func CertHMACOverlay(cert *stdtls.Certificate, authKey []byte) (*stdtls.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, ErrCertNone
	}
	if cert.Leaf == nil {
		return nil, ErrCertNoLeaf
	}

	mac, err := certMAC(authKey, cert.Leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	out, err := replaceSignature(cert.Certificate[0], mac)
	if err != nil {
		return nil, err
	}

	// Only the leaf is replaced; the private key and any chain carry over.
	chain := make([][]byte, len(cert.Certificate))
	copy(chain, cert.Certificate)
	chain[0] = out

	// Re-parse rather than carrying the original leaf over. Carrying it would
	// leave a Leaf whose Signature disagrees with the bytes on the wire — a trap
	// for anyone who later compares the two, in exchange for saving a parse that
	// costs microseconds against the key generation this whole function exists
	// to avoid repeating.
	leaf, err := x509.ParseCertificate(out)
	if err != nil {
		return nil, fmt.Errorf("reality cert: reparse after overlay: %w", err)
	}
	// The overlay has to land in the field the client reads and disturb nothing
	// the MAC is computed over. Checked rather than assumed: the failure mode it
	// guards is certificates that look fine and silently fail to authenticate.
	if !hmac.Equal(leaf.Signature, mac) || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, cert.Leaf.RawSubjectPublicKeyInfo) {
		return nil, errors.New("reality cert: overlay did not land in the signature field")
	}

	return &stdtls.Certificate{
		Certificate:                  chain,
		PrivateKey:                   cert.PrivateKey,
		Leaf:                         leaf,
		SupportedSignatureAlgorithms: cert.SupportedSignatureAlgorithms,
		OCSPStaple:                   cert.OCSPStaple,
		SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
	}, nil
}

// rawCertificate is RFC 5280's Certificate with the two signed parts left
// opaque. They are carried through byte for byte; only signatureValue is ours.
type rawCertificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

// replaceSignature re-encodes der with sig in the signatureValue field.
//
// The MAC is not the width of the ECDSA signature it replaces, so the field
// cannot be painted over where it lies: the BIT STRING's length changes, and
// the enclosing SEQUENCE's along with it, possibly changing length form.
// Re-encoding keeps the two in agreement. Hand-patching the length bytes works
// until the first certificate that crosses a boundary, and then produces
// certificates that fail to parse on the client.
func replaceSignature(der, sig []byte) ([]byte, error) {
	var c rawCertificate
	rest, err := asn1.Unmarshal(der, &c)
	if err != nil {
		return nil, fmt.Errorf("reality cert: parse DER for overlay: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("reality cert: %d trailing bytes after certificate", len(rest))
	}

	c.SignatureValue = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	out, err := asn1.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("reality cert: re-encode after overlay: %w", err)
	}
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

	// Before the MAC is derived, not after: the length of the comparison is the
	// number of bytes a forger has to produce, and it arrives from the wire.
	if len(cert.Signature) != certMACLen {
		return ErrCertHMACLen
	}

	want, err := certMAC(authKey, cert.RawSubjectPublicKeyInfo)
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
