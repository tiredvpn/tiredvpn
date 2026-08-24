package tls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
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
// variable-length DER rather than a fixed tail, which costs us only that the
// length has to be read rather than assumed.

// certMACInfo separates the certificate MAC from every other use of authKey.
const certMACInfo = "tiredvpn-reality-cert-v1"

var (
	// ErrCertNone reports an empty certificate list.
	ErrCertNone = errors.New("reality cert: peer sent no certificates")

	// ErrCertHMACMismatch reports a peer certificate whose signature field does
	// not carry our MAC. The peer does not hold the server's static key.
	ErrCertHMACMismatch = errors.New("reality cert: certificate HMAC mismatch")

	// ErrCertNoLeaf reports a certificate handed to the overlay without its
	// parsed leaf, which the overlay needs to locate the signature.
	ErrCertNoLeaf = errors.New("reality cert: certificate has no parsed leaf")
)

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

// CertHMACOverlay returns a per-connection copy of cert with the signature
// field replaced by the connection's MAC.
//
// It takes a minted certificate rather than minting one, so the expensive part
// — key generation and DER encoding — stays cached per SNI by whoever owns the
// minting, and the per-connection cost is one HMAC and one copy.
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

	der := cert.Certificate[0]
	sigLen := len(cert.Leaf.Signature)
	if sigLen == 0 || sigLen > len(der) {
		return nil, fmt.Errorf("reality cert: implausible signature length %d", sigLen)
	}
	// signatureValue is the last field of the Certificate SEQUENCE, so it is the
	// tail of the DER. Checked rather than assumed: if this ever stops holding,
	// it fails here instead of producing certificates that silently fail to
	// authenticate.
	if !hmac.Equal(cert.Leaf.Signature, der[len(der)-sigLen:]) {
		return nil, errors.New("reality cert: signature is not the DER tail, cannot overwrite in place")
	}

	mac, err := certMAC(authKey, cert.Leaf.RawSubjectPublicKeyInfo, sigLen)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(der))
	copy(out, der)
	copy(out[len(out)-sigLen:], mac)

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

	return &stdtls.Certificate{
		Certificate:                  chain,
		PrivateKey:                   cert.PrivateKey,
		Leaf:                         leaf,
		SupportedSignatureAlgorithms: cert.SupportedSignatureAlgorithms,
		OCSPStaple:                   cert.OCSPStaple,
		SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
	}, nil
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
