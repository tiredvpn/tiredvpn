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
	"math/big"
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
// painted over — and, more to the point, the MAC has to be shaped like one
// rather than poured into the space one occupied. See certSignature.

// certMACInfo separates the certificate MAC from every other use of authKey.
const certMACInfo = "tiredvpn-reality-cert-v1"

const (
	// certMACHalf is the width of each of the two integers the MAC is cut into.
	// 32 bytes is the width of r and s in a P-256 signature.
	certMACHalf = 32

	// certMACLen is what the derivation produces: r and s side by side.
	certMACLen = 2 * certMACHalf
)

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

// certMAC derives the raw MAC: HMAC-SHA512 over the certificate's
// SubjectPublicKeyInfo, expanded to certMACLen.
//
// The width is a constant, never an argument. It used to be the length of the
// peer's signature field, because the verifier expanded to len(cert.Signature)
// and then compared the two. HKDF output is prefix-consistent — the 31-byte
// expansion is the first 31 bytes of the 32-byte one — so that let the peer
// choose how many bytes of the same stream it had to produce: one byte is a
// 1-in-256 guess per attempt, and a zero-length field passed unconditionally,
// since hmac.Equal of two empty slices is true.
func certMAC(authKey, spki []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, authKey)
	mac.Write(spki)
	out, err := hkdf.Expand(sha512.New, mac.Sum(nil), certMACInfo, certMACLen)
	if err != nil {
		return nil, fmt.Errorf("reality cert: expand MAC: %w", err)
	}
	return out, nil
}

// ecdsaSignature is the on-the-wire shape of an ECDSA signature: RFC 3279's
// Ecdsa-Sig-Value.
type ecdsaSignature struct {
	R, S *big.Int
}

// certSignature derives the signature field: the MAC cut in half and encoded
// the way a real ECDSA P-256 signature is, as SEQUENCE { INTEGER r, INTEGER s }.
//
// Shaped rather than merely sized. A MAC of some constant width would close the
// same hole, but it would leave a new mark in its place: a real P-256 signature
// is 70, 71 or 72 bytes with weights near 1/4, 1/2, 1/4 — DER prepends a zero
// byte to an integer whose top bit is set, which happens to r and to s
// independently, half the time each. A field that is always the same length has
// no such distribution, and a flat one has the wrong shape. Encoding two
// pseudorandom 32-byte integers through the same rules reproduces the
// distribution because it is the same mechanism producing it, and the field
// parses as a signature rather than as opaque bytes.
//
// r and s are uniform over 32 bytes rather than reduced modulo the group order,
// so one in about 2^32 lands above it. A signature with r >= n is invalid, not
// merely unusual, but nothing on the path verifies this signature — that is the
// premise of the whole file — and at that rate no observer collects one.
//
// The length of the result comes from authKey and the SPKI. Nothing about it is
// read off the wire, which is what closes the hole certMAC describes.
func certSignature(authKey, spki []byte) ([]byte, error) {
	mac, err := certMAC(authKey, spki)
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(mac[:certMACHalf]),
		S: new(big.Int).SetBytes(mac[certMACHalf:]),
	})
	if err != nil {
		return nil, fmt.Errorf("reality cert: encode MAC as a signature: %w", err)
	}
	return sig, nil
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

	sig, err := certSignature(authKey, cert.Leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	out, err := replaceSignature(cert.Certificate[0], sig)
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
	if !hmac.Equal(leaf.Signature, sig) || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, cert.Leaf.RawSubjectPublicKeyInfo) {
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
// Our signature is drawn from the same length distribution as the one it
// replaces, but that does not make it the same length — three times in four the
// two differ, and then the BIT STRING's length changes and the enclosing
// SEQUENCE's with it. Re-encoding keeps the two in agreement. Painting over the
// tail in place, which is what this used to do, silently required the lengths
// to match.
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

	// want is derived from authKey and the certificate's public key alone. Its
	// length is therefore ours, not the peer's — cert.Signature is read once, on
	// the line below, and nothing about the derivation depends on it. That is the
	// property to preserve here: the version that expanded the MAC to
	// len(cert.Signature) let a peer pick how many bytes it had to guess.
	want, err := certSignature(authKey, cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	// hmac.Equal, not bytes.Equal: this is a MAC comparison, and the upstream
	// implementation using bytes.Equal here is not a reason to copy it. A field
	// of the wrong length fails here too, since the lengths disagree.
	if !hmac.Equal(want, cert.Signature) {
		return ErrCertHMACMismatch
	}
	return nil
}
