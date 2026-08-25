package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// REALITY client authentication carried in the TLS session_id.
//
// The construction follows XTLS/REALITY (.ref/REALITY/tls.go:230-247 on the
// server, .ref/Xray-core/transport/internet/reality/reality.go:141-176 on the
// client) with two deliberate departures, both documented in the B1 epic:
//
//   - The HKDF info string is ours, not the upstream "REALITY" literal. Wire
//     compatibility at this layer buys nothing — our certificate, server flight
//     and JA4S differ anyway — while inheriting upstream's policy defaults
//     (MinClientVer and friends) costs us control.
//   - Plaintext byte 3 is a capability flags field where upstream reserves it.
//     It is only ever read from inside the AEAD, so it is invisible on the wire
//     and gives version negotiation for free.
//
// Why session_id at all: it is 32 bytes every TLS 1.3 ClientHello already
// carries, indistinguishable from the random value a real client puts there.
// The padding extension this replaces (reality_extension.go) is 256 bytes that
// no shipping browser sends at our ClientHello size — a stable signature across
// every installation.
const (
	// AuthHKDFInfo is the HKDF info string binding the derived key to this
	// protocol and version. Changing it is a one-line format break, by design.
	AuthHKDFInfo = "tiredvpn-reality-v1"

	// ShortIDInfo is the HMAC message that derives a client's short ID.
	ShortIDInfo = "tiredvpn-reality-shortid-v1"

	// AuthPlaintextLen is the size of the sealed payload before the GCM tag.
	AuthPlaintextLen = 16

	// AuthSessionIDLen is the size on the wire: plaintext plus GCM tag. It is
	// also exactly the legacy_session_id length a TLS 1.3 client sends, which
	// is what makes the whole scheme invisible.
	AuthSessionIDLen = 32

	// AuthShortIDLen is the length of the per-client short identifier.
	AuthShortIDLen = 8
)

// Capability flags carried in AuthPayload.Flags.
//
// These are how the two ends agree on optional behaviour without an extra
// round trip and without an operator having to set matching flags on both
// sides. A flag on a command line cannot work here: a staged rollout always has
// a window where only one side has been updated, so any option documented as
// "must match the client setting" can never be turned on safely. The bit rides
// inside the sealed session_id, so the server learns what the client supports
// before it answers anything.
//
// The rule for every bit in this field: the CLIENT advertises what it can
// tolerate, the SERVER decides what to do. A client sets its bits
// unconditionally and never waits for the server to act on them, so a new
// client against an old server behaves exactly like an old client. That is what
// lets clients ship first.
const (
	// AuthFlagExporterBinding advertises that the client will send the
	// exporter-binding record (see reality_binding.go) as its first
	// application data.
	AuthFlagExporterBinding = 1 << 0

	// AuthFlagReshapeCapable advertises that the client understands
	// server-initiated traffic reshaping and will not be confused by it.
	//
	// It is a statement about tolerance, not intent: the client does not
	// reshape anything itself and does not wait for the server to. A server
	// that never reshapes is indistinguishable, from the client's side, from
	// one that has not been updated - which is exactly the property that makes
	// it safe to deploy clients before servers.
	AuthFlagReshapeCapable = 1 << 1
)

// ClientHello field sizes, used to locate session_id without hardcoding 39.
// Hardcoding it is the failure mode the epic calls out by name: the first uTLS
// profile with a different session_id length would produce a wrong AAD and a
// silent authorization failure with no usable diagnostic.
const (
	handshakeHeaderLen  = 4  // msg_type(1) + length(3)
	helloLegacyVersLen  = 2  // legacy_version
	helloRandomLen      = 32 // random
	handshakeTypeHello  = 0x01
	extensionKeyShare   = 0x0033
	groupX25519         = 0x001d
	groupX25519MLKEM768 = 0x11ec
)

// Errors returned by this file. They are distinguishable so a caller can log
// which invariant broke, but note the security requirement from the epic: a
// server MUST NOT let any of them produce observably different behaviour on the
// wire, or the version byte becomes a version oracle.
var (
	ErrHelloTruncated    = errors.New("reality auth: ClientHello truncated")
	ErrHelloNotClient    = errors.New("reality auth: not a ClientHello handshake message")
	ErrSessionIDLen      = errors.New("reality auth: legacy_session_id_length is not 32")
	ErrSessionIDNotZero  = errors.New("reality auth: session_id is not zeroed in the AAD")
	ErrNoPeerKeyShare    = errors.New("reality auth: no usable X25519 key share in ClientHello")
	ErrAuthOpen          = errors.New("reality auth: session_id did not open")
	ErrRandomLen         = errors.New("reality auth: ClientHello.Random must be 32 bytes")
	ErrShortSharedSecret = errors.New("reality auth: X25519 shared secret rejected")
	ErrNoClientEphemeral = errors.New("reality auth: profile offers no X25519 key share, cannot do REALITY")
)

// AuthPayload is the 16-byte plaintext sealed into session_id.
//
// Wire layout, big-endian:
//
//	0..2   Version   client major/minor/patch
//	3      Flags     capability bits, see AuthFlag*
//	4..7   Time      unix seconds, uint32
//	8..15  ShortID   HMAC-derived per-client identifier
type AuthPayload struct {
	Version [3]byte
	Flags   byte
	Time    uint32
	ShortID [AuthShortIDLen]byte
}

// Marshal renders the payload in wire order.
func (p AuthPayload) Marshal() [AuthPlaintextLen]byte {
	var out [AuthPlaintextLen]byte
	copy(out[0:3], p.Version[:])
	out[3] = p.Flags
	binary.BigEndian.PutUint32(out[4:8], p.Time)
	copy(out[8:16], p.ShortID[:])
	return out
}

// parseAuthPayload is the inverse of Marshal.
func parseAuthPayload(b []byte) (AuthPayload, error) {
	if len(b) != AuthPlaintextLen {
		return AuthPayload{}, fmt.Errorf("reality auth: payload is %d bytes, want %d", len(b), AuthPlaintextLen)
	}
	var p AuthPayload
	copy(p.Version[:], b[0:3])
	p.Flags = b[3]
	p.Time = binary.BigEndian.Uint32(b[4:8])
	copy(p.ShortID[:], b[8:16])
	return p, nil
}

// HasFlag reports whether a capability bit is set.
func (p AuthPayload) HasFlag(flag byte) bool { return p.Flags&flag != 0 }

// ShortIDFor derives a client's short identifier from its secret.
//
// The server keeps a set of known short IDs and rejects anything else. Deriving
// it from the secret rather than provisioning a separate value means adding a
// client needs no extra field anywhere.
func ShortIDFor(secret []byte) [AuthShortIDLen]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ShortIDInfo))
	var out [AuthShortIDLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// ClientAuthKey derives the connection's authentication key from the client's
// side: ECDH between its ephemeral key share and the server's static public key.
//
// SealSessionID derives the same value internally, so a client that only seals
// need not call this. It is exported because the key is also the HMAC key for
// cert-HMAC (see VerifyCertHMAC), and a client doing both should derive once and
// pass the result to each.
func ClientAuthKey(clientEphemeral *ecdh.PrivateKey, serverStaticPub, random []byte) ([]byte, error) {
	if clientEphemeral == nil {
		return nil, ErrNoClientEphemeral
	}
	if clientEphemeral.Curve() != ecdh.X25519() {
		return nil, errors.New("reality auth: client ephemeral key is not X25519")
	}
	serverPub, err := ecdh.X25519().NewPublicKey(serverStaticPub)
	if err != nil {
		return nil, fmt.Errorf("reality auth: server static key: %w", err)
	}
	shared, err := clientEphemeral.ECDH(serverPub)
	if err != nil {
		// X25519 rejects low-order points, which is what an all-zero shared
		// secret would come from.
		return nil, fmt.Errorf("%w: %w", ErrShortSharedSecret, err)
	}
	return deriveAuthKey(shared, random)
}

// ServerAuthKey is the server-side counterpart of ClientAuthKey: ECDH between
// the server's static private key and the client's key share.
func ServerAuthKey(serverStaticPriv, peerPub, random []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(serverStaticPriv)
	if err != nil {
		return nil, fmt.Errorf("reality auth: server static key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("reality auth: peer key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShortSharedSecret, err)
	}
	return deriveAuthKey(shared, random)
}

// deriveAuthKey performs the shared half of seal and open: X25519 followed by
// HKDF-SHA256 salted with the first 20 bytes of ClientHello.Random.
//
// Using Random as the salt is what makes the key per-connection even though the
// server's static key never changes: a replayed ClientHello derives the same
// key, which is why the server also needs a replay cache, but two genuine
// connections never share one.
func deriveAuthKey(shared, random []byte) ([]byte, error) {
	if len(random) != helloRandomLen {
		return nil, ErrRandomLen
	}
	key, err := hkdf.Key(sha256.New, shared, random[:20], AuthHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("reality auth: hkdf: %w", err)
	}
	return key, nil
}

// newAuthAEAD builds AES-256-GCM over the derived key.
func newAuthAEAD(authKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("reality auth: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality auth: gcm: %w", err)
	}
	return aead, nil
}

// SealSessionID produces the 32 bytes a client puts in ClientHello.session_id.
//
// clientEphemeral is the X25519 private key from the client's own key_share —
// on the uTLS path, HandshakeState.State13.KeyShareKeys.Ecdhe, falling back to
// .MlkemEcdhe when the profile only offers the hybrid group.
//
// helloRaw is the ClientHello handshake message (uTLS Hello.Raw: type byte,
// 3-byte length, then the body — no 5-byte record header) with session_id
// already zeroed. It is the AEAD's additional data, so every other byte of the
// ClientHello is authenticated: an in-path rewrite of the SNI, the extension
// list or the key share invalidates the session_id.
//
// random is ClientHello.Random.
func SealSessionID(clientEphemeral *ecdh.PrivateKey, serverStaticPub []byte,
	helloRaw, random []byte, p AuthPayload,
) ([AuthSessionIDLen]byte, error) {
	var out [AuthSessionIDLen]byte

	if err := requireZeroedSessionID(helloRaw); err != nil {
		return out, err
	}

	authKey, err := ClientAuthKey(clientEphemeral, serverStaticPub, random)
	if err != nil {
		return out, err
	}
	aead, err := newAuthAEAD(authKey)
	if err != nil {
		return out, err
	}

	plaintext := p.Marshal()
	sealed := aead.Seal(nil, random[20:32], plaintext[:], helloRaw)
	if len(sealed) != AuthSessionIDLen {
		return out, fmt.Errorf("reality auth: sealed session_id is %d bytes, want %d", len(sealed), AuthSessionIDLen)
	}
	copy(out[:], sealed)
	return out, nil
}

// OpenSessionID is the server side of SealSessionID.
//
// peerPub is the client's X25519 public key taken from its key_share (see
// ExtractPeerX25519). helloRawZeroed is the received ClientHello with its
// session_id zeroed — the same AAD the client sealed against.
//
// A failure here means only "not one of ours". The caller must treat every
// failure identically, including in timing, and fall through to the donor.
func OpenSessionID(serverStaticPriv, peerPub []byte,
	helloRawZeroed, random []byte, sessionID [AuthSessionIDLen]byte,
) (AuthPayload, error) {
	if err := requireZeroedSessionID(helloRawZeroed); err != nil {
		return AuthPayload{}, err
	}

	authKey, err := ServerAuthKey(serverStaticPriv, peerPub, random)
	if err != nil {
		return AuthPayload{}, err
	}
	aead, err := newAuthAEAD(authKey)
	if err != nil {
		return AuthPayload{}, err
	}

	plaintext, err := aead.Open(nil, random[20:32], sessionID[:], helloRawZeroed)
	if err != nil {
		return AuthPayload{}, ErrAuthOpen
	}
	return parseAuthPayload(plaintext)
}

// SessionIDOffset returns the offset of session_id inside a ClientHello
// handshake message and verifies that it is 32 bytes long.
//
// The offset is derived from the message structure, never assumed: see the
// comment on handshakeHeaderLen.
func SessionIDOffset(helloRaw []byte) (int, error) {
	const lenOffset = handshakeHeaderLen + helloLegacyVersLen + helloRandomLen

	if len(helloRaw) < lenOffset+1 {
		return 0, ErrHelloTruncated
	}
	if helloRaw[0] != handshakeTypeHello {
		return 0, ErrHelloNotClient
	}
	// The handshake length must describe exactly the bytes we were given;
	// anything else means we are looking at a fragment or at two coalesced
	// messages, and the AAD would not match what the peer computed.
	bodyLen := int(helloRaw[1])<<16 | int(helloRaw[2])<<8 | int(helloRaw[3])
	if bodyLen != len(helloRaw)-handshakeHeaderLen {
		return 0, ErrHelloTruncated
	}
	if int(helloRaw[lenOffset]) != AuthSessionIDLen {
		return 0, ErrSessionIDLen
	}
	offset := lenOffset + 1
	if len(helloRaw) < offset+AuthSessionIDLen {
		return 0, ErrHelloTruncated
	}
	return offset, nil
}

// ZeroSessionID returns a copy of helloRaw with its session_id zeroed, ready to
// be used as AEAD additional data.
func ZeroSessionID(helloRaw []byte) ([]byte, error) {
	offset, err := SessionIDOffset(helloRaw)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(helloRaw))
	copy(out, helloRaw)
	clear(out[offset : offset+AuthSessionIDLen])
	return out, nil
}

// SessionIDFrom extracts the session_id bytes from a ClientHello.
func SessionIDFrom(helloRaw []byte) ([AuthSessionIDLen]byte, error) {
	var out [AuthSessionIDLen]byte
	offset, err := SessionIDOffset(helloRaw)
	if err != nil {
		return out, err
	}
	copy(out[:], helloRaw[offset:offset+AuthSessionIDLen])
	return out, nil
}

// requireZeroedSessionID guards the single mistake that turns this scheme into
// an intermittent, undebuggable "the server sometimes does not authorize me":
// sealing or opening against an AAD whose session_id was not zeroed. It is
// cheap, and it converts a silent mismatch into an error at the call site.
func requireZeroedSessionID(helloRaw []byte) error {
	offset, err := SessionIDOffset(helloRaw)
	if err != nil {
		return err
	}
	for _, b := range helloRaw[offset : offset+AuthSessionIDLen] {
		if b != 0 {
			return ErrSessionIDNotZero
		}
	}
	return nil
}

// ExtractPeerX25519 pulls the client's X25519 public key out of its key_share.
//
// A plain X25519 share wins when present. Otherwise the hybrid X25519MLKEM768
// share is used, whose client value is the ML-KEM encapsulation key followed by
// the X25519 point — so the key is the 32-byte tail, not the head.
func ExtractPeerX25519(helloRaw []byte) ([]byte, error) {
	exts, err := helloExtensions(helloRaw)
	if err != nil {
		return nil, err
	}

	var classical, hybrid []byte
	var walkErr error
	if err := walkExtensions(exts, func(_ int, extType uint16, body []byte) bool {
		if extType != extensionKeyShare {
			return false
		}
		if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
			walkErr = ErrHelloTruncated
			return true
		}
		for shares := body[2:]; len(shares) >= 4; {
			group := binary.BigEndian.Uint16(shares)
			keyLen := int(binary.BigEndian.Uint16(shares[2:]))
			if len(shares) < 4+keyLen {
				walkErr = ErrHelloTruncated
				return true
			}
			key := shares[4 : 4+keyLen]
			shares = shares[4+keyLen:]

			switch {
			case group == groupX25519 && keyLen == 32:
				classical = key
			case group == groupX25519MLKEM768 && keyLen == mlkem.EncapsulationKeySize768+32:
				hybrid = key[mlkem.EncapsulationKeySize768:]
			}
		}
		return true
	}); err != nil {
		return nil, err
	}
	if walkErr != nil {
		return nil, walkErr
	}

	// Preference order: plain X25519, then the hybrid group's X25519 half. This
	// MUST mirror the client's choice of which private key to seal with (see
	// SelectClientEphemeral) — if the two disagree, the server derives a
	// different shared secret and every open fails.
	if classical != nil {
		return append([]byte(nil), classical...), nil
	}
	if hybrid != nil {
		return append([]byte(nil), hybrid...), nil
	}
	return nil, ErrNoPeerKeyShare
}

// SelectClientEphemeral picks the private key a client must seal with. It is
// the exact mirror of ExtractPeerX25519 and the two must never diverge: the
// server derives its half of the shared secret from whichever public key
// ExtractPeerX25519 picks off the wire, so the client has to seal with the
// matching private key.
//
// Order: the plain X25519 key first, then the X25519 half of the hybrid group.
//
// The distinction is not academic. Firefox is built with
// ReuseHybridAndClassicalKeyShares, so its Ecdhe and MlkemEcdhe are the same
// key and either choice works. Chrome offers both groups with different keys,
// so choosing the hybrid half there while the server reads the classical share
// produces two different secrets and a handshake that fails every time.
//
// keys comes from uconn.HandshakeState.State13.KeyShareKeys. A nil result means
// the profile does not do TLS 1.3 and cannot be used for REALITY at all — the
// Android OkHttp profile is the one we ship that falls in this bucket.
func SelectClientEphemeral(keys *utls.KeySharePrivateKeys) (*ecdh.PrivateKey, error) {
	if keys == nil {
		return nil, ErrNoClientEphemeral
	}
	// Ecdhe is the classical share's key; it is only the X25519 one when the
	// profile's classical group is X25519. A profile offering, say, P-256 as
	// its classical group must fall through to the hybrid half.
	if keys.Ecdhe != nil && keys.Ecdhe.Curve() == ecdh.X25519() {
		return keys.Ecdhe, nil
	}
	if keys.MlkemEcdhe != nil && keys.MlkemEcdhe.Curve() == ecdh.X25519() {
		return keys.MlkemEcdhe, nil
	}
	return nil, ErrNoClientEphemeral
}

// helloExtensions returns the extensions block of a ClientHello, skipping past
// session_id, cipher_suites and compression_methods.
func helloExtensions(helloRaw []byte) ([]byte, error) {
	start, length, err := helloExtensionsAt(helloRaw)
	if err != nil {
		return nil, err
	}
	return helloRaw[start : start+length], nil
}

// helloExtensionsAt locates the extensions block of a ClientHello handshake
// message and returns its offset and length.
//
// Everything in this package that needs to find an extension goes through here.
// Scanning the raw bytes for an extension type instead — which is what the
// legacy padding helpers used to do — matches inside key_share data, where a
// post-quantum share puts over a kilobyte of effectively random bytes in front
// of every other extension.
func helloExtensionsAt(helloRaw []byte) (start, length int, err error) {
	offset, err := SessionIDOffset(helloRaw)
	if err != nil {
		return 0, 0, err
	}
	pos := offset + AuthSessionIDLen

	if len(helloRaw) < pos+2 {
		return 0, 0, ErrHelloTruncated
	}
	pos += 2 + int(binary.BigEndian.Uint16(helloRaw[pos:])) // cipher_suites
	if len(helloRaw) < pos+1 {
		return 0, 0, ErrHelloTruncated
	}
	pos += 1 + int(helloRaw[pos]) // compression_methods
	if len(helloRaw) < pos+2 {
		return 0, 0, ErrHelloTruncated
	}
	extLen := int(binary.BigEndian.Uint16(helloRaw[pos:]))
	pos += 2
	if len(helloRaw) < pos+extLen {
		return 0, 0, ErrHelloTruncated
	}
	return pos, extLen, nil
}

// walkExtensions calls fn for each extension in an extensions block, passing the
// offset of the extension's 4-byte header relative to the block start, its type
// and its body. fn returns true to stop the walk.
func walkExtensions(block []byte, fn func(offset int, extType uint16, body []byte) bool) error {
	for pos := 0; pos < len(block); {
		if len(block)-pos < 4 {
			return ErrHelloTruncated
		}
		extType := binary.BigEndian.Uint16(block[pos:])
		bodyLen := int(binary.BigEndian.Uint16(block[pos+2:]))
		if len(block)-pos-4 < bodyLen {
			return ErrHelloTruncated
		}
		if fn(pos, extType, block[pos+4:pos+4+bodyLen]) {
			return nil
		}
		pos += 4 + bodyLen
	}
	return nil
}

// DecodeKeyBase64 accepts any of the four base64 alphabets an operator might
// paste for a REALITY key.
//
// We emit raw-url (that is what `tiredvpn reality-keygen` prints), but a key
// copied out of a JSON config arrives padded, and one pasted from a shell
// history may have been re-encoded. A startup failure that reads like a corrupt
// key, when the bytes are fine and only the alphabet differs, is a bad hour for
// whoever hits it.
//
// Shared between the server, which reads its private key, and the client, which
// reads the server's public key — the two must accept exactly the same set, or
// a key pair that works on one end fails on the other.
func DecodeKeyBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("reality auth: key is not valid base64")
}
