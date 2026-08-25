package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"go/build"
	"slices"
	"strings"
	"testing"
	"time"
)

// testShare is one key_share entry in a synthetic ClientHello.
type testShare struct {
	group uint16
	key   []byte
}

// buildTestHello assembles a ClientHello handshake message (no record header)
// containing the given key shares. sessionIDLen is a parameter so the tests can
// produce the malformed cases the parser has to reject.
func buildTestHello(t *testing.T, shares []testShare, sessionIDLen int) []byte {
	t.Helper()

	var keyShares []byte
	for _, s := range shares {
		keyShares = binary.BigEndian.AppendUint16(keyShares, s.group)
		keyShares = binary.BigEndian.AppendUint16(keyShares, uint16(len(s.key)))
		keyShares = append(keyShares, s.key...)
	}

	var exts []byte
	if len(shares) > 0 {
		body := binary.BigEndian.AppendUint16(nil, uint16(len(keyShares)))
		body = append(body, keyShares...)
		exts = binary.BigEndian.AppendUint16(exts, extensionKeyShare)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(body)))
		exts = append(exts, body...)
	}

	random := make([]byte, helloRandomLen)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand: %v", err)
	}

	body := []byte{0x03, 0x03} // legacy_version
	body = append(body, random...)
	body = append(body, byte(sessionIDLen))
	body = append(body, make([]byte, sessionIDLen)...)
	body = binary.BigEndian.AppendUint16(body, 2) // cipher_suites length
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)                                     // compression_methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts))) // extensions length
	body = append(body, exts...)

	out := []byte{handshakeTypeHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// helloRandom returns the Random field of a ClientHello handshake message.
func helloRandom(hello []byte) []byte {
	start := handshakeHeaderLen + helloLegacyVersLen
	return hello[start : start+helloRandomLen]
}

func mustX25519(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// samplePayload is a payload with every field distinct, so a field-ordering bug
// cannot round-trip by accident.
func samplePayload() AuthPayload {
	return AuthPayload{
		Version: [3]byte{1, 3, 27},
		Flags:   AuthFlagExporterBinding,
		Time:    uint32(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC).Unix()),
		ShortID: [AuthShortIDLen]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
	}
}

// authFixture is a matched client/server pair plus a zeroed ClientHello.
type authFixture struct {
	clientEph  *ecdh.PrivateKey
	serverPriv *ecdh.PrivateKey
	hello      []byte // session_id already zeroed
	random     []byte
}

func newAuthFixture(t *testing.T) authFixture {
	t.Helper()
	clientEph := mustX25519(t)
	serverPriv := mustX25519(t)
	hello := buildTestHello(t, []testShare{{groupX25519, clientEph.PublicKey().Bytes()}}, AuthSessionIDLen)
	return authFixture{
		clientEph:  clientEph,
		serverPriv: serverPriv,
		hello:      hello,
		random:     helloRandom(hello),
	}
}

func TestSealOpenSessionIDRoundTrip(t *testing.T) {
	f := newAuthFixture(t)
	want := samplePayload()

	sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, want)
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}
	if len(sid) != AuthSessionIDLen {
		t.Fatalf("sealed session_id is %d bytes, want %d", len(sid), AuthSessionIDLen)
	}

	peerPub, err := ExtractPeerX25519(f.hello)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}

	got, err := OpenSessionID(f.serverPriv.Bytes(), peerPub, f.hello, f.random, sid)
	if err != nil {
		t.Fatalf("OpenSessionID: %v", err)
	}
	if got != want {
		t.Fatalf("payload round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

// TestSealSessionIDIsNotStable guards the property that makes replay detection
// meaningful in the first place: two ClientHellos never produce the same
// session_id, because Random feeds both the HKDF salt and the GCM nonce.
func TestSealSessionIDIsNotStable(t *testing.T) {
	p := samplePayload()
	seen := make(map[[AuthSessionIDLen]byte]bool, 32)
	for range 32 {
		f := newAuthFixture(t)
		sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, p)
		if err != nil {
			t.Fatalf("SealSessionID: %v", err)
		}
		if seen[sid] {
			t.Fatal("two ClientHellos produced the same session_id")
		}
		seen[sid] = true
	}
}

// TestOpenSessionIDRejectsAnyHelloMutation is the AAD binding test: flipping any
// byte of the ClientHello other than the session_id itself must break the open.
// This is what stops an in-path rewrite of the SNI, the extension list or the
// key share from surviving.
func TestOpenSessionIDRejectsAnyHelloMutation(t *testing.T) {
	f := newAuthFixture(t)
	sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, samplePayload())
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}
	peerPub, err := ExtractPeerX25519(f.hello)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}
	sidOffset, err := SessionIDOffset(f.hello)
	if err != nil {
		t.Fatalf("SessionIDOffset: %v", err)
	}

	survived := 0
	for i := range f.hello {
		if i >= sidOffset && i < sidOffset+AuthSessionIDLen {
			continue // the session_id is the ciphertext, not the AAD
		}
		mutated := slices.Clone(f.hello)
		mutated[i] ^= 0x01

		// The peer key and Random are read out of the ClientHello in
		// production too, so re-derive them from the mutated bytes rather than
		// reusing the pristine ones — otherwise the test is weaker than the
		// real code path.
		mutPub := peerPub
		if p, err := ExtractPeerX25519(mutated); err == nil {
			mutPub = p
		}
		if _, err := OpenSessionID(f.serverPriv.Bytes(), mutPub, mutated, helloRandom(mutated), sid); err == nil {
			t.Errorf("flipping byte %d of the ClientHello still opened", i)
			survived++
			if survived > 5 {
				t.Fatal("too many surviving mutations, stopping")
			}
		}
	}
}

// TestOpenSessionIDRejectsRandomMutation covers the other input: the Random
// passed alongside the hello feeds both the HKDF salt and the GCM nonce.
func TestOpenSessionIDRejectsRandomMutation(t *testing.T) {
	f := newAuthFixture(t)
	sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, samplePayload())
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}
	peerPub, err := ExtractPeerX25519(f.hello)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}

	for i := range helloRandomLen {
		mutated := slices.Clone(f.random)
		mutated[i] ^= 0x01
		if _, err := OpenSessionID(f.serverPriv.Bytes(), peerPub, f.hello, mutated, sid); err == nil {
			t.Errorf("flipping byte %d of Random still opened", i)
		}
	}
}

func TestOpenSessionIDRejectsWrongKeys(t *testing.T) {
	f := newAuthFixture(t)
	sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, samplePayload())
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}
	peerPub, err := ExtractPeerX25519(f.hello)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}

	t.Run("wrong server key", func(t *testing.T) {
		other := mustX25519(t)
		if _, err := OpenSessionID(other.Bytes(), peerPub, f.hello, f.random, sid); err == nil {
			t.Fatal("opened with the wrong server static key")
		}
	})

	t.Run("wrong peer key", func(t *testing.T) {
		other := mustX25519(t)
		if _, err := OpenSessionID(f.serverPriv.Bytes(), other.PublicKey().Bytes(), f.hello, f.random, sid); err == nil {
			t.Fatal("opened with the wrong client key")
		}
	})

	t.Run("mutated ciphertext", func(t *testing.T) {
		bad := sid
		bad[0] ^= 0x01
		if _, err := OpenSessionID(f.serverPriv.Bytes(), peerPub, f.hello, f.random, bad); err == nil {
			t.Fatal("opened a mutated session_id")
		}
	})
}

// TestSealOpenRejectUnzeroedSessionID pins the guard against the integration
// mistake that would otherwise surface as "the server sometimes does not
// authorize me": computing the AAD over a hello whose session_id is still set.
func TestSealOpenRejectUnzeroedSessionID(t *testing.T) {
	f := newAuthFixture(t)
	offset, err := SessionIDOffset(f.hello)
	if err != nil {
		t.Fatalf("SessionIDOffset: %v", err)
	}
	dirty := slices.Clone(f.hello)
	dirty[offset] = 0x7F

	if _, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), dirty, f.random, samplePayload()); err != ErrSessionIDNotZero {
		t.Errorf("SealSessionID on a dirty hello: err = %v, want ErrSessionIDNotZero", err)
	}
	if _, err := OpenSessionID(f.serverPriv.Bytes(), f.clientEph.PublicKey().Bytes(), dirty, f.random, [AuthSessionIDLen]byte{}); err != ErrSessionIDNotZero {
		t.Errorf("OpenSessionID on a dirty hello: err = %v, want ErrSessionIDNotZero", err)
	}
}

func TestSessionIDOffsetRejectsMalformed(t *testing.T) {
	good := buildTestHello(t, []testShare{{groupX25519, make([]byte, 32)}}, AuthSessionIDLen)

	t.Run("well formed", func(t *testing.T) {
		offset, err := SessionIDOffset(good)
		if err != nil {
			t.Fatalf("SessionIDOffset: %v", err)
		}
		// 4 header + 2 legacy_version + 32 random + 1 length. Asserted as a
		// value so a structural change is visible, but the parser derives it.
		if offset != 39 {
			t.Fatalf("session_id offset = %d, want 39", offset)
		}
	})

	t.Run("wrong session id length", func(t *testing.T) {
		bad := buildTestHello(t, []testShare{{groupX25519, make([]byte, 32)}}, 16)
		if _, err := SessionIDOffset(bad); err != ErrSessionIDLen {
			t.Fatalf("err = %v, want ErrSessionIDLen", err)
		}
	})

	t.Run("empty session id", func(t *testing.T) {
		bad := buildTestHello(t, []testShare{{groupX25519, make([]byte, 32)}}, 0)
		if _, err := SessionIDOffset(bad); err != ErrSessionIDLen {
			t.Fatalf("err = %v, want ErrSessionIDLen", err)
		}
	})

	t.Run("not a ClientHello", func(t *testing.T) {
		bad := slices.Clone(good)
		bad[0] = 0x02 // ServerHello
		if _, err := SessionIDOffset(bad); err != ErrHelloNotClient {
			t.Fatalf("err = %v, want ErrHelloNotClient", err)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		for _, n := range []int{0, 1, 4, 10, 38, 39, 50} {
			if n >= len(good) {
				continue
			}
			if _, err := SessionIDOffset(good[:n]); err == nil {
				t.Errorf("truncation to %d bytes accepted", n)
			}
		}
	})

	t.Run("length field disagrees with buffer", func(t *testing.T) {
		bad := slices.Clone(good)
		bad[3]++ // claim one byte more than we hold
		if _, err := SessionIDOffset(bad); err != ErrHelloTruncated {
			t.Fatalf("err = %v, want ErrHelloTruncated", err)
		}
	})
}

func TestExtractPeerX25519(t *testing.T) {
	x25519Key := bytes.Repeat([]byte{0xAA}, 32)
	hybridKey := append(bytes.Repeat([]byte{0xBB}, mlkem.EncapsulationKeySize768), bytes.Repeat([]byte{0xCC}, 32)...)

	t.Run("plain X25519", func(t *testing.T) {
		hello := buildTestHello(t, []testShare{{groupX25519, x25519Key}}, AuthSessionIDLen)
		got, err := ExtractPeerX25519(hello)
		if err != nil {
			t.Fatalf("ExtractPeerX25519: %v", err)
		}
		if !bytes.Equal(got, x25519Key) {
			t.Fatalf("got % x, want % x", got[:8], x25519Key[:8])
		}
	})

	t.Run("hybrid only takes the tail", func(t *testing.T) {
		hello := buildTestHello(t, []testShare{{groupX25519MLKEM768, hybridKey}}, AuthSessionIDLen)
		got, err := ExtractPeerX25519(hello)
		if err != nil {
			t.Fatalf("ExtractPeerX25519: %v", err)
		}
		if len(got) != 32 {
			t.Fatalf("got %d bytes, want 32", len(got))
		}
		if !bytes.Equal(got, bytes.Repeat([]byte{0xCC}, 32)) {
			t.Fatalf("took the head of the hybrid share, not the tail: % x", got[:8])
		}
	})

	t.Run("both groups prefer plain X25519", func(t *testing.T) {
		// Hybrid listed first, so a first-match implementation would fail here.
		hello := buildTestHello(t, []testShare{
			{groupX25519MLKEM768, hybridKey},
			{groupX25519, x25519Key},
		}, AuthSessionIDLen)
		got, err := ExtractPeerX25519(hello)
		if err != nil {
			t.Fatalf("ExtractPeerX25519: %v", err)
		}
		if !bytes.Equal(got, x25519Key) {
			t.Fatalf("did not prefer the plain X25519 share: % x", got[:8])
		}
	})

	t.Run("no usable group", func(t *testing.T) {
		hello := buildTestHello(t, []testShare{{0x0017, make([]byte, 65)}}, AuthSessionIDLen) // secp256r1
		if _, err := ExtractPeerX25519(hello); err != ErrNoPeerKeyShare {
			t.Fatalf("err = %v, want ErrNoPeerKeyShare", err)
		}
	})

	t.Run("no key_share extension", func(t *testing.T) {
		hello := buildTestHello(t, nil, AuthSessionIDLen)
		if _, err := ExtractPeerX25519(hello); err != ErrNoPeerKeyShare {
			t.Fatalf("err = %v, want ErrNoPeerKeyShare", err)
		}
	})

	t.Run("wrong length for the declared group", func(t *testing.T) {
		hello := buildTestHello(t, []testShare{{groupX25519, make([]byte, 31)}}, AuthSessionIDLen)
		if _, err := ExtractPeerX25519(hello); err != ErrNoPeerKeyShare {
			t.Fatalf("err = %v, want ErrNoPeerKeyShare", err)
		}
	})
}

// TestExtractPeerX25519OnRealClientHellos runs the parser against what uTLS
// actually emits for the profiles we ship, not just synthetic input. This is
// where a mismatch between our assumptions and a parrot's real key_share
// layout would show up.
func TestExtractPeerX25519OnRealClientHellos(t *testing.T) {
	for _, name := range FingerprintNames() {
		if name == "randomized" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			fp, ok := LookupFingerprint(name)
			if !ok {
				t.Fatalf("profile %q does not resolve", name)
			}
			record, err := BuildClientHelloBytes(&Config{
				ServerName:         "github.com",
				Fingerprint:        name,
				ALPN:               []string{"h2", "http/1.1"},
				InsecureSkipVerify: true,
			}, fp)
			if err != nil {
				t.Fatalf("BuildClientHelloBytes: %v", err)
			}
			hello := record[5:] // strip the TLS record header

			offset, err := SessionIDOffset(hello)
			if err != nil {
				t.Fatalf("SessionIDOffset on a real %s hello: %v", name, err)
			}
			if offset != 39 {
				t.Fatalf("session_id offset = %d, want 39", offset)
			}

			key, err := ExtractPeerX25519(hello)
			if err != nil {
				// Pre-TLS1.3 parrots legitimately have no X25519 key share;
				// B1 refuses those profiles rather than mis-parsing them.
				t.Skipf("profile %s offers no X25519 key share: %v", name, err)
			}
			if len(key) != 32 {
				t.Fatalf("extracted %d bytes, want 32", len(key))
			}
			if _, err := ecdh.X25519().NewPublicKey(key); err != nil {
				t.Fatalf("extracted bytes are not a valid X25519 point: %v", err)
			}
		})
	}
}

func TestShortIDFor(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		secret := []byte("a-client-secret")
		first := ShortIDFor(secret)
		for range 8 {
			if ShortIDFor(secret) != first {
				t.Fatal("ShortIDFor is not deterministic")
			}
		}
	})

	t.Run("no collisions over 1000 secrets", func(t *testing.T) {
		seen := make(map[[AuthShortIDLen]byte][]byte, 1000)
		for range 1000 {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				t.Fatalf("rand: %v", err)
			}
			id := ShortIDFor(secret)
			if prev, dup := seen[id]; dup {
				t.Fatalf("short ID collision: % x and % x both give % x", prev[:8], secret[:8], id)
			}
			seen[id] = secret
		}
	})

	t.Run("differs from a one-bit secret change", func(t *testing.T) {
		a := []byte("secret")
		b := []byte("secret")
		b[0] ^= 0x01
		if ShortIDFor(a) == ShortIDFor(b) {
			t.Fatal("one-bit secret change produced the same short ID")
		}
	})
}

func TestAuthPayloadMarshalRoundTrip(t *testing.T) {
	want := samplePayload()
	raw := want.Marshal()
	if len(raw) != AuthPlaintextLen {
		t.Fatalf("marshalled payload is %d bytes, want %d", len(raw), AuthPlaintextLen)
	}
	got, err := parseAuthPayload(raw[:])
	if err != nil {
		t.Fatalf("parseAuthPayload: %v", err)
	}
	if got != want {
		t.Fatalf("round trip: got %+v, want %+v", got, want)
	}
	if !want.HasFlag(AuthFlagExporterBinding) {
		t.Error("HasFlag missed a set bit")
	}
	if (AuthPayload{}).HasFlag(AuthFlagExporterBinding) {
		t.Error("HasFlag reported an unset bit")
	}
}

func TestZeroSessionIDDoesNotMutateInput(t *testing.T) {
	hello := buildTestHello(t, []testShare{{groupX25519, make([]byte, 32)}}, AuthSessionIDLen)
	offset, err := SessionIDOffset(hello)
	if err != nil {
		t.Fatalf("SessionIDOffset: %v", err)
	}
	for i := range AuthSessionIDLen {
		hello[offset+i] = byte(i + 1)
	}
	original := slices.Clone(hello)

	zeroed, err := ZeroSessionID(hello)
	if err != nil {
		t.Fatalf("ZeroSessionID: %v", err)
	}
	if !bytes.Equal(hello, original) {
		t.Fatal("ZeroSessionID mutated its input")
	}
	if !bytes.Equal(zeroed[offset:offset+AuthSessionIDLen], make([]byte, AuthSessionIDLen)) {
		t.Fatal("session_id was not zeroed")
	}
	if !bytes.Equal(zeroed[:offset], original[:offset]) ||
		!bytes.Equal(zeroed[offset+AuthSessionIDLen:], original[offset+AuthSessionIDLen:]) {
		t.Fatal("ZeroSessionID changed bytes outside the session_id")
	}

	got, err := SessionIDFrom(hello)
	if err != nil {
		t.Fatalf("SessionIDFrom: %v", err)
	}
	if !bytes.Equal(got[:], original[offset:offset+AuthSessionIDLen]) {
		t.Fatal("SessionIDFrom returned the wrong bytes")
	}
}

// TestPackageStaysALeafLayer enforces the constraint from the task: this is the
// shared crypto layer, imported by both the client strategy and the server, so
// it must not depend on either. A cycle here would be found at compile time,
// but only after someone has already built the wrong thing.
func TestPackageStaysALeafLayer(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}
	forbidden := []string{
		"github.com/tiredvpn/tiredvpn/internal/strategy",
		"github.com/tiredvpn/tiredvpn/internal/server",
		"github.com/tiredvpn/tiredvpn/internal/client",
	}
	for _, imp := range slices.Concat(pkg.Imports, pkg.TestImports) {
		for _, bad := range forbidden {
			if imp == bad || strings.HasPrefix(imp, bad+"/") {
				t.Errorf("internal/tls imports %s; the shared crypto layer must stay below it", imp)
			}
		}
	}
}
