package tls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"testing"
)

func testKeyPair(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func testSalt(t *testing.T) [32]byte {
	t.Helper()
	var s [32]byte
	if _, err := rand.Read(s[:]); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestClientDataV2RoundTrip(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	priv, pub := testKeyPair(t)
	salt := testSalt(t)

	ext, err := NewClientREALITYExtensionDataV2(secret, priv, salt)
	if err != nil {
		t.Fatal(err)
	}
	if len(ext.Extra) != DataV2ExtraLength {
		t.Fatalf("Extra len = %d, want %d", len(ext.Extra), DataV2ExtraLength)
	}
	if ext.PubKey != pub {
		t.Fatal("pubkey mismatch")
	}

	got, ok := ParseClientDataV2(secret, ext.PubKey, ext.Extra)
	if !ok {
		t.Fatal("valid v2 signal not recognised")
	}
	if got != salt {
		t.Fatal("salt mismatch")
	}
}

func TestClientDataV2Rejects(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	priv, _ := testKeyPair(t)
	salt := testSalt(t)
	ext, err := NewClientREALITYExtensionDataV2(secret, priv, salt)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		check func() ([32]byte, bool)
	}{
		{"random extra (v1 client)", func() ([32]byte, bool) {
			random := make([]byte, DataV2ExtraLength)
			rand.Read(random) //nolint:errcheck // test
			return ParseClientDataV2(secret, ext.PubKey, random)
		}},
		{"no extra at all", func() ([32]byte, bool) {
			return ParseClientDataV2(secret, ext.PubKey, nil)
		}},
		{"truncated extra", func() ([32]byte, bool) {
			return ParseClientDataV2(secret, ext.PubKey, ext.Extra[:DataV2ExtraLength-1])
		}},
		{"wrong secret", func() ([32]byte, bool) {
			return ParseClientDataV2([]byte("other-secret"), ext.PubKey, ext.Extra)
		}},
		{"swapped pubkey", func() ([32]byte, bool) {
			_, other := testKeyPair(t)
			return ParseClientDataV2(secret, other, ext.Extra)
		}},
		{"flipped mac bit", func() ([32]byte, bool) {
			bad := append([]byte(nil), ext.Extra...)
			bad[len(bad)-1] ^= 0x01
			return ParseClientDataV2(secret, ext.PubKey, bad)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.check(); ok {
				t.Fatal("accepted an invalid v2 signal")
			}
		})
	}
}

// TestServerDataV2BindsPublicKey covers the active-attacker case: the server's
// auth token does not cover its own key share, so the confirmation MAC has to.
// Swapping in a different server key must invalidate it.
func TestServerDataV2BindsPublicKey(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	_, clientPub := testKeyPair(t)
	serverPriv, serverPub := testKeyPair(t)
	clientSalt, serverSalt := testSalt(t), testSalt(t)

	ext, err := NewServerREALITYExtensionDataV2(secret, serverPriv, clientPub, clientSalt, serverSalt)
	if err != nil {
		t.Fatal(err)
	}
	if ext.PubKey != serverPub {
		t.Fatal("server pubkey mismatch")
	}

	if _, ok := ParseServerDataV2(secret, clientPub, ext.PubKey, clientSalt, ext.Extra); !ok {
		t.Fatal("valid server confirmation rejected")
	}

	_, attackerPub := testKeyPair(t)
	if _, ok := ParseServerDataV2(secret, clientPub, attackerPub, clientSalt, ext.Extra); ok {
		t.Fatal("confirmation still valid after the server key was swapped")
	}

	if _, ok := ParseServerDataV2(secret, clientPub, ext.PubKey, testSalt(t), ext.Extra); ok {
		t.Fatal("confirmation still valid under a different client salt")
	}
}

// TestPaddingCarriesV2WithoutGrowing checks the wire cost of the negotiation:
// the signal lives inside the existing 256-byte padding block, so a v2
// ClientHello must be byte-for-byte the same size as a v1 one.
func TestPaddingCarriesV2WithoutGrowing(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	priv, _ := testKeyPair(t)
	salt := testSalt(t)

	v1Ext, err := NewClientREALITYExtension(secret, priv)
	if err != nil {
		t.Fatal(err)
	}
	v2Ext, err := NewClientREALITYExtensionDataV2(secret, priv, salt)
	if err != nil {
		t.Fatal(err)
	}

	base := syntheticClientHello(t)
	v1Hello, err := AddPaddingWithREALITY(base, v1Ext, MinPaddingSize)
	if err != nil {
		t.Fatal(err)
	}
	v2Hello, err := AddPaddingWithREALITY(base, v2Ext, MinPaddingSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(v1Hello) != len(v2Hello) {
		t.Fatalf("v2 ClientHello is %d bytes, v1 is %d: the signal must fit in the existing padding",
			len(v2Hello), len(v1Hello))
	}

	// And it must survive the round trip through the padding block.
	padding := findPaddingBody(t, v2Hello)
	got, err := ExtractREALITYFromPadding(padding)
	if err != nil {
		t.Fatal(err)
	}
	if got.PubKey != v2Ext.PubKey || got.AuthToken != v2Ext.AuthToken {
		t.Fatal("core fields did not survive injection")
	}
	if _, ok := ParseClientDataV2(secret, got.PubKey, got.Extra); !ok {
		t.Fatal("v2 signal did not survive injection")
	}

	// A v1 extension goes through the same path and stays v1.
	v1Padding := findPaddingBody(t, v1Hello)
	v1Got, err := ExtractREALITYFromPadding(v1Padding)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ParseClientDataV2(secret, v1Got.PubKey, v1Got.Extra); ok {
		t.Fatal("random v1 padding was read as a v2 signal")
	}
}

// syntheticClientHello builds a minimal but structurally valid ClientHello with
// no extensions, enough for the padding-injection helpers to parse.
func syntheticClientHello(t *testing.T) []byte {
	t.Helper()

	body := make([]byte, 0, 96)
	body = append(body, 0x03, 0x03)          // legacy version
	body = append(body, make([]byte, 32)...) // random
	// 32-byte session id, as in every real TLS 1.3 ClientHello.
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression methods
	body = append(body, 0x00, 0x00)             // extensions len = 0
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

// findPaddingBody returns the body of the padding extension in a ClientHello
// produced by AddPaddingWithREALITY.
//
// It walks the extension list through findPaddingExtension, the parser the
// client uses. It used to take the last 00 15 in the record, which is the byte
// scan findPaddingExtension replaced: the padding body is random, so about one
// hello in 256 has a later 00 15 in it, and as many again have a public key
// whose first byte 0x15 pairs with the low byte of the 0x0100 length.
func findPaddingBody(t *testing.T, hello []byte) []byte {
	t.Helper()

	offset, bodyLen, err := findPaddingExtension(hello)
	if err != nil {
		t.Fatalf("padding extension: %v", err)
	}
	return hello[offset+4 : offset+4+bodyLen]
}

// collidingPrivKey has an X25519 public key starting with 0x15, so the padding
// header it produces reads 00 15 01 00 15: the last 00 15 in the record is one
// byte inside the length field. Found by hashing "padding-collision-31".
const collidingPrivKey = "5f74c063d4fde37ed029e0a06f3d9b1795f64fb624c387c24734edd7f4441dff"

// TestFindPaddingBodyIgnoresMarkerInBody pins the two inputs that made
// TestPaddingCarriesV2WithoutGrowing fail at random: a 00 15 straddling the
// header and the body, and a 00 15 with a large length inside the random tail.
// The padding is appended right after base, so its offset is known exactly.
func TestFindPaddingBodyIgnoresMarkerInBody(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	var priv [32]byte
	if _, err := hex.Decode(priv[:], []byte(collidingPrivKey)); err != nil {
		t.Fatal(err)
	}
	ext, err := NewClientREALITYExtensionDataV2(secret, priv, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if ext.PubKey[0] != 0x15 {
		t.Fatalf("fixture public key starts with %#02x, want 0x15", ext.PubKey[0])
	}

	base := syntheticClientHello(t)
	hello, err := AddPaddingWithREALITY(base, ext, MinPaddingSize)
	if err != nil {
		t.Fatal(err)
	}

	// The random tail is whatever crypto/rand gave; planting a header there is
	// one of its possible values.
	planted := slices.Clone(hello)
	tail := len(base) + 4 + REALITYExtensionLength + DataV2ExtraLength
	copy(planted[tail+10:], []byte{0x00, 0x15, 0xff, 0xff})

	for name, h := range map[string][]byte{"key straddles header": hello, "marker in random tail": planted} {
		t.Run(name, func(t *testing.T) {
			want := h[len(base)+4:]
			if got := findPaddingBody(t, h); !bytes.Equal(got, want) {
				t.Fatalf("padding body at the wrong place: got %d bytes, want %d", len(got), len(want))
			}
			got, err := ExtractREALITYFromPadding(findPaddingBody(t, h))
			if err != nil {
				t.Fatal(err)
			}
			if got.PubKey != ext.PubKey || got.AuthToken != ext.AuthToken {
				t.Fatal("core fields did not survive injection")
			}
			if _, ok := ParseClientDataV2(secret, got.PubKey, got.Extra); !ok {
				t.Fatal("v2 signal did not survive injection")
			}
		})
	}
}

// TestPaddingRoundTripAcrossKeys runs the injection and the parser over many
// random keys and salts. About one hello in 128 carries a stray 00 15 in its
// padding, so 2000 runs put the parser through roughly 16 collisions.
func TestPaddingRoundTripAcrossKeys(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	base := syntheticClientHello(t)
	for range 2000 {
		priv, _ := testKeyPair(t)
		ext, err := NewClientREALITYExtensionDataV2(secret, priv, testSalt(t))
		if err != nil {
			t.Fatal(err)
		}
		hello, err := AddPaddingWithREALITY(base, ext, MinPaddingSize)
		if err != nil {
			t.Fatal(err)
		}
		offset, bodyLen, err := findPaddingExtension(hello)
		if err != nil {
			t.Fatalf("pubkey %x: %v", ext.PubKey, err)
		}
		if offset != len(base) || bodyLen != MinPaddingSize {
			t.Fatalf("pubkey %x: padding at %d len %d, want %d len %d",
				ext.PubKey, offset, bodyLen, len(base), MinPaddingSize)
		}
		got, err := ExtractREALITYFromPadding(hello[offset+4 : offset+4+bodyLen])
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ParseClientDataV2(secret, got.PubKey, got.Extra); !ok {
			t.Fatalf("pubkey %x: v2 signal did not survive injection", ext.PubKey)
		}
	}
}
