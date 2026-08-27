package strategy

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// TestBuildClientHelloCarriesAuthAndDataV2 walks a real ClientHello the way the
// server does and checks that both things we hide in the padding survive: the
// auth token, and the v2 data-layer signal behind it.
//
// This is the seam between two changes that landed independently. The padding
// extension used to be dropped by uTLS, so InjectREALITYIntoPadding always
// failed and the code fell through to AddPaddingWithREALITY, which splices the
// extension into the marshalled bytes afterwards. With the uTLS padding fixed,
// injection is the live path and the splice is the fallback - a different code
// path writing our 128 bytes, at a different offset, into a block uTLS filled
// with zeros. Nothing on either branch covers that end to end.
//
// Every profile is checked because the padding handling differs between them:
// some carry a BoringPaddingStyle extension that gets replaced, others get one
// appended, and randomized profiles have no spec at all and take the fallback.
func TestBuildClientHelloCarriesAuthAndDataV2(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")

	for _, name := range customtls.FingerprintNames() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := NewREALITYStrategy(nil, secret)
			r.SetFingerprint(name)

			clientPriv, clientPub, err := customtls.GenerateX25519KeyPair()
			if err != nil {
				t.Fatal(err)
			}
			var salt [32]byte
			if _, err := rand.Read(salt[:]); err != nil {
				t.Fatal(err)
			}

			hello, err := r.buildClientHello("github.com:443", clientPriv, salt, r.secret)
			if err != nil {
				t.Fatal(err)
			}

			padding, ok := paddingExtensionBody(hello)
			if !ok {
				t.Fatal("no padding extension in the ClientHello")
			}
			if len(padding) < customtls.REALITYExtensionLength+customtls.DataV2ExtraLength {
				t.Fatalf("padding is %d bytes, too small to carry the 128-byte block", len(padding))
			}

			ext, err := customtls.ExtractREALITYFromPadding(padding)
			if err != nil {
				t.Fatal(err)
			}
			if ext.PubKey != clientPub {
				t.Fatal("padding does not hold this connection's public key: injection wrote to the wrong place")
			}
			if !customtls.VerifyClientAuth(secret, ext.PubKey, ext.AuthToken) {
				t.Fatal("auth token does not verify")
			}
			gotSalt, v2 := customtls.ParseClientDataV2(secret, ext.PubKey, ext.Extra)
			if !v2 {
				t.Fatal("v2 data-layer signal did not survive injection into the padding")
			}
			if gotSalt != salt {
				t.Fatal("salt mismatch")
			}
		})
	}
}

// TestBuildClientHelloRotatesKeyMaterial checks that two ClientHellos from one
// strategy carry different key material. The strategy holds no key pair any
// more - a process-wide one is what made every connection reuse a keystream -
// so this guards against anyone reintroducing one behind buildClientHello.
func TestBuildClientHelloRotatesKeyMaterial(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	r := NewREALITYStrategy(nil, secret)

	seen := make(map[[32]byte]bool)
	for i := range 3 {
		priv, _, err := customtls.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		var salt [32]byte
		if _, err := rand.Read(salt[:]); err != nil {
			t.Fatal(err)
		}
		hello, err := r.buildClientHello("github.com:443", priv, salt, r.secret)
		if err != nil {
			t.Fatal(err)
		}
		padding, ok := paddingExtensionBody(hello)
		if !ok {
			t.Fatal("no padding extension")
		}
		ext, err := customtls.ExtractREALITYFromPadding(padding)
		if err != nil {
			t.Fatal(err)
		}
		if seen[ext.PubKey] {
			t.Fatalf("ClientHello %d repeats a public key seen before", i)
		}
		seen[ext.PubKey] = true
	}
}

// paddingExtensionBody walks the ClientHello properly - record header, handshake
// header, then the extension list - and returns the body of extension 0x0015.
//
// Deliberately not the byte scan for 0x00 0x15 that InjectREALITYIntoPadding
// uses: the point of this test is to find the extension the way a parser does,
// so that a scan landing on a false match inside key_share random shows up as a
// failure here instead of passing itself off as success.
func paddingExtensionBody(hello []byte) ([]byte, bool) {
	if len(hello) < 5+4 {
		return nil, false
	}
	body := hello[5:]                     // skip record header
	if len(body) < 4 || body[0] != 0x01 { // handshake type: ClientHello
		return nil, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		return nil, false
	}
	p := body[4 : 4+hsLen]

	if len(p) < 34 {
		return nil, false
	}
	off := 34 // legacy version + random
	if off >= len(p) {
		return nil, false
	}
	off += 1 + int(p[off]) // session id
	if off+2 > len(p) {
		return nil, false
	}
	off += 2 + int(binary.BigEndian.Uint16(p[off:])) // cipher suites
	if off >= len(p) {
		return nil, false
	}
	off += 1 + int(p[off]) // compression methods
	if off+2 > len(p) {
		return nil, false
	}
	extLen := int(binary.BigEndian.Uint16(p[off:]))
	off += 2
	if off+extLen > len(p) {
		return nil, false
	}
	exts := p[off : off+extLen]

	for i := 0; i+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[i:])
		n := int(binary.BigEndian.Uint16(exts[i+2:]))
		i += 4
		if i+n > len(exts) {
			return nil, false
		}
		if typ == customtls.PaddingExtensionType {
			return exts[i : i+n], true
		}
		i += n
	}
	return nil, false
}
