package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// helloWithREALITY builds a ClientHello carrying ext in its padding extension,
// the same way the client does, so the test walks the real server-side parser.
func helloWithREALITY(t *testing.T, ext *customtls.REALITYExtension) []byte {
	t.Helper()

	body := make([]byte, 0, 96)
	body = append(body, 0x03, 0x03)          // legacy version
	body = append(body, make([]byte, 32)...) // random
	// A 32-byte session id, as every TLS 1.3 ClientHello carries in compat
	// mode. B1 authentication lives in exactly these bytes, so the parsers
	// reject anything else - an empty one made this fixture unlike any real
	// client and unlike what the auth package will accept.
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression methods
	body = append(body, 0x00, 0x00)             // extensions len = 0

	hello, err := customtls.AddPaddingWithREALITY(wrapClientHello(body), ext, customtls.MinPaddingSize)
	if err != nil {
		t.Fatal(err)
	}
	return hello
}

// TestServerAcceptsBothDataLayerVersions is the transition-period acceptance
// test: one upgraded server has to keep serving clients on the old data layer
// while recognising the new one, because the rollout goes exits → relays →
// clients and the fleet is mixed in between.
func TestServerAcceptsBothDataLayerVersions(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	priv, _, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("legacy v1 client", func(t *testing.T) {
		ext, err := customtls.NewClientREALITYExtension(secret, priv)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ExtractREALITYExtensionFromClientHello(helloWithREALITY(t, ext))
		if err != nil {
			t.Fatal(err)
		}
		if !customtls.VerifyClientAuth(secret, got.PubKey, got.AuthToken) {
			t.Fatal("v1 client failed auth on the upgraded server")
		}
		if _, v2 := customtls.ParseClientDataV2(secret, got.PubKey, got.Extra); v2 {
			t.Fatal("v1 client was classified as v2")
		}
	})

	t.Run("v2 client", func(t *testing.T) {
		var salt [32]byte
		if _, err := rand.Read(salt[:]); err != nil {
			t.Fatal(err)
		}
		ext, err := customtls.NewClientREALITYExtensionDataV2(secret, priv, salt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ExtractREALITYExtensionFromClientHello(helloWithREALITY(t, ext))
		if err != nil {
			t.Fatal(err)
		}
		if !customtls.VerifyClientAuth(secret, got.PubKey, got.AuthToken) {
			t.Fatal("v2 client failed auth")
		}
		gotSalt, v2 := customtls.ParseClientDataV2(secret, got.PubKey, got.Extra)
		if !v2 {
			t.Fatal("v2 client was not recognised")
		}
		if gotSalt != salt {
			t.Fatal("salt mismatch")
		}

		// And the server can complete its half: ephemeral key, ECDH, data conn.
		serverPriv, _, err := customtls.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		ecdh, err := strategy.RealityV2ECDH(serverPriv, got.PubKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(ecdh) != 32 {
			t.Fatalf("ecdh len = %d", len(ecdh))
		}
	})
}

// TestServerHelloPaddingIsRandom guards the fixed byte(i*7%256) ramp that used
// to fill 192 bytes of every ServerHello we sent — one DPI rule for the whole
// fleet, independent of IP and SNI.
func TestServerHelloPaddingIsRandom(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	serverPriv, _, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, clientPub, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ext, err := customtls.NewServerREALITYExtension(secret, serverPriv, clientPub)
	if err != nil {
		t.Fatal(err)
	}

	first, err := InjectREALITYExtension(syntheticServerHello(), ext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InjectREALITYExtension(syntheticServerHello(), ext)
	if err != nil {
		t.Fatal(err)
	}

	tail := func(b []byte) []byte { return b[len(b)-(customtls.MinPaddingSize-customtls.REALITYExtensionLength):] }
	if bytes.Equal(tail(first), tail(second)) {
		t.Fatal("padding is identical across two ServerHellos: still deterministic")
	}

	// The old filler was byte(i*7%256); assert that exact sequence is gone.
	ramp := make([]byte, len(tail(first)))
	for i := range ramp {
		ramp[i] = byte(i * 7 % 256)
	}
	if bytes.Equal(tail(first), ramp) {
		t.Fatal("padding still uses the i*7 ramp")
	}
}

// syntheticServerHello builds a minimal ServerHello with an empty extensions
// block, enough for InjectREALITYExtension to parse and extend.
func syntheticServerHello() []byte {
	body := make([]byte, 0, 48)
	body = append(body, 0x03, 0x03)          // legacy version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id len
	body = append(body, 0x13, 0x01)          // cipher suite
	body = append(body, 0x00)                // compression method
	body = append(body, 0x00, 0x00)          // extensions len = 0

	hs := make([]byte, 4+len(body))
	hs[0] = handshakeTypeServerHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = recordTypeHandshake
	binary.BigEndian.PutUint16(rec[1:3], 0x0303)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}
