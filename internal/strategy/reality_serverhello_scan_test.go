package strategy

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// validateServerHello finds the server's credentials by scanning the whole
// record for the bytes 00 15, not by walking the extensions. That is safe only
// because a candidate failing VerifyServerAuth sends the scan on to the next
// one: random, the echoed session id and a post-quantum key_share all sit
// ahead of the padding, and a stray 00 15 with a plausible length turns up
// there in about 2% of real ServerHellos. A scan that stopped at the first
// candidate would drop those handshakes. These tests plant the decoy on purpose.

// shScanKeyShareLen is the server's X25519MLKEM768 share: 1088 bytes of ML-KEM
// ciphertext and 32 bytes of X25519.
const shScanKeyShareLen = 1120

// shScanDecoy is a padding header with a length the scan accepts, 64 bytes,
// followed by bytes that are not anyone's credentials.
var shScanDecoy = []byte{0x00, 0x15, 0x00, 0x40}

// shScanServerHello assembles a ServerHello record shaped like a PQ donor's:
// random, a 32-byte session id echo, key_share, supported_versions, then the
// REALITY padding the server appends last. place, if set, gets the finished
// record and the offset of the key share bytes, and may plant a decoy.
func shScanServerHello(t *testing.T, ext *customtls.REALITYExtension, place func(hello []byte, keyShareAt int)) []byte {
	t.Helper()

	random := make([]byte, 32)
	sessionID := make([]byte, 32)
	keyShare := make([]byte, shScanKeyShareLen)
	for _, b := range [][]byte{random, sessionID, keyShare} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}

	padding := make([]byte, customtls.MinPaddingSize)
	n := copy(padding, ext.Marshal())
	if _, err := rand.Read(padding[n:]); err != nil {
		t.Fatal(err)
	}

	var exts []byte
	exts = binary.BigEndian.AppendUint16(exts, 0x0033) // key_share
	exts = binary.BigEndian.AppendUint16(exts, uint16(4+len(keyShare)))
	exts = binary.BigEndian.AppendUint16(exts, 0x11ec) // X25519MLKEM768
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(keyShare)))
	keyShareAt := len(exts)
	exts = append(exts, keyShare...)
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions: TLS 1.3
	exts = binary.BigEndian.AppendUint16(exts, customtls.PaddingExtensionType)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(padding)))
	exts = append(exts, padding...)

	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, 0x13, 0x01, 0x00) // TLS_AES_128_GCM_SHA256, no compression
	extsAt := len(body) + 2
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hello := []byte{0x16, 0x03, 0x03}
	hello = binary.BigEndian.AppendUint16(hello, uint16(4+len(body)))
	hello = append(hello, 0x02, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	bodyAt := len(hello)
	hello = append(hello, body...)

	if place != nil {
		place(hello, bodyAt+extsAt+keyShareAt)
	}
	return hello
}

func TestValidateServerHelloSkipsDecoyBeforePadding(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")
	_, clientPub, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, serverPub, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientSalt, serverSalt := [32]byte{1}, [32]byte{2}
	ext, err := customtls.NewServerREALITYExtensionDataV2(secret, serverPriv, clientPub, clientSalt, serverSalt)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		place func(hello []byte, keyShareAt int)
	}{
		{"no decoy", nil},
		// Record header 5, handshake header 4, version 2: random starts at 11.
		{"decoy in random", func(hello []byte, _ int) { copy(hello[11+4:], shScanDecoy) }},
		{"decoy in key share", func(hello []byte, at int) { copy(hello[at+500:], shScanDecoy) }},
		// A decoy whose declared body runs past the real header: a scan that
		// skipped a failed candidate's body would never see the credentials.
		{"decoy body spans the padding", func(hello []byte, _ int) {
			decoyAt := 11 + 4
			bodyLen := len(hello) - (decoyAt + 4) - 100
			copy(hello[decoyAt:], []byte{0x00, 0x15, byte(bodyLen >> 8), byte(bodyLen)})
		}},
		{"two decoys", func(hello []byte, at int) {
			copy(hello[11+4:], shScanDecoy)
			copy(hello[at+shScanKeyShareLen-100:], shScanDecoy)
		}},
	}

	r := &REALITYStrategy{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := shScanServerHello(t, ext, tt.place)
			got, err := r.validateServerHello(hello, clientPub, secret)
			if err != nil {
				t.Fatalf("validateServerHello: %v", err)
			}
			if got.PubKey != serverPub || got.AuthToken != ext.AuthToken {
				t.Fatal("credentials read from the wrong place")
			}
			if _, ok := customtls.ParseServerDataV2(secret, clientPub, got.PubKey, clientSalt, got.Extra); !ok {
				t.Fatal("v2 confirmation did not survive the scan")
			}
		})
	}
}
