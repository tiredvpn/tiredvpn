package tls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// A byte scan for the padding extension type cannot tell a real extension from
// the same two bytes occurring inside another extension's data. That was
// harmless while uTLS silently discarded our padding extension, because the
// scan then never found anything and the caller fell back to appending one by
// hand. Once the padding became real, the bug became live: a post-quantum
// key_share carries over a kilobyte of effectively random bytes, it sits before
// the padding (which is appended last), so a false match beats the real thing.
//
// These tests plant the collision on purpose instead of waiting for chance.

// buildHelloWithDecoyPadding assembles a full ClientHello record whose key_share
// contains a decoy 0x0015 with a plausible length, followed by a genuine padding
// extension. decoyBody is what the decoy claims to hold, so a scan-based
// implementation writes REALITY credentials into the key share.
func buildHelloWithDecoyPadding(t *testing.T, decoyPayloadLen, realPaddingLen int) []byte {
	t.Helper()

	// The key share value: [.. 00 15 <len> <len> ...] with enough bytes after
	// the fake header that a naive scan accepts it.
	keyShareValue := make([]byte, 0, 8+decoyPayloadLen)
	keyShareValue = append(keyShareValue, 0xAB, 0xCD)
	keyShareValue = binary.BigEndian.AppendUint16(keyShareValue, extensionPadding)
	keyShareValue = binary.BigEndian.AppendUint16(keyShareValue, uint16(decoyPayloadLen))
	keyShareValue = append(keyShareValue, bytes.Repeat([]byte{0xEE}, decoyPayloadLen)...)

	shares := binary.BigEndian.AppendUint16(nil, groupX25519MLKEM768)
	shares = binary.BigEndian.AppendUint16(shares, uint16(len(keyShareValue)))
	shares = append(shares, keyShareValue...)

	keyShareBody := binary.BigEndian.AppendUint16(nil, uint16(len(shares)))
	keyShareBody = append(keyShareBody, shares...)

	var exts []byte
	exts = binary.BigEndian.AppendUint16(exts, extensionKeyShare)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(keyShareBody)))
	exts = append(exts, keyShareBody...)

	// The genuine padding extension, last, as uTLS emits it.
	exts = binary.BigEndian.AppendUint16(exts, extensionPadding)
	exts = binary.BigEndian.AppendUint16(exts, uint16(realPaddingLen))
	exts = append(exts, make([]byte, realPaddingLen)...)

	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x11}, helloRandomLen)...)
	body = append(body, AuthSessionIDLen)
	body = append(body, bytes.Repeat([]byte{0x22}, AuthSessionIDLen)...)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hello := []byte{handshakeTypeHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hello = append(hello, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}
	return append(record, hello...)
}

// realPaddingOffset returns where the genuine padding extension body starts,
// computed independently of the code under test.
func realPaddingOffset(t *testing.T, record []byte, realPaddingLen int) int {
	t.Helper()
	// The genuine padding is the last extension, so its body is the final
	// realPaddingLen bytes of the record.
	return len(record) - realPaddingLen
}

func TestInjectREALITYIgnoresDecoyPaddingInKeyShare(t *testing.T) {
	const realPaddingLen = MinPaddingSize

	// The decoy is large enough to satisfy a scan that only checks
	// extLen >= REALITYExtensionLength.
	for _, decoyLen := range []int{REALITYExtensionLength, REALITYExtensionLength + 32, 200} {
		t.Run("", func(t *testing.T) {
			record := buildHelloWithDecoyPadding(t, decoyLen, realPaddingLen)
			before := bytes.Clone(record)

			ext, err := NewClientREALITYExtension([]byte("test-secret"), [32]byte{9})
			if err != nil {
				t.Fatalf("NewClientREALITYExtension: %v", err)
			}
			out, err := InjectREALITYIntoPadding(record, ext)
			if err != nil {
				t.Fatalf("InjectREALITYIntoPadding: %v", err)
			}
			if len(out) != len(record) {
				t.Fatalf("injection changed the record length %d -> %d", len(record), len(out))
			}

			// The credentials must land in the genuine padding.
			padStart := realPaddingOffset(t, out, realPaddingLen)
			want := ext.Marshal()
			if !bytes.Equal(out[padStart:padStart+REALITYExtensionLength], want) {
				t.Fatal("REALITY data did not land in the real padding extension; " +
					"the decoy inside key_share won")
			}

			// And the key share must come back untouched. Everything before the
			// genuine padding body is unchanged.
			if !bytes.Equal(out[:padStart], before[:padStart]) {
				t.Fatal("injection wrote outside the padding extension; the key share was corrupted")
			}

			// The server side must recover exactly what we injected.
			got, err := ExtractREALITYFromPadding(out[padStart : padStart+realPaddingLen])
			if err != nil {
				t.Fatalf("ExtractREALITYFromPadding: %v", err)
			}
			if got.PubKey != ext.PubKey || got.AuthToken != ext.AuthToken {
				t.Fatal("round trip through the padding lost the credentials")
			}
		})
	}
}

// TestAddPaddingWithREALITYIgnoresDecoy covers the sibling function, whose scan
// was looser still — it did not even require the match to be long enough, so a
// two-byte collision anywhere would send it into replacePaddingExtension and
// corrupt the message.
func TestAddPaddingWithREALITYIgnoresDecoy(t *testing.T) {
	record := buildHelloWithDecoyPadding(t, 8, MinPaddingSize)

	ext, err := NewClientREALITYExtension([]byte("test-secret"), [32]byte{9})
	if err != nil {
		t.Fatalf("NewClientREALITYExtension: %v", err)
	}
	out, err := AddPaddingWithREALITY(record, ext, MinPaddingSize)
	if err != nil {
		t.Fatalf("AddPaddingWithREALITY: %v", err)
	}

	// The genuine padding was replaced in place, so the size must not change.
	if len(out) != len(record) {
		t.Fatalf("record length changed %d -> %d; the decoy was replaced instead of the real padding",
			len(record), len(out))
	}
	assertRecordLengthsConsistent(t, out)

	offset, bodyLen, err := findPaddingExtension(out)
	if err != nil {
		t.Fatalf("findPaddingExtension on the result: %v", err)
	}
	if bodyLen != MinPaddingSize {
		t.Fatalf("padding body is %d bytes, want %d", bodyLen, MinPaddingSize)
	}
	got, err := ExtractREALITYFromPadding(out[offset+4 : offset+4+bodyLen])
	if err != nil {
		t.Fatalf("ExtractREALITYFromPadding: %v", err)
	}
	if got.PubKey != ext.PubKey {
		t.Fatal("credentials did not survive AddPaddingWithREALITY")
	}
}

// TestAddPaddingWithREALITYAppendsWhenAbsent is the other branch: no padding
// extension at all, so one is appended and every length field must be fixed up.
func TestAddPaddingWithREALITYAppendsWhenAbsent(t *testing.T) {
	// A hello with only a key_share, no padding.
	inner := buildTestHello(t, []testShare{{groupX25519, make([]byte, 32)}}, AuthSessionIDLen)
	record := append([]byte{0x16, 0x03, 0x01, byte(len(inner) >> 8), byte(len(inner))}, inner...)

	ext, err := NewClientREALITYExtension([]byte("test-secret"), [32]byte{9})
	if err != nil {
		t.Fatalf("NewClientREALITYExtension: %v", err)
	}
	out, err := AddPaddingWithREALITY(record, ext, MinPaddingSize)
	if err != nil {
		t.Fatalf("AddPaddingWithREALITY: %v", err)
	}
	if len(out) != len(record)+4+MinPaddingSize {
		t.Fatalf("appended %d bytes, want %d", len(out)-len(record), 4+MinPaddingSize)
	}
	assertRecordLengthsConsistent(t, out)

	offset, bodyLen, err := findPaddingExtension(out)
	if err != nil {
		t.Fatalf("findPaddingExtension: %v", err)
	}
	got, err := ExtractREALITYFromPadding(out[offset+4 : offset+4+bodyLen])
	if err != nil {
		t.Fatalf("ExtractREALITYFromPadding: %v", err)
	}
	if got.AuthToken != ext.AuthToken {
		t.Fatal("credentials did not survive the append path")
	}
}

func TestInjectREALITYRejectsMissingPadding(t *testing.T) {
	inner := buildTestHello(t, []testShare{{groupX25519, make([]byte, 32)}}, AuthSessionIDLen)
	record := append([]byte{0x16, 0x03, 0x01, byte(len(inner) >> 8), byte(len(inner))}, inner...)

	ext, err := NewClientREALITYExtension([]byte("test-secret"), [32]byte{9})
	if err != nil {
		t.Fatalf("NewClientREALITYExtension: %v", err)
	}
	if _, err := InjectREALITYIntoPadding(record, ext); err == nil {
		t.Fatal("injected into a ClientHello that has no padding extension")
	}
}

// TestInjectREALITYOnRealClientHellos is the end of the chain: build the
// ClientHello the production path builds, inject, then read the credentials
// back the way the server does.
func TestInjectREALITYOnRealClientHellos(t *testing.T) {
	for _, name := range []string{"firefox", "chrome", "safari", "chrome120"} {
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
				PaddingLen:         MinPaddingSize,
			}, fp)
			if err != nil {
				t.Fatalf("BuildClientHelloBytes: %v", err)
			}

			ext, err := NewClientREALITYExtension([]byte("test-secret"), [32]byte{9})
			if err != nil {
				t.Fatalf("NewClientREALITYExtension: %v", err)
			}
			out, err := InjectREALITYIntoPadding(record, ext)
			if err != nil {
				t.Fatalf("InjectREALITYIntoPadding: %v", err)
			}
			assertRecordLengthsConsistent(t, out)

			offset, bodyLen, err := findPaddingExtension(out)
			if err != nil {
				t.Fatalf("findPaddingExtension: %v", err)
			}
			got, err := ExtractREALITYFromPadding(out[offset+4 : offset+4+bodyLen])
			if err != nil {
				t.Fatalf("ExtractREALITYFromPadding: %v", err)
			}
			if got.PubKey != ext.PubKey || got.AuthToken != ext.AuthToken {
				t.Fatalf("credentials did not survive a real %s ClientHello", name)
			}
		})
	}
}

// assertRecordLengthsConsistent checks that the record header, the handshake
// header and the extensions block all agree with the actual byte count. A
// mismatch here is what a corrupted splice looks like on the wire.
func assertRecordLengthsConsistent(t *testing.T, record []byte) {
	t.Helper()

	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen != len(record)-5 {
		t.Fatalf("record length %d does not match the %d bytes present", recordLen, len(record)-5)
	}
	hello := record[5:]
	hsLen := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
	if hsLen != len(hello)-4 {
		t.Fatalf("handshake length %d does not match the %d bytes present", hsLen, len(hello)-4)
	}
	// helloExtensionsAt re-derives the extensions bounds and errors if the
	// declared length runs past the buffer.
	if _, _, err := helloExtensionsAt(hello); err != nil {
		t.Fatalf("extensions block is inconsistent: %v", err)
	}
}
