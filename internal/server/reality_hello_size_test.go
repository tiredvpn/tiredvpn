package server

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// The 256-byte boundary, explained.
//
// A second measurement found ClientHellos failing that supposedly carried no
// padding extension, with a clean cutoff: 238, 249, 253, 255 answered; 257,
// 259, 263, 279, 361 did not. A round number like that looks like a fixed
// buffer or a length check, and it is neither.
//
// BoringSSL and OpenSSL add the padding extension to any ClientHello that would
// otherwise land between 256 and 511 bytes - a workaround for an old F5 bug.
// Below 256 they add nothing, so there is no extension and the hello was
// answered. At 256 and above the extension appears, and the old code dropped
// the connection. The boundary is not ours: it is the threshold at which TLS
// stacks start adding the extension.
//
// The same trap is why some uTLS profiles appear to fail "without padding":
// the Edge 85 and iOS 14 parrots carry a BoringPaddingStyle padding extension
// in the spec itself, so they send one whether or not the caller asks for it.

// helloNoPadding builds a ClientHello of exactly total bytes carrying no
// padding extension, growing the SNI to reach the size.
func helloNoPadding(t *testing.T, total int) []byte {
	t.Helper()

	build := func(sni string) []byte {
		var exts []byte
		name := []byte(sni)
		sniBody := []byte{0x00}
		sniBody = binary.BigEndian.AppendUint16(sniBody, uint16(len(name)))
		sniBody = append(sniBody, name...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(sniBody)))
		list = append(list, sniBody...)
		exts = binary.BigEndian.AppendUint16(exts, 0x0000)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(list)))
		exts = append(exts, list...)

		sv := []byte{0x02, 0x03, 0x04}
		exts = binary.BigEndian.AppendUint16(exts, 0x002b)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(sv)))
		exts = append(exts, sv...)

		b := []byte{0x03, 0x03}
		b = append(b, bytes.Repeat([]byte{0x42}, 32)...)
		b = append(b, 32)
		b = append(b, bytes.Repeat([]byte{0x43}, 32)...)
		b = binary.BigEndian.AppendUint16(b, 2)
		b = binary.BigEndian.AppendUint16(b, 0x1301)
		b = append(b, 1, 0)
		b = binary.BigEndian.AppendUint16(b, uint16(len(exts)))
		b = append(b, exts...)

		hs := append([]byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
		return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	}

	need := 1
	h := build("a")
	for len(h) < total {
		need++
		h = build("a" + strings.Repeat("x", need-1))
	}
	if len(h) != total {
		t.Skipf("cannot hit %d bytes exactly with SNI padding (nearest %d)", total, len(h))
	}
	return h
}

// TestNoPaddingExtensionAnswersAtEverySize sweeps the boundary the second
// measurement pointed at, with hellos that genuinely carry no padding
// extension. All of them answer - which is what shows the boundary belongs to
// the extension and not to the length.
func TestNoPaddingExtensionAnswersAtEverySize(t *testing.T) {
	srvCtx := b1PaddingCtx(t, true, true)

	for _, size := range []int{200, 238, 249, 253, 255, 256, 257, 259, 263, 279, 361, 495, 512, 700, 1012, 1500} {
		hello := helloNoPadding(t, size)
		if answered, _ := answersClientHello(t, srvCtx, hello); !answered {
			t.Errorf("CH %d bytes without a padding extension got no answer", size)
		}
	}
}

// TestRealClientHellosGetServerHello is the strongest form of the check: the
// ClientHellos uTLS actually produces, not synthetic ones. A synthetic hello
// with no key share can only ever earn an alert, which proves "not silent" but
// not "the handshake completes". These get a real ServerHello.
//
// Run against the code before the fix, edge and ios fail here even with
// paddingLen 0, because their parrots carry a padding extension of their own -
// which is exactly the confusion that made the boundary look like a length
// problem.
func TestRealClientHellosGetServerHello(t *testing.T) {
	srvCtx := b1PaddingCtx(t, true, true)

	for _, profile := range []string{"edge", "ios", "chrome120", "firefox120", "safari", "chrome", "firefox"} {
		fp, ok := customtls.LookupFingerprint(profile)
		if !ok {
			t.Fatalf("profile %q does not resolve", profile)
		}
		for _, pad := range []int{0, customtls.MinPaddingSize} {
			hello, err := customtls.BuildClientHelloBytes(&customtls.Config{
				ServerName:         "www.microsoft.com",
				Fingerprint:        profile,
				ALPN:               []string{"h2", "http/1.1"},
				InsecureSkipVerify: true,
				PaddingLen:         pad,
			}, fp)
			if err != nil {
				t.Fatalf("%s: %v", profile, err)
			}
			answered, first := answersClientHello(t, srvCtx, hello)
			if !answered {
				t.Errorf("%s (paddingLen %d, CH %d bytes): no answer", profile, pad, len(hello))
				continue
			}
			if first[0] != 0x16 {
				t.Errorf("%s (paddingLen %d, CH %d bytes): answered %#x, want a ServerHello",
					profile, pad, len(hello), first[0])
			}
		}
	}
}
