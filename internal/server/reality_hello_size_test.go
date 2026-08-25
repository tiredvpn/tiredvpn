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
	requireNoCoverDomain(t, srvCtx)

	// A stepped range, not a handful of points. Three points misled this
	// investigation twice: once into a length hypothesis, once into a second
	// failure point that does not exist.
	for size := 200; size <= 2000; size += 7 {
		hello := helloNoPadding(t, size)
		if answered, _ := answersClientHello(t, srvCtx, hello); !answered {
			t.Fatalf("CH %d bytes without a padding extension got no answer", size)
		}
	}
}

// requireNoCoverDomain is the acceptance criterion that keeps this suite honest.
//
// The defect only exists when REALITYCoverDomain is unset: with a cover domain
// the server proxies unauthenticated hellos to a donor and everything looks
// fine. Every test that configures one would pass over a broken server, which
// is precisely why the defect survived - it lived only in the configuration
// production runs and tests do not.
func requireNoCoverDomain(t *testing.T, srvCtx *serverContext) {
	t.Helper()
	if srvCtx.cfg.REALITYCoverDomain != "" {
		t.Fatalf("this test must run without a cover domain, got %q: with one set it "+
			"cannot observe the behaviour it exists to check", srvCtx.cfg.REALITYCoverDomain)
	}
}

// TestPaddingLengthDecidesRouting pins the single condition that explains the
// whole picture: DetectREALITYExtension routes a ClientHello into the REALITY
// handler when its padding extension is at least REALITYExtensionLength bytes,
// and not otherwise. The cutoff is on the padding, not on the hello.
//
// Measured against the pre-fix code, padding of 63 bytes passed and 64 bytes
// was dropped, at hello sizes from 121 to 521 - which is what rules the length
// hypothesis out rather than merely arguing against it.
func TestPaddingLengthDecidesRouting(t *testing.T) {
	srvCtx := b1PaddingCtx(t, true, true)
	requireNoCoverDomain(t, srvCtx)

	for padLen := 0; padLen <= 300; padLen++ {
		hello := helloWithPaddingLen(t, "www.microsoft.com", padLen)

		detected := DetectREALITYExtension(hello)
		wantDetected := padLen >= customtls.REALITYExtensionLength
		if detected != wantDetected {
			t.Fatalf("padLen %d: DetectREALITYExtension = %v, want %v", padLen, detected, wantDetected)
		}

		// Routed or not, the answer must be the same: something comes back.
		if answered, _ := answersClientHello(t, srvCtx, hello); !answered {
			t.Fatalf("padLen %d (CH %d bytes): no answer", padLen, len(hello))
		}
	}
}

// helloWithPaddingLen builds a ClientHello with a padding extension of exactly
// padLen bytes.
func helloWithPaddingLen(t *testing.T, sni string, padLen int) []byte {
	t.Helper()

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

	exts = binary.BigEndian.AppendUint16(exts, 0x0015)
	exts = binary.BigEndian.AppendUint16(exts, uint16(padLen))
	exts = append(exts, make([]byte, padLen)...)

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
	requireNoCoverDomain(t, srvCtx)

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
