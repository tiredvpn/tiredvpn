package tls

import (
	"encoding/binary"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestDefaultFingerprintTracksCurrentBrowser is the guard against the failure
// this package already had once: a profile named after a browser version while
// silently pointing at whatever uTLS happened to ship. If an upstream bump ever
// moves HelloFirefox_Auto off a current release, this test is where we notice.
func TestDefaultFingerprintTracksCurrentBrowser(t *testing.T) {
	fp, ok := LookupFingerprint("")
	if !ok {
		t.Fatal("empty name did not resolve to the default profile")
	}
	if fp != FingerprintFirefoxAuto {
		t.Fatalf("default profile = %s, want the Firefox auto profile", fp.Name)
	}
	if got := fp.ClientHello.Version; got != "148" {
		t.Fatalf("HelloFirefox_Auto parrots Firefox %s; the default was chosen because "+
			"it matched shipping Firefox 148 — re-check the choice against Xray #6293 "+
			"and the live browser versions before changing this", got)
	}
}

func TestLookupFingerprintUnknownFallsBackAndReports(t *testing.T) {
	fp, ok := LookupFingerprint("netscape")
	if ok {
		t.Fatal("unknown profile reported as recognised")
	}
	if fp != FingerprintMap[DefaultFingerprintName] {
		t.Fatalf("unknown profile resolved to %s, want the default", fp.Name)
	}
}

func TestLookupFingerprintIsCaseInsensitive(t *testing.T) {
	fp, ok := LookupFingerprint("FireFox")
	if !ok || fp != FingerprintFirefoxAuto {
		t.Fatalf("case-insensitive lookup failed: fp=%v ok=%v", fp, ok)
	}
}

// TestFingerprintNamesAreResolvable keeps the help text honest: every name we
// advertise on the CLI must actually resolve.
func TestFingerprintNamesAreResolvable(t *testing.T) {
	names := FingerprintNames()
	if len(names) != len(FingerprintMap) {
		t.Fatalf("FingerprintNames returned %d names for %d entries", len(names), len(FingerprintMap))
	}
	for _, name := range names {
		if _, ok := LookupFingerprint(name); !ok {
			t.Errorf("advertised profile %q does not resolve", name)
		}
	}
	if !strings.Contains(strings.Join(names, ","), DefaultFingerprintName) {
		t.Errorf("default profile %q missing from advertised names", DefaultFingerprintName)
	}
}

// TestVersionSuffixedNamesArePinned enforces the naming rule for what is now
// operator-facing config: a name ending in a version must resolve to exactly
// that parrot, never to an _Auto alias that moves on the next uTLS bump. This
// package already shipped that bug once as FingerprintChrome124 -> Chrome 133.
func TestVersionSuffixedNamesArePinned(t *testing.T) {
	for name, fp := range FingerprintMap {
		suffix := strings.TrimLeft(name, "abcdefghijklmnopqrstuvwxyz")
		if suffix == "" {
			continue // bare browser name, tracking upstream is the contract
		}
		if got := fp.ClientHello.Version; got != suffix {
			t.Errorf("profile %q resolves to version %q; a version-suffixed name must be pinned to the version it names", name, got)
		}
	}
}

// TestBuildClientHelloCarriesPaddingForEveryProfile is the regression test for
// the default switch. REALITY hides its credentials in the padding extension
// (0x0015), and neither the Chrome 133 nor the Firefox 148 parrot emits one on
// its own — the padding comes from NewUConn. If that ever stops working for a
// profile, the handshake silently loses its auth material.
func TestBuildClientHelloCarriesPaddingForEveryProfile(t *testing.T) {
	for _, name := range FingerprintNames() {
		if name == "randomized" {
			continue // randomized specs are not stable enough to assert on
		}
		t.Run(name, func(t *testing.T) {
			fp, ok := LookupFingerprint(name)
			if !ok {
				t.Fatalf("profile %q does not resolve", name)
			}
			cfg := &Config{
				ServerName:         "github.com",
				Fingerprint:        name,
				ALPN:               []string{"h2", "http/1.1"},
				InsecureSkipVerify: true,
				PaddingLen:         MinPaddingSize,
			}
			hello, err := BuildClientHelloBytes(cfg, fp)
			if err != nil {
				t.Fatalf("BuildClientHelloBytes: %v", err)
			}
			if len(hello) < 5 || hello[0] != 0x16 {
				t.Fatalf("not a handshake record: % x", hello[:min(8, len(hello))])
			}
			recordLen := int(hello[3])<<8 | int(hello[4])
			if recordLen != len(hello)-5 {
				t.Fatalf("record length %d does not match body %d", recordLen, len(hello)-5)
			}

			exts := walkClientHelloExtensions(t, hello)
			padCount := 0
			for _, e := range exts {
				if e.typ == 0x0015 {
					padCount++
					if e.length != MinPaddingSize {
						t.Errorf("padding extension is %d bytes, want %d", e.length, MinPaddingSize)
					}
				}
			}
			if padCount != 1 {
				t.Fatalf("ClientHello carries %d padding extensions, want exactly 1", padCount)
			}
			if last := exts[len(exts)-1]; last.typ != 0x0015 {
				t.Errorf("padding is not the final extension (last is 0x%04x); "+
					"BoringSSL and NSS both emit padding last", last.typ)
			}

			ext, err := NewClientREALITYExtension([]byte("test-secret"), [32]byte{7})
			if err != nil {
				t.Fatalf("NewClientREALITYExtension: %v", err)
			}
			injected, err := InjectREALITYIntoPadding(hello, ext)
			if err != nil {
				t.Fatalf("no usable padding extension in the %s ClientHello: %v", name, err)
			}
			if len(injected) != len(hello) {
				t.Fatalf("injection changed ClientHello length %d -> %d", len(hello), len(injected))
			}
		})
	}
}

type helloExt struct {
	typ    uint16
	length int
}

// walkClientHelloExtensions parses a complete ClientHello record down to its
// extension list. It is deliberately a separate, straightforward parser rather
// than a reuse of the production byte-scanning helpers, so that a bug in those
// cannot mask itself in the tests.
func walkClientHelloExtensions(t *testing.T, record []byte) []helloExt {
	t.Helper()

	// record hdr 5 | hs type 1 + len 3 | legacy_version 2 | random 32
	off := 5 + 4 + 2 + 32
	if off >= len(record) {
		t.Fatalf("ClientHello truncated at %d bytes", len(record))
	}
	off += 1 + int(record[off]) // session id
	if off+2 > len(record) {
		t.Fatal("ClientHello truncated before cipher suites")
	}
	off += 2 + int(binary.BigEndian.Uint16(record[off:])) // cipher suites
	if off >= len(record) {
		t.Fatal("ClientHello truncated before compression methods")
	}
	off += 1 + int(record[off]) // compression methods
	if off+2 > len(record) {
		t.Fatal("ClientHello has no extensions block")
	}
	end := off + 2 + int(binary.BigEndian.Uint16(record[off:]))
	off += 2
	if end > len(record) {
		t.Fatalf("extensions block runs %d bytes past the record", end-len(record))
	}

	var exts []helloExt
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(record[off:])
		length := int(binary.BigEndian.Uint16(record[off+2:]))
		exts = append(exts, helloExt{typ: typ, length: length})
		off += 4 + length
	}
	if off != end {
		t.Fatalf("extension list ended at %d, block ends at %d", off, end)
	}
	return exts
}

// TestFirefoxProfileCarriesGREASEECH documents why the HRR gap
// (internal/strategy/reality_hrr.go) matters for the new default: the Firefox
// parrot advertises GREASE ECH, and RFC 9849 6.2.1 makes GREASE ECH and real
// ECH tell each other apart under HelloRetryRequest.
func TestFirefoxProfileCarriesGREASEECH(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(*FingerprintFirefoxAuto.ClientHello)
	if err != nil {
		t.Fatalf("UTLSIdToSpec: %v", err)
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return
		}
	}
	t.Skip("Firefox parrot no longer advertises GREASE ECH; re-check the HRR notes in reality_hrr.go")
}
