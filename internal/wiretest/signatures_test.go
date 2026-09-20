// signatures_test.go fixes the on-wire fingerprints the strategy audit has not
// reached yet. Every test here asserts that a marker IS present, because it is
// present in the code under test and the detector has to be shown finding it
// before its silence can mean anything (verification.md, rule 2).
//
// When a marker is removed, the test moves to absence_test.go and gains a
// positive control on a synthetic 1.10.0 sample - the confusion TIRED detector
// went that way when the sealed carrier landed. Inverting in place without the
// control turns "the marker is gone" into "the matcher stopped working", which
// looks identical from here.
package wiretest_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/wiretest"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The stego "TIRD" magic, the Salamander upgrade headers, and the QUIC ALPN and
// "QVPN"/"QACK" magics were fixed in the 1.11.0 audit; their detectors moved to
// absence_test.go, where each carries its own positive control.

// ---------------------------------------------------------------------------
// WebSocket Padded and Geneva: the upgrade fixture (shared with absence_test.go)
// ---------------------------------------------------------------------------

// serveWSUpgrade answers the WebSocket upgrade both strategies send. readDispatch
// covers the one-byte protocol discriminator that websocket_padded sends and
// geneva does not.
func serveWSUpgrade(t *testing.T, ln *wiretest.Listener, readDispatch bool) <-chan session {
	return serveTLS(t, ln, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if readDispatch {
			var one [1]byte
			if _, err := io.ReadFull(c, one[:]); err != nil {
				return
			}
		}
		if _, err := readHTTPHeaders(c); err != nil {
			return
		}
		_, _ = c.Write([]byte(wsUpgradeResponse))
	})
}

// ---------------------------------------------------------------------------
// REALITY: the 200-byte ClientHello grid, and the record that replaced the
// dispatch byte
// ---------------------------------------------------------------------------

// TestSignatureREALITYWireShape fixes what the REALITY handshake still shows an
// observer who decrypts nothing.
//
//   - The length of the first record the client sends after the ServerHello.
//     S5 moved the mux discriminator inside the encrypted layer, which removed
//     the lone 0x08 (see absence_test.go) and put a constant-length Application
//     Data record in its place. Rule 8 of the verification rules: a masking fix
//     has to say how it was checked for a new signature of its own. This is
//     that check, and it currently finds one - the length is single-valued.
//
// The 200-byte ClientHello grid this test used to fix landed in S10; its
// inverted form, with a positive control on a synthetic grid, is now
// TestREALITYClientHelloNotOn200Grid in absence_test.go.
//
// The server here is a reconstruction (see fakeREALITYServer) — the client is
// the shipped artifact and the bytes under test are its.
func TestSignatureREALITYWireShape(t *testing.T) {
	dumps := realityHandshakes(t, 6)

	lengths := map[int]int{}
	for i, d := range dumps {
		c2s := d.Bytes(wiretest.C2S)
		off := reassembledHelloLen(c2s)
		if len(c2s) < off+5 {
			t.Fatalf("handshake %d: only %d bytes after the ClientHello, no record header",
				i, len(c2s)-off)
		}
		if c2s[off] != 0x17 {
			t.Fatalf("handshake %d: first post-handshake record type is 0x%02x, want 0x17",
				i, c2s[off])
		}
		lengths[int(c2s[off+3])<<8|int(c2s[off+4])]++
	}
	if len(lengths) != 1 {
		t.Fatalf("first post-handshake record length is no longer single-valued: %v; "+
			"if it was given a variable size on purpose that is an improvement - "+
			"replace this with the distribution it now has", lengths)
	}
	for n := range lengths {
		t.Logf("first post-handshake record is always %d bytes over %d handshakes: "+
			"the dispatch byte is encrypted, but its record is still a constant-length one",
			n, len(dumps))
	}
}

// reassembledHelloLen returns the length of the leading TLS record in a stream,
// or -1 when the stream does not start with one or is short.
func reassembledHelloLen(b []byte) int {
	if len(b) < 5 || b[0] != 0x16 {
		return -1
	}
	n := 5 + int(b[3])<<8 + int(b[4])
	if len(b) < n {
		return -1
	}
	return n
}
