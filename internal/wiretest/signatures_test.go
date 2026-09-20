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
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
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
//   - The 200-byte ClientHello grid. reality.go splits the first flight mid-SNI
//     and then emits fixed 200-byte chunks, so the segment boundaries sit on a
//     regular pitch no browser produces. S10 has not landed, so this is still a
//     positive control.
//   - The length of the first record the client sends after the ServerHello.
//     S5 moved the mux discriminator inside the encrypted layer, which removed
//     the lone 0x08 (see absence_test.go) and put a constant-length Application
//     Data record in its place. Rule 8 of the verification rules: a masking fix
//     has to say how it was checked for a new signature of its own. This is
//     that check, and it currently finds one - the length is single-valued.
//
// The server here is a reconstruction (see fakeREALITYServer) — the client is
// the shipped artifact and the bytes under test are its.
func TestSignatureREALITYWireShape(t *testing.T) {
	dumps := realityHandshakes(t, 6)

	var grid wiretest.Finding
	gotGrid := false
	for _, d := range dumps {
		if f, ok := wiretest.Grid(d, wiretest.C2S, 200, 3); ok {
			grid, gotGrid = f, true
			break
		}
	}
	if !gotGrid {
		t.Fatalf("expected the ClientHello to be written on a 200-byte grid in %d handshakes; "+
			"if the fragment size was randomised on purpose, invert this assertion", len(dumps))
	}
	t.Logf("200-byte ClientHello grid found at %s", grid)

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

// ---------------------------------------------------------------------------
// Anti-Probe: the knock sequence repeats byte for byte
// ---------------------------------------------------------------------------

// TestSignatureAntiProbeKnockDeterministic fixes the fact that the anti-probe
// knock is a pure function of the key.
//
// generateKnockSequence derives five packet sizes and five delays from
// HMAC(secret, "knock-sequence"), and fillPacketData derives the packet bodies
// from the same key. Nothing per-connection enters any of it, so two sessions
// of one client produce identical sizes, identical delays and identical bytes.
// A censor does not need to break the TLS wrapper to link them — sizes and
// timing survive encryption, and here they repeat exactly.
//
// This is the "distribution has a shape" failure from verification.md rule 3 in
// its purest form: the shape is a single point.
func TestSignatureAntiProbeKnockDeterministic(t *testing.T) {
	ln := wiretest.Listen(t, "antiprobe", wiretest.LayerTCP)
	sessions := serveTLS(t, ln, func(c net.Conn) {
		var one [1]byte
		if _, err := io.ReadFull(c, one[:]); err != nil {
			return
		}
		// Drain knock packets until the client goes quiet, then acknowledge.
		// The packets are 50-200 ms apart, so each read returns exactly one.
		buf := make([]byte, 4096)
		for {
			_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte{0x01})
	})

	m := managerAt(t, ln.Addr())
	s := strategy.NewAntiProbeStrategy(m, testSecret)

	var got []session
	for i := 0; i < 2; i++ {
		go func() {
			conn, err := s.Connect(testCtx(t), "wiretest")
			if err == nil {
				conn.Close()
			}
		}()
		select {
		case sess := <-sessions:
			got = append(got, sess)
		case <-time.After(20 * time.Second):
			t.Fatalf("knock %d never completed", i)
		}
	}

	a, b := got[0].Plain, got[1].Plain

	// Six chunks: the dispatch byte plus five knock packets.
	if n := len(a.Sizes(wiretest.C2S)); n != 6 {
		t.Fatalf("expected 6 client chunks (dispatch + 5 knock packets), got %d: %v",
			n, a.Sizes(wiretest.C2S))
	}

	f, ok := wiretest.SameSizes(a, b, wiretest.C2S, 1)
	if !ok {
		t.Fatalf("expected identical knock packet sizes across two connections (%v vs %v); "+
			"if the sizes were randomised on purpose, invert this assertion",
			a.Sizes(wiretest.C2S), b.Sizes(wiretest.C2S))
	}
	t.Logf("knock sizes repeat: %s", f)

	f, ok = wiretest.SameStream(a, b, wiretest.C2S, a.Len(wiretest.C2S))
	if !ok {
		t.Fatal("expected byte-identical knock payloads across two connections; " +
			"if the payload was randomised on purpose, invert this assertion")
	}
	t.Logf("knock payload repeats: %s", f)

	f, ok = wiretest.SameGaps(a, b, wiretest.C2S, 0, 60*time.Millisecond)
	if !ok {
		t.Fatalf("expected the knock delays to repeat within 60ms (%v vs %v); "+
			"if the timing was randomised on purpose, invert this assertion",
			a.Gaps(wiretest.C2S), b.Gaps(wiretest.C2S))
	}
	t.Logf("knock delays repeat: %s", f)

	// The sharper statement, and the one that does not need a second
	// connection: anyone holding the key computes the sizes and the delays in
	// advance. Sizes are checked exactly — they cannot drift under load. Delays
	// get a one-sided allowance, because a Sleep on a busy runner overshoots and
	// never undershoots.
	wantSizes, wantDelays := predictKnock(testSecret)
	gotSizes := a.Sizes(wiretest.C2S)[1:]
	for i := range wantSizes {
		if gotSizes[i] != wantSizes[i] {
			t.Fatalf("knock packet %d is %d bytes, predicted %d from the key alone; "+
				"if the sizes stopped being key-derived, invert this assertion",
				i, gotSizes[i], wantSizes[i])
		}
	}
	gotDelays := a.Gaps(wiretest.C2S)
	for i := range wantDelays {
		if d := gotDelays[i] - wantDelays[i]; d < -5*time.Millisecond || d > 60*time.Millisecond {
			t.Fatalf("knock delay %d is %v, predicted %v from the key alone; "+
				"if the timing stopped being key-derived, invert this assertion",
				i, gotDelays[i], wantDelays[i])
		}
	}
	t.Logf("knock is predictable from the key: sizes %v, delays %v", wantSizes, wantDelays)
}

// predictKnock recomputes the knock schedule the way a censor holding the key
// would: HMAC-SHA256 over the constant string, five sizes and five delays
// straight out of the digest.
//
// Restating the derivation instead of calling into the strategy is the point.
// The claim under test is "an observer who knows the key predicts the traffic",
// and an observer does not get to call generateKnockSequence.
func predictKnock(secret []byte) ([]int, []time.Duration) {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("knock-sequence"))
	sum := h.Sum(nil)

	sizes := make([]int, 5)
	delays := make([]time.Duration, 5)
	for i := range sizes {
		delays[i] = time.Duration(50+int(sum[i])%150) * time.Millisecond
		sizes[i] = 10 + int(sum[i+5])%90
	}
	return sizes, delays
}
