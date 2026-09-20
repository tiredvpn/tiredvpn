// absence_test.go holds the detectors whose subject has been fixed, so the
// assertion now reads "this marker is NOT on the wire".
//
// An absence assertion is worth nothing on its own: a matcher that has quietly
// stopped working produces exactly the same green. So every test here carries
// its own positive control, in the same run, against the same matcher — a
// synthetic dump built to the 1.10.0 wire format, which the matcher must still
// find. The shape is always:
//
//  1. legacy sample → matcher fires (the instrument works)
//  2. live bytes from the current client → matcher silent (the marker is gone)
//  3. the live capture is non-trivial (we were looking at something)
//
// Drop step 1 or step 3 and the test degenerates into "nothing was measured".
package wiretest_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/wiretest"
)

// ---------------------------------------------------------------------------
// Protocol Confusion
// ---------------------------------------------------------------------------

// legacyConfusionDNSPreamble rebuilds the 1.10.0 DNS confusion first packet:
// a DNS-over-TCP query with "\x00\x00TIRED", a 4-byte length and the user's
// bytes appended verbatim after the question section.
//
// Copied from buildDNSConfusion as it stood on origin/main before
// "fix(confusion): require proof of the secret before relay, seal the payload".
// It exists to feed the matcher something it is known to match; it is not a
// reimplementation anything depends on.
func legacyConfusionDNSPreamble(payload []byte) []byte {
	var dns bytes.Buffer
	dns.Write([]byte{0x2f, 0xa1})                                     // transaction id
	dns.Write([]byte{0x01, 0x00})                                     // standard query
	dns.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // counts
	dns.Write([]byte{6, 'y', 'a', 'n', 'd', 'e', 'x', 2, 'r', 'u', 0})
	dns.Write([]byte{0x00, 0x01, 0x00, 0x01})                   // type A, class IN
	dns.Write([]byte{0x00, 0x00, 0x54, 0x49, 0x52, 0x45, 0x44}) // \0\0TIRED
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(payload)))
	dns.Write(l[:])
	dns.Write(payload)

	msg := dns.Bytes()
	out := make([]byte, 0, 2+len(msg))
	out = append(out, byte(len(msg)>>8), byte(len(msg)))
	return append(out, msg...)
}

// confusionCanary is payload a detector can look for unambiguously. Nothing
// derives it, so a hit means the plaintext itself reached the socket.
const confusionCanary = "CANARY-confusion-plaintext-9d3f41"

// TestConfusionCarriesNoTIREDMarkerOrPlaintext is the inverted form of the
// 1.10.0 fixation.
//
// Before: the first packet carried the ASCII literal TIRED at a near-fixed
// offset and the user's bytes after it, on a raw socket. Both are gone — the
// marker is now a variable-length HKDF output over (secret, nonce, variant) and
// the payload is sealed with ChaCha20-Poly1305 before it enters the carrier.
//
// The positive control is the 1.10.0 packet layout, which the same two matchers
// must still find in this run.
func TestConfusionCarriesNoTIREDMarkerOrPlaintext(t *testing.T) {
	legacy := wiretest.NewDump("confusion-1.10.0", wiretest.LayerTCP)
	legacy.Record(wiretest.C2S, legacyConfusionDNSPreamble([]byte(confusionCanary)))

	f, ok := wiretest.LiteralWithin(legacy, wiretest.C2S, "TIRED", 256)
	if !ok {
		t.Fatal("control: the TIRED matcher does not fire on the 1.10.0 preamble, " +
			"so its silence below would mean nothing")
	}
	t.Logf("control: TIRED still matched on the 1.10.0 sample at %s", f)

	if _, ok := wiretest.Literal(legacy, wiretest.C2S, confusionCanary); !ok {
		t.Fatal("control: the plaintext matcher does not fire on the 1.10.0 preamble")
	}

	live := driveConfusion(t, strategy.ConfusionDNSoverTLS, [][]byte{
		[]byte(confusionCanary),
		[]byte(confusionCanary + "-second-frame"),
	})

	if n := live.Len(wiretest.C2S); n < 64 {
		t.Fatalf("only %d client bytes captured: nothing was measured, so 'no marker' is vacuous", n)
	}
	if f, ok := wiretest.Literal(live, wiretest.C2S, "TIRED"); ok {
		t.Fatalf("the TIRED marker is back on the confusion wire at %s", f)
	}
	if f, ok := wiretest.Literal(live, wiretest.C2S, confusionCanary); ok {
		t.Fatalf("user plaintext reached the confusion wire at %s", f)
	}
	t.Logf("%d client bytes carried neither the marker nor the payload", live.Len(wiretest.C2S))
}

// driveConfusion runs one confusion connection against a draining socket and
// returns the capture. The server end never answers: every byte under test is
// written before the client waits for anything.
func driveConfusion(t *testing.T, variant strategy.ConfusionType, writes [][]byte) *wiretest.Dump {
	t.Helper()
	ln := wiretest.Listen(t, "confusion", wiretest.LayerTCP)
	drained := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		for {
			_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			if _, err := c.Read(buf); err != nil {
				close(drained)
				return
			}
		}
	}()

	m := managerAt(t, ln.Addr())
	s := strategy.NewProtocolConfusionStrategy(m, variant, testSecret)
	conn, err := s.Connect(testCtx(t), "wiretest")
	if err != nil {
		t.Fatalf("confusion connect: %v", err)
	}
	defer conn.Close()

	for _, w := range writes {
		if _, err := conn.Write(w); err != nil {
			t.Fatalf("confusion write: %v", err)
		}
	}

	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("confusion fixture never went idle")
	}
	return ln.First()
}

// TestConfusionMarkerLengthSpansItsRange records what the new marker length
// actually looks like over many connections.
//
// The code documents the marker as flat over [16,48) and says outright that
// there is no measured population to check that shape against. That leaves the
// next audit with nothing to compare to, which is what this fixes: the
// distribution the implementation produces is measured here, so a later change
// that narrows or pins it is visible as a diff rather than as an opinion.
//
// It also records the part an observer gets for free. The length is not a field
// on the wire, but the carrier's body is nonce + marker + one sealed frame, and
// the sealed frame is a fixed size for a fixed payload. So body length minus a
// constant IS the marker length, and this test pins that the constant really is
// constant — i.e. the length leaks by subtraction the moment payload size is
// known or guessed.
func TestConfusionMarkerLengthSpansItsRange(t *testing.T) {
	const conns = 30
	payload := bytes.Repeat([]byte{0x5a}, 96)

	seen := map[int]int{}
	var sealedLen = -1

	for i := 0; i < conns; i++ {
		d := driveConfusion(t, strategy.ConfusionDNSoverTLS, [][]byte{payload})
		carrier, err := strategy.ParseConfusionRequest(d.Bytes(wiretest.C2S))
		if err != nil {
			t.Fatalf("connection %d: parsing the carrier: %v", i, err)
		}
		n, ok := strategy.MatchConfusionClientMarker(testSecret, carrier.Nonce, carrier.Variant, carrier.Body)
		if !ok {
			t.Fatalf("connection %d: the client marker did not verify against the secret", i)
		}
		seen[n]++

		if sealedLen < 0 {
			sealedLen = len(carrier.Body) - n
		} else if got := len(carrier.Body) - n; got != sealedLen {
			t.Fatalf("connection %d: sealed frame is %d bytes, every other one was %d; "+
				"the body-length readout of the marker length is no longer exact", i, got, sealedLen)
		}
	}

	lo, hi := 1<<30, -1
	for n := range seen {
		if n < 16 || n >= 48 {
			t.Fatalf("marker length %d is outside the documented [16,48)", n)
		}
		lo, hi = min(lo, n), max(hi, n)
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct marker lengths over %d connections (%v); "+
			"a length this concentrated is a fingerprint, not a range", len(seen), conns, seen)
	}

	t.Logf("marker length over %d connections: %d distinct values, observed range [%d,%d], histogram %v",
		conns, len(seen), lo, hi, seen)
	t.Logf("carrier body is marker + %d bytes of sealed frame for a %d-byte payload, "+
		"so the body length reads the marker length off directly", sealedLen, len(payload))
}

// ---------------------------------------------------------------------------
// IMAP Camouflage
// ---------------------------------------------------------------------------

const imapCanary = "CANARY-imap-plaintext-71b0ac"

// legacyIMAPUsername is the 1.10.0 login local part: hex of the first four
// bytes of the shared secret, at a fixed place in a cleartext LOGIN line.
func legacyIMAPUsername(secret []byte) string {
	n := min(4, len(secret))
	return hex.EncodeToString(secret[:n]) + "@icloud.com"
}

// legacyIMAPSession rebuilds the 1.10.0 client side: greeting, CAPABILITY, a
// cleartext LOGIN carrying the secret-derived address and a time-bucketed
// token, then an APPEND literal with the user's bytes in the clear. Taken from
// performIMAPClientHandshake and IMAPCamouflageConn.Write as they stood on
// origin/main before the STARTTLS work.
func legacyIMAPSession(secret []byte, payload []byte) []byte {
	h := hmac.New(sha256.New, secret)
	var bucket [8]byte
	binary.BigEndian.PutUint64(bucket[:], uint64(time.Now().Unix()/30))
	h.Write([]byte("imap-auth"))
	h.Write(bucket[:])
	token := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var b bytes.Buffer
	b.WriteString(strategy.IMAPGreeting)
	b.WriteString("A001 CAPABILITY\r\n")
	fmt.Fprintf(&b, "A002 LOGIN %s %s\r\n", legacyIMAPUsername(secret), token)
	b.WriteString("A003 SELECT INBOX\r\n")
	fmt.Fprintf(&b, "A001 APPEND INBOX (\\Seen) {%d}\r\n", len(payload))
	b.Write(payload)
	b.WriteString("\r\n")
	return b.Bytes()
}

// TestIMAPCarriesNoSecretPrefixOrPlaintext is the inverted form of the two IMAP
// leaks.
//
// Before: the login address was hex(secret[:4])@icloud.com, sent in the clear,
// so four bytes of the shared secret were readable off any capture and two
// sessions of one client were trivially linkable by it. The tunnel payload was
// on the bare socket as well. Now the whole exchange after STARTTLS is inside
// TLS and the local part is keyed by the server's per-session challenge.
//
// Positive control: the 1.10.0 session layout, which the same matchers find.
func TestIMAPCarriesNoSecretPrefixOrPlaintext(t *testing.T) {
	legacy := wiretest.NewDump("imap-1.10.0", wiretest.LayerTCP)
	legacy.Record(wiretest.C2S, legacyIMAPSession(testSecret, []byte(imapCanary)))

	user := legacyIMAPUsername(testSecret)
	f, ok := wiretest.Literal(legacy, wiretest.C2S, user)
	if !ok {
		t.Fatalf("control: the matcher does not find %q in the 1.10.0 session, "+
			"so its silence below would mean nothing", user)
	}
	t.Logf("control: the secret-derived address still matched at %s", f)

	if _, ok := wiretest.Literal(legacy, wiretest.C2S, imapCanary); !ok {
		t.Fatal("control: the plaintext matcher does not fire on the 1.10.0 session")
	}

	live := driveIMAP(t, [][]byte{[]byte(imapCanary)})

	if n := live.Len(wiretest.C2S); n < 512 {
		t.Fatalf("only %d client bytes captured: nothing was measured", n)
	}
	if f, ok := wiretest.Literal(live, wiretest.C2S, user); ok {
		t.Fatalf("the secret-derived login address is back on the IMAP wire at %s", f)
	}
	if f, ok := wiretest.Literal(live, wiretest.C2S, hex.EncodeToString(testSecret[:4])); ok {
		t.Fatalf("the first four bytes of the secret are readable on the IMAP wire at %s", f)
	}
	if f, ok := wiretest.Literal(live, wiretest.C2S, imapCanary); ok {
		t.Fatalf("user plaintext reached the IMAP wire at %s", f)
	}

	// Layer control. AUTH=CRAM-MD5 is only ever sent inside the TLS session, so
	// finding it on the socket would mean the fixture never upgraded and every
	// absence above is an artefact of an empty TLS phase.
	if _, ok := wiretest.Literal(live, wiretest.S2C, "AUTH=CRAM-MD5"); ok {
		t.Fatal("the post-STARTTLS capability line is readable on the socket — " +
			"the fixture is not encrypting, so the absences above prove nothing")
	}
	t.Logf("%d client bytes carried neither the secret nor the payload", live.Len(wiretest.C2S))
}

// TestIMAPCleartextPrologueIsExactlyThreeLines fixes what the STARTTLS design
// deliberately leaves in the clear.
//
// A real IMAP session on port 143 opens in cleartext and upgrades; hiding that
// would make us the odd one out. So the greeting, one CAPABILITY and the
// STARTTLS command are meant to be readable, and this test says so in the code
// rather than leaving it as an unwritten intention. It also pins the boundary:
// the byte right after the STARTTLS command is the start of a TLS handshake
// record, so nothing else slipped into the clear.
func TestIMAPCleartextPrologueIsExactlyThreeLines(t *testing.T) {
	live := driveIMAP(t, [][]byte{[]byte("payload-after-the-upgrade")})

	want := strategy.IMAPGreeting + "A001 CAPABILITY\r\n" + "A002 STARTTLS\r\n"
	c2s := live.Bytes(wiretest.C2S)

	if !bytes.HasPrefix(c2s, []byte(want)) {
		t.Fatalf("the cleartext prologue changed; got %q, want %q",
			string(c2s[:min(len(c2s), len(want))]), want)
	}
	if len(c2s) <= len(want) {
		t.Fatal("the session stopped at the prologue; the TLS boundary was never reached")
	}
	if b := c2s[len(want)]; b != 0x16 {
		t.Fatalf("byte after the STARTTLS command is 0x%02x, want 0x16 (TLS handshake); "+
			"something is being sent in the clear that should not be", b)
	}

	// The greeting is server-speaks-first in real IMAP and client-first here, to
	// fit the peek-based dispatch. That inversion is the one shape difference a
	// stateful observer can see, and it is recorded rather than asserted away.
	t.Logf("cleartext prologue is %d bytes, TLS starts at offset %d; "+
		"the greeting travels client→server, which real IMAP does not do",
		len(want), len(want))
}

// driveIMAP runs one IMAP camouflage session against the fake server and
// returns the raw socket capture.
func driveIMAP(t *testing.T, writes [][]byte) *wiretest.Dump {
	t.Helper()
	ln := wiretest.Listen(t, "imap", wiretest.LayerTCP)
	fakeIMAPServer(t, ln, testSecret)

	m := managerAt(t, ln.Addr())
	s := strategy.NewIMAPCamouflageStrategy(m, testSecret)

	conn, err := s.Connect(testCtx(t), "wiretest")
	if err != nil {
		t.Fatalf("imap connect: %v", err)
	}
	defer conn.Close()

	for _, w := range writes {
		if _, err := conn.Write(w); err != nil {
			t.Fatalf("imap write: %v", err)
		}
	}

	// Wait for the writes to cross the socket: the recorder only sees bytes the
	// server actually reads, so asserting before then would test an empty dump.
	d := ln.First()
	if d == nil {
		t.Fatal("no connection was accepted")
	}
	before := d.Len(wiretest.C2S)
	waitFor(t, 5*time.Second, "imap tunnel bytes to cross the socket", func() bool {
		return d.Len(wiretest.C2S) > before-1 && quiesced(d, wiretest.C2S)
	})
	return d
}

// quiesced reports whether nothing new has been recorded for a short while.
func quiesced(d *wiretest.Dump, dir wiretest.Direction) bool {
	segs := d.Segments()
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i].Dir == dir {
			return time.Since(segs[i].At) > 200*time.Millisecond
		}
	}
	return false
}
