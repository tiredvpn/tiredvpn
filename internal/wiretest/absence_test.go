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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/tiredvpn/tiredvpn/internal/server"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/wiretest"
	"golang.org/x/net/http2"
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

// ---------------------------------------------------------------------------
// HTTP/2 Stego: the "TIRD" DATA-frame magic (S7)
// ---------------------------------------------------------------------------

// legacyStegoDump rebuilds a 1.10.0 covert DATA frame: [TIRD][flags:1][len:2]
// [payload], carried in one HTTP/2 DATA frame. It exists to feed the frame
// matcher something it is known to match; nothing depends on it.
func legacyStegoDump(t *testing.T) *wiretest.Dump {
	t.Helper()
	frame := append([]byte("TIRD"), 0x00) // magic + raw flag
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], 4)
	frame = append(frame, l[:]...)
	frame = append(frame, []byte("data")...)

	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	fr.AllowIllegalWrites = true
	if err := fr.WriteData(1, false, frame); err != nil {
		t.Fatalf("build legacy stego frame: %v", err)
	}
	d := wiretest.NewDump("stego-1.10.0", wiretest.LayerFraming)
	d.Record(wiretest.C2S, buf.Bytes())
	return d
}

// stegoDataPayloads parses the HTTP/2 frames in one direction and returns each
// DATA frame's payload, so a test can inspect the keyed prefix directly.
func stegoDataPayloads(d *wiretest.Dump, dir wiretest.Direction) [][]byte {
	b := bytes.TrimPrefix(d.Bytes(dir), []byte(http2.ClientPreface))
	fr := http2.NewFramer(io.Discard, bytes.NewReader(b))
	fr.AllowIllegalReads = true
	fr.SetMaxReadFrameSize(1 << 20)
	var out [][]byte
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		if df, ok := f.(*http2.DataFrame); ok {
			out = append(out, append([]byte(nil), df.Data()...))
		}
	}
	return out
}

// driveStego runs one stego connection, writes `writes` chunks of `size` bytes,
// and returns the framing-layer capture once at least `writes` DATA frames have
// crossed the socket.
func driveStego(t *testing.T, writes, size int) *wiretest.Dump {
	t.Helper()
	ln := wiretest.Listen(t, "stego", wiretest.LayerFraming)
	srvReady := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv := strategy.NewHTTP2StegoConn(c, testSecret, false, strategy.NaivePaddingStandard, nil)
		if err := srv.Handshake(); err != nil {
			return
		}
		close(srvReady)
		_, _ = io.Copy(io.Discard, srv)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	cli := strategy.NewHTTP2StegoConn(raw, testSecret, true, strategy.NaivePaddingStandard, nil)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("stego client handshake: %v", err)
	}
	<-srvReady

	for i := 0; i < writes; i++ {
		if _, err := cli.Write(make([]byte, size)); err != nil {
			t.Fatalf("stego write %d: %v", i, err)
		}
	}

	waitFor(t, 10*time.Second, "covert DATA frames", func() bool {
		return len(stegoDataPayloads(ln.First(), wiretest.C2S)) >= writes
	})
	return ln.First()
}

// TestStegoCarriesNoTIRDMagic is the inverted form of the 1.10.0 fixation.
//
// Before: every covert DATA frame opened with the ASCII literal "TIRD". Now it
// opens with [nonce][marker] keyed to the secret. The positive control is a
// 1.10.0 DATA frame, which the same frame matcher must still find.
func TestStegoCarriesNoTIRDMagic(t *testing.T) {
	legacy := legacyStegoDump(t)
	if _, ok := wiretest.H2DataPayloadPrefix(legacy, wiretest.C2S, "TIRD"); !ok {
		t.Fatal("control: the TIRD matcher does not fire on a 1.10.0 DATA frame, " +
			"so its silence below would mean nothing")
	}

	live := driveStego(t, 1, 1200)
	if _, ok := wiretest.H2DataPayloadPrefix(live, wiretest.C2S, ""); !ok {
		t.Fatal("no covert DATA frame captured: 'no TIRD' would be vacuous")
	}
	if f, ok := wiretest.H2DataPayloadPrefix(live, wiretest.C2S, "TIRD"); ok {
		t.Fatalf("the TIRD magic is back at the head of a stego DATA frame at %s", f)
	}
	t.Log("covert DATA frames open with a keyed marker, not TIRD")
}

// TestStegoMarkerLengthSpansItsRange records the marker-length distribution over
// many DATA frames. The code documents the marker as flat over [8,24) with no
// measured population to check the shape against; this pins what the
// implementation actually produces so a later narrowing shows up as a diff.
func TestStegoMarkerLengthSpansItsRange(t *testing.T) {
	live := driveStego(t, 80, 500)
	payloads := stegoDataPayloads(live, wiretest.C2S)
	if len(payloads) < 16 {
		t.Fatalf("only %d covert DATA frames captured; too few to measure a distribution", len(payloads))
	}

	seen := map[int]int{}
	for i, p := range payloads {
		if len(p) < strategy.StegoNonceLen {
			t.Fatalf("frame %d shorter than the nonce", i)
		}
		nonce := p[:strategy.StegoNonceLen]
		marker := strategy.StegoClientMarker(testSecret, nonce)
		if len(p) < strategy.StegoNonceLen+len(marker) ||
			!hmac.Equal(p[strategy.StegoNonceLen:strategy.StegoNonceLen+len(marker)], marker) {
			t.Fatalf("frame %d: the keyed client marker did not verify against the secret", i)
		}
		seen[len(marker)]++
	}

	for n := range seen {
		if n < 8 || n >= 24 {
			t.Fatalf("stego marker length %d is outside the documented [8,24)", n)
		}
	}
	if len(seen) < 8 {
		t.Fatalf("only %d distinct marker lengths over %d frames (%v); "+
			"a length this concentrated is a fingerprint, not a range", len(seen), len(payloads), seen)
	}
	t.Logf("stego marker length over %d frames: %d distinct values, histogram %v",
		len(payloads), len(seen), seen)
}

// driveStegoTunMixed runs one stego connection in the default tun path
// (NaivePaddingMinimal, the deployment default) writing the given packet sizes
// in order, and pairs each write with the length of the covert DATA frame that
// carried it.
func driveStegoTunMixed(t *testing.T, sizes []int) []wiretest.LenSample {
	t.Helper()
	ln := wiretest.Listen(t, "stego-tun", wiretest.LayerFraming)
	srvReady := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv := strategy.NewHTTP2StegoConn(c, testSecret, false, strategy.NaivePaddingMinimal, nil)
		if err := srv.Handshake(); err != nil {
			return
		}
		close(srvReady)
		_, _ = io.Copy(io.Discard, srv)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	cli := strategy.NewHTTP2StegoConn(raw, testSecret, true, strategy.NaivePaddingMinimal, nil)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("stego tun client handshake: %v", err)
	}
	<-srvReady

	for i, sz := range sizes {
		if _, err := cli.Write(make([]byte, sz)); err != nil {
			t.Fatalf("stego tun write %d: %v", i, err)
		}
	}

	waitFor(t, 10*time.Second, "covert tun DATA frames", func() bool {
		return len(stegoDataPayloads(ln.First(), wiretest.C2S)) >= len(sizes)
	})

	payloads := stegoDataPayloads(ln.First(), wiretest.C2S)
	var out []wiretest.LenSample
	for i := 0; i < len(sizes) && i < len(payloads); i++ {
		out = append(out, wiretest.LenSample{Inner: sizes[i], Record: len(payloads[i])})
	}
	return out
}

// TestStegoTunRecordLengthDoesNotTrackPacketLength is the inverted form of the
// 1.10.0 fixation for the default tun path.
//
// Before: the fast/tun path appended no cover, so every DATA frame length was a
// fixed offset from the packet it carried and the record-length distribution was
// a copy of the packet-length distribution. Now each frame is grown to a random
// size bucket, so small packets sometimes occupy the same record length as
// full-size ones and the record length no longer separates them.
//
// The positive control is a synthetic stream whose record length equals the
// packet length (what the no-padding path produced): the same matcher must fire
// on it, or its silence on the live capture would be vacuous (verification rule
// 2). To confirm the matcher against the real broken shape, the padding line in
// writeViaDataFast was temporarily reverted during development and this test went
// red, as required by verification rule 1.
func TestStegoTunRecordLengthDoesNotTrackPacketLength(t *testing.T) {
	var control []wiretest.LenSample
	for i := 0; i < 100; i++ {
		control = append(control, wiretest.LenSample{Inner: 40, Record: 40})
		control = append(control, wiretest.LenSample{Inner: 1200, Record: 1200})
	}
	if _, ok := wiretest.LengthTracksPayload(control); !ok {
		t.Fatal("control: matcher does not fire when record length equals packet length; " +
			"its silence on the live capture below would mean nothing")
	}

	// Live default-path capture: interleave small and full-size packets.
	var sizes []int
	for i := 0; i < 150; i++ {
		sizes = append(sizes, 40, 1200)
	}
	samples := driveStegoTunMixed(t, sizes)
	if len(samples) < 100 {
		t.Fatalf("only %d covert tun DATA frames captured; too few to measure", len(samples))
	}

	if f, ok := wiretest.LengthTracksPayload(samples); ok {
		t.Fatalf("the tun-path record length still tracks the packet length: %s", f)
	}
	t.Log("tun-path record length no longer separates small packets from full-size ones")
}

// ---------------------------------------------------------------------------
// WebSocket Padded and Geneva: the product headers (S8)
// ---------------------------------------------------------------------------

// legacyWSUpgrade is the 1.10.0 upgrade request head, product headers included.
const legacyWSUpgrade = "GET /ws HTTP/1.1\r\n" +
	"Host: chat.openai.com\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
	"Sec-WebSocket-Version: 13\r\n" +
	"X-Salamander-Version: 1.0\r\n" +
	"X-Auth-Token: deadbeef\r\n" +
	"User-Agent: Mozilla/5.0 (compatible; TiredVPN/2.0)\r\n" +
	"\r\n"

// assertNoProductHeaders is the inverted assertUpgradeMarkers: the two product
// headers must NOT be in the TLS plaintext, but the keyed X-Auth-Token still is.
func assertNoProductHeaders(t *testing.T, sess session, who string) {
	t.Helper()

	if _, ok := wiretest.Literal(sess.Plain, wiretest.C2S, "Upgrade: websocket"); !ok {
		t.Fatalf("%s: no upgrade request reached the plaintext; 'no product headers' would be vacuous", who)
	}
	if f, ok := wiretest.Literal(sess.Plain, wiretest.C2S, "X-Salamander-Version"); ok {
		t.Fatalf("%s: the X-Salamander-Version header is back in the plaintext at %s", who, f)
	}
	if f, ok := wiretest.Literal(sess.Plain, wiretest.C2S, "TiredVPN/2.0"); ok {
		t.Fatalf("%s: the TiredVPN/2.0 self-report is back in the plaintext at %s", who, f)
	}
	if _, ok := wiretest.Literal(sess.Plain, wiretest.C2S, "X-Auth-Token:"); !ok {
		t.Fatalf("%s: the keyed X-Auth-Token discriminator is missing", who)
	}
}

// TestWebSocketPaddedDropsProductHeaders is the inverted form of the header
// fixation. The positive control is the 1.10.0 upgrade text, which the same
// literal matcher must still find.
func TestWebSocketPaddedDropsProductHeaders(t *testing.T) {
	control := wiretest.NewDump("ws-1.10.0", wiretest.LayerTLSPlaintext)
	control.Record(wiretest.C2S, []byte(legacyWSUpgrade))
	if _, ok := wiretest.Literal(control, wiretest.C2S, "X-Salamander-Version: 1.0"); !ok {
		t.Fatal("control: the X-Salamander-Version matcher does not fire on the 1.10.0 upgrade")
	}
	if _, ok := wiretest.Literal(control, wiretest.C2S, "TiredVPN/2.0"); !ok {
		t.Fatal("control: the TiredVPN/2.0 matcher does not fire on the 1.10.0 upgrade")
	}

	ln := wiretest.Listen(t, "ws-padded", wiretest.LayerTCP)
	sessions := serveWSUpgrade(t, ln, true)
	m := managerAt(t, ln.Addr())
	s := strategy.NewWebSocketPaddedStrategy(m, testSecret)
	go func() {
		if conn, err := s.Connect(testCtx(t), "wiretest"); err == nil {
			conn.Close()
		}
	}()

	select {
	case sess := <-sessions:
		assertNoProductHeaders(t, sess, "websocket_padded")
	case <-time.After(15 * time.Second):
		t.Fatal("websocket_padded upgrade never reached the server")
	}
}

// TestGenevaDropsProductHeaders fixes the same two headers on the Geneva path,
// which sends a byte-for-byte copy of the WebSocket upgrade.
func TestGenevaDropsProductHeaders(t *testing.T) {
	ln := wiretest.Listen(t, "geneva", wiretest.LayerTCP)
	sessions := serveWSUpgrade(t, ln, false)
	m := managerAt(t, ln.Addr())
	s := strategy.NewGenevaStrategy(m, testSecret, "russia")
	defer s.Close()
	go func() {
		if conn, err := s.Connect(testCtx(t), "wiretest"); err == nil {
			conn.Close()
		}
	}()

	select {
	case sess := <-sessions:
		assertNoProductHeaders(t, sess, "geneva")
	case <-time.After(15 * time.Second):
		t.Fatal("geneva upgrade never reached the server")
	}
}

// ---------------------------------------------------------------------------
// QUIC: the "tiredvpn" ALPN and the "QVPN" stream magic (S7 + S8)
// ---------------------------------------------------------------------------

// driveQUIC runs one QUIC client against a listener that answers h3 and captures
// the ClientHello ALPN plus the first stream's opening bytes. The fixture never
// acks, so the client's Handshake times out after writing its auth frame - by
// which point both observation points are recorded.
func driveQUIC(t *testing.T) (protos []string, streamHead []byte) {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udp.Close()

	alpn := make(chan []string, 4)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{testCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case alpn <- chi.SupportedProtos:
			default:
			}
			return nil, nil
		},
	}
	ln, err := quic.Listen(udp, tlsConf, &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()

	headCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		buf := make([]byte, 64)
		n, _ := io.ReadFull(st, buf)
		headCh <- buf[:n]
	}()

	m := managerAt(t, udp.LocalAddr())
	s := strategy.NewQUICStrategy(m, testSecret, 0)
	go func() {
		if conn, err := s.Connect(testCtx(t), "wiretest"); err == nil {
			conn.Close()
		}
	}()

	select {
	case protos = <-alpn:
	case <-time.After(15 * time.Second):
		t.Fatal("no QUIC ClientHello reached the server")
	}
	select {
	case streamHead = <-headCh:
	case <-time.After(15 * time.Second):
		t.Fatal("no QUIC stream head captured")
	}
	return protos, streamHead
}

// TestQUICAdvertisesH3NotTiredVPN checks the ALPN was renamed to the RFC 9114
// "h3" token and that our client's advertised ALPN matches a stock quic-go h3
// client's, so the Initial is compared against a real h3 client rather than
// against nothing (verification rule 4).
func TestQUICAdvertisesH3NotTiredVPN(t *testing.T) {
	if _, ok := wiretest.Contains([]string{"tiredvpn"}, "tiredvpn"); !ok {
		t.Fatal("control: Contains does not match tiredvpn in a list that holds it")
	}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udp.Close()

	alpn := make(chan []string, 8)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{testCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case alpn <- chi.SupportedProtos:
			default:
			}
			return nil, nil
		},
	}
	ln, err := quic.Listen(udp, tlsConf, &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()

	// Our client.
	m := managerAt(t, udp.LocalAddr())
	s := strategy.NewQUICStrategy(m, testSecret, 0)
	go func() {
		if conn, err := s.Connect(testCtx(t), "wiretest"); err == nil {
			conn.Close()
		}
	}()

	// Positive control: a stock quic-go client advertising the h3 token.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ctrl := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "localhost"}
		if c, err := quic.DialAddr(ctx, udp.LocalAddr().String(), ctrl, &quic.Config{}); err == nil {
			c.CloseWithError(0, "")
		}
	}()

	var got [][]string
	deadline := time.After(20 * time.Second)
	for len(got) < 2 {
		select {
		case p := <-alpn:
			got = append(got, p)
		case <-deadline:
			t.Fatalf("only %d of 2 ClientHellos reached the server: %v", len(got), got)
		}
	}

	for _, p := range got {
		if f, ok := wiretest.Contains(p, "tiredvpn"); ok {
			t.Fatalf("the tiredvpn ALPN is back in a QUIC ClientHello at %s", f)
		}
		if _, ok := wiretest.Contains(p, "h3"); !ok {
			t.Fatalf("expected the h3 ALPN, got %v", p)
		}
	}
	t.Logf("our client and a stock quic-go h3 client both advertised h3: %v", got)
}

// TestQUICStreamHeadCarriesNoQVPN is the inverted form of the QVPN fixation.
func TestQUICStreamHeadCarriesNoQVPN(t *testing.T) {
	legacy := wiretest.NewDump("quic-1.10.0", wiretest.LayerQUICStream)
	legacy.Record(wiretest.C2S, append([]byte("QVPN"), make([]byte, 32)...))
	if _, ok := wiretest.PrefixAt(legacy, wiretest.C2S, "QVPN"); !ok {
		t.Fatal("control: the QVPN matcher does not fire on a 1.10.0 auth frame")
	}

	_, head := driveQUIC(t)
	if len(head) < strategy.QUICNonceLen {
		t.Fatalf("only %d stream bytes captured: 'no QVPN' would be vacuous", len(head))
	}

	live := wiretest.NewDump("quic-stream-live", wiretest.LayerQUICStream)
	live.Record(wiretest.C2S, head)
	if f, ok := wiretest.PrefixAt(live, wiretest.C2S, "QVPN"); ok {
		t.Fatalf("the QVPN magic is back at offset 0 of the QUIC stream at %s", f)
	}

	// The keyed marker must verify where QVPN used to sit.
	nonce := head[:strategy.QUICNonceLen]
	marker := strategy.QUICClientMarker(testSecret, nonce)
	if len(head) < strategy.QUICNonceLen+len(marker) ||
		!hmac.Equal(head[strategy.QUICNonceLen:strategy.QUICNonceLen+len(marker)], marker) {
		t.Fatal("the keyed client marker did not verify against the secret")
	}
	t.Log("the QUIC stream opens with a fresh nonce and keyed marker, not QVPN")
}

// TestQUICNonceMakesMarkersDiffer confirms the nonce actually varies the opening
// bytes: two connections with the same secret must not produce the same marker.
func TestQUICNonceMakesMarkersDiffer(t *testing.T) {
	_, a := driveQUIC(t)
	_, b := driveQUIC(t)
	if len(a) < strategy.QUICNonceLen || len(b) < strategy.QUICNonceLen {
		t.Fatalf("stream heads too short: %d, %d", len(a), len(b))
	}
	if bytes.Equal(a[:strategy.QUICNonceLen], b[:strategy.QUICNonceLen]) {
		t.Fatal("two connections chose the same nonce; the opening bytes repeat")
	}
	na := strategy.QUICClientMarker(testSecret, a[:strategy.QUICNonceLen])
	nb := strategy.QUICClientMarker(testSecret, b[:strategy.QUICNonceLen])
	if bytes.Equal(a[:strategy.QUICNonceLen+len(na)], b[:strategy.QUICNonceLen+len(nb)]) {
		t.Fatal("two connections produced identical nonce+marker prefixes")
	}
}

// TestQUICMarkerLengthSpansItsRange records the QUIC marker-length distribution.
// The length is derived from the nonce and documented as flat over [16,32) with
// no measured population to check against; this pins what is produced.
func TestQUICMarkerLengthSpansItsRange(t *testing.T) {
	const conns = 24
	seen := map[int]int{}
	for i := 0; i < conns; i++ {
		_, head := driveQUIC(t)
		if len(head) < strategy.QUICNonceLen {
			t.Fatalf("connection %d: stream head too short (%d bytes)", i, len(head))
		}
		nonce := head[:strategy.QUICNonceLen]
		marker := strategy.QUICClientMarker(testSecret, nonce)
		if len(head) < strategy.QUICNonceLen+len(marker) ||
			!hmac.Equal(head[strategy.QUICNonceLen:strategy.QUICNonceLen+len(marker)], marker) {
			t.Fatalf("connection %d: the keyed marker did not verify", i)
		}
		if got := strategy.QUICMarkerLen(nonce); got != len(marker) {
			t.Fatalf("connection %d: QUICMarkerLen says %d, marker is %d bytes", i, got, len(marker))
		}
		seen[len(marker)]++
	}

	for n := range seen {
		if n < 16 || n >= 32 {
			t.Fatalf("QUIC marker length %d is outside the documented [16,32)", n)
		}
	}
	if len(seen) < 8 {
		t.Fatalf("only %d distinct marker lengths over %d connections (%v); "+
			"a length this concentrated is a fingerprint, not a range", len(seen), conns, seen)
	}
	t.Logf("QUIC marker length over %d connections: %d distinct values, histogram %v",
		conns, len(seen), seen)
}

// ---------------------------------------------------------------------------
// REALITY: the mux dispatch byte
// ---------------------------------------------------------------------------

// legacyREALITYDispatchDump rebuilds the 1.10.0 post-ServerHello shape: the
// ClientHello written as a mid-SNI first fragment plus 200-byte chunks, then a
// bare one-byte write carrying protocol.TypeMux, then the first smux bytes.
//
// Taken from connect() as it stood before "feat(reality): carry the dispatch
// byte inside the encrypted layer": WriteDispatch(tcpConn, TypeMux) ran on the
// raw socket, between validateServerHello and wrapDataLayer.
func legacyREALITYDispatchDump() (*wiretest.Dump, int) {
	body := bytes.Repeat([]byte{0xa5}, 1024)
	hello := make([]byte, 0, 5+len(body))
	hello = append(hello, 0x16, 0x03, 0x01, byte(len(body)>>8), byte(len(body)))
	hello = append(hello, body...)

	d := wiretest.NewDump("reality-1.10.0", wiretest.LayerTCP)
	d.Record(wiretest.C2S, hello[:130]) // first fragment ends mid-SNI
	for off := 130; off < len(hello); off += 200 {
		d.Record(wiretest.C2S, hello[off:min(off+200, len(hello))])
	}
	d.Record(wiretest.C2S, []byte{0x08})                         // the bare discriminator
	d.Record(wiretest.C2S, []byte{0x00, 0x01, 0x00, 0x00, 0x00}) // smux SYN, in the clear
	return d, len(hello)
}

// TestREALITYDispatchByteIsNoLongerOnTheWire is the inverted form of the 1.10.0
// fixation.
//
// Before: a lone one-byte TCP segment carrying 0x08 sat between the ServerHello
// and the first data record. 0x08 is not a TLS content type at all, so a single
// stateless rule - "one-byte segment, invalid record type, right after a
// handshake" - identified the protocol without decrypting anything. S5 moved
// the discriminator inside the encrypted layer, where it is an ordinary
// Application Data record.
//
// Positive control: the 1.10.0 segment layout, which wiretest.LoneByte must
// still find in this run. Without it, a LoneByte that had quietly stopped
// scanning would produce exactly the same green as a fixed protocol.
func TestREALITYDispatchByteIsNoLongerOnTheWire(t *testing.T) {
	legacy, legacyHelloLen := legacyREALITYDispatchDump()
	f, ok := wiretest.LoneByte(legacy, wiretest.C2S, 0x08, legacyHelloLen)
	if !ok {
		t.Fatal("control: LoneByte does not find the bare 0x08 in the 1.10.0 layout, " +
			"so its silence below would mean nothing")
	}
	t.Logf("control: the bare dispatch byte still matched at %s", f)

	for i, d := range realityHandshakes(t, 6) {
		c2s := d.Bytes(wiretest.C2S)
		off := reassembledHelloLen(c2s)

		if f, ok := wiretest.LoneByte(d, wiretest.C2S, 0x08, off); ok {
			t.Fatalf("handshake %d: the bare mux dispatch byte is back on the wire at %s", i, f)
		}
		// The byte that replaced it has to be a TLS content type, not some other
		// bare discriminator: "no 0x08" alone would also hold for 0x09.
		switch b := c2s[off]; b {
		case 0x14, 0x15, 0x16, 0x17:
		default:
			t.Fatalf("handshake %d: byte after the ClientHello is 0x%02x, "+
				"which is not a TLS content type - something bare is still on the wire", i, b)
		}
	}
	t.Log("the discriminator now rides inside an Application Data record")
}

// ---------------------------------------------------------------------------
// Anti-Probe: the knock no longer repeats across connections
// ---------------------------------------------------------------------------

// legacyKnockDump rebuilds the 1.10.0 knock as the plaintext behind TLS: the
// dispatch byte, then five packets whose sizes and bodies are a pure function of
// the secret (HMAC(secret,"knock-sequence") for the sizes, HMAC(secret,[i]) for
// the bodies). Two of these are byte-identical, which is exactly what SameSizes
// and SameStream must fire on.
func legacyKnockDump() *wiretest.Dump {
	seqHash := hmac.New(sha256.New, testSecret)
	seqHash.Write([]byte("knock-sequence"))
	sum := seqHash.Sum(nil)

	d := wiretest.NewDump("antiprobe-1.10.0", wiretest.LayerTLSPlaintext)
	d.Record(wiretest.C2S, []byte{0x07}) // TypeAntiProbe dispatch byte
	for i := 0; i < 5; i++ {
		size := 10 + int(sum[i+5])%90
		pkt := make([]byte, size)
		pkt[0] = byte(i)
		h := hmac.New(sha256.New, testSecret)
		h.Write([]byte{byte(i)})
		body := h.Sum(nil)
		for j := 1; j < size; j++ {
			pkt[j] = body[(j-1)%len(body)]
		}
		d.Record(wiretest.C2S, pkt)
	}
	return d
}

// antiprobeKnock drives one real anti-probe Connect against a TLS server that
// only drains the knock and ACKs it, and returns the decrypted client-side
// stream. The client is the shipped artifact; the fixture proves nothing about
// the server.
func antiprobeKnock(t *testing.T) *wiretest.Dump {
	t.Helper()
	ln := wiretest.Listen(t, "antiprobe", wiretest.LayerTCP)
	sessions := serveTLS(t, ln, func(c net.Conn) {
		var one [1]byte
		if _, err := io.ReadFull(c, one[:]); err != nil {
			return
		}
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
	go func() {
		if conn, err := s.Connect(testCtx(t), "wiretest"); err == nil {
			conn.Close()
		}
	}()
	select {
	case sess := <-sessions:
		return sess.Plain
	case <-time.After(20 * time.Second):
		t.Fatal("knock never completed")
		return nil
	}
}

// knockNonce pulls the per-connection nonce out of the decrypted knock stream:
// [dispatch:1][seq:1][bucket:8][nonce:16]...
func knockNonce(t *testing.T, d *wiretest.Dump) []byte {
	t.Helper()
	c2s := d.Bytes(wiretest.C2S)
	off := 1 + 1 + 8 // dispatch + seq + bucket
	if len(c2s) < off+strategy.KnockNonceLen {
		t.Fatalf("knock stream too short for a nonce: %d bytes", len(c2s))
	}
	return c2s[off : off+strategy.KnockNonceLen]
}

// verifyKnockTag confirms the bytes after the header are the keyed tag for this
// connection's nonce and bucket — i.e. we captured a real knock, not noise.
func verifyKnockTag(t *testing.T, d *wiretest.Dump) {
	t.Helper()
	c2s := d.Bytes(wiretest.C2S)
	// After the dispatch byte, packet 0 is [seq:1][bucket:8][nonce:16][tag:16].
	p0 := c2s[1:]
	if len(p0) < strategy.KnockHeaderLen+strategy.KnockTagLen {
		t.Fatalf("knock packet 0 too short: %d bytes", len(p0))
	}
	bucket := int64(binary.BigEndian.Uint64(p0[1:9]))
	nonce := p0[9:strategy.KnockHeaderLen]
	want := strategy.KnockTag(testSecret, nonce, bucket)
	got := p0[strategy.KnockHeaderLen : strategy.KnockHeaderLen+strategy.KnockTagLen]
	if !hmac.Equal(got, want) {
		t.Fatal("the keyed knock tag did not verify against the secret")
	}
}

// TestAntiProbeKnockVariesPerConnection is the inverted form of the 1.10.0
// knock fixation. In v1 the sizes, delays and bodies were a pure function of the
// secret, so two dials of one client repeated byte for byte and a censor could
// link them (or replay them) without touching the TLS wrapper. v2 mixes a fresh
// nonce into the schedule, so nothing repeats.
//
// Positive control: two identical 1.10.0 knocks, on which SameSizes and
// SameStream must still fire. Without it, a matcher that had stopped working
// would produce the same green as a fixed knock.
func TestAntiProbeKnockVariesPerConnection(t *testing.T) {
	legacyA, legacyB := legacyKnockDump(), legacyKnockDump()
	if _, ok := wiretest.SameSizes(legacyA, legacyB, wiretest.C2S, 1); !ok {
		t.Fatal("control: SameSizes does not fire on two identical 1.10.0 knocks")
	}
	if _, ok := wiretest.SameStream(legacyA, legacyB, wiretest.C2S, legacyA.Len(wiretest.C2S)); !ok {
		t.Fatal("control: SameStream does not fire on two identical 1.10.0 knocks")
	}
	t.Log("control: both matchers fire on the deterministic 1.10.0 knock")

	a, b := antiprobeKnock(t), antiprobeKnock(t)
	if len(a.Sizes(wiretest.C2S)) < 2 || len(b.Sizes(wiretest.C2S)) < 2 {
		t.Fatalf("knock capture too short: %v / %v", a.Sizes(wiretest.C2S), b.Sizes(wiretest.C2S))
	}

	if f, ok := wiretest.SameSizes(a, b, wiretest.C2S, 1); ok {
		t.Fatalf("knock packet sizes still repeat across two connections at %s", f)
	}
	n := min(a.Len(wiretest.C2S), b.Len(wiretest.C2S))
	if f, ok := wiretest.SameStream(a, b, wiretest.C2S, n); ok {
		t.Fatalf("knock payload still identical across two connections at %s", f)
	}

	verifyKnockTag(t, a)
	verifyKnockTag(t, b)
	if bytes.Equal(knockNonce(t, a), knockNonce(t, b)) {
		t.Fatal("two connections chose the same nonce; the knock opening repeats")
	}
	t.Log("the knock schedule, tag and bodies differ across two connections and the tag still verifies")
}

// ---------------------------------------------------------------------------
// REALITY: the ClientHello is no longer written on a 200-byte grid
// ---------------------------------------------------------------------------

// legacyREALITYGridDump rebuilds the 1.10.0 ClientHello fragmentation: a first
// fragment that ends mid-SNI, then fixed 200-byte chunks. The Grid matcher must
// fire on this.
func legacyREALITYGridDump() *wiretest.Dump {
	d := wiretest.NewDump("reality-grid-1.10.0", wiretest.LayerTCP)
	body := bytes.Repeat([]byte{0xa5}, 900)
	hello := append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
	d.Record(wiretest.C2S, hello[:130]) // first fragment ends mid-SNI
	for off := 130; off < len(hello); off += 200 {
		d.Record(wiretest.C2S, hello[off:min(off+200, len(hello))])
	}
	return d
}

// TestREALITYClientHelloNotOn200Grid is the inverted form of the 1.10.0 grid
// fixation. reality.go used to emit fixed 200-byte ClientHello fragments, a
// pitch no browser produces; S10 draws each fragment size from a CSPRNG per
// connection.
//
// Distribution note (verification rules 3, 4, 8): no browser fragments its
// ClientHello at the record level at all — Chrome sends one record — so there is
// no donor fragment-size distribution to match, recorded here as "сверять не с
// чем". The point of the change is only to remove the fixed 200-byte grid; the
// sizes are drawn flat from a CSPRNG. TestREALITYFragmentSizesVaryAndCarryHello
// pins that they vary and that every hello still reassembles.
//
// Positive control: a synthetic 200-byte grid, on which Grid must still fire.
func TestREALITYClientHelloNotOn200Grid(t *testing.T) {
	if _, ok := wiretest.Grid(legacyREALITYGridDump(), wiretest.C2S, 200, 3); !ok {
		t.Fatal("control: Grid does not find the 200-byte pitch in the 1.10.0 layout, " +
			"so its silence below would mean nothing")
	}
	t.Log("control: the 200-byte grid still matched on the 1.10.0 sample")

	dumps := realityHandshakes(t, 6)
	for i, d := range dumps {
		if f, ok := wiretest.Grid(d, wiretest.C2S, 200, 3); ok {
			t.Fatalf("handshake %d: the ClientHello is still on a 200-byte grid at %s", i, f)
		}
	}
	t.Log("no handshake writes the ClientHello on a 200-byte grid")
}

// TestREALITYFragmentSizesVaryAndCarryHello checks two things the grid flip
// leans on: the fragment sizes actually vary between connections (so "no grid"
// is not just read() coalescing), and every hello still reassembles into a
// record the server routes into the REALITY path (the >= 64-byte padding
// invariant, checked against the real server detector).
func TestREALITYFragmentSizesVaryAndCarryHello(t *testing.T) {
	dumps := realityHandshakes(t, 6)

	// Every generated ClientHello must still be recognised by the server, or the
	// padding profile has dropped below the 64-byte routing gate and ~99% of prod
	// traffic would go to the fake site.
	for i, d := range dumps {
		c2s := d.Bytes(wiretest.C2S)
		off := reassembledHelloLen(c2s)
		if off <= 0 {
			t.Fatalf("handshake %d: no complete ClientHello record captured", i)
		}
		if !server.DetectREALITYExtension(c2s[:off]) {
			t.Fatalf("handshake %d: the server no longer routes this ClientHello into REALITY "+
				"(padding extension fell below the 64-byte gate)", i)
		}
	}
	t.Logf("all %d generated ClientHellos still route into the REALITY path", len(dumps))

	// The ClientHello fragment boundaries must differ across connections: collect
	// the leading-fragment size vector for each and require at least two distinct
	// vectors. A fixed grid would make them all identical.
	seen := map[string]int{}
	for _, d := range dumps {
		seen[fmt.Sprintf("%v", d.Sizes(wiretest.C2S))]++
	}
	if len(seen) < 2 {
		t.Fatalf("fragment size vectors are identical across %d handshakes (%v); "+
			"the fragmentation is not per-connection", len(dumps), seen)
	}
	t.Logf("fragment size vectors over %d handshakes: %d distinct", len(dumps), len(seen))
}
