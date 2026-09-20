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
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
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

// ---------------------------------------------------------------------------
// HTTP/2 Stego: the "TIRD" DATA-frame magic
// ---------------------------------------------------------------------------

// TestSignatureStegoTIRDFrameMagic fixes the four-byte magic that opens every
// covert DATA frame.
//
// stego.go builds [TIRD][flags:1][len:2][payload][cover] and hands it to the
// HTTP/2 framer. Anything that can see the HTTP/2 framing — our own server, a
// TLS-terminating middlebox, a CDN we tunnel through — reads a constant at
// offset 0 of every DATA payload. Real gRPC, which this is dressed as, puts a
// 1-byte compressed flag and a 4-byte length there.
//
// Observation point is the HTTP/2 framing, not the TCP stream: production wraps
// this in TLS, so the magic is one decrypt away from a passive observer, not
// visible to one.
func TestSignatureStegoTIRDFrameMagic(t *testing.T) {
	ln := wiretest.Listen(t, "stego", wiretest.LayerFraming)
	srvReady := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv := strategy.NewHTTP2StegoConn(c, testSecret, false, strategy.NaivePaddingStandard)
		if err := srv.Handshake(); err != nil {
			t.Errorf("stego server handshake: %v", err)
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

	cli := strategy.NewHTTP2StegoConn(raw, testSecret, true, strategy.NaivePaddingStandard)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("stego client handshake: %v", err)
	}
	<-srvReady

	if _, err := cli.Write(make([]byte, 1200)); err != nil {
		t.Fatalf("stego write: %v", err)
	}

	var f wiretest.Finding
	var ok bool
	waitFor(t, 5*time.Second, "covert DATA frame", func() bool {
		f, ok = wiretest.H2DataPayloadPrefix(ln.First(), wiretest.C2S, "TIRD")
		return ok
	})
	t.Logf("TIRD magic found at %s", f)
}

// ---------------------------------------------------------------------------
// WebSocket Padded and Geneva: the Salamander upgrade headers
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

// TestSignatureWebSocketPaddedHeaders fixes the two constant headers the
// WebSocket Padded upgrade carries.
//
// X-Salamander-Version is not a header any real client sends — the server's own
// detectWebSocketPadded keys off it, which is exactly the property that makes
// it a fingerprint. The User-Agent names the product in clear text. Both sit in
// the TLS plaintext, so a passive box does not see them; anything terminating
// TLS, including the CDN edges we route through, does.
func TestSignatureWebSocketPaddedHeaders(t *testing.T) {
	ln := wiretest.Listen(t, "ws-padded", wiretest.LayerTCP)
	sessions := serveWSUpgrade(t, ln, true)

	m := managerAt(t, ln.Addr())
	s := strategy.NewWebSocketPaddedStrategy(m, testSecret)

	go func() {
		conn, err := s.Connect(testCtx(t), "wiretest")
		if err == nil {
			conn.Close()
		}
	}()

	var sess session
	select {
	case sess = <-sessions:
	case <-time.After(15 * time.Second):
		t.Fatal("websocket_padded upgrade never reached the server")
	}

	assertUpgradeMarkers(t, sess, "websocket_padded")
}

// TestSignatureGenevaHeaders fixes the same two headers on the Geneva path.
//
// Geneva fragments the ClientHello to defeat SNI matching and then sends a
// byte-for-byte copy of the WebSocket Padded upgrade, product name included.
// The packet-level evasion and the application-level giveaway are independent:
// fixing one does nothing for the other.
func TestSignatureGenevaHeaders(t *testing.T) {
	ln := wiretest.Listen(t, "geneva", wiretest.LayerTCP)
	sessions := serveWSUpgrade(t, ln, false)

	m := managerAt(t, ln.Addr())
	s := strategy.NewGenevaStrategy(m, testSecret, "russia")
	defer s.Close()

	go func() {
		conn, err := s.Connect(testCtx(t), "wiretest")
		if err == nil {
			conn.Close()
		}
	}()

	var sess session
	select {
	case sess = <-sessions:
	case <-time.After(15 * time.Second):
		t.Fatal("geneva upgrade never reached the server")
	}

	assertUpgradeMarkers(t, sess, "geneva")
}

func assertUpgradeMarkers(t *testing.T, sess session, who string) {
	t.Helper()

	f, ok := wiretest.Literal(sess.Plain, wiretest.C2S, "X-Salamander-Version: 1.0")
	if !ok {
		t.Fatalf("%s: expected the X-Salamander-Version header in the TLS plaintext; "+
			"if it is gone on purpose, invert this assertion", who)
	}
	t.Logf("%s: X-Salamander-Version found at %s", who, f)

	f, ok = wiretest.Literal(sess.Plain, wiretest.C2S, "TiredVPN/2.0")
	if !ok {
		t.Fatalf("%s: expected the TiredVPN/2.0 User-Agent in the TLS plaintext; "+
			"if it is gone on purpose, invert this assertion", who)
	}
	t.Logf("%s: TiredVPN/2.0 User-Agent found at %s", who, f)

	// Positive control for the layer split: the same bytes must NOT be readable
	// on the TCP stream. If they were, the capture would be reading the
	// plaintext twice and every "not on the wire" claim from this harness would
	// be worthless.
	if _, hit := wiretest.Literal(sess.Wire, wiretest.C2S, "X-Salamander-Version"); hit {
		t.Fatalf("%s: the header is readable on the raw TCP stream — "+
			"the fixture is not actually encrypting, so the layer labels lie", who)
	}
}

// ---------------------------------------------------------------------------
// QUIC: the "tiredvpn" ALPN and the "QVPN" stream magic
// ---------------------------------------------------------------------------

// TestSignatureQUICALPNAndMagic fixes two QUIC fingerprints at once, because
// one fixture produces both.
//
//   - ALPN "tiredvpn" in the ClientHello. QUIC Initial packets are protected
//     with keys derived from the published salt in RFC 9001, so any QUIC-aware
//     box decrypts them without a session key and reads the ALPN. A protocol
//     name nobody else uses identifies the deployment outright.
//   - "QVPN" at offset 0 of the first stream. Constant magic in the first four
//     bytes a peer reads, followed by a fixed 32-byte token.
//
// The two are recorded at different points and the test says which: ALPN comes
// from the server's parse of the ClientHello, QVPN from the stream plaintext.
// Neither is a raw datagram scan — the datagram capture is kept as a control
// below, where it must NOT find the literal.
func TestSignatureQUICALPNAndMagic(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udp.Close()

	datagrams := wiretest.NewDump("quic", wiretest.LayerQUICDatagram)
	rec := wiretest.NewPacketConn(udp, datagrams)

	alpn := make(chan []string, 4)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{testCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"tiredvpn"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case alpn <- chi.SupportedProtos:
			default:
			}
			return nil, nil
		},
	}

	ln, err := quic.Listen(rec, tlsConf, &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()

	streamHead := wiretest.NewDump("quic-stream", wiretest.LayerQUICStream)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		buf := make([]byte, 36)
		n, _ := io.ReadFull(st, buf)
		streamHead.Record(wiretest.C2S, buf[:n])
	}()

	m := managerAt(t, udp.LocalAddr())
	s := strategy.NewQUICStrategy(m, testSecret, 0)
	go func() {
		conn, err := s.Connect(testCtx(t), "wiretest")
		if err == nil {
			conn.Close()
		}
	}()

	var protos []string
	select {
	case protos = <-alpn:
	case <-time.After(15 * time.Second):
		t.Fatal("no QUIC ClientHello reached the server")
	}

	f, ok := wiretest.Contains(protos, "tiredvpn")
	if !ok {
		t.Fatalf("expected ALPN \"tiredvpn\" in the QUIC ClientHello, got %v; "+
			"if it was renamed on purpose, invert this assertion", protos)
	}
	t.Logf("ALPN tiredvpn found at %s", f)

	waitFor(t, 15*time.Second, "QUIC auth frame", func() bool {
		return streamHead.Len(wiretest.C2S) >= 4
	})
	f, ok = wiretest.PrefixAt(streamHead, wiretest.C2S, "QVPN")
	if !ok {
		t.Fatalf("expected the QVPN magic at offset 0 of the first QUIC stream; " +
			"if it is gone on purpose, invert this assertion")
	}
	t.Logf("QVPN magic found at %s", f)

	// Control: header protection means a byte scan of the datagrams finds
	// nothing. This is what keeps the two observation points honest — if this
	// ever fires, the ALPN finding above stops meaning "one Initial decrypt
	// away" and starts meaning "in the clear".
	if datagrams.Len(wiretest.C2S) == 0 {
		t.Fatal("no datagrams captured: the packet-conn recorder is not wired up")
	}
	if _, hit := wiretest.Literal(datagrams, wiretest.C2S, "tiredvpn"); hit {
		t.Fatal("ALPN is readable in the raw datagrams without unprotecting the Initial")
	}
}

// ---------------------------------------------------------------------------
// REALITY: the lone 0x08 after ServerHello, and the 200-byte ClientHello grid
// ---------------------------------------------------------------------------

// TestSignatureREALITYWireShape fixes two shape fingerprints of the REALITY
// handshake. Both are observable without decrypting anything.
//
//   - The mux dispatch byte. Right after the ServerHello the client writes a
//     single 0x08 to a NODELAY socket, so a lone one-byte TCP segment carrying
//     a constant lands between the handshake and the first data record. Real
//     TLS never puts a one-byte record there.
//   - The 200-byte ClientHello grid. reality.go splits the first flight
//     mid-SNI and then emits fixed 200-byte chunks, so the segment boundaries
//     sit on a regular pitch no browser produces.
//
// The server here is a reconstruction (see fakeREALITYServer) — the client is
// the shipped artifact and the bytes under test are its.
//
// Both observations are boundary-sensitive, and read() may merge two segments.
// The loop takes the first connection that shows the boundary cleanly rather
// than asserting on a single noisy sample; the byte-value check underneath is
// coalescing-proof and runs on every attempt.
func TestSignatureREALITYWireShape(t *testing.T) {
	ln := wiretest.Listen(t, "reality", wiretest.LayerTCP)
	fakeREALITYServer(t, ln, testSecret)

	m := managerAt(t, ln.Addr())
	s := strategy.NewREALITYStrategy(m, testSecret)

	const attempts = 6
	var (
		dispatch   wiretest.Finding
		grid       wiretest.Finding
		gotDisp    bool
		gotGrid    bool
		handshakes int
	)

	for i := 0; i < attempts && (!gotDisp || !gotGrid); i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		conn, err := s.Connect(ctx, "wiretest")
		if err == nil {
			conn.Close()
		}
		cancel()

		dumps := ln.Dumps()
		if len(dumps) <= i {
			continue
		}
		d := dumps[i]

		// The client only writes the dispatch byte once it has accepted the
		// ServerHello, so its presence is also the proof the fake server got
		// far enough to exercise the real handshake path.
		c2s := d.Bytes(wiretest.C2S)
		helloLen := reassembledHelloLen(c2s)
		if helloLen <= 0 || len(c2s) <= helloLen {
			continue
		}
		handshakes++
		if c2s[helloLen] != 0x08 {
			t.Fatalf("attempt %d: byte after ClientHello is 0x%02x, want the mux dispatch 0x08",
				i, c2s[helloLen])
		}

		if !gotDisp {
			if f, ok := wiretest.LoneByte(d, wiretest.C2S, 0x08, helloLen); ok {
				dispatch, gotDisp = f, true
			}
		}
		if !gotGrid {
			if f, ok := wiretest.Grid(d, wiretest.C2S, 200, 3); ok {
				grid, gotGrid = f, true
			}
		}
	}

	if handshakes == 0 {
		t.Fatal("no REALITY handshake completed against the fixture — the harness, not the code, is broken")
	}
	if !gotDisp {
		t.Fatalf("expected a lone 0x08 segment after the ServerHello in %d handshakes; "+
			"if the dispatch byte was folded into the record layer on purpose, invert this assertion", handshakes)
	}
	t.Logf("mux dispatch byte found at %s", dispatch)

	if !gotGrid {
		t.Fatalf("expected the ClientHello to be written on a 200-byte grid in %d handshakes; "+
			"if the fragment size was randomised on purpose, invert this assertion", handshakes)
	}
	t.Logf("200-byte ClientHello grid found at %s", grid)
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
