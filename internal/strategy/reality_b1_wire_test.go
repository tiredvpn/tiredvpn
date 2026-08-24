package strategy

import (
	"bytes"
	stdtls "crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// Wire tests: everything here is checked against the bytes that went through a
// socket, never against the structures the client built.
//
// The distinction matters because the client's own view is exactly what a bug
// here would agree with. Task 001 proved the ClientHello survives repeated
// marshalling by comparing Hello.Raw across calls — true, and not the same
// claim as "the bytes the server receives are the bytes we sealed against".
// Between the two sits HandshakeContext, which marshals again.

// b1DialResult carries what one instrumented dial observed.
type b1DialResult struct {
	writes [][]byte
}

// dialB1Recorded runs one full B1 connection, recording every byte the client
// wrote, and returns once the tunnel is up.
func dialB1Recorded(t *testing.T, profile string, srv *b1TestServer, tune func(*stdtls.Config)) b1DialResult {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv.tuneTLS = tune
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.serve(t, conn)
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	rec := &b1RecordingConn{Conn: tcpConn}
	deadline := time.Now().Add(15 * time.Second)
	_ = tcpConn.SetDeadline(deadline)

	r := b1Client(t, srv)
	r.SetFingerprint(profile)

	conn, err := r.connectB1(t.Context(), rec, "github.com:443", deadline)
	if err != nil {
		t.Fatalf("connectB1 with %s: %v", profile, err)
	}
	conn.Close()
	<-srvDone

	return b1DialResult{writes: rec.writes()}
}

// clientHelloFromWire extracts the ClientHello handshake message from the first
// record the client wrote.
func clientHelloFromWire(t *testing.T, writes [][]byte) []byte {
	t.Helper()
	if len(writes) == 0 {
		t.Fatal("the client wrote nothing")
	}
	rec := writes[0]
	if len(rec) < 5 || rec[0] != 0x16 {
		t.Fatalf("first write is not a handshake record: % x", rec[:min(6, len(rec))])
	}
	recordLen := int(binary.BigEndian.Uint16(rec[3:5]))
	if recordLen != len(rec)-5 {
		t.Fatalf("record claims %d bytes, write holds %d", recordLen, len(rec)-5)
	}
	return rec[5:]
}

// TestB1WireSessionIDOpensFromTheSocket is the central wire test: take the
// ClientHello exactly as it left the socket, and run the server's gate on those
// bytes. If the re-marshal inside HandshakeContext moved anything, the AEAD
// fails to open and this is where it shows.
//
// Run across profiles and repeatedly, because the failure this guards against
// would be intermittent — a field that only sometimes differs.
func TestB1WireSessionIDOpensFromTheSocket(t *testing.T) {
	for _, profile := range []string{"firefox", "chrome", "safari"} {
		t.Run(profile, func(t *testing.T) {
			srv := newB1TestServer(t)
			for i := range 25 {
				res := dialB1Recorded(t, profile, srv, nil)
				helloRaw := clientHelloFromWire(t, res.writes)

				peerPub, err := customtls.ExtractPeerX25519(helloRaw)
				if err != nil {
					t.Fatalf("iteration %d: ExtractPeerX25519 from the wire: %v", i, err)
				}
				sessionID, err := customtls.SessionIDFrom(helloRaw)
				if err != nil {
					t.Fatalf("iteration %d: SessionIDFrom: %v", i, err)
				}
				zeroed, err := customtls.ZeroSessionID(helloRaw)
				if err != nil {
					t.Fatalf("iteration %d: ZeroSessionID: %v", i, err)
				}
				random := helloRaw[4+2 : 4+2+32]

				payload, err := customtls.OpenSessionID(srv.staticPriv.Bytes(), peerPub, zeroed, random, sessionID)
				if err != nil {
					t.Fatalf("iteration %d: the session_id on the wire did not open: %v", i, err)
				}
				if payload.ShortID != customtls.ShortIDFor(srv.secret) {
					t.Fatalf("iteration %d: short ID on the wire does not match the secret", i)
				}
				if !payload.HasFlag(customtls.AuthFlagExporterBinding) {
					t.Fatalf("iteration %d: exporter-binding flag missing from the payload", i)
				}
			}
		})
	}
}

// TestB1WireSessionIDIsNotConstant guards the property the replay cache depends
// on: two connections must never put the same session_id on the wire.
func TestB1WireSessionIDIsNotConstant(t *testing.T) {
	srv := newB1TestServer(t)
	seen := make(map[[customtls.AuthSessionIDLen]byte]bool, 16)
	for i := range 16 {
		res := dialB1Recorded(t, "firefox", srv, nil)
		sid, err := customtls.SessionIDFrom(clientHelloFromWire(t, res.writes))
		if err != nil {
			t.Fatalf("iteration %d: SessionIDFrom: %v", i, err)
		}
		if seen[sid] {
			t.Fatal("two connections put the same session_id on the wire")
		}
		seen[sid] = true
	}
}

// TestB1WireNoPlaintextAfterHandshake is the shape check, on the socket. The
// legacy path's giveaway was a bare 0x08 in its own segment between the
// handshake and the data; nothing like it may appear here.
func TestB1WireNoPlaintextAfterHandshake(t *testing.T) {
	srv := newB1TestServer(t)
	res := dialB1Recorded(t, "firefox", srv, nil)

	var sawAppData bool
	for i, w := range res.writes {
		if len(w) == 1 {
			t.Fatalf("write %d is a bare single byte: the dispatch byte is back on the wire", i)
		}
		if len(w) >= 3 && w[0] == 0x17 && w[1] == 0x03 && w[2] == 0x03 {
			sawAppData = true
		}
		// Nothing after the first record may be a plaintext handshake record
		// either: that would mean a renegotiation or a second flight in clear.
		if i > 0 && len(w) > 0 && w[0] == 0x16 {
			// The client's Finished travels inside 0x16 records during the
			// handshake, which is normal; only flag them once application data
			// has started.
			if sawAppData {
				t.Fatalf("write %d is a plaintext handshake record after application data began", i)
			}
		}
	}
	if !sawAppData {
		t.Fatal("no application-data record found; the binding record did not go out encrypted")
	}
}

// TestB1WireEphemeralVector is the test vector the epic asks for: on both
// profiles, the X25519 public key the server reads off the wire is the one
// whose private half the client sealed with.
//
// Firefox reuses one key for its classical and hybrid shares
// (ReuseHybridAndClassicalKeyShares); Chrome does not. A preference order that
// disagreed between the two sides would therefore break Chrome and only Chrome,
// which is why both are here rather than one representative profile.
func TestB1WireEphemeralVector(t *testing.T) {
	for _, profile := range []string{"firefox", "chrome"} {
		t.Run(profile, func(t *testing.T) {
			srv := newB1TestServer(t)
			res := dialB1Recorded(t, profile, srv, nil)
			helloRaw := clientHelloFromWire(t, res.writes)

			peerPub, err := customtls.ExtractPeerX25519(helloRaw)
			if err != nil {
				t.Fatalf("ExtractPeerX25519: %v", err)
			}
			if len(peerPub) != 32 {
				t.Fatalf("extracted %d bytes, want 32", len(peerPub))
			}

			// The proof that this is the right key: the session_id opens under
			// it. A key from the wrong share would give a different secret.
			random := helloRaw[4+2 : 4+2+32]
			sessionID, err := customtls.SessionIDFrom(helloRaw)
			if err != nil {
				t.Fatalf("SessionIDFrom: %v", err)
			}
			zeroed, err := customtls.ZeroSessionID(helloRaw)
			if err != nil {
				t.Fatalf("ZeroSessionID: %v", err)
			}
			if _, err := customtls.OpenSessionID(srv.staticPriv.Bytes(), peerPub, zeroed, random, sessionID); err != nil {
				t.Fatalf("session_id did not open under the extracted key: %v", err)
			}
		})
	}
}

// TestB1SurvivesHelloRetryRequest covers the case the epic flagged as a risk.
//
// The concern was that session_id is sealed over the first ClientHello, so a
// server that answers with HelloRetryRequest makes the client send a second one
// with a different key share — and the sealed value would no longer describe
// what is on the wire.
//
// It works, for a reason worth writing down: the gate runs once, on the first
// ClientHello, which is peeked before crypto/tls ever sees the connection. The
// auth key both sides derive comes from that first message on both ends, and it
// is independent of whatever group the TLS key exchange eventually settles on.
// The retry changes the TLS handshake, not the authentication.
//
// If this ever starts failing, the likely cause is someone moving the gate to
// run on the post-retry ClientHello.
func TestB1SurvivesHelloRetryRequest(t *testing.T) {
	srv := newB1TestServer(t)

	// Accept only P-384, which every browser profile lists in supported_groups but
	// none of them sends a key share for. That is exactly the
	// condition for HelloRetryRequest.
	forceRetry := func(cfg *stdtls.Config) {
		cfg.CurvePreferences = []stdtls.CurveID{stdtls.CurveP384}
	}

	res := dialB1Recorded(t, "firefox", srv, forceRetry)

	// Two ClientHellos on the wire is what proves the retry actually happened;
	// without it this test would pass while testing nothing.
	hellos := 0
	for _, w := range res.writes {
		if len(w) > 5 && w[0] == 0x16 && w[5] == 0x01 {
			hellos++
		}
	}
	if hellos < 2 {
		t.Fatalf("saw %d ClientHellos, want 2: the server did not send a HelloRetryRequest, "+
			"so this test is not exercising the retry path", hellos)
	}

	// And the session_id from the first one still opens.
	helloRaw := clientHelloFromWire(t, res.writes)
	peerPub, err := customtls.ExtractPeerX25519(helloRaw)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}
	sessionID, err := customtls.SessionIDFrom(helloRaw)
	if err != nil {
		t.Fatalf("SessionIDFrom: %v", err)
	}
	zeroed, err := customtls.ZeroSessionID(helloRaw)
	if err != nil {
		t.Fatalf("ZeroSessionID: %v", err)
	}
	random := helloRaw[4+2 : 4+2+32]
	if _, err := customtls.OpenSessionID(srv.staticPriv.Bytes(), peerPub, zeroed, random, sessionID); err != nil {
		t.Fatalf("the first ClientHello's session_id stopped opening after a retry: %v", err)
	}
}

// TestB1WireSecondHelloKeepsTheSessionID pins the RFC 8446 requirement the
// retry path leans on: the second ClientHello carries the same legacy_session_id
// as the first. If uTLS ever regenerated it, a server that gated on the second
// message would see a value that does not open.
func TestB1WireSecondHelloKeepsTheSessionID(t *testing.T) {
	srv := newB1TestServer(t)
	res := dialB1Recorded(t, "firefox", srv, func(cfg *stdtls.Config) {
		cfg.CurvePreferences = []stdtls.CurveID{stdtls.CurveP384}
	})

	var sids [][]byte
	for _, w := range res.writes {
		if len(w) <= 5 || w[0] != 0x16 || w[5] != 0x01 {
			continue
		}
		sid, err := customtls.SessionIDFrom(w[5:])
		if err != nil {
			t.Fatalf("SessionIDFrom: %v", err)
		}
		sids = append(sids, bytes.Clone(sid[:]))
	}
	if len(sids) < 2 {
		t.Fatalf("saw %d ClientHellos, want 2", len(sids))
	}
	if !bytes.Equal(sids[0], sids[1]) {
		t.Fatal("the second ClientHello carries a different session_id than the first")
	}
}

// TestB1ServerMustNotSelectP256 records a constraint on the server's
// CurvePreferences that is easy to violate and fails in a confusing way.
//
// The Firefox profile sends three key shares: X25519MLKEM768, X25519 and
// P-256. uTLS, however, keeps one classical private key in
// State13.KeyShareKeys, for one CurveID. If the server selects P-256 the client
// has no private key to finish with and the handshake dies on "invalid server
// key share" — on the client side, with nothing in the server log to explain it.
//
// No HelloRetryRequest is involved, which is what makes it confusing: the
// server picked a group the client genuinely offered.
//
// Our server prefers X25519MLKEM768 then X25519, so this cannot happen today.
// The test exists so that anyone widening CurvePreferences finds out here.
func TestB1ServerMustNotSelectP256(t *testing.T) {
	srv := newB1TestServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv.tuneTLS = func(cfg *stdtls.Config) {
		cfg.CurvePreferences = []stdtls.CurveID{stdtls.CurveP256}
	}
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.serve(t, conn)
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = tcpConn.SetDeadline(deadline)

	r := b1Client(t, srv)
	r.SetFingerprint("firefox")
	_, err = r.connectB1(t.Context(), tcpConn, "github.com:443", deadline)
	tcpConn.Close()
	<-srvDone

	if err == nil {
		t.Fatal("the client completed a handshake on P-256; uTLS grew multi-key-share " +
			"support and the constraint on CurvePreferences can be relaxed")
	}
}
