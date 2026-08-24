package strategy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/xtaci/smux"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// negotiate runs the real handshake-side negotiation for one connection: the
// client builds its REALITY extension with the v2 signal, the server parses it,
// answers with its own, and the client verifies the answer. It returns the key
// material each side ends up with, so a test can assert the two agree without
// standing up a TLS handshake.
func negotiate(t *testing.T, secret []byte) (clientSide, serverSide RealityV2Params) {
	t.Helper()

	clientPriv, clientPub, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var clientSalt [32]byte
	if _, err := rand.Read(clientSalt[:]); err != nil {
		t.Fatal(err)
	}

	clientExt, err := customtls.NewClientREALITYExtensionDataV2(secret, clientPriv, clientSalt)
	if err != nil {
		t.Fatal(err)
	}
	if clientExt.PubKey != clientPub {
		t.Fatal("extension pubkey does not match generated key")
	}

	// Server side.
	gotSalt, ok := customtls.ParseClientDataV2(secret, clientExt.PubKey, clientExt.Extra)
	if !ok {
		t.Fatal("server did not recognise the v2 client signal")
	}
	if gotSalt != clientSalt {
		t.Fatal("server read a different client salt")
	}

	serverPriv, serverPub, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var serverSalt [32]byte
	if _, err := rand.Read(serverSalt[:]); err != nil {
		t.Fatal(err)
	}
	serverExt, err := customtls.NewServerREALITYExtensionDataV2(secret, serverPriv, clientExt.PubKey, gotSalt, serverSalt)
	if err != nil {
		t.Fatal(err)
	}
	serverECDH, err := RealityV2ECDH(serverPriv, clientExt.PubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Back on the client.
	gotServerSalt, ok := customtls.ParseServerDataV2(secret, clientExt.PubKey, serverExt.PubKey, clientSalt, serverExt.Extra)
	if !ok {
		t.Fatal("client did not recognise the v2 server confirmation")
	}
	clientECDH, err := RealityV2ECDH(clientPriv, serverExt.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientECDH, serverECDH) {
		t.Fatal("ecdh outputs differ")
	}

	clientSide = RealityV2Params{
		SharedSecret: secret,
		ECDH:         clientECDH,
		ClientPub:    clientExt.PubKey,
		ServerPub:    serverExt.PubKey,
		ClientSalt:   clientSalt,
		ServerSalt:   gotServerSalt,
	}
	serverSide = RealityV2Params{
		SharedSecret: secret,
		ECDH:         serverECDH,
		ClientPub:    clientExt.PubKey,
		ServerPub:    serverPub,
		ClientSalt:   gotSalt,
		ServerSalt:   serverSalt,
	}
	return clientSide, serverSide
}

func TestRealityDataConnV2RoundTrip(t *testing.T) {
	t.Parallel()

	cp, sp := negotiate(t, []byte("shared-secret"))

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	clientConn, err := NewRealityDataConnV2(clientRaw, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := NewRealityDataConnV2(serverRaw, sp, false)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello from client")
	reply := []byte("ack from server")

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(buf, msg) {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err := serverConn.Write(reply)
		done <- err
	}()

	if _, err := clientConn.Write(msg); err != nil {
		t.Fatal("client write:", err)
	}
	ack := make([]byte, len(reply))
	if _, err := io.ReadFull(clientConn, ack); err != nil {
		t.Fatal("client read:", err)
	}
	if err := <-done; err != nil {
		t.Fatal("server:", err)
	}
	if !bytes.Equal(ack, reply) {
		t.Fatalf("client got %q, want %q", ack, reply)
	}
}

func TestRealityDataConnV2Large(t *testing.T) {
	t.Parallel()

	cp, sp := negotiate(t, []byte("shared-secret"))

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	clientConn, _ := NewRealityDataConnV2(clientRaw, cp, true)
	serverConn, _ := NewRealityDataConnV2(serverRaw, sp, false)

	// Spans several records, so the sequence number has to advance in step on
	// both sides or the tags stop verifying.
	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			got <- nil
			return
		}
		got <- buf
	}()

	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal("client write:", err)
	}
	received := <-got
	if received == nil {
		t.Fatal("server read failed")
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("payload mismatch across multi-record write")
	}
}

// TestRealityDataConnV2TamperDetected is the acceptance test for the missing
// authentication: flipping one bit inside the tunnel must break the connection
// instead of quietly delivering corrupted plaintext, which is what the bare
// ChaCha20 of v1 does.
func TestRealityDataConnV2TamperDetected(t *testing.T) {
	t.Parallel()

	cp, sp := negotiate(t, []byte("shared-secret"))

	// Capture the client's record, flip a bit, feed it to the server.
	var wire bytes.Buffer
	clientConn, err := NewRealityDataConnV2(writeOnlyConn{Writer: &wire}, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	if _, err := clientConn.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	record := wire.Bytes()
	if len(record) != 5+len(plaintext)+16 {
		t.Fatalf("record len = %d, want %d (plaintext + 16-byte tag)", len(record), 5+len(plaintext)+16)
	}

	for _, tc := range []struct {
		name string
		pos  int
	}{
		{"ciphertext", 5 + 3},
		{"tag", len(record) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), record...)
			tampered[tc.pos] ^= 0x01

			serverConn, err := NewRealityDataConnV2(readOnlyConn{Reader: bytes.NewReader(tampered)}, sp, false)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(plaintext))
			if _, err := serverConn.Read(buf); err == nil {
				t.Fatal("tampered record was accepted")
			}
			// The failure is sticky: no resynchronising on attacker-chosen bytes.
			if _, err := serverConn.Read(buf); err == nil {
				t.Fatal("read after tamper succeeded")
			}
		})
	}

	// Control: untouched record decrypts.
	serverConn, err := NewRealityDataConnV2(readOnlyConn{Reader: bytes.NewReader(record)}, sp, false)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(plaintext))
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatal("clean record rejected:", err)
	}
	if !bytes.Equal(buf, plaintext) {
		t.Fatal("clean record decrypted to the wrong plaintext")
	}
}

// TestRealityDataConnV2RecordLengthCarriesTag guards the size shift: a v1 record
// body was exactly the plaintext length, which is itself a giveaway because a
// real TLS 1.3 record is 16-24 bytes longer.
func TestRealityDataConnV2RecordLengthCarriesTag(t *testing.T) {
	t.Parallel()

	cp, _ := negotiate(t, []byte("shared-secret"))

	var wire bytes.Buffer
	conn, err := NewRealityDataConnV2(writeOnlyConn{Writer: &wire}, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	body := binary.BigEndian.Uint16(wire.Bytes()[3:5])
	if body != 116 {
		t.Fatalf("record body = %d, want 116 (100 plaintext + 16 tag)", body)
	}
}

// TestRealityDataConnV2MaxRecord checks the plaintext cap: a full-size write
// must still produce a record body within the 16383 limit the reader accepts.
func TestRealityDataConnV2MaxRecord(t *testing.T) {
	t.Parallel()

	cp, sp := negotiate(t, []byte("shared-secret"))

	var wire bytes.Buffer
	client, err := NewRealityDataConnV2(writeOnlyConn{Writer: &wire}, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, realityV2MaxPlaintext)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if body := int(binary.BigEndian.Uint16(wire.Bytes()[3:5])); body != 16383 {
		t.Fatalf("record body = %d, want 16383", body)
	}
	if wire.Len() != 5+16383 {
		t.Fatalf("wrote %d bytes, want one full record", wire.Len())
	}

	server, err := NewRealityDataConnV2(readOnlyConn{Reader: bytes.NewReader(wire.Bytes())}, sp, false)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(payload))
	if _, err := io.ReadFull(server, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("max-size record did not round-trip")
	}
}

// TestRealityKeystreamUniquePerConnection is the acceptance test for the bug
// this change exists to fix: with a process-wide client key, every connection
// encrypted the same plaintext to the same bytes from counter zero, so XOR of
// two captures recovered the plaintexts. Both the v2 path and the v1 fallback
// (which an upgraded client still uses against an old server) must diverge.
func TestRealityKeystreamUniquePerConnection(t *testing.T) {
	t.Parallel()

	secret := []byte("one-secret-for-every-connection")
	plaintext := bytes.Repeat([]byte("SMUX-HEADER-KNOWN-PLAINTEXT"), 8)

	capture := func(newConn func(net.Conn) (net.Conn, error)) []byte {
		var wire bytes.Buffer
		c, err := newConn(writeOnlyConn{Writer: &wire})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(plaintext); err != nil {
			t.Fatal(err)
		}
		return wire.Bytes()
	}

	t.Run("v2", func(t *testing.T) {
		cp1, _ := negotiate(t, secret)
		cp2, _ := negotiate(t, secret)
		a := capture(func(c net.Conn) (net.Conn, error) { return NewRealityDataConnV2(c, cp1, true) })
		b := capture(func(c net.Conn) (net.Conn, error) { return NewRealityDataConnV2(c, cp2, true) })
		assertNoKeystreamReuse(t, a, b, plaintext)
	})

	t.Run("v1 fallback with per-connection key", func(t *testing.T) {
		_, pub1, err := customtls.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		_, pub2, err := customtls.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		a := capture(func(c net.Conn) (net.Conn, error) { return NewRealityDataConn(c, secret, pub1[:], true) })
		b := capture(func(c net.Conn) (net.Conn, error) { return NewRealityDataConn(c, secret, pub2[:], true) })
		assertNoKeystreamReuse(t, a, b, plaintext)
	})
}

// TestWrapDataLayerVersionChoice covers the client's half of the negotiation:
// which record layer it ends up on given what the server put in its ServerHello
// padding, and what -reality-require-data-v2 changes about that.
func TestWrapDataLayerVersionChoice(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")

	setup := func(t *testing.T) (r *REALITYStrategy, clientPriv, clientPub, clientSalt [32]byte, serverPriv [32]byte) {
		t.Helper()
		r = &REALITYStrategy{secret: secret}
		var err error
		clientPriv, clientPub, err = customtls.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		clientSalt = testSalt32(t)
		serverPriv, _, err = customtls.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		return r, clientPriv, clientPub, clientSalt, serverPriv
	}

	t.Run("server confirms v2", func(t *testing.T) {
		r, priv, pub, salt, serverPriv := setup(t)
		ext, err := customtls.NewServerREALITYExtensionDataV2(secret, serverPriv, pub, salt, testSalt32(t))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := r.wrapDataLayer(writeOnlyConn{Writer: io.Discard}, ext, priv, pub, salt)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := conn.(*realityDataConnV2); !ok {
			t.Fatalf("got %T, want the v2 record layer", conn)
		}
	})

	t.Run("legacy server falls back", func(t *testing.T) {
		r, priv, pub, salt, serverPriv := setup(t)
		ext, err := customtls.NewServerREALITYExtension(secret, serverPriv, pub)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := r.wrapDataLayer(writeOnlyConn{Writer: io.Discard}, ext, priv, pub, salt)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := conn.(*realityDataConn); !ok {
			t.Fatalf("got %T, want the v1 record layer", conn)
		}
	})

	t.Run("legacy server refused when v2 required", func(t *testing.T) {
		r, priv, pub, salt, serverPriv := setup(t)
		r.SetRequireDataV2(true)
		ext, err := customtls.NewServerREALITYExtension(secret, serverPriv, pub)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.wrapDataLayer(writeOnlyConn{Writer: io.Discard}, ext, priv, pub, salt); err == nil {
			t.Fatal("fell back to v1 despite requireDataV2")
		}
	})
}

func testSalt32(t *testing.T) [32]byte {
	t.Helper()
	var s [32]byte
	if _, err := rand.Read(s[:]); err != nil {
		t.Fatal(err)
	}
	return s
}

// assertNoKeystreamReuse checks the two captures are not two-time pads: XORing
// them must not reveal the plaintext, which it does when the keystream repeats.
func assertNoKeystreamReuse(t *testing.T, a, b, plaintext []byte) {
	t.Helper()

	if bytes.Equal(a, b) {
		t.Fatal("two connections produced identical ciphertext")
	}

	// XOR the record bodies and look for the known plaintext. With a repeated
	// keystream, a^b == p1^p2, and since p1 == p2 here that is a run of zeros.
	n := min(len(a), len(b))
	x := make([]byte, n-5)
	for i := range x {
		x[i] = a[5+i] ^ b[5+i]
	}
	zeros := make([]byte, len(plaintext)/2)
	if bytes.Contains(x, zeros) {
		t.Fatal("XOR of two captures collapses to zeros: keystream reused")
	}
}

// writeOnlyConn / readOnlyConn adapt a buffer to net.Conn so a test can inspect
// or replay exactly the bytes that hit the wire.
type writeOnlyConn struct {
	net.Conn
	io.Writer
}

func (c writeOnlyConn) Write(p []byte) (int, error) { return c.Writer.Write(p) }

type readOnlyConn struct {
	net.Conn
	io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

// TestRealityDataConnV2UnderSmux runs the real stack — smux over the v2 record
// layer over a loopback TCP pair — because that is what production does, and
// smux drives Read and Write from separate goroutines with its own framing.
func TestRealityDataConnV2UnderSmux(t *testing.T) {
	t.Parallel()

	cp, sp := negotiate(t, []byte("shared-secret"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()
		dc, err := NewRealityDataConnV2(raw, sp, false)
		if err != nil {
			serverDone <- err
			return
		}
		sess, err := smux.Server(dc, smux.DefaultConfig())
		if err != nil {
			serverDone <- err
			return
		}
		defer sess.Close()
		stream, err := sess.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		// Echo everything back.
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, buf); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buf, payload) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err = stream.Write(buf)
		serverDone <- err
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	dc, err := NewRealityDataConnV2(raw, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := smux.Client(dc, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	echoed := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stream, echoed)
		readDone <- err
	}()

	if _, err := stream.Write(payload); err != nil {
		t.Fatal("client write:", err)
	}
	if err := <-readDone; err != nil {
		t.Fatal("client read:", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal("server:", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatal("echo mismatch through smux")
	}
}

// BenchmarkRealityDataConnV2Write mirrors BenchmarkRealityDataConnWrite so the
// cost of moving from a bare keystream to AEAD is measurable, not guessed.
func BenchmarkRealityDataConnV2Write(b *testing.B) {
	var params RealityV2Params
	params.SharedSecret = []byte("bench-secret")
	params.ECDH = make([]byte, 32)

	conn, err := NewRealityDataConnV2(discardConn{}, params, true)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, realityV2MaxPlaintext) // one full record per Write
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// TestRealityV2TunnelPacketFitsOneSegment pins the on-wire cost of one
// MTU-sized tunnel packet, because the Poly1305 tag makes every record 16 bytes
// longer than it was under v1.
//
// The REALITY data layer is a byte stream under smux, so the tag cannot cause a
// blackhole the way an oversized frame can on a datagram-shaped transport - TCP
// segments and reassembles whatever it is handed. What the tag does eat is the
// headroom that keeps one tunnel packet inside one TCP segment. Crossing that
// boundary costs a second segment per packet, which is a throughput and latency
// regression, not a drop. This test makes the remaining headroom explicit so a
// later change that eats it fails here instead of on a relay.
//
// Chain per packet: IP packet (<= inner MTU) -> tunnel frame [len:4] ->
// smux frame header (8) -> one TLS record (5 header + body + 16 tag).
func TestRealityV2TunnelPacketFitsOneSegment(t *testing.T) {
	t.Parallel()

	const (
		tunnelLenPrefix = 4  // [length:4][data:N], internal/tun/vpn.go
		smuxHeader      = 8  // smux v1 rawHeader
		tlsHeader       = 5  // TLS record header
		tag             = 16 // chacha20poly1305.Overhead
		// TCP payload budget on a plain 1500-byte IPv4 path with timestamps:
		// 1500 - 20 (IP) - 20 (TCP) - 12 (timestamp option).
		mssWithTimestamps = 1448
	)

	cp, _ := negotiate(t, []byte("shared-secret"))

	tests := []struct {
		name     string
		innerMTU int
		wantWire int
	}{
		{"default 1280", 1280, 1280 + tunnelLenPrefix + smuxHeader + tlsHeader + tag},
		{"production 1400", 1400, 1400 + tunnelLenPrefix + smuxHeader + tlsHeader + tag},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wire bytes.Buffer
			conn, err := NewRealityDataConnV2(writeOnlyConn{Writer: &wire}, cp, true)
			if err != nil {
				t.Fatal(err)
			}
			// What smux hands the record layer for one full-MTU packet.
			smuxFrame := make([]byte, smuxHeader+tunnelLenPrefix+tt.innerMTU)
			if _, err := conn.Write(smuxFrame); err != nil {
				t.Fatal(err)
			}

			if wire.Len() != tt.wantWire {
				t.Fatalf("on-wire bytes = %d, want %d", wire.Len(), tt.wantWire)
			}
			if wire.Len() > mssWithTimestamps {
				t.Fatalf("one tunnel packet needs %d bytes, over the %d-byte TCP segment budget: "+
					"every packet now costs two segments", wire.Len(), mssWithTimestamps)
			}
			t.Logf("inner MTU %d: %d bytes on the wire, %d bytes of headroom left in one segment",
				tt.innerMTU, wire.Len(), mssWithTimestamps-wire.Len())
		})
	}
}
