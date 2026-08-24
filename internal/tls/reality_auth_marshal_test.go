package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"slices"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The AAD contract this whole scheme rests on.
//
// SealSessionID authenticates the ClientHello bytes, so the bytes the client
// sealed against and the bytes that reach the server must differ in the 32
// session_id bytes and nowhere else. That is not obviously true with uTLS:
// buildHandshakeState re-runs MarshalClientHello on every call, and
// HandshakeContext calls it again before the handshake, so the ClientHello is
// marshalled at least three times per connection.
//
// If any of those marshals were nondeterministic, the client's AAD would differ
// from the server's and authorization would fail — intermittently, per
// connection, with no useful diagnostic. Both failure modes below are silent in
// production, which is why they are pinned here rather than left to task 008's
// end-to-end capture.
//
// The load-bearing upstream detail is that GREASE ECH computes its payload once
// under a sync.Once and reuses it (u_ech.go), so a re-marshal reproduces it
// byte for byte. That matters specifically because our default profile is
// Firefox, which sends GREASE ECH.

// newTestUConn builds a uTLS client over a discarded pipe, the same way
// BuildClientHelloBytes does, so the ClientHello is realistic.
func newTestUConn(t *testing.T, profile string) (*utls.UConn, func()) {
	t.Helper()

	fp, ok := LookupFingerprint(profile)
	if !ok {
		t.Fatalf("profile %q does not resolve", profile)
	}
	client, server := net.Pipe()

	// B1 drops the padding extension entirely: the auth moves into session_id,
	// so paddingLen is 0 here on purpose.
	uconn, err := newUConn(client, &utls.Config{
		ServerName:         "github.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, fp, 0)
	if err != nil {
		client.Close()
		server.Close()
		t.Fatalf("newUConn: %v", err)
	}
	return uconn, func() { client.Close(); server.Close() }
}

// TestMarshalClientHelloIsDeterministic runs the exact client sequence from the
// B1 epic and checks the invariant on every iteration.
func TestMarshalClientHelloIsDeterministic(t *testing.T) {
	for _, profile := range []string{"firefox", "chrome", "safari"} {
		t.Run(profile, func(t *testing.T) {
			// 200 iterations: enough that a nondeterministic field with even a
			// modest chance of differing shows up rather than hiding until prod.
			for iteration := range 200 {
				uconn, cleanup := newTestUConn(t, profile)

				if err := uconn.BuildHandshakeState(); err != nil {
					cleanup()
					t.Fatalf("BuildHandshakeState: %v", err)
				}
				hello := uconn.HandshakeState.Hello

				// Step 2-3 of the epic sequence: zero session_id, re-marshal.
				hello.SessionId = make([]byte, AuthSessionIDLen)
				if err := uconn.MarshalClientHello(); err != nil {
					cleanup()
					t.Fatalf("MarshalClientHello (zeroed): %v", err)
				}
				aad := slices.Clone(hello.Raw)

				// Step 6-7: install the sealed session_id and re-marshal, the
				// way HandshakeContext would.
				sentinel := make([]byte, AuthSessionIDLen)
				if _, err := rand.Read(sentinel); err != nil {
					cleanup()
					t.Fatalf("rand: %v", err)
				}
				hello.SessionId = sentinel
				if err := uconn.MarshalClientHello(); err != nil {
					cleanup()
					t.Fatalf("MarshalClientHello (sealed): %v", err)
				}
				final := slices.Clone(hello.Raw)
				cleanup()

				if len(final) != len(aad) {
					t.Fatalf("iteration %d: re-marshal changed the ClientHello length %d -> %d; "+
						"the runtime length guard in the client must reject this", iteration, len(aad), len(final))
				}

				offset, err := SessionIDOffset(aad)
				if err != nil {
					t.Fatalf("iteration %d: SessionIDOffset on a real hello: %v", iteration, err)
				}

				// Everything outside session_id must be byte-identical.
				if !bytes.Equal(aad[:offset], final[:offset]) {
					t.Fatalf("iteration %d: bytes before session_id changed across marshals", iteration)
				}
				tail := offset + AuthSessionIDLen
				if !bytes.Equal(aad[tail:], final[tail:]) {
					t.Fatalf("iteration %d: bytes after session_id changed across marshals "+
						"(first differing offset %d)", iteration, tail+firstDiff(aad[tail:], final[tail:]))
				}
				// And session_id must actually carry what we installed,
				// otherwise the marshal is reading from somewhere other than
				// Hello.SessionId and the whole approach is wrong.
				if !bytes.Equal(final[offset:tail], sentinel) {
					t.Fatalf("iteration %d: session_id on the wire is not the value we set", iteration)
				}
			}
		})
	}
}

// TestMarshalledHelloCarriesTheEphemeralKey closes the loop between the two
// halves: the private key we seal with must be the one whose public half is in
// the marshalled key_share. A mismatch would make every server-side open fail.
func TestMarshalledHelloCarriesTheEphemeralKey(t *testing.T) {
	for _, profile := range []string{"firefox", "chrome"} {
		t.Run(profile, func(t *testing.T) {
			uconn, cleanup := newTestUConn(t, profile)
			defer cleanup()

			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState: %v", err)
			}
			hello := uconn.HandshakeState.Hello
			hello.SessionId = make([]byte, AuthSessionIDLen)
			if err := uconn.MarshalClientHello(); err != nil {
				t.Fatalf("MarshalClientHello: %v", err)
			}

			eph := clientEphemeral(t, uconn)
			onWire, err := ExtractPeerX25519(hello.Raw)
			if err != nil {
				t.Fatalf("ExtractPeerX25519: %v", err)
			}
			if !bytes.Equal(eph.PublicKey().Bytes(), onWire) {
				t.Fatal("the key_share on the wire does not match KeyShareKeys; " +
					"sealing with this key would never open on the server")
			}
		})
	}
}

// TestSealAgainstRealClientHello is the closest this package can get to the
// real thing without a socket: seal against an actual uTLS ClientHello, then
// open it the way the server will, from the marshalled bytes alone.
func TestSealAgainstRealClientHello(t *testing.T) {
	uconn, cleanup := newTestUConn(t, "firefox")
	defer cleanup()

	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	hello := uconn.HandshakeState.Hello
	hello.SessionId = make([]byte, AuthSessionIDLen)
	if err := uconn.MarshalClientHello(); err != nil {
		t.Fatalf("MarshalClientHello: %v", err)
	}
	aad := slices.Clone(hello.Raw)

	serverStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	want := samplePayload()

	sid, err := SealSessionID(clientEphemeral(t, uconn), serverStatic.PublicKey().Bytes(), aad, hello.Random, want)
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}

	// Put it on the wire and re-marshal, as HandshakeContext would.
	hello.SessionId = sid[:]
	if err := uconn.MarshalClientHello(); err != nil {
		t.Fatalf("MarshalClientHello: %v", err)
	}
	wire := slices.Clone(hello.Raw)

	// From here on, only the wire bytes — exactly what the server has.
	peerPub, err := ExtractPeerX25519(wire)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}
	gotSID, err := SessionIDFrom(wire)
	if err != nil {
		t.Fatalf("SessionIDFrom: %v", err)
	}
	zeroed, err := ZeroSessionID(wire)
	if err != nil {
		t.Fatalf("ZeroSessionID: %v", err)
	}
	random := helloRandom(wire)

	got, err := OpenSessionID(serverStatic.Bytes(), peerPub, zeroed, random, gotSID)
	if err != nil {
		t.Fatalf("OpenSessionID against a real ClientHello: %v", err)
	}
	if got != want {
		t.Fatalf("payload mismatch: got %+v, want %+v", got, want)
	}
}

// clientEphemeral mirrors what the client code will do: prefer the plain X25519
// private key, fall back to the hybrid group's X25519 half.
func clientEphemeral(t *testing.T, uconn *utls.UConn) *ecdh.PrivateKey {
	t.Helper()
	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		t.Fatal("no key share keys; the profile does not offer TLS 1.3")
	}
	if keys.Ecdhe != nil {
		return keys.Ecdhe
	}
	if keys.MlkemEcdhe != nil {
		return keys.MlkemEcdhe
	}
	t.Fatal("neither Ecdhe nor MlkemEcdhe is set")
	return nil
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
