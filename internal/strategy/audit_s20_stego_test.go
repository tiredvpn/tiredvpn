package strategy

import (
	"crypto/hmac"
	"net"
	"testing"
	"time"
)

// S20: the stego auth token must accept adjacent minute buckets (so a client
// whose clock drifts by up to a minute still authenticates) and compare
// constant-time; the server's ack proof must be bound to a per-connection nonce
// instead of one static value for the life of the secret.

func TestVerifyAuthTokenAcceptsAdjacentBuckets(t *testing.T) {
	t.Parallel()
	secret := []byte("stego-skew-secret")
	ekm := []byte("session-exporter-material-32bytes!!")
	now := time.Now().Unix() / 60

	// Tokens minted for now-1, now, now+1 must all verify: a client one bucket
	// off from the server is exactly the clock-skew case this fixes.
	for _, off := range []int64{-1, 0, 1} {
		tok := generateAuthTokenBoundAt(secret, ekm, uint64(now+off))
		if !verifyAuthTokenBound(secret, ekm, tok) {
			t.Fatalf("token for bucket now%+d was rejected", off)
		}
	}

	// Two buckets away is outside the window and must be rejected - otherwise
	// "accept adjacent" would just be "accept everything recent".
	for _, off := range []int64{-2, 2} {
		tok := generateAuthTokenBoundAt(secret, ekm, uint64(now+off))
		if verifyAuthTokenBound(secret, ekm, tok) {
			t.Fatalf("token for bucket now%+d was accepted; window too wide", off)
		}
	}

	// A token under the wrong secret never verifies.
	if verifyAuthTokenBound(secret, ekm, generateAuthTokenBoundAt([]byte("other"), ekm, uint64(now))) {
		t.Fatal("token under a different secret verified")
	}
}

// TestVerifyAuthTokenBindsToSession is the S22 session-binding guard for the
// shared strategy token: a token minted on one TLS session's exporter must be
// rejected on another. Predelivered to the pre-binding code (ekm dropped from
// the HMAC) this fails, because the token would then be portable across
// sessions.
func TestVerifyAuthTokenBindsToSession(t *testing.T) {
	t.Parallel()
	secret := []byte("stego-bind-secret")
	ekmA := []byte("exporter-session-A-0123456789abcdef")
	ekmB := []byte("exporter-session-B-0123456789abcdef")

	tokA := generateAuthTokenBound(secret, ekmA)

	if !verifyAuthTokenBound(secret, ekmA, tokA) {
		t.Fatal("token minted on session A was rejected on session A")
	}
	if verifyAuthTokenBound(secret, ekmB, tokA) {
		t.Fatal("token minted on session A verified on session B; not session-bound")
	}
}

func TestServerAckProofIsNonceBound(t *testing.T) {
	t.Parallel()
	secret := []byte("stego-ack-secret")

	n1 := []byte("nonce-aaa")
	n2 := []byte("nonce-bbb")

	p1 := serverAckMaterial(secret, n1)[:16]
	p2 := serverAckMaterial(secret, n2)[:16]

	// Different connections carry different nonces, so their proofs differ.
	if hmac.Equal(p1, p2) {
		t.Fatal("ack proof does not depend on the nonce (same for two connections)")
	}
	// Deterministic given the nonce, so the peer can verify it.
	if !hmac.Equal(p1, serverAckMaterial(secret, n1)[:16]) {
		t.Fatal("ack proof is not reproducible for a fixed nonce")
	}

	// The pre-fix proof was the static deriveKey(secret,"server-ack"); the
	// nonce-bound proof must not collapse back to it.
	static := deriveKey(secret, "server-ack")[:16]
	if hmac.Equal(p1, static) {
		t.Fatal("nonce-bound ack proof still equals the old static value")
	}
}

// TestStegoHandshakeE2E runs the real client and server handshake roles over a
// loopback TCP pair. It exercises the whole path - token generation and
// skew-tolerant verify, plus the nonce-bound ack round-trip - and would fail if
// the client and server disagreed on the ack format.
func TestStegoHandshakeE2E(t *testing.T) {
	t.Parallel()
	secret := []byte("stego-e2e-secret")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer raw.Close()
		s := NewHTTP2StegoConn(raw, secret, false, NaivePaddingMinimal, nil)
		srvErr <- s.Handshake()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := NewHTTP2StegoConn(raw, secret, true, NaivePaddingMinimal, nil)
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}
}
