package strategy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/geneva"
)

// S21: the seqovl strategy rides its own REALITY handshake. It must share the
// parent REALITY's handshake gate and SNI rotator instead of standing up a
// second set - otherwise the per-SNI "at most two handshakes" ceiling doubles
// to four and the rotators walk out of step. The packet-level marker must carry
// a nonce so it is not the same bytes on every connection.

func TestSeqovlSharesRealityGateAndRotator(t *testing.T) {
	t.Parallel()
	m := &Manager{}
	secret := []byte("seqovl-share-secret")

	seq := NewSeqovlStrategy(m, secret, false)
	baseline := NewREALITYStrategy(m, secret)

	if seq.reality.gate != baseline.gate {
		t.Fatal("seqovl uses a separate handshake gate; the per-SNI ceiling doubles")
	}
	if seq.reality.sniRotator != baseline.sniRotator {
		t.Fatal("seqovl uses a separate SNI rotator; rotation is uncoordinated")
	}

	// A REALITY strategy on a *different* Manager must NOT share, so the sharing
	// is scoped to one client process and not a global accident.
	other := NewREALITYStrategy(&Manager{}, secret)
	if other.gate == baseline.gate {
		t.Fatal("gate leaked across managers")
	}
}

func TestSeqovlPacketMarkerNonceBound(t *testing.T) {
	t.Parallel()
	secret := []byte("seqovl-packet-secret")

	n1 := []byte("nonceAAA") // exactly seqovlPacketNonceLen (8) bytes
	n2 := []byte("nonceBBB")

	m1 := seqovlPacketMarker(secret, n1)
	m2 := seqovlPacketMarker(secret, n2)

	if len(m1) != geneva.OverlapMarkerLen {
		t.Fatalf("marker length %d, want %d", len(m1), geneva.OverlapMarkerLen)
	}
	// Different nonces -> different markers: no single static value on every
	// connection's fake segments.
	if bytes.Equal(m1, m2) {
		t.Fatal("packet marker does not depend on the nonce")
	}

	// The marker is self-describing: [nonce][HMAC(secret, salt||nonce)]. A server
	// dropper recomputes the MAC over the embedded nonce, so verify that shape.
	if !bytes.Equal(m1[:seqovlPacketNonceLen], n1) {
		t.Fatal("marker does not carry the nonce prefix")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(seqovlPacketSalt))
	mac.Write(n1)
	want := mac.Sum(nil)[:geneva.OverlapMarkerLen-seqovlPacketNonceLen]
	if !hmac.Equal(m1[seqovlPacketNonceLen:], want) {
		t.Fatal("marker MAC does not verify over the embedded nonce")
	}

	// Wrong secret must not verify.
	if bytes.Equal(m1, seqovlPacketMarker([]byte("wrong-secret"), n1)) {
		t.Fatal("marker verifies under a different secret")
	}
}
