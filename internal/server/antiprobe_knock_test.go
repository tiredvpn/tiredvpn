package server

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// buildKnock assembles the v2 knock wire bytes a client would send for a given
// nonce and bucket, using the exported strategy derivation the client itself
// uses. Restating the layout (not the crypto) here keeps the test honest about
// what it feeds the verifier.
func buildKnock(secret, nonce []byte, bucket int64) []byte {
	seq := strategy.KnockScheduleFor(secret, nonce, bucket)
	tag := strategy.KnockTag(secret, nonce, bucket)

	var buf []byte
	for i := 0; i < strategy.KnockPackets; i++ {
		pkt := make([]byte, seq.Sizes[i])
		pkt[0] = byte(i)
		if i == 0 {
			binary.BigEndian.PutUint64(pkt[1:9], uint64(bucket))
			copy(pkt[9:strategy.KnockHeaderLen], nonce)
			copy(pkt[strategy.KnockHeaderLen:strategy.KnockHeaderLen+strategy.KnockTagLen], tag)
			copy(pkt[strategy.KnockHeaderLen+strategy.KnockTagLen:], strategy.KnockBody(secret, nonce, bucket, 0, seq.Sizes[0]-strategy.KnockHeaderLen-strategy.KnockTagLen))
		} else {
			copy(pkt[1:], strategy.KnockBody(secret, nonce, bucket, i, seq.Sizes[i]-1))
		}
		buf = append(buf, pkt...)
	}
	return buf
}

// runVerify feeds knock bytes to verifyFullKnockSequence over a pipe and returns
// its verdict.
func runVerify(t *testing.T, srvCtx *serverContext, secret, knock []byte) bool {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(knock)
	}()
	return verifyFullKnockSequence(s, secret, srvCtx, log.WithPrefix("knock-test"))
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, strategy.KnockNonceLen)
	if _, err := rand.Read(n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestKnockReplayRejected is the replay-window test. A knock verifies once; the
// exact same bytes, replayed inside the window, must be rejected. A fresh nonce
// still passes.
//
// Predjavit slomannomu (verification rule 1): with the replay cache removed
// (checkAndRecord always returning true), the second call below passes and this
// test goes red. The v1 knock had no such cache and no nonce, so a captured
// knock replayed verbatim was always accepted.
func TestKnockReplayRejected(t *testing.T) {
	secret := []byte("knock-replay-secret")
	srvCtx := &serverContext{cfg: &Config{}}

	nonce := freshNonce(t)
	bucket := strategy.KnockBucketNow()
	knock := buildKnock(secret, nonce, bucket)

	if !runVerify(t, srvCtx, secret, knock) {
		t.Fatal("first knock did not verify")
	}
	if runVerify(t, srvCtx, secret, knock) {
		t.Fatal("a replayed knock was accepted; the replay window is not doing its job")
	}

	// A different nonce is a different connection and must still be let in.
	knock2 := buildKnock(secret, freshNonce(t), strategy.KnockBucketNow())
	if !runVerify(t, srvCtx, secret, knock2) {
		t.Fatal("a fresh-nonce knock was rejected")
	}
}

// TestKnockDetectAndStaleBucket checks the first-packet matcher: it accepts a
// fresh knock for the right secret, rejects the wrong secret, and rejects a
// knock whose bucket has drifted out of the freshness window (a stale replay).
func TestKnockDetectAndStaleBucket(t *testing.T) {
	secret := []byte("knock-detect-secret")
	nonce := freshNonce(t)
	bucket := strategy.KnockBucketNow()

	knock := buildKnock(secret, nonce, bucket)
	if !detectTimingKnock(knock, secret) {
		t.Fatal("a fresh knock was not detected for the right secret")
	}
	if detectTimingKnock(knock, []byte("a-different-secret")) {
		t.Fatal("the knock matched a secret it was not built with")
	}

	staleBucket := bucket - int64(strategy.KnockBucketGrace) - 5
	stale := buildKnock(secret, nonce, staleBucket)
	if detectTimingKnock(stale, secret) {
		t.Fatal("a knock with a stale bucket was accepted; the replay window is unbounded")
	}
}
