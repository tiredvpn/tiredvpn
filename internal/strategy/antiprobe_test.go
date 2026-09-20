package strategy

import (
	"bytes"
	"testing"
	"time"
)

// The v2 knock derives its schedule and bodies from a per-connection nonce and
// a time bucket, not from the secret alone. These tests pin the new shape:
// deterministic given (secret, nonce, bucket), different for a different nonce,
// and within the documented ranges. The "two dials differ" claim on the wire is
// in internal/wiretest (TestAntiProbeKnockVariesPerConnection); the replay
// window is in internal/server (TestKnockReplayRejected).

func testNonce(b byte) []byte {
	n := make([]byte, KnockNonceLen)
	for i := range n {
		n[i] = b + byte(i)
	}
	return n
}

// TestKnockScheduleShape checks the sizes and delays land in their documented
// ranges. There is no measured donor distribution to check the shape against
// (verification rule 3, recorded in antiprobe.go): this only pins the range.
func TestKnockScheduleShape(t *testing.T) {
	secret := []byte("test-secret-key")
	seq := knockSchedule(secret, testNonce(1), KnockBucketNow())

	if len(seq.Delays) != KnockPackets {
		t.Fatalf("expected %d delays, got %d", KnockPackets, len(seq.Delays))
	}
	if len(seq.Sizes) != KnockPackets {
		t.Fatalf("expected %d sizes, got %d", KnockPackets, len(seq.Sizes))
	}
	for i, d := range seq.Delays {
		ms := d.Milliseconds()
		if ms < knockDelayMinMs || ms >= knockDelayMinMs+knockDelaySpanMs {
			t.Errorf("delay %d: %dms outside [%d,%d)", i, ms, knockDelayMinMs, knockDelayMinMs+knockDelaySpanMs)
		}
	}
	for i, s := range seq.Sizes {
		if s < knockSizeMin || s >= knockSizeMin+knockSizeSpan {
			t.Errorf("size %d: %d outside [%d,%d)", i, s, knockSizeMin, knockSizeMin+knockSizeSpan)
		}
		// Packet 0 must have room for the header and the tag.
		if i == 0 && s < KnockHeaderLen+KnockTagLen {
			t.Errorf("size 0 = %d cannot hold header(%d)+tag(%d)", s, KnockHeaderLen, KnockTagLen)
		}
	}
}

// TestKnockDeterministicGivenNonce checks the derivation is a pure function of
// (secret, nonce, bucket): the server must be able to recompute exactly what the
// client sent.
func TestKnockDeterministicGivenNonce(t *testing.T) {
	secret := []byte("deterministic-secret")
	nonce := testNonce(7)
	bucket := KnockBucketNow()

	a := knockSchedule(secret, nonce, bucket)
	b := knockSchedule(secret, nonce, bucket)
	for i := range a.Sizes {
		if a.Sizes[i] != b.Sizes[i] || a.Delays[i] != b.Delays[i] {
			t.Fatalf("schedule not deterministic at %d", i)
		}
	}
	if !bytes.Equal(KnockTag(secret, nonce, bucket), KnockTag(secret, nonce, bucket)) {
		t.Fatal("tag not deterministic")
	}
	if !bytes.Equal(KnockBody(secret, nonce, bucket, 2, 40), KnockBody(secret, nonce, bucket, 2, 40)) {
		t.Fatal("body not deterministic")
	}
}

// TestKnockVariesWithNonce is the core of the v2 fix: the same secret with a
// different nonce yields a different schedule, tag and bodies. This is what
// stops two dials of one client from repeating on the wire.
func TestKnockVariesWithNonce(t *testing.T) {
	secret := []byte("same-secret")
	bucket := KnockBucketNow()
	n1, n2 := testNonce(1), testNonce(200)

	s1 := knockSchedule(secret, n1, bucket)
	s2 := knockSchedule(secret, n2, bucket)
	sameSizes := true
	for i := range s1.Sizes {
		if s1.Sizes[i] != s2.Sizes[i] {
			sameSizes = false
			break
		}
	}
	if sameSizes {
		t.Error("two nonces produced identical packet sizes")
	}

	if bytes.Equal(KnockTag(secret, n1, bucket), KnockTag(secret, n2, bucket)) {
		t.Error("two nonces produced identical tags")
	}
	if bytes.Equal(KnockBody(secret, n1, bucket, 0, 32), KnockBody(secret, n2, bucket, 0, 32)) {
		t.Error("two nonces produced identical bodies")
	}
}

// TestKnockVariesWithSecret keeps the old guarantee: a different secret still
// yields a different tag.
func TestKnockVariesWithSecret(t *testing.T) {
	nonce := testNonce(9)
	bucket := KnockBucketNow()
	if bytes.Equal(KnockTag([]byte("secret-one"), nonce, bucket), KnockTag([]byte("secret-two"), nonce, bucket)) {
		t.Error("different secrets produced identical tags")
	}
}

// TestKnockBucketFreshWindow checks the bucket freshness window matches the
// documented grace.
func TestKnockBucketFreshWindow(t *testing.T) {
	now := KnockBucketNow()
	for off := int64(-KnockBucketGrace); off <= KnockBucketGrace; off++ {
		if !KnockBucketFresh(now + off) {
			t.Errorf("bucket at offset %d should be fresh", off)
		}
	}
	if KnockBucketFresh(now - KnockBucketGrace - 1) {
		t.Error("stale bucket accepted (too old)")
	}
	if KnockBucketFresh(now + KnockBucketGrace + 1) {
		t.Error("bucket accepted (too far ahead)")
	}
}

func TestAntiProbeTimingWindow(t *testing.T) {
	strat := NewAntiProbeStrategy(NewManager(), []byte("secret"))
	if strat.timingWindow != 100*time.Millisecond {
		t.Errorf("expected timing window 100ms, got %v", strat.timingWindow)
	}
}

func TestAntiProbeStrategyMetadata(t *testing.T) {
	strat := NewAntiProbeStrategy(NewManager(), []byte("secret"))
	if strat.Name() == "" {
		t.Error("Name should not be empty")
	}
	if strat.ID() != "antiprobe" {
		t.Errorf("expected ID 'antiprobe', got %s", strat.ID())
	}
	if strat.Priority() < 0 || strat.Priority() > 100 {
		t.Errorf("priority %d out of range", strat.Priority())
	}
	if strat.Description() == "" {
		t.Error("Description should not be empty")
	}
	if !strat.RequiresServer() {
		t.Error("AntiProbe requires server")
	}
}
