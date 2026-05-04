package presets

import (
	"bytes"
	"testing"
)

// newTestDistShaper builds a distShaper with deterministic constant size/delay
// so Wrap fragmentation is reproducible across runs without depending on the
// production preset histograms.
func newTestDistShaper(packetSize int) *distShaper {
	return &distShaper{
		sizeUp:    constDist(packetSize),
		sizeDown:  constDist(packetSize),
		delayUp:   constDist(0),
		delayDown: constDist(0),
		mtu:       defaultMTU,
	}
}

// TestDistShaper_Release_Roundtrip checks that buffers handed back via Release
// are reusable on the next Wrap and that the Wrap → Unwrap roundtrip still
// reconstructs the original payload byte-for-byte.
func TestDistShaper_Release_Roundtrip(t *testing.T) {
	d := newTestDistShaper(300)
	payload := bytes.Repeat([]byte("xyzzy-"), 1024) // ~6 KiB → many frames

	for range 8 {
		frames := d.Wrap(payload)
		got := d.Unwrap(frames)
		if !bytes.Equal(got, payload) {
			t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(payload))
		}
		d.Release(frames)
	}
}

// TestDistShaper_Release_MismatchedFramesIgnored: Release with a slice that
// does not match the most-recent Wrap output is a programmer error and is
// silently ignored — never panic, never corrupt the pool.
func TestDistShaper_Release_MismatchedFramesIgnored(t *testing.T) {
	d := newTestDistShaper(300)
	payload := bytes.Repeat([]byte{0xAA}, 256)
	frames := d.Wrap(payload)

	// Foreign slice with a different length triggers the mismatch branch.
	foreign := [][]byte{[]byte("not from wrap")}
	d.Release(foreign)

	// The original frames are still valid; Unwrap roundtrip must succeed.
	if got := d.Unwrap(frames); !bytes.Equal(got, payload) {
		t.Fatalf("frames corrupted after foreign Release")
	}
	d.Release(frames)
}

// TestDistShaper_Release_NilAndEmpty: Release(nil) and Release([]) are safe.
func TestDistShaper_Release_NilAndEmpty(t *testing.T) {
	d := newTestDistShaper(300)
	d.Release(nil)
	d.Release([][]byte{})
}

// TestDistShaper_Wrap_ReusesPooledBuffers: after Release, the next Wrap gets
// at least one buffer from the pool. We can detect reuse by checking that
// Wrap doesn't allocate every frame from scratch — verified via testing's
// AllocsPerRun helper.
func TestDistShaper_Wrap_ReusesPooledBuffers(t *testing.T) {
	d := newTestDistShaper(300)
	payload := bytes.Repeat([]byte{0x42}, 4096)

	// Warm the pool.
	for range 4 {
		d.Release(d.Wrap(payload))
	}

	allocs := testing.AllocsPerRun(50, func() {
		frames := d.Wrap(payload)
		d.Release(frames)
	})

	// Without pooling, ~14 frames × ~1 alloc/frame = >14 allocs. With the
	// pool warmed, allocs/op drops to a small constant dominated by
	// sync.Pool's internal per-P bookkeeping under -race; what matters is
	// that the per-frame buffer alloc is gone.
	if allocs > 10 {
		t.Fatalf("expected <=10 allocs/op after warmup, got %.1f", allocs)
	}
}

// TestDistShaper_EmptyPayload_Roundtrip: empty payload still produces a
// header-only frame that Unwrap turns back into nothing.
func TestDistShaper_EmptyPayload_Roundtrip(t *testing.T) {
	d := newTestDistShaper(300)
	frames := d.Wrap(nil)
	if len(frames) != 1 {
		t.Fatalf("Wrap(nil) returned %d frames, want 1", len(frames))
	}
	if got := d.Unwrap(frames); len(got) != 0 {
		t.Fatalf("empty payload roundtrip: got %d bytes, want 0", len(got))
	}
	d.Release(frames)
}
