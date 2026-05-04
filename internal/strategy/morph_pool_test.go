package strategy

import "testing"

// TestAcquirePacketBuf_Bucketing verifies that requested sizes route to the
// expected bucket index (and -1 for oversize requests).
func TestAcquirePacketBuf_Bucketing(t *testing.T) {
	cases := []struct {
		size   int
		bucket int
	}{
		{1, 0},
		{100, 0},
		{256, 0},
		{257, 1},
		{400, 1},
		{512, 1},
		{513, 2},
		{900, 2},
		{1024, 2},
		{1025, 3},
		{1500, 3},
		{1501, -1},
		{2000, -1},
		{8192, -1},
	}
	for _, c := range cases {
		buf, bucket := acquirePacketBuf(c.size)
		if bucket != c.bucket {
			t.Errorf("acquirePacketBuf(%d): bucket=%d, want %d", c.size, bucket, c.bucket)
		}
		if len(buf) != c.size {
			t.Errorf("acquirePacketBuf(%d): len=%d, want %d", c.size, len(buf), c.size)
		}
		releasePacketBuf(buf, bucket)
	}
}

// TestAcquirePacketBuf_ReturnsCapacityAtLeastRequested ensures the returned
// buffer's capacity covers the requested size for all buckets.
func TestAcquirePacketBuf_ReturnsCapacityAtLeastRequested(t *testing.T) {
	for _, size := range []int{1, 256, 257, 512, 513, 1024, 1025, 1500, 1501, 4096} {
		buf, bucket := acquirePacketBuf(size)
		if cap(buf) < size {
			t.Errorf("size=%d: cap(buf)=%d < requested %d", size, cap(buf), size)
		}
		// Bucketed allocations should sit at the bucket capacity exactly so
		// release routes them back into the matching pool.
		if bucket >= 0 && cap(buf) != packetBucketSizes[bucket] {
			t.Errorf("size=%d: cap(buf)=%d, want bucket cap %d",
				size, cap(buf), packetBucketSizes[bucket])
		}
		releasePacketBuf(buf, bucket)
	}
}

// TestReleasePacketBuf_RoundTrip checks that, over many iterations, a freed
// buffer comes back from the same bucket. sync.Pool is not deterministic, so
// we only assert "at least one round-trip succeeded" rather than per-iteration
// equality.
func TestReleasePacketBuf_RoundTrip(t *testing.T) {
	for bucket := range packetBucketSizes {
		size := packetBucketSizes[bucket]
		// Drain whatever was already pooled so the New constructor stops
		// shadowing real round-trips.
		for range 32 {
			b, bk := acquirePacketBuf(size)
			releasePacketBuf(b, bk)
		}

		seen := false
		for range 64 {
			b1, bk1 := acquirePacketBuf(size)
			if bk1 != bucket {
				t.Fatalf("size=%d routed to bucket %d, want %d", size, bk1, bucket)
			}
			ptr1 := &b1[:1][0]
			releasePacketBuf(b1, bk1)
			b2, bk2 := acquirePacketBuf(size)
			if bk2 != bucket {
				t.Fatalf("size=%d routed to bucket %d, want %d (after release)", size, bk2, bucket)
			}
			if &b2[:1][0] == ptr1 {
				seen = true
			}
			releasePacketBuf(b2, bk2)
			if seen {
				break
			}
		}
		if !seen {
			t.Errorf("bucket %d (size %d): never observed buffer reuse across release/acquire", bucket, size)
		}
	}
}

// TestReleasePacketBuf_NoopForOverflow verifies that bucket=-1 release is a
// safe no-op and does not panic or attempt to put oversized buffers into a
// pool.
func TestReleasePacketBuf_NoopForOverflow(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("release panicked: %v", r)
		}
	}()
	buf, bucket := acquirePacketBuf(8192)
	if bucket != -1 {
		t.Fatalf("expected oversize bucket=-1, got %d", bucket)
	}
	releasePacketBuf(buf, bucket)
	// Calling again should still be safe.
	releasePacketBuf(nil, -1)
	releasePacketBuf([]byte{}, -1)
}
