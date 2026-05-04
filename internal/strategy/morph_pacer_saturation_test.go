package strategy

import (
	"errors"
	"testing"
	"time"
)

// TestPacer_SaturationDoesNotDeadlock pumps 100 MiB through a slow shaper
// (5 ms per-frame target delay, capped to 50 ms by pacerMaxDelay) into a
// fast consumer. Under adaptive throttle the queue fills, factor → 0, and
// the producer must keep making progress. We assert completion within a
// generous bound; the test fails by timeout if the pacer ever deadlocks.
func TestPacer_SaturationDoesNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("perf-sensitive saturation test")
	}
	c := &countingConn{}
	p := newWritePacer(c, &constShaper{delay: 5 * time.Millisecond, size: 1500})

	const totalFrames = 100 * 1024 * 1024 / 1500 // ~100 MiB / 1500 B
	frame := make([]byte, 1500)

	doneCh := make(chan error, 1)
	go func() {
		for range totalFrames {
			if err := p.enqueue(pacedFrame{packet: frame, bucket: -1}); err != nil {
				doneCh <- err
				return
			}
		}
		doneCh <- nil
	}()

	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("enqueue failed under saturation: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("pacer deadlocked: enqueued %d/%d frames in 30s", c.Writes(), totalFrames)
	}
	p.close()
	if got := c.Writes(); int(got) != totalFrames {
		t.Fatalf("post-close writes = %d, want %d", got, totalFrames)
	}
}

// TestPacer_AdaptiveThrottle_Effective measures throughput in two phases:
// (1) a baseline burst that fills past the 50% throttle threshold so factor
// drops, then (2) a steady-state phase where the pacer should sustain
// throughput well above the unscaled per-frame rate. The assertion is that
// effective frames/sec under saturation greatly exceeds 1/delay (the rate a
// non-throttling pacer would deliver), confirming the throttle keeps the
// queue moving.
func TestPacer_AdaptiveThrottle_Effective(t *testing.T) {
	if testing.Short() {
		t.Skip("perf-sensitive throttle test")
	}
	c := &countingConn{}
	const perFrameDelay = 2 * time.Millisecond
	p := newWritePacer(c, &constShaper{delay: perFrameDelay, size: 1500})

	const N = 4096
	frame := make([]byte, 1500)
	start := time.Now()
	for range N {
		if err := p.enqueue(pacedFrame{packet: frame, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	elapsed := time.Since(start)

	// Without throttling the floor would be N * perFrameDelay = 4096 * 2ms ≈ 8.2s.
	// Under adaptive throttling effective rate must exceed 5× that floor.
	naive := time.Duration(N) * perFrameDelay
	if elapsed > naive/5 {
		t.Fatalf("throttle ineffective: elapsed=%v, naive=%v (want < naive/5)", elapsed, naive)
	}
	if got := c.Writes(); int(got) != N {
		t.Fatalf("writes=%d, want %d", got, N)
	}
}

// TestPacer_OverflowReturnsError pins the contract documented in ADR §7:
// when the upstream cannot drain for longer than pacerEnqueueTimeout (1s),
// enqueue returns ErrShaperOverflow rather than blocking the producer
// forever. We hold the consumer wedged by gating Conn.Write so even with a
// zero shaper delay the queue can't move; this is the same condition a real
// downstream stall would create.
func TestPacer_OverflowReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("uses 1s+ wallclock for the overflow timer")
	}
	c := &countingConn{}
	gate := make(chan struct{})
	c.blockWrite = gate
	p := newWritePacer(c, &constShaper{delay: 0, size: 1})

	frame := []byte{0}
	// Fill: pacerQueueCap in the channel plus up to maxCoalesceFrames the
	// pacer goroutine has pulled into its local writev vector while blocked
	// on the gated Conn.Write.
	for range pacerQueueCap + maxCoalesceFrames {
		if err := p.enqueue(pacedFrame{packet: frame, bucket: -1}); err != nil {
			t.Fatalf("fill: %v", err)
		}
	}
	start := time.Now()
	err := p.enqueue(pacedFrame{packet: frame, bucket: -1})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrShaperOverflow) {
		t.Fatalf("got %v, want ErrShaperOverflow", err)
	}
	if elapsed < pacerEnqueueTimeout || elapsed > pacerEnqueueTimeout+750*time.Millisecond {
		t.Fatalf("elapsed %v outside [%v, +750ms]", elapsed, pacerEnqueueTimeout)
	}
	close(gate)
	p.close()
}
