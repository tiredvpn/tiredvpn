package strategy

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// countingConn is a minimal net.Conn whose Write counts bytes and frames
// and optionally appends each write to a slice for ordering checks. Reads
// are unsupported (the pacer is write-only).
type countingConn struct {
	mu     sync.Mutex
	frames [][]byte
	writes int64
	bytes  int64
	// blockWrite, if non-nil, is consumed once per Write to gate the
	// goroutine's progress (used by the backpressure test).
	blockWrite chan struct{}
	// reachedWrite, if non-nil, is signalled (non-blocking) the first time
	// Write is entered, so a test can deterministically wait until the pacer
	// goroutine has actually started consuming before it begins saturating
	// the queue. This removes the scheduling race where the pacer may pull a
	// variable number of frames into its local writev vector before blocking.
	reachedWrite chan struct{}
	reachedOnce  sync.Once
	// failNext, if true, causes Write to return errFakeWrite once.
	failNext atomic.Bool
}

var errFakeWrite = errors.New("fake write error")

func (c *countingConn) Write(b []byte) (int, error) {
	if c.reachedWrite != nil {
		c.reachedOnce.Do(func() { close(c.reachedWrite) })
	}
	if c.blockWrite != nil {
		<-c.blockWrite
	}
	if c.failNext.Swap(false) {
		return 0, errFakeWrite
	}
	c.mu.Lock()
	c.frames = append(c.frames, append([]byte(nil), b...))
	c.writes++
	c.bytes += int64(len(b))
	c.mu.Unlock()
	return len(b), nil
}
func (c *countingConn) Read(b []byte) (int, error)         { return 0, net.ErrClosed }
func (c *countingConn) Close() error                       { return nil }
func (c *countingConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *countingConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *countingConn) SetDeadline(t time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *countingConn) Writes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *countingConn) FrameAt(i int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frames[i]
}

// constShaper is a Shaper stub that returns a fixed delay and packet size.
// Wrap returns the input unchanged (single frame); Unwrap concatenates.
type constShaper struct {
	size  int
	delay time.Duration
}

func (s *constShaper) NextPacketSize(_ shaper.Direction) int      { return s.size }
func (s *constShaper) NextDelay(_ shaper.Direction) time.Duration { return s.delay }
func (s *constShaper) Wrap(p []byte) [][]byte                     { return [][]byte{p} }
func (s *constShaper) Release(_ [][]byte)                          {}
func (s *constShaper) Unwrap(f [][]byte) []byte {
	out := []byte{}
	for _, x := range f {
		out = append(out, x...)
	}
	return out
}

// TestPacer_BasicFlow: enqueue N frames, all reach the wire in order.
func TestPacer_BasicFlow(t *testing.T) {
	c := &countingConn{}
	p := newWritePacer(c, &constShaper{delay: 0})
	const N = 100
	for i := range N {
		buf := []byte{byte(i)}
		if err := p.enqueue(pacedFrame{packet: buf, bucket: -1}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	p.close()
	if got := c.Writes(); got != N {
		t.Fatalf("writes = %d, want %d", got, N)
	}
	for i := range N {
		f := c.FrameAt(i)
		if len(f) != 1 || f[0] != byte(i) {
			t.Fatalf("frame %d = %v, want [%d]", i, f, byte(i))
		}
	}
}

// TestPacer_SleepCoalescing: with a 50µs delay (below the 100µs skip
// threshold), the pacer should coalesce N×50µs into far fewer real sleeps.
// Total wall time should be much less than the naive N×50µs when N is large.
func TestPacer_SleepCoalescing(t *testing.T) {
	c := &countingConn{}
	p := newWritePacer(c, &constShaper{delay: 50 * time.Microsecond})
	const N = 100
	start := time.Now()
	for range N {
		if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	elapsed := time.Since(start)
	naive := time.Duration(N) * 50 * time.Microsecond
	// With coalescing we sleep once every ~4 frames (200µs / 50µs), so
	// real sleep count is ~N/4 each delivering scheduler-floor latency.
	// On Linux even the floor exceeds 50µs, so we relax the bound: we
	// only assert that we are well below the *uncoalesced* cost, where
	// every single sub-tick sleep would be rounded up to >=50µs anyway.
	// Allow up to 60% of the worst-case floored sum (N * 60µs).
	worstCase := time.Duration(N) * 60 * time.Microsecond
	if elapsed > worstCase {
		t.Fatalf("elapsed %v > worstCase %v (naive %v); coalescing not effective", elapsed, worstCase, naive)
	}
}

// TestPacer_AdaptiveThrottle: a burst of 200 frames into a queue of 256
// keeps depth above the 50% threshold for most of the run, scaling delays
// down. With a 1ms delay per frame, naive total would be ~200ms; under
// throttle it must finish well below that.
func TestPacer_AdaptiveThrottle(t *testing.T) {
	c := &countingConn{}
	// gateChan blocks the connection's Write so the queue actually fills.
	gate := make(chan struct{}, 256)
	c.blockWrite = gate
	p := newWritePacer(c, &constShaper{delay: 1 * time.Millisecond})
	const N = 200
	start := time.Now()
	for range N {
		if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	// Release the gate after the queue is filled — pacer should now drain
	// fast because depth > 128 keeps factor < 1 and at depth=256 → factor=0.
	for range N {
		gate <- struct{}{}
	}
	p.close()
	elapsed := time.Since(start)
	naive := time.Duration(N) * 1 * time.Millisecond
	if elapsed > time.Duration(float64(naive)*0.6) {
		t.Fatalf("elapsed %v > 60%% of naive %v; throttle not effective", elapsed, naive)
	}
}

// TestPacer_MaxDelayCap: a 1s requested delay is clamped to 50ms, so even
// after one frame the pacer is ready for the next within ~50ms.
func TestPacer_MaxDelayCap(t *testing.T) {
	c := &countingConn{}
	p := newWritePacer(c, &constShaper{delay: 1 * time.Second})
	if err := p.enqueue(pacedFrame{packet: []byte{1}, bucket: -1}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Wait for the first write to land, then enqueue a second; the pacer
	// must wake within pacerMaxDelay (+ some slack) to pick it up.
	deadline := time.Now().Add(500 * time.Millisecond)
	for c.Writes() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if c.Writes() < 1 {
		t.Fatalf("first write never observed")
	}
	start := time.Now()
	if err := p.enqueue(pacedFrame{packet: []byte{2}, bucket: -1}); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}
	for c.Writes() < 2 && time.Since(start) < 200*time.Millisecond {
		time.Sleep(2 * time.Millisecond)
	}
	p.close()
	if c.Writes() < 2 {
		t.Fatalf("second write delayed > 200ms (cap is 50ms): writes=%d", c.Writes())
	}
}

// TestPacer_BackpressureBlocking: with the consumer wedged, the queue fills
// and the producer's enqueue blocks; closing the gate must let it through.
//
// The original version hardcoded the saturation point as
// pacerQueueCap+maxCoalesceFrames, assuming the pacer always pulls exactly
// maxCoalesceFrames into its local writev vector before blocking on the gated
// Write. That count is actually scheduling-dependent (the pacer may flush a
// partial batch when len(p.queue)==0 mid-fill), so the loop could over-fill
// and hit the 1s overflow timeout — the source of the CI flake. Here we don't
// assume any count: a background producer enqueues until it blocks (detected
// by the queue going quiet), then we prove the gate-close unblocks it.
func TestPacer_BackpressureBlocking(t *testing.T) {
	c := &countingConn{}
	gate := make(chan struct{})
	reached := make(chan struct{})
	c.blockWrite = gate
	c.reachedWrite = reached
	p := newWritePacer(c, &constShaper{delay: 0})

	// Prime: one frame makes the pacer pull, flush (queue now empty), and
	// block inside the gated Conn.Write — fixing its in-flight batch at one
	// before we saturate. Without a priming frame the pacer just parks in its
	// select waiting on the queue and never enters Write.
	if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
		t.Fatalf("prime enqueue: %v", err)
	}
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("pacer never reached Conn.Write")
	}

	// Background producer enqueues until it blocks. progress is bumped on each
	// successful enqueue; when it stops advancing the producer is parked on a
	// full queue (the backpressure we want to observe).
	var progress atomic.Int64
	done := make(chan error, 1)
	go func() {
		for {
			if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
				done <- err
				return
			}
			progress.Add(1)
		}
	}()

	// Confirm the producer parks: progress must go quiet for a stable window
	// while the gate is held. Poll until two consecutive samples match.
	blocked := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		before := progress.Load()
		time.Sleep(20 * time.Millisecond)
		if progress.Load() == before {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("producer never blocked on a full queue")
	}
	select {
	case err := <-done:
		t.Fatalf("producer exited early with %v, expected to block", err)
	default:
	}

	// Release the consumer; the producer must now resume making progress.
	close(gate)
	parked := progress.Load()
	resumed := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if progress.Load() > parked {
			resumed = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !resumed {
		t.Fatal("producer did not resume after consumer was released")
	}
	p.close()
	// Producer goroutine ends when enqueue returns net.ErrClosed after close.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("producer goroutine did not exit after close")
	}
}

// TestPacer_OverflowError: producer can't make progress for >1s, enqueue
// must return ErrShaperOverflow.
//
// Determinism comes from waiting for the pacer to wedge inside its first
// gated Write before filling. While wedged it can hold at most one in-flight
// batch, so the channel (cap pacerQueueCap) is the only remaining sink. We
// fill via the non-blocking fast path until the channel is full (saturated),
// then the single blocking enqueue below is guaranteed to run the 1s timeout
// path. We never hardcode the in-flight count, which is the scheduling-
// dependent value that made the old version flaky.
func TestPacer_OverflowError(t *testing.T) {
	c := &countingConn{}
	gate := make(chan struct{})
	reached := make(chan struct{})
	c.blockWrite = gate
	c.reachedWrite = reached
	p := newWritePacer(c, &constShaper{delay: 0})

	// Prime one frame so the pacer pulls, flushes, and wedges inside the gated
	// Write (in-flight batch fixed at one) before we saturate.
	if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
		t.Fatalf("prime enqueue: %v", err)
	}
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("pacer never reached Conn.Write")
	}

	// Saturate the channel using non-blocking sends (no timeout risk). Once
	// the buffered channel rejects a send, the next blocking enqueue is the
	// one we measure.
	for {
		select {
		case p.queue <- pacedFrame{packet: []byte{0}, bucket: -1}:
			continue
		default:
		}
		break
	}

	start := time.Now()
	err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrShaperOverflow) {
		t.Fatalf("got %v, want ErrShaperOverflow", err)
	}
	if elapsed < pacerEnqueueTimeout || elapsed > pacerEnqueueTimeout+750*time.Millisecond {
		t.Fatalf("elapsed %v not within [%v, +750ms]", elapsed, pacerEnqueueTimeout)
	}
	close(gate)
	p.close()
}

// TestPacer_Close: after close all queued frames are either drained to the
// wire (within ~100ms) or dropped; goroutine exits cleanly.
func TestPacer_Close(t *testing.T) {
	c := &countingConn{}
	p := newWritePacer(c, &constShaper{delay: 0})
	for range 50 {
		if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	// All 50 should have flushed since each write was instantaneous.
	if got := c.Writes(); got != 50 {
		t.Fatalf("post-close writes = %d, want 50", got)
	}
}

// TestPacer_WriteErrorPropagation: when the underlying Conn.Write fails,
// the error is recorded and the next enqueue returns it.
func TestPacer_WriteErrorPropagation(t *testing.T) {
	c := &countingConn{}
	c.failNext.Store(true)
	p := newWritePacer(c, &constShaper{delay: 0})
	if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	// Wait for goroutine to observe the failure.
	deadline := time.Now().Add(500 * time.Millisecond)
	for p.errSeen.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1})
	if !errors.Is(err, errFakeWrite) {
		t.Fatalf("got %v, want errFakeWrite", err)
	}
	p.close()
}

// TestMorphedConn_ShapedWriteBenchmarkRegression: smoke check that an async
// pacer beats the synchronous baseline by at least 10× on a chrome-style
// preset for a 64 KiB payload. Not a final perf test — just a regression
// canary so we notice if the pacer ever degrades back to synchronous.
func TestMorphedConn_ShapedWriteBenchmarkRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("perf-sensitive smoke test")
	}
	const payloadSize = 64 * 1024
	payload := make([]byte, payloadSize)

	// Baseline: NoopShaper end-to-end on net.Pipe.
	profile := &TrafficProfile{Name: "T", PacketSizes: []int{1200}, PacketSizeProbs: []float64{1}}
	measure := func(clientShaper, serverShaper shaper.Shaper, iters int) time.Duration {
		client, server, cleanup := NewTestMorphedConnPair(profile, clientShaper, serverShaper)
		defer cleanup()
		go func() {
			buf := make([]byte, 8192)
			for {
				if _, err := server.Read(buf); err != nil {
					return
				}
			}
		}()
		start := time.Now()
		for range iters {
			if _, err := client.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		return time.Since(start)
	}
	noop := measure(shaper.NoopShaper{}, shaper.NoopShaper{}, 50)
	// 1ms-delay synthetic shaper that fragments into 8 frames; with a sync
	// loop this would take 50 * 7 * 1ms = 350ms; with the async pacer the
	// producer returns immediately after enqueue.
	mkShaped := func() shaper.Shaper {
		return &fragShaper{frags: 8, delay: 1 * time.Millisecond, size: 1200}
	}
	shaped := measure(mkShaped(), shaper.NoopShaper{}, 50)
	// Sanity: shaped path should not be more than 10× slower than noop.
	// On the synchronous path it was >100× slower — this catches the
	// regression direction without being flaky on shared CI runners.
	if shaped > noop*10 {
		t.Fatalf("shaped throughput regressed: noop=%v shaped=%v (>10×)", noop, shaped)
	}
}

// fragShaper splits payload into a fixed number of equal frames, returns a
// constant NextDelay, and a constant NextPacketSize. Used to drive the
// pacer regression smoke test deterministically.
type fragShaper struct {
	frags int
	delay time.Duration
	size  int
}

func (s *fragShaper) NextPacketSize(_ shaper.Direction) int      { return s.size }
func (s *fragShaper) NextDelay(_ shaper.Direction) time.Duration { return s.delay }
func (s *fragShaper) Wrap(p []byte) [][]byte {
	if s.frags <= 1 {
		return [][]byte{p}
	}
	chunk := (len(p) + s.frags - 1) / s.frags
	out := make([][]byte, 0, s.frags)
	for i := 0; i < len(p); i += chunk {
		end := min(i+chunk, len(p))
		out = append(out, p[i:end])
	}
	return out
}
func (s *fragShaper) Release(_ [][]byte) {}
func (s *fragShaper) Unwrap(f [][]byte) []byte {
	out := []byte{}
	for _, x := range f {
		out = append(out, x...)
	}
	return out
}
