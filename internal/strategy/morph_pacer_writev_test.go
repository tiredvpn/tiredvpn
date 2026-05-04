package strategy

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// batchConn is a placeholder net.Conn whose Write must never be called —
// tests inject a writev hook into writePacer that records vectored writes
// directly, so the pacer's per-frame Conn.Write code path is bypassed.
type batchConn struct {
	mu      sync.Mutex
	batches [][][]byte
	bytes   atomic.Int64
}

func (c *batchConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *batchConn) Read(b []byte) (int, error)         { return 0, net.ErrClosed }
func (c *batchConn) Close() error                       { return nil }
func (c *batchConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *batchConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *batchConn) SetDeadline(t time.Time) error      { return nil }
func (c *batchConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *batchConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *batchConn) snapshot() [][][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][][]byte, len(c.batches))
	copy(out, c.batches)
	return out
}

// newBatchPacer wires up a writePacer with a writev hook that records each
// vectored write as a distinct batch on c. Equivalent to newWritePacer
// otherwise.
func newBatchPacer(c *batchConn, sh shaper.Shaper) *writePacer {
	return newWritePacerWithWritev(c, sh, func(bufs *net.Buffers) (int64, error) {
		c.mu.Lock()
		batch := make([][]byte, 0, len(*bufs))
		var n int64
		for _, b := range *bufs {
			batch = append(batch, append([]byte(nil), b...))
			n += int64(len(b))
		}
		c.batches = append(c.batches, batch)
		c.mu.Unlock()
		c.bytes.Add(n)
		*bufs = (*bufs)[len(*bufs):]
		return n, nil
	})
}

// scriptedShaper returns delays from a script (in order); falls back to the
// last value once exhausted. Used to construct precise sub-tick / tick
// boundaries in tests.
type scriptedShaper struct {
	mu     sync.Mutex
	script []time.Duration
	idx    int
}

func (s *scriptedShaper) NextPacketSize(_ shaper.Direction) int { return 1200 }
func (s *scriptedShaper) NextDelay(_ shaper.Direction) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx < len(s.script) {
		d := s.script[s.idx]
		s.idx++
		return d
	}
	if len(s.script) == 0 {
		return 0
	}
	return s.script[len(s.script)-1]
}
func (s *scriptedShaper) Wrap(p []byte) [][]byte { return [][]byte{p} }
func (s *scriptedShaper) Release(_ [][]byte)     {}
func (s *scriptedShaper) Unwrap(f [][]byte) []byte {
	out := []byte{}
	for _, x := range f {
		out = append(out, x...)
	}
	return out
}

// TestPacer_Coalesce_BatchesFrames: a burst of sub-tick frames followed by
// frames whose accumulated delay crosses the sleep floor must coalesce into
// fewer batches than the frame count. We accept any batching ≥ 1 as long as
// the average batch size is meaningfully > 1 — that's the win.
func TestPacer_Coalesce_BatchesFrames(t *testing.T) {
	c := &batchConn{}
	// 60 sub-tick frames (10µs each) trigger sleep-floor flushes every
	// ~20 frames (200µs / 10µs); plus the vector cap caps any single batch
	// at 32. So we expect a handful of batches, not 60.
	script := make([]time.Duration, 60)
	for i := range script {
		script[i] = 10 * time.Microsecond
	}
	sh := &scriptedShaper{script: script}
	p := newBatchPacer(c, sh)
	const N = 60
	for i := range N {
		if err := p.enqueue(pacedFrame{packet: []byte{byte(i)}, bucket: -1}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	p.close()

	bs := c.snapshot()
	total := 0
	for _, b := range bs {
		total += len(b)
		if len(b) > maxCoalesceFrames {
			t.Fatalf("batch size %d > cap %d", len(b), maxCoalesceFrames)
		}
	}
	if total != N {
		t.Fatalf("total frames across batches = %d, want %d", total, N)
	}
	if len(bs) >= N {
		t.Fatalf("no coalescing happened: %d batches for %d frames", len(bs), N)
	}
}

// TestPacer_Coalesce_FlushOnSleepBoundary: a 50µs delay coalesces (skip),
// a 200µs delay forces flush before sleep.
func TestPacer_Coalesce_FlushOnSleepBoundary(t *testing.T) {
	c := &batchConn{}
	sh := &scriptedShaper{script: []time.Duration{
		50 * time.Microsecond, // frame 1: sub-tick, may coalesce
		200 * time.Microsecond, // frame 2: above floor, flush before sleep
	}}
	p := newBatchPacer(c, sh)
	for i := range 2 {
		if err := p.enqueue(pacedFrame{packet: []byte{byte(i)}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	bs := c.snapshot()
	total := 0
	for _, b := range bs {
		total += len(b)
	}
	if total != 2 {
		t.Fatalf("frames = %d, want 2", total)
	}
}

// TestPacer_Coalesce_FlushOnMaxFrames: with all-zero delay and a queue
// faster than the consumer, the pacer must split into batches no larger than
// maxCoalesceFrames.
func TestPacer_Coalesce_FlushOnMaxFrames(t *testing.T) {
	c := &batchConn{}
	// Use a very small sub-tick delay so coalescing kicks in but pendingDelay
	// never reaches flush threshold within 100 frames (100 * 1µs = 100µs).
	sh := &scriptedShaper{script: []time.Duration{1 * time.Microsecond}}
	p := newBatchPacer(c, sh)
	const N = 100
	for i := range N {
		if err := p.enqueue(pacedFrame{packet: []byte{byte(i)}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	bs := c.snapshot()
	for i, b := range bs {
		if len(b) > maxCoalesceFrames {
			t.Fatalf("batch %d has %d frames > maxCoalesceFrames %d", i, len(b), maxCoalesceFrames)
		}
	}
	total := 0
	for _, b := range bs {
		total += len(b)
	}
	if total != N {
		t.Fatalf("frames total = %d, want %d", total, N)
	}
}

// TestPacer_Coalesce_DrainOnClose: enqueue 5, close — all 5 frames must
// land before the goroutine exits.
func TestPacer_Coalesce_DrainOnClose(t *testing.T) {
	c := &batchConn{}
	sh := &scriptedShaper{script: []time.Duration{50 * time.Microsecond}}
	p := newBatchPacer(c, sh)
	for i := range 5 {
		if err := p.enqueue(pacedFrame{packet: []byte{byte(i)}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	bs := c.snapshot()
	total := 0
	for _, b := range bs {
		total += len(b)
	}
	if total != 5 {
		t.Fatalf("post-close frames = %d, want 5", total)
	}
}

// TestPacer_Coalesce_PreservesByteOrder: byte stream is reconstructible
// across batches in FIFO order.
func TestPacer_Coalesce_PreservesByteOrder(t *testing.T) {
	c := &batchConn{}
	sh := &scriptedShaper{script: []time.Duration{1 * time.Microsecond}}
	p := newBatchPacer(c, sh)
	const N = 50
	want := make([]byte, 0, N*4)
	for i := range N {
		buf := []byte{byte(i), byte(i >> 8), 0xAA, 0xBB}
		want = append(want, buf...)
		if err := p.enqueue(pacedFrame{packet: buf, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	bs := c.snapshot()
	got := []byte{}
	for _, b := range bs {
		for _, frame := range b {
			got = append(got, frame...)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("byte stream mismatch: got %x want %x", got, want)
	}
}

// TestPacer_Coalesce_FifoOrder: frames retain enqueue order across coalesced
// batches.
func TestPacer_Coalesce_FifoOrder(t *testing.T) {
	c := &batchConn{}
	sh := &scriptedShaper{script: []time.Duration{1 * time.Microsecond}}
	p := newBatchPacer(c, sh)
	const N = 80
	for i := range N {
		if err := p.enqueue(pacedFrame{packet: []byte{byte(i)}, bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	p.close()
	bs := c.snapshot()
	idx := byte(0)
	for _, b := range bs {
		for _, frame := range b {
			if frame[0] != idx {
				t.Fatalf("frame at idx %d = %d, want %d", idx, frame[0], idx)
			}
			idx++
		}
	}
	if int(idx) != N {
		t.Fatalf("got %d frames, want %d", idx, N)
	}
}
