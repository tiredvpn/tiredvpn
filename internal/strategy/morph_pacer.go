package strategy

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// ErrShaperOverflow is returned by writeShaped when the async pacer queue
// stays full for longer than the producer-side block timeout (1s). Upper
// layers (e.g. TUN) decide whether to drop or surface to the caller; we
// never silently drop frames in the pacer itself.
var ErrShaperOverflow = errors.New("shaper queue overflow")

// ErrShaperCloseIncomplete is returned by Close when frames that Write had
// already accepted into the pacer queue were not all handed to the
// connection: it did not take them by the close deadline, or it failed with
// frames still queued. Handed over is all Close can know. Bytes the kernel
// or the TLS layer accepted count as delivered, though a later reset can
// still lose them. The count in the message is of framed bytes (header and
// padding included), not of the payload bytes the caller wrote. The error
// wraps the write error that stopped the pacer, if any.
var ErrShaperCloseIncomplete = errors.New("shaper close: queued frames not handed to the conn")

// pacerCloseTimeout bounds how long MorphedConn.Close spends writing out
// the queue. Close puts it on the connection as the write deadline, unless
// the caller's own write deadline is earlier, so it also cuts short a write
// that is already blocked on a peer that does not read. The queue is
// bounded (pacerQueueCap frames), so a peer that reads keeps up with it
// well inside this; one that does not costs Close this long and an
// ErrShaperCloseIncomplete. A var so tests can shorten it.
var pacerCloseTimeout = 5 * time.Second

// pacer tuning constants — see ADR §7. Exposed as package-private so tests
// can reference them without re-deriving.
const (
	pacerQueueCap          = 256
	pacerThrottleStart     = pacerQueueCap / 2 // 128
	pacerMaxDelay          = 50 * time.Millisecond
	pacerCoalesceSkipBelow = 100 * time.Microsecond
	pacerCoalesceFlushAt   = 200 * time.Microsecond
	pacerEnqueueTimeout    = 1 * time.Second
	// maxCoalesceFrames bounds the number of buffers in a single writev
	// vector. 32 × 1500B ≈ 48 KiB ≈ one TCP send window's worth of payload,
	// which keeps tail-latency bounded while reducing syscall count by an
	// order of magnitude on bulk chrome-style transfers.
	maxCoalesceFrames = 32
)

// pacedFrame is a fully built [header][data][padding] packet ready for
// Conn.Write. bucket is the bucketed-pool index returned by buildFrame
// and must be passed to releasePacketBuf after the write; bucket=-1 means
// the buffer was heap-allocated and release is a no-op.
type pacedFrame struct {
	packet []byte
	bucket int
}

// writePacer serialises shaped writes off the producer goroutine. The
// producer (caller of Write) only enqueues; a single dedicated goroutine
// drains the queue and applies inter-frame spacing with sleep coalescing
// and adaptive throttle as described in adr-shaper-perf.md.
type writePacer struct {
	conn  net.Conn
	sh    shaper.Shaper
	queue chan pacedFrame

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup

	// sendMu orders enqueue against close: enqueue sends under the read
	// lock, close takes the write lock before it closes queue, so no frame
	// can be accepted after the drain has seen the last one. Without it a
	// frame sent between the drain finding the queue empty and the goroutine
	// exiting was accepted by Write and never written.
	sendMu sync.RWMutex
	closed bool

	// lost counts the bytes of accepted frames released without reaching
	// the wire. shutdown reports them as ErrShaperCloseIncomplete.
	lost atomic.Int64

	// errSeen holds the last non-nil Conn.Write error observed by the
	// pacer goroutine. Producers consult it before enqueue so a broken
	// connection fails fast instead of filling the queue with frames
	// that will never reach the wire.
	errSeen atomic.Pointer[error]

	// writev is the vectored-write hook. Default is net.Buffers.WriteTo,
	// which dispatches to syscall.Writev on TCP/Unix conns and falls back
	// to per-buffer Write elsewhere. Tests override it to observe batch
	// boundaries.
	writev func(bufs *net.Buffers) (int64, error)
}

// newWritePacer constructs and starts a pacer goroutine bound to conn.
// Caller owns conn and must invoke shutdown before closing the underlying
// connection so the queued frames have a chance to reach it.
func newWritePacer(conn net.Conn, sh shaper.Shaper) *writePacer {
	return newWritePacerWithWritev(conn, sh, nil)
}

// newWritePacerWithWritev is the test-friendly constructor that lets the
// vectored-write function be overridden. Production code uses
// newWritePacer, which defaults to net.Buffers.WriteTo.
func newWritePacerWithWritev(conn net.Conn, sh shaper.Shaper, writev func(*net.Buffers) (int64, error)) *writePacer {
	p := &writePacer{
		conn:  conn,
		sh:    sh,
		queue: make(chan pacedFrame, pacerQueueCap),
		done:  make(chan struct{}),
	}
	if writev == nil {
		writev = func(bufs *net.Buffers) (int64, error) {
			return bufs.WriteTo(conn)
		}
	}
	p.writev = writev
	p.wg.Add(1)
	go p.run()
	return p
}

// throttleFactor implements the linear scale-down between 50% and 100% queue
// depth described in ADR §7. Below threshold the factor is 1; at full depth
// it is 0; in between it scales linearly. The factor multiplies the next
// requested delay before sleep coalescing.
func throttleFactor(depth int) float64 {
	if depth <= pacerThrottleStart {
		return 1.0
	}
	over := depth - pacerThrottleStart
	span := pacerQueueCap - pacerThrottleStart
	f := 1.0 - float64(over)/float64(span)
	if f < 0 {
		return 0
	}
	return f
}

// run is the pacer goroutine. It pulls one frame at a time, writes it to
// the wire, then computes the next inter-frame delay applying:
//  1. cap to pacerMaxDelay,
//  2. adaptive throttle by current queue depth,
//  3. sleep coalescing (skip <100µs, flush at ≥200µs accumulated).
//
// On Conn.Write error the goroutine records the error, drains and releases
// any queued frames so producers see ErrShaperOverflow / errSeen quickly,
// and exits.
func (p *writePacer) run() {
	defer p.wg.Done()

	var (
		pendingDelay   time.Duration
		pending        net.Buffers
		pendingPackets []pacedFrame
	)

	releaseFrame := func(f pacedFrame) {
		releasePacketBuf(f.packet, f.bucket)
	}

	releasePending := func() {
		for _, f := range pendingPackets {
			releaseFrame(f)
		}
		pending = pending[:0]
		pendingPackets = pendingPackets[:0]
	}

	// flush writes accumulated buffers via vectored I/O (net.Buffers.WriteTo
	// dispatches to writev on TCP/Unix conns) and releases pooled buffers.
	// Returns true if writing should stop (error path).
	flush := func() bool {
		if len(pending) == 0 {
			return false
		}
		want := buffersLen(pending)
		if n, err := p.writev(&pending); err != nil {
			e := err
			p.errSeen.Store(&e)
			p.lost.Add(want - n)
			releasePending()
			p.drain(false, releaseFrame)
			return true
		}
		releasePending()
		return false
	}

	for {
		// Close takes priority over the queue: once it is called the rest
		// goes out unpaced, inside the close deadline, instead of sleeping
		// out shaper delays frame by frame.
		select {
		case <-p.done:
			if flush() {
				return
			}
			p.drain(true, releaseFrame)
			return
		default:
		}
		select {
		case <-p.done:
			if flush() {
				return
			}
			p.drain(true, releaseFrame)
			return
		case f, ok := <-p.queue:
			if !ok {
				// shutdown closed the queue and this select picked it over
				// done. Nothing is pending: an iteration that leaves the
				// queue empty flushes, and a closed queue is empty.
				return
			}
			pending = append(pending, f.packet)
			pendingPackets = append(pendingPackets, f)

			d := p.sh.NextDelay(shaper.DirectionUp)
			if d > pacerMaxDelay {
				d = pacerMaxDelay
			}
			var scaled time.Duration
			if d > 0 {
				depth := len(p.queue)
				factor := throttleFactor(depth)
				scaled = time.Duration(float64(d) * factor)
			}

			// Sub-tick (incl. zero) budget: keep packing while we have room.
			// Flush early on vector cap, on accumulated delay reaching the
			// sleep floor, or when the queue has drained (so peer sees the
			// bytes promptly instead of waiting for the next producer push).
			if scaled < pacerCoalesceSkipBelow && len(pending) < maxCoalesceFrames {
				if scaled > 0 {
					pendingDelay += scaled
				}
				if pendingDelay >= pacerCoalesceFlushAt {
					if flush() {
						return
					}
					time.Sleep(pendingDelay)
					pendingDelay = 0
					continue
				}
				if len(p.queue) == 0 {
					if flush() {
						return
					}
				}
				continue
			}

			// At or above the sleep floor (or vector cap reached): flush so
			// the peer's reader doesn't wait for the next frame, then sleep
			// on the combined budget.
			if flush() {
				return
			}
			if scaled > 0 {
				if pendingDelay > 0 {
					scaled += pendingDelay
					pendingDelay = 0
				}
				time.Sleep(scaled)
			}
		}
	}
}

// drain empties the queue after stop. With send set (close path) it writes
// the frames out in writev batches until shutdown closes the queue; the
// write deadline the owner put on the connection bounds every batch. Without
// send (Conn.Write failure path) the connection is dead: it only releases
// what is queued now, without waiting for close. Every frame released
// without being written is counted in lost.
// Uses the writev hook so the same batching path is exercised on shutdown.
func (p *writePacer) drain(send bool, release func(pacedFrame)) {
	var pending net.Buffers
	var pendingPackets []pacedFrame
	flushDrain := func() {
		if len(pending) == 0 {
			return
		}
		want := buffersLen(pending)
		if p.errSeen.Load() != nil {
			p.lost.Add(want)
		} else if n, err := p.writev(&pending); err != nil {
			e := err
			p.errSeen.Store(&e)
			p.lost.Add(want - n)
		}
		for _, f := range pendingPackets {
			release(f)
		}
		pending = pending[:0]
		pendingPackets = pendingPackets[:0]
	}
	if !send {
		for {
			select {
			case f, ok := <-p.queue:
				if !ok {
					return
				}
				p.lost.Add(int64(len(f.packet)))
				release(f)
			default:
				return
			}
		}
	}
	for f := range p.queue {
		pending = append(pending, f.packet)
		pendingPackets = append(pendingPackets, f)
		// Batch what is already queued; write once it runs dry or the
		// vector is full, so the tail does not wait for close.
		if len(pending) >= maxCoalesceFrames || len(p.queue) == 0 {
			flushDrain()
		}
	}
	flushDrain()
}

// buffersLen is the byte length of bufs.
func buffersLen(bufs net.Buffers) int64 {
	var n int64
	for _, b := range bufs {
		n += int64(len(b))
	}
	return n
}

// enqueue hands a built frame to the pacer goroutine. Returns the cached
// connection error if Conn.Write previously failed, ErrShaperOverflow if
// the queue stays full for longer than pacerEnqueueTimeout, or nil on
// successful handoff.
func (p *writePacer) enqueue(frame pacedFrame) error {
	p.sendMu.RLock()
	defer p.sendMu.RUnlock()
	if p.closed {
		releasePacketBuf(frame.packet, frame.bucket)
		return net.ErrClosed
	}
	if errp := p.errSeen.Load(); errp != nil {
		releasePacketBuf(frame.packet, frame.bucket)
		return *errp
	}
	select {
	case <-p.done:
		releasePacketBuf(frame.packet, frame.bucket)
		return net.ErrClosed
	case p.queue <- frame:
		return nil
	default:
	}
	timer := time.NewTimer(pacerEnqueueTimeout)
	defer timer.Stop()
	select {
	case p.queue <- frame:
		return nil
	case <-p.done:
		releasePacketBuf(frame.packet, frame.bucket)
		return net.ErrClosed
	case <-timer.C:
		releasePacketBuf(frame.packet, frame.bucket)
		return ErrShaperOverflow
	}
}

// shutdown stops the pacer and returns once every frame accepted by
// enqueue has been written or given up on. Queued frames go out unpaced.
// The owner bounds the drain: it puts a write deadline on the connection
// first, and closes the socket if a write outlives it. If any accepted
// frame was not handed to the connection, shutdown returns
// ErrShaperCloseIncomplete with the byte count; it never drops one
// silently. Safe to call multiple times; later calls return the first
// result.
func (p *writePacer) shutdown() error {
	p.closeOnce.Do(func() {
		close(p.done)
		// Producers parked in enqueue see done and leave; after that none
		// can send, and closing the queue tells the drain it has the last
		// frame.
		p.sendMu.Lock()
		p.closed = true
		close(p.queue)
		p.sendMu.Unlock()
		p.wg.Wait()
		// The goroutine may have stopped on a write error before close:
		// whatever was queued after that is still here.
		for f := range p.queue {
			p.lost.Add(int64(len(f.packet)))
			releasePacketBuf(f.packet, f.bucket)
		}
		if lost := p.lost.Load(); lost > 0 {
			p.closeErr = fmt.Errorf("%w: %d framed bytes", ErrShaperCloseIncomplete, lost)
			if errp := p.errSeen.Load(); errp != nil {
				p.closeErr = fmt.Errorf("%w: %w", p.closeErr, *errp)
			}
		}
	})
	return p.closeErr
}
