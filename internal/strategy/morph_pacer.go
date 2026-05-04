package strategy

import (
	"errors"
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

// pacer tuning constants — see ADR §7. Exposed as package-private so tests
// can reference them without re-deriving.
const (
	pacerQueueCap         = 256
	pacerThrottleStart    = pacerQueueCap / 2 // 128
	pacerMaxDelay         = 50 * time.Millisecond
	pacerCoalesceSkipBelow = 100 * time.Microsecond
	pacerCoalesceFlushAt  = 200 * time.Microsecond
	pacerEnqueueTimeout   = 1 * time.Second
	pacerDrainTimeout     = 100 * time.Millisecond
)

// pacedFrame is a fully built [header][data][padding] packet ready for
// Conn.Write. fromPool indicates whether the underlying buffer must be
// returned to packetPool after the write.
type pacedFrame struct {
	packet   []byte
	fromPool bool
}

// writePacer serialises shaped writes off the producer goroutine. The
// producer (caller of Write) only enqueues; a single dedicated goroutine
// drains the queue and applies inter-frame spacing with sleep coalescing
// and adaptive throttle as described in adr-shaper-perf.md.
type writePacer struct {
	conn  net.Conn
	sh    shaper.Shaper
	queue chan pacedFrame

	done    chan struct{}
	closeOnce sync.Once
	wg      sync.WaitGroup

	// errSeen holds the last non-nil Conn.Write error observed by the
	// pacer goroutine. Producers consult it before enqueue so a broken
	// connection fails fast instead of filling the queue with frames
	// that will never reach the wire.
	errSeen atomic.Pointer[error]
}

// newWritePacer constructs and starts a pacer goroutine bound to conn.
// Caller owns conn and must invoke close() before closing the underlying
// connection so the drain timeout has a chance to flush queued frames.
func newWritePacer(conn net.Conn, sh shaper.Shaper) *writePacer {
	p := &writePacer{
		conn:  conn,
		sh:    sh,
		queue: make(chan pacedFrame, pacerQueueCap),
		done:  make(chan struct{}),
	}
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

	var pendingDelay time.Duration

	releaseFrame := func(f pacedFrame) {
		if f.fromPool {
			packetPool.Put(f.packet[:cap(f.packet)])
		}
	}

	for {
		select {
		case <-p.done:
			p.drain(time.Now().Add(pacerDrainTimeout), releaseFrame)
			return
		case f, ok := <-p.queue:
			if !ok {
				return
			}
			if _, err := p.conn.Write(f.packet); err != nil {
				e := err
				p.errSeen.Store(&e)
				releaseFrame(f)
				p.drain(time.Time{}, releaseFrame)
				return
			}
			releaseFrame(f)

			d := p.sh.NextDelay(shaper.DirectionUp)
			if d <= 0 {
				continue
			}
			if d > pacerMaxDelay {
				d = pacerMaxDelay
			}
			depth := len(p.queue)
			factor := throttleFactor(depth)
			scaled := time.Duration(float64(d) * factor)
			if scaled <= 0 {
				continue
			}
			if scaled < pacerCoalesceSkipBelow {
				pendingDelay += scaled
				if pendingDelay >= pacerCoalesceFlushAt {
					time.Sleep(pendingDelay)
					pendingDelay = 0
				}
				continue
			}
			if pendingDelay > 0 {
				scaled += pendingDelay
				pendingDelay = 0
			}
			time.Sleep(scaled)
		}
	}
}

// drain best-effort flushes pending frames after stop. If deadline is the
// zero value (Conn.Write failure path) we just release buffers without
// touching the wire — connection is dead, frames are unsendable.
func (p *writePacer) drain(deadline time.Time, release func(pacedFrame)) {
	for {
		select {
		case f, ok := <-p.queue:
			if !ok {
				return
			}
			if !deadline.IsZero() && time.Now().Before(deadline) && p.errSeen.Load() == nil {
				if _, err := p.conn.Write(f.packet); err != nil {
					e := err
					p.errSeen.Store(&e)
				}
			}
			release(f)
		default:
			return
		}
	}
}

// enqueue hands a built frame to the pacer goroutine. Returns the cached
// connection error if Conn.Write previously failed, ErrShaperOverflow if
// the queue stays full for longer than pacerEnqueueTimeout, or nil on
// successful handoff.
func (p *writePacer) enqueue(frame pacedFrame) error {
	if errp := p.errSeen.Load(); errp != nil {
		if frame.fromPool {
			packetPool.Put(frame.packet[:cap(frame.packet)])
		}
		return *errp
	}
	select {
	case <-p.done:
		if frame.fromPool {
			packetPool.Put(frame.packet[:cap(frame.packet)])
		}
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
		if frame.fromPool {
			packetPool.Put(frame.packet[:cap(frame.packet)])
		}
		return net.ErrClosed
	case <-timer.C:
		if frame.fromPool {
			packetPool.Put(frame.packet[:cap(frame.packet)])
		}
		return ErrShaperOverflow
	}
}

// close signals the pacer goroutine to stop, drains pending frames within
// pacerDrainTimeout, and waits for goroutine exit. Safe to call multiple
// times; subsequent calls are no-ops.
func (p *writePacer) close() {
	p.closeOnce.Do(func() {
		close(p.done)
	})
	p.wg.Wait()
}
