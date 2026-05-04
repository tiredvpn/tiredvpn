package presets

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// errUnwrapBufferTooSmall is returned by UnwrapInto when the destination
// buffer cannot fit the unwrapped payload.
var errUnwrapBufferTooSmall = errors.New("dist_shaper: UnwrapInto destination too small")

// wrapBufPool reuses per-frame byte slices produced by distShaper.Wrap.
// Buffers are sized at MTU (1500) so any frame up to MTU shares a single
// pool tier; the slice is re-sliced to the requested length on acquire.
// Storing *[]byte avoids the pointer-indirection alloc that sync.Pool
// performs for non-pointer interface values.
var wrapBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, defaultMTU)
		return &b
	},
}

// acquireWrapBuf returns a *[]byte handle whose underlying slice has length n
// and capacity ≥ defaultMTU. Callers MUST call releaseWrapBuf with the same
// handle once the buffer's contents are no longer needed; failing to do so
// only leaks the pooled allocation, never corrupts state.
func acquireWrapBuf(n int) *[]byte {
	bp := wrapBufPool.Get().(*[]byte)
	if cap(*bp) < n {
		// Pool buffer is too small (n > defaultMTU). Drop the pooled slice
		// and allocate a tight fit; this should never happen in practice
		// because Wrap clamps target to mtu.
		wrapBufPool.Put(bp)
		fresh := make([]byte, n)
		return &fresh
	}
	*bp = (*bp)[:n]
	return bp
}

// releaseWrapBuf returns bp to the wrap-buffer pool. Buffers smaller than
// defaultMTU are dropped on the floor — they would only pollute the pool
// with too-small slices and force the next acquire to re-allocate anyway.
func releaseWrapBuf(bp *[]byte) {
	if bp == nil || cap(*bp) < defaultMTU {
		return
	}
	*bp = (*bp)[:cap(*bp)]
	wrapBufPool.Put(bp)
}

// Default constants applied across presets unless overridden.
const (
	defaultMTU        = 1500
	defaultPacketSize = 1200

	// Domain separators used when deriving per-feature seeds from a single
	// preset seed. They keep size/delay/burst RNG streams independent.
	seedSaltSizeUp    = int64(0x5A1751756553697A) // "SALTsizeUp" mash
	seedSaltSizeDown  = int64(0x5A1753697A65446F) // "SALTsizeDown"
	seedSaltDelayUp   = int64(0x5A1744656C617955) // "SALTDelayU"
	seedSaltDelayDown = int64(0x5A1744656C617944) // "SALTDelayD"
	seedSaltDelay     = int64(0x5A1744656C617900) // "SALTDelay"
	seedSaltBurst     = int64(0x5A1742757273746D) // "SALTBurstm"
)

// distShaper is a Shaper backed by four Distribution engines (size and delay
// for each direction). The unit of NextDelay output is milliseconds: the
// underlying Distribution.Next() is interpreted as a number of millis.
//
// distShaper is single-producer: Wrap and Release are expected to alternate
// on the same goroutine (the writer side of one MorphedConn). The wrap-
// buffer handle slice is held on the shaper itself so Release can return
// pooled buffers without allocating fresh *[]byte slot pointers.
type distShaper struct {
	sizeUp    dist.Distribution
	sizeDown  dist.Distribution
	delayUp   dist.Distribution
	delayDown dist.Distribution
	mtu       int

	// wrapMu serialises Wrap/Release. The fast path (single-goroutine
	// producer) holds the mutex briefly and uncontended; the lock exists
	// purely to make accidental concurrent use safe rather than fast.
	wrapMu sync.Mutex
	// wrapHandles holds *[]byte handles parallel to the slice returned by
	// Wrap. Capacity grows monotonically up to the worst case (≈ MTU
	// fragments per Wrap). Cleared on Release and reused.
	wrapHandles []*[]byte
	// wrapFrames is the outer slice handed back from Wrap. We retain it
	// so Release can clear inner pointers and the next Wrap can reuse
	// the header without a fresh make.
	wrapFrames [][]byte
}

// constDist is a degenerate Distribution that always returns the same value;
// used as a placeholder when a custom-config field is omitted.
type constDist float64

func (c constDist) Next() float64 { return float64(c) }
func (constDist) Reset()          {}

// applyRandomization configures jitter on any histogram-based engine. Engines
// that do not support jitter (LogNormal, Pareto, Markov) intrinsically have
// continuous variance, so this is a no-op for them.
func (d *distShaper) applyRandomization(r float64) {
	for _, e := range []dist.Distribution{d.sizeUp, d.sizeDown, d.delayUp, d.delayDown} {
		if h, ok := e.(*dist.Histogram); ok {
			_ = h.SetRandomizationRange(r)
		}
	}
}

// NextPacketSize returns the next target packet size, clamped to [1, mtu].
func (d *distShaper) NextPacketSize(dir shaper.Direction) int {
	src := d.sizeUp
	if dir == shaper.DirectionDown {
		src = d.sizeDown
	}
	v := src.Next()
	n := int(v + 0.5)
	if n < 1 {
		n = 1
	}
	if n > d.mtu {
		n = d.mtu
	}
	return n
}

// NextDelay returns the next inter-packet delay. The Distribution value is
// treated as milliseconds.
func (d *distShaper) NextDelay(dir shaper.Direction) time.Duration {
	src := d.delayUp
	if dir == shaper.DirectionDown {
		src = d.delayDown
	}
	v := src.Next()
	if v < 0 {
		v = 0
	}
	return time.Duration(v * float64(time.Millisecond))
}

// frameHeader is a 4-byte little-endian uvarint-style length prefix that
// records the **payload** length carried by a single frame. The remainder of
// the frame, up to NextPacketSize, is zero-padding.
const frameHeaderLen = 4

// Wrap fragments payload into one or more frames sized by NextPacketSize and
// pads each with zero bytes to reach the target. Each frame is laid out as:
//
//	| len:uint32-le | payload[len] | padding |
//
// where len is the actual payload byte count. Empty payload produces a single
// header-only frame so that Wrap/Unwrap is a total roundtrip.
func (d *distShaper) Wrap(payload []byte) [][]byte {
	d.wrapMu.Lock()
	defer d.wrapMu.Unlock()

	frames := d.wrapFrames[:0]
	handles := d.wrapHandles[:0]

	if len(payload) == 0 {
		bp := acquireWrapBuf(frameHeaderLen)
		frame := *bp
		clear(frame[:frameHeaderLen])
		frames = append(frames, frame)
		handles = append(handles, bp)
		d.wrapFrames = frames
		d.wrapHandles = handles
		return frames
	}

	pos := 0
	for pos < len(payload) {
		target := d.NextPacketSize(shaper.DirectionUp)
		// Reserve space for the header.
		capacity := target - frameHeaderLen
		if capacity < 1 {
			capacity = 1
			target = capacity + frameHeaderLen
		}
		take := capacity
		if remaining := len(payload) - pos; remaining < take {
			take = remaining
		}
		bp := acquireWrapBuf(target)
		frame := *bp
		binary.LittleEndian.PutUint32(frame[:frameHeaderLen], uint32(take)) //nolint:gosec // bounded by mtu
		copy(frame[frameHeaderLen:], payload[pos:pos+take])
		// Zero the trailing pad region — a fresh make would have given us
		// zeros, but pooled buffers may carry the previous frame's bytes.
		if tail := frame[frameHeaderLen+take:]; len(tail) > 0 {
			clear(tail)
		}
		frames = append(frames, frame)
		handles = append(handles, bp)
		pos += take
	}
	d.wrapFrames = frames
	d.wrapHandles = handles
	return frames
}

// Release returns each frame buffer in frames to the wrap-buffer pool. After
// Release the caller MUST NOT use frames or any of the inner buffers; they
// may be handed out to a subsequent Wrap call. Calling Release on a nil or
// empty slice is safe; a slice that doesn't match the most recent Wrap
// output is a programmer error and silently ignored.
func (d *distShaper) Release(frames [][]byte) {
	if len(frames) == 0 {
		return
	}
	d.wrapMu.Lock()
	defer d.wrapMu.Unlock()

	// Best-effort: only honour Release for the most recent Wrap. The
	// alternative (looking up handles from the [][]byte alone) requires
	// either a map or unsafe pointer arithmetic; the documented contract
	// is "call Release with the slice you got from Wrap", and that
	// matches d.wrapFrames by header pointer + len.
	if len(d.wrapHandles) != len(frames) {
		return
	}
	for i, bp := range d.wrapHandles {
		releaseWrapBuf(bp)
		d.wrapHandles[i] = nil
		frames[i] = nil
	}
	d.wrapHandles = d.wrapHandles[:0]
	d.wrapFrames = frames[:0]
}

// Unwrap reverses Wrap by stripping the length prefix and any trailing padding
// from each frame and concatenating the payload bytes.
func (d *distShaper) Unwrap(frames [][]byte) []byte {
	if len(frames) == 0 {
		return nil
	}
	var total int
	for _, f := range frames {
		if len(f) < frameHeaderLen {
			continue
		}
		total += int(binary.LittleEndian.Uint32(f[:frameHeaderLen]))
	}
	out := make([]byte, 0, total)
	for _, f := range frames {
		if len(f) < frameHeaderLen {
			continue
		}
		n := int(binary.LittleEndian.Uint32(f[:frameHeaderLen]))
		if n > len(f)-frameHeaderLen {
			n = len(f) - frameHeaderLen
		}
		out = append(out, f[frameHeaderLen:frameHeaderLen+n]...)
	}
	return out
}

// UnwrapInto writes the unwrapped payload from frames into out and returns the
// number of bytes written. Callers may pass an out slice with capacity ≥ the
// expected payload length (an MTU-sized scratch buffer is sufficient for the
// single-frame case used by the receiver hot path). Returns an error only if
// the destination buffer is too small.
func (d *distShaper) UnwrapInto(out []byte, frames [][]byte) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	pos := 0
	for _, f := range frames {
		if len(f) < frameHeaderLen {
			continue
		}
		n := int(binary.LittleEndian.Uint32(f[:frameHeaderLen]))
		if n > len(f)-frameHeaderLen {
			n = len(f) - frameHeaderLen
		}
		if pos+n > len(out) {
			return pos, errUnwrapBufferTooSmall
		}
		copy(out[pos:pos+n], f[frameHeaderLen:frameHeaderLen+n])
		pos += n
	}
	return pos, nil
}
