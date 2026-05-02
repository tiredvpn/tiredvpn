package presets

import (
	"encoding/binary"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

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
type distShaper struct {
	sizeUp    dist.Distribution
	sizeDown  dist.Distribution
	delayUp   dist.Distribution
	delayDown dist.Distribution
	mtu       int
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
	if len(payload) == 0 {
		return [][]byte{make([]byte, frameHeaderLen)}
	}

	var frames [][]byte
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
		frame := make([]byte, target)
		binary.LittleEndian.PutUint32(frame[:frameHeaderLen], uint32(take)) //nolint:gosec // bounded by mtu
		copy(frame[frameHeaderLen:], payload[pos:pos+take])
		frames = append(frames, frame)
		pos += take
	}
	return frames
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
