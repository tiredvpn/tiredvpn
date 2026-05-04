// Package shaper defines the behavioral traffic-shaping abstraction used to
// decouple TLS transport from anti-DPI shaping. Concrete shapers can mimic
// browsing patterns, video streams, etc.; tests and the default pipeline use
// NoopShaper to keep traffic unchanged.
package shaper

import "time"

// Direction distinguishes upstream (client→server) from downstream traffic so
// shapers can produce asymmetric profiles (e.g. video: small up, large down).
type Direction int

const (
	// DirectionUp is client→server traffic.
	DirectionUp Direction = iota
	// DirectionDown is server→client traffic.
	DirectionDown
)

// Shaper drives packet sizing, inter-packet delays and frame fragmentation to
// reshape a raw byte stream into a traffic profile that resists DPI behavioral
// fingerprinting. Implementations must be safe for concurrent use only when
// documented; the default is per-direction single-goroutine usage.
type Shaper interface {
	// NextPacketSize returns the target size in bytes for the next packet
	// emitted in direction d. The caller may use this as a hint when batching
	// or padding; returning len(payload) means "no preference".
	NextPacketSize(d Direction) int

	// NextDelay returns how long the caller should sleep before emitting the
	// next packet in direction d. Zero means "send immediately".
	NextDelay(d Direction) time.Duration

	// Wrap fragments/pads payload into one or more frames ready for the wire.
	// Implementations must preserve byte order so Unwrap can reconstruct the
	// original payload.
	Wrap(payload []byte) [][]byte

	// Release hands the slice headers and underlying buffers returned by Wrap
	// back to the implementation for reuse. Callers MUST stop touching the
	// frames before calling Release. Implementations that do not pool buffers
	// (e.g. NoopShaper) treat Release as a no-op. Calling Release on a nil or
	// empty slice is always safe.
	Release(frames [][]byte)

	// Unwrap reassembles frames produced by Wrap (possibly across calls) into
	// the original payload bytes.
	Unwrap(frames [][]byte) []byte
}
