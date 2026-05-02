// Package dist provides probability distribution engines used by the traffic
// shaper to generate randomized packet sizes and inter-arrival delays. The
// goal is to avoid fixed statistical signatures that DPI middleboxes can
// fingerprint.
package dist

// Distribution is the common interface implemented by every sampler in this
// package. Implementations are deterministic given a seed and must support a
// Reset that rewinds the internal RNG to the original seed.
type Distribution interface {
	// Next returns the next sample from the distribution.
	Next() float64
	// Reset rewinds the internal RNG so that subsequent samples reproduce
	// the exact sequence emitted right after construction.
	Reset()
}
