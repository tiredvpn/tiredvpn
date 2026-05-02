package shaper

import "time"

// NoopShaper is a passthrough Shaper: it imposes no sizing, delay or
// fragmentation. It exists so the pipeline can always hold a non-nil Shaper
// and so tests have a deterministic baseline.
type NoopShaper struct{}

// NewNoopShaper returns a passthrough shaper. The zero value is also usable;
// the constructor exists for symmetry with future shapers that take config.
func NewNoopShaper() *NoopShaper {
	return &NoopShaper{}
}

// NextPacketSize returns len(payload)-equivalent semantics by returning 0,
// which callers interpret as "use whatever size the payload already has".
// Direction is ignored.
func (NoopShaper) NextPacketSize(_ Direction) int {
	return 0
}

// NextDelay always returns zero — passthrough never throttles.
func (NoopShaper) NextDelay(_ Direction) time.Duration {
	return 0
}

// Wrap returns the payload as a single frame without copying. Callers must
// not mutate payload after the call until the returned frames are consumed.
func (NoopShaper) Wrap(payload []byte) [][]byte {
	return [][]byte{payload}
}

// Unwrap concatenates frames in order. A nil/empty input yields nil to keep
// roundtrip semantics with Wrap(nil).
func (NoopShaper) Unwrap(frames [][]byte) []byte {
	if len(frames) == 0 {
		return nil
	}
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	out := make([]byte, 0, total)
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}
