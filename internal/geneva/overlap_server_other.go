//go:build !linux

package geneva

import "context"

// OverlapServerDropper is a no-op on non-Linux platforms (no NFQUEUE). The pure
// classification logic in overlap_server.go still builds and is testable
// everywhere; only the runtime hook is Linux-only.
type OverlapServerDropper struct {
	QueueNum uint16
	Verify   func(payload []byte) bool
}

// NewOverlapServerDropper constructs a stub dropper.
func NewOverlapServerDropper(queueNum uint16, verify func(payload []byte) bool) *OverlapServerDropper {
	return &OverlapServerDropper{QueueNum: queueNum, Verify: verify}
}

// Start always returns ErrOverlapDropperUnimplemented on non-Linux.
func (d *OverlapServerDropper) Start(_ context.Context) error {
	return ErrOverlapDropperUnimplemented
}

// Stop is a no-op.
func (d *OverlapServerDropper) Stop() {}
