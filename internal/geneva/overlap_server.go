package geneva

import (
	"context"
	"errors"
)

// OverlapServerDropper is the (not-yet-implemented) server-side counterpart to
// the packet-level seqovl overlap. Its job: attach an *input* NFQUEUE hook on
// the relay, identify a seqovl fake segment by its secret marker
// (OverlapPayloadHasMarker) and DROP it before kernel reassembly, so the
// application receives only the real ClientHello.
//
// It is only required for the aggressive "overlap-into-ClientHello" geometry
// (OverlapPrimitive.FakeLen > OverlapLen). With the default safe geometry the
// fake segment sits entirely below the server's rcv_nxt and the kernel discards
// it on its own, so no input NFQUEUE hook is needed - which is why this is a
// deliberate stub for now.
//
// TODO(seqovl-level-A): implement the input NFQUEUE drop. Deferred because:
//   - The relay boxes are memory-constrained (3 GB, prior OOM history); an
//     always-on input NFQUEUE over all inbound traffic is a real resource and
//     stability risk and must be gated behind an explicit flag and a narrow
//     iptables match (source-port / connection-mark), not the whole ingress.
//   - The safe client geometry already gives a working, non-corrupting overlap
//     without it, so it is not on the critical path for shipping level A.
type OverlapServerDropper struct {
	// QueueNum is the input NFQUEUE number the dropper will attach to.
	QueueNum uint16
	// Markers holds the per-secret markers a fake segment may carry.
	Markers [][]byte
}

// ErrOverlapDropperUnimplemented is returned until the input NFQUEUE drop lands.
var ErrOverlapDropperUnimplemented = errors.New("geneva: seqovl server-side overlap dropper not implemented (safe client geometry needs no server drop)")

// NewOverlapServerDropper constructs a dropper for the given queue and markers.
func NewOverlapServerDropper(queueNum uint16, markers [][]byte) *OverlapServerDropper {
	return &OverlapServerDropper{QueueNum: queueNum, Markers: markers}
}

// Start is a stub. It never attaches an NFQUEUE hook and returns
// ErrOverlapDropperUnimplemented so callers degrade cleanly.
func (d *OverlapServerDropper) Start(_ context.Context) error {
	return ErrOverlapDropperUnimplemented
}

// Stop is a no-op for the stub.
func (d *OverlapServerDropper) Stop() {}
