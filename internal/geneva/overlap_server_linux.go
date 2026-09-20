//go:build linux

package geneva

import (
	"context"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// OverlapServerDropper attaches an input NFQUEUE hook that drops seqovl fake
// segments before kernel reassembly. See overlap_server.go for why this must
// live at the packet layer and why it is only needed for the aggressive overlap
// geometry.
//
// The operator must provision a *narrow* INPUT NFQUEUE rule (source port /
// connection mark, never the whole ingress), e.g.:
//
//	iptables -I INPUT -p tcp --dport <listen-port> -j NFQUEUE --queue-num <N>
type OverlapServerDropper struct {
	// QueueNum is the input NFQUEUE number the dropper attaches to.
	QueueNum uint16
	// Verify reports whether a TCP payload is an authentic seqovl fake segment.
	// Supplied by the caller (see OverlapMarkerVerifier / AnyOverlapVerifier) so
	// this package stays agnostic of the marker's HMAC salt and secret set.
	Verify func(payload []byte) bool

	nfq    *nfqueue.Nfqueue
	cancel context.CancelFunc
}

// NewOverlapServerDropper constructs a dropper for the given input queue that
// drops packets for which verify returns true.
func NewOverlapServerDropper(queueNum uint16, verify func(payload []byte) bool) *OverlapServerDropper {
	return &OverlapServerDropper{QueueNum: queueNum, Verify: verify}
}

// Start opens the input NFQUEUE and begins classifying inbound packets: an
// authentic fake segment is dropped, everything else is accepted untouched.
func (d *OverlapServerDropper) Start(ctx context.Context) error {
	if d.Verify == nil {
		return fmt.Errorf("geneva overlap dropper: nil Verify")
	}

	cfg := &nfqueue.Config{
		NfQueue:      d.QueueNum,
		MaxPacketLen: 65535,
		MaxQueueLen:  128,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}
	nfq, err := nfqueue.Open(cfg)
	if err != nil {
		return fmt.Errorf("geneva overlap dropper: nfqueue open failed (need CAP_NET_ADMIN): %w", err)
	}
	d.nfq = nfq

	innerCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	hook := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		if a.Payload == nil {
			d.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			return 0
		}
		if overlapPacketIsFake(*a.Payload, d.Verify) {
			d.nfq.SetVerdict(*a.PacketID, nfqueue.NfDrop)
			return 0
		}
		d.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		return 0
	}

	errFn := func(e error) int {
		select {
		case <-innerCtx.Done():
			return 1
		default:
			log.Debug("Geneva overlap dropper: nfqueue error: %v", e)
			return 0
		}
	}

	if err := d.nfq.RegisterWithErrorFunc(innerCtx, hook, errFn); err != nil {
		d.nfq.Close()
		d.nfq = nil
		cancel()
		d.cancel = nil
		return fmt.Errorf("geneva overlap dropper: register failed: %w", err)
	}

	log.Info("Geneva overlap dropper: active on input queue %d", d.QueueNum)
	return nil
}

// Stop cancels the classifier goroutine and releases the queue.
func (d *OverlapServerDropper) Stop() {
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	if d.nfq != nil {
		d.nfq.Close()
		d.nfq = nil
	}
	log.Info("Geneva overlap dropper: stopped")
}
