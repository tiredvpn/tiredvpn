package presets

import (
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// PresetIMAPSync is the registry name for an IMAP email-sync session.
const PresetIMAPSync = "imap_sync"

// imap_sync models a desktop mail client kept connected to an IMAP server
// (mail.ru / icloud.com / gmail). The session has three observable phases:
//
//   - Initial inbox sync: a short burst of FETCH responses, one per message,
//     each carrying a 5-150 KB body. Download sizes therefore cluster around
//     full-MTU frames with a long tail toward large messages.
//   - Idle: the client mostly waits, sending IMAP NOOP keepalives every
//     20-120 s. This dominates the inter-arrival distribution (tens of seconds
//     median, minutes-scale tail).
//   - Occasional send: an APPEND uploading a 10-80 KB message every 1-5 min.
//     Upstream sizes are small (commands + the odd APPEND literal frame).
//
// Download size histogram (bytes), reflecting body chunks fragmented to MTU:
//
//	| value | weight | rationale                                   |
//	|-------|--------|---------------------------------------------|
//	|  1448 |   0.55 | MTU-sized body fragment, dominant           |
//	|  1200 |   0.20 | TLS-record-sized fragment                   |
//	|   600 |   0.10 | trailing partial fragment                   |
//	|   140 |   0.10 | small FETCH metadata / "* OK" lines         |
//	|    40 |   0.05 | bare tagged status / NOOP echo              |
//
// Upload size histogram (bytes), command-dominated with rare APPEND bodies:
//
//	| value | weight | rationale                                   |
//	|-------|--------|---------------------------------------------|
//	|    24 |   0.50 | "A00x NOOP" keepalive                       |
//	|    64 |   0.25 | FETCH / SELECT command lines                |
//	|   300 |   0.15 | APPEND header + small body fragment         |
//	|  1448 |   0.10 | APPEND body fragment (sending a message)    |
//
// Inter-arrival is LogNormal in milliseconds for both directions, sized to the
// idle keepalive cadence: mu=10.5, sigma=1.6 -> median ~36 s with a tail into
// minutes, matching the 20-120 s NOOP / 1-5 min APPEND behaviour.
func init() {
	// DataPlaneSafe=false: tens-of-seconds median delay — cover-traffic scale.
	// The IMAP camouflage conn borrows only a capped jitter from this preset;
	// data-plane callers that build it directly must use ByNameAllowAny.
	register(PresetIMAPSync, false, buildIMAPSync)
}

func buildIMAPSync(seed int64) (shaper.Shaper, error) {
	downBins := []dist.HistogramBin{
		{Value: 1448, Weight: 0.55},
		{Value: 1200, Weight: 0.20},
		{Value: 600, Weight: 0.10},
		{Value: 140, Weight: 0.10},
		{Value: 40, Weight: 0.05},
	}
	upBins := []dist.HistogramBin{
		{Value: 24, Weight: 0.50},   // NOOP keepalive
		{Value: 64, Weight: 0.25},   // command lines
		{Value: 300, Weight: 0.15},  // APPEND header + small body
		{Value: 1448, Weight: 0.10}, // APPEND body fragment
	}
	sizeUp, err := dist.NewHistogram(upBins, seed^seedSaltSizeUp)
	if err != nil {
		return nil, err
	}
	sizeDown, err := dist.NewHistogram(downBins, seed^seedSaltSizeDown)
	if err != nil {
		return nil, err
	}
	// Delay is in milliseconds; LogNormal(mu=10.5, sigma=1.6) -> median ~36 s,
	// reproducing the idle NOOP cadence and APPEND inter-arrival tail.
	return &distShaper{
		sizeUp:    sizeUp,
		sizeDown:  sizeDown,
		delayUp:   dist.NewLogNormal(10.5, 1.6, seed^seedSaltDelayUp),
		delayDown: dist.NewLogNormal(10.5, 1.6, seed^seedSaltDelayDown),
		mtu:       defaultMTU,
	}, nil
}
