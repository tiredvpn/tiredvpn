package presets

import (
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// PresetBitTorrentIdle is the registry name for an idle BT swarm participant.
const PresetBitTorrentIdle = "bittorrent_idle"

// bittorrent_idle models a BT client that has joined a swarm but is mostly
// idle: occasional short PEX/keepalive/handshake exchanges separated by
// long pauses. The size histogram is sparse and small; inter-arrival is a
// LogNormal with large sigma to reproduce minutes-scale gaps.
//
// Packet size histogram (bytes):
//
//	| value | weight | rationale                                   |
//	|-------|--------|---------------------------------------------|
//	|    68 |   0.40 | BitTorrent KEEPALIVE / CHOKE                |
//	|   144 |   0.25 | HAVE / PEX small message                    |
//	|   320 |   0.20 | EXTENDED / handshake                        |
//	|   600 |   0.10 | small piece request batch                   |
//	|  1200 |   0.05 | rare bitfield exchange                      |
//
// Inter-arrival: LogNormal(mu=2, sigma=2.5) → median ~7 s, with tail to
// minutes — matching observed idle-swarm telemetry.
func init() {
	// DataPlaneSafe=false: median delay ~7 s — cover-traffic only. Building
	// for the data plane would collapse throughput; callers that need this
	// preset for cover-traffic must use ByNameAllowAny.
	register(PresetBitTorrentIdle, false, buildBitTorrentIdle)
}

func buildBitTorrentIdle(seed int64) (shaper.Shaper, error) {
	bins := []dist.HistogramBin{
		{Value: 68, Weight: 0.40},
		{Value: 144, Weight: 0.25},
		{Value: 320, Weight: 0.20},
		{Value: 600, Weight: 0.10},
		{Value: 1200, Weight: 0.05},
	}
	sizeUp, err := dist.NewHistogram(bins, seed^seedSaltSizeUp)
	if err != nil {
		return nil, err
	}
	sizeDown, err := dist.NewHistogram(bins, seed^seedSaltSizeDown)
	if err != nil {
		return nil, err
	}
	// Delay is in milliseconds; LogNormal(mu=2,sigma=2.5) -> median ~7400 ms.
	return &distShaper{
		sizeUp:    sizeUp,
		sizeDown:  sizeDown,
		delayUp:   dist.NewLogNormal(8.9, 2.5, seed^seedSaltDelayUp),
		delayDown: dist.NewLogNormal(8.9, 2.5, seed^seedSaltDelayDown),
		mtu:       defaultMTU,
	}, nil
}
