package presets

import (
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// PresetYouTubeStreaming is the registry name for an HD video stream.
const PresetYouTubeStreaming = "youtube_streaming"

// youtube_streaming models high-bitrate adaptive video: packets are nearly
// always full-MTU on download, requests upstream are tiny (segment GETs and
// ACKs), and inter-arrival on download is heavy-tailed (Pareto) because
// playback alternates between burst-fill and rebuffering pauses.
//
// Numbers are derived from morph-audit Yandex/VK profiles (large packets
// 1200–1400, ratio 15–18) plus published QUIC video traces.
//
// Download size histogram (bytes):
//
//	| value | weight | rationale                                  |
//	|-------|--------|--------------------------------------------|
//	|  1300 |   0.20 | TLS record, typical                        |
//	|  1400 |   0.30 | MSS-aligned                                |
//	|  1450 |   0.40 | near-MTU, dominant                         |
//	|   600 |   0.05 | rare partial frame                         |
//	|   100 |   0.05 | ACK / control                              |
//
// Upload size histogram is sparse and small (mostly ACKs and segment GETs).
//
// Inter-arrival: Pareto(xm=0.05 ms, alpha=1.5) on download (heavy tail for
// rebuffering); LogNormal(mu=-3, sigma=1.5) on upload (sparse GETs).
func init() {
	register(PresetYouTubeStreaming, buildYouTubeStreaming)
}

func buildYouTubeStreaming(seed int64) (shaper.Shaper, error) {
	downBins := []dist.HistogramBin{
		{Value: 1300, Weight: 0.20},
		{Value: 1400, Weight: 0.30},
		{Value: 1450, Weight: 0.40},
		{Value: 600, Weight: 0.05},
		{Value: 100, Weight: 0.05},
	}
	upBins := []dist.HistogramBin{
		{Value: 60, Weight: 0.55},  // ACKs
		{Value: 200, Weight: 0.30}, // segment GETs
		{Value: 500, Weight: 0.10},
		{Value: 1300, Weight: 0.05}, // rare keep-alive PING with payload
	}
	sizeUp, err := dist.NewHistogram(upBins, seed^seedSaltSizeUp)
	if err != nil {
		return nil, err
	}
	sizeDown, err := dist.NewHistogram(downBins, seed^seedSaltSizeDown)
	if err != nil {
		return nil, err
	}
	return &distShaper{
		sizeUp:    sizeUp,
		sizeDown:  sizeDown,
		delayUp:   dist.NewLogNormal(-3, 1.5, seed^seedSaltDelayUp),
		delayDown: dist.NewPareto(0.05, 1.5, seed^seedSaltDelayDown),
		mtu:       defaultMTU,
	}, nil
}
