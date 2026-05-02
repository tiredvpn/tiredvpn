package presets

import (
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// PresetChromeBrowsing is the registry name for general HTTPS web browsing.
const PresetChromeBrowsing = "chrome_browsing"

// chrome_browsing models a typical desktop Chrome session over HTTPS:
// many small TLS-record-sized requests with bursty mid-size responses,
// long pauses between user clicks. Numbers are derived from morph-audit
// (`Web Browsing` profile) plus inspection of typical TLS record histograms.
//
// Packet size histogram (bytes):
//
//	| value | weight | rationale                                              |
//	|-------|--------|--------------------------------------------------------|
//	|    60 |   0.20 | TCP/TLS keepalive, ACKs                                |
//	|   180 |   0.25 | typical request line + headers                         |
//	|   500 |   0.20 | small JSON / favicons                                  |
//	|   900 |   0.15 | mid-size XHR responses                                 |
//	|  1300 |   0.15 | full TLS record, near-MTU                              |
//	|  1400 |   0.05 | jumbo, MSS-aligned                                     |
//
// Inter-arrival: LogNormal(mu=-7, sigma=1) → median ~0.9 ms, tail to ~50 ms,
// matches HTTP/2 multiplexed bursts followed by rendering pauses.
//
// No burst engine — browsing is request/response, not steady-state.
func init() {
	register(PresetChromeBrowsing, buildChromeBrowsing)
}

func buildChromeBrowsing(seed int64) (shaper.Shaper, error) {
	bins := []dist.HistogramBin{
		{Value: 60, Weight: 0.20},
		{Value: 180, Weight: 0.25},
		{Value: 500, Weight: 0.20},
		{Value: 900, Weight: 0.15},
		{Value: 1300, Weight: 0.15},
		{Value: 1400, Weight: 0.05},
	}
	sizeUp, err := dist.NewHistogram(bins, seed^seedSaltSizeUp)
	if err != nil {
		return nil, err
	}
	sizeDown, err := dist.NewHistogram(bins, seed^seedSaltSizeDown)
	if err != nil {
		return nil, err
	}
	return &distShaper{
		sizeUp:    sizeUp,
		sizeDown:  sizeDown,
		delayUp:   dist.NewLogNormal(-7, 1, seed^seedSaltDelayUp),
		delayDown: dist.NewLogNormal(-7, 1, seed^seedSaltDelayDown),
		mtu:       defaultMTU,
	}, nil
}
