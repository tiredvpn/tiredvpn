package presets

import (
	"math/rand/v2"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// PresetRandomPerSession is the registry name for a per-session randomized
// preset: it picks one of {chrome_browsing, youtube_streaming, bittorrent_idle}
// using `seed` and applies a ±randomizationFraction jitter to histogram bins
// so that even repeated picks of the same base preset produce subtly different
// signatures.
const PresetRandomPerSession = "random_per_session"

// randomizationFraction is the default ±jitter applied to histogram bins
// (15%). Operators can override it via cfg.RandomizationRange when the
// preset is selected from TOML.
const randomizationFraction = 0.15

func init() {
	register(PresetRandomPerSession, buildRandomPerSession)
}

// buildRandomPerSession derives the basis preset name from `seed`, builds
// it, then applies bin jitter on every histogram engine inside the resulting
// distShaper. The function intentionally re-uses the same `seed` for the
// underlying preset so that a known seed reproduces the exact same shape.
func buildRandomPerSession(seed int64) (shaper.Shaper, error) {
	candidates := []string{
		PresetChromeBrowsing,
		PresetYouTubeStreaming,
		PresetBitTorrentIdle,
	}
	// Use a dedicated PCG stream to choose the basis preset so that the choice
	// is independent of the underlying preset's RNG sequence.
	chooserSeed1 := uint64(seed) //nolint:gosec
	chooserSeed2 := uint64(seed) ^ 0xA5A5A5A5A5A5A5A5
	chooser := rand.New(rand.NewPCG(chooserSeed1, chooserSeed2))
	pick := candidates[chooser.IntN(len(candidates))]

	s, err := ByName(pick, seed)
	if err != nil {
		return nil, err
	}
	if ds, ok := s.(*distShaper); ok {
		for _, e := range []dist.Distribution{ds.sizeUp, ds.sizeDown, ds.delayUp, ds.delayDown} {
			if h, ok := e.(*dist.Histogram); ok {
				_ = h.SetRandomizationRange(randomizationFraction)
			}
		}
	}
	return s, nil
}
