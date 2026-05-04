package presets

import (
	"math"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// chiSquare returns Pearson's χ² statistic for the given observed and
// expected counts. len(observed) must equal len(expected) and len > 1.
func chiSquare(observed, expected []float64) float64 {
	var x2 float64
	for i := range observed {
		d := observed[i] - expected[i]
		x2 += d * d / expected[i]
	}
	return x2
}

// chiSquarePValue approximates the upper-tail p-value of a χ² statistic with
// k degrees of freedom using a Wilson–Hilferty cube-root normal transform.
// For df ≥ 3 (which is our case), the approximation is accurate enough for
// goodness-of-fit decisions at α = 0.05 / 0.01.
func chiSquarePValue(x2 float64, df int) float64 {
	if df < 1 || x2 < 0 {
		return 0
	}
	k := float64(df)
	// Wilson–Hilferty: Z = ((χ²/k)^(1/3) - (1 - 2/(9k))) / sqrt(2/(9k))
	z := (math.Cbrt(x2/k) - (1 - 2.0/(9*k))) / math.Sqrt(2.0/(9*k))
	// p = P(Z > z) = 0.5 * erfc(z / sqrt(2))
	return 0.5 * math.Erfc(z/math.Sqrt2)
}

// histogramFit draws N samples from the size distribution of a preset (Down
// direction) and computes χ² against the target weights, returning the
// p-value. Only the listed bin values are counted; unexpected values
// (shouldn't happen with default zero jitter) are reported as a fail.
func histogramFit(t *testing.T, s shaper.Shaper, dir shaper.Direction, weights map[int]float64, N int) float64 {
	t.Helper()
	counts := map[int]int{}
	for range N {
		v := s.NextPacketSize(dir)
		counts[v]++
	}
	// Normalize weights and verify all observed values are in the expected set.
	var totalW float64
	for _, w := range weights {
		totalW += w
	}
	observed := make([]float64, 0, len(weights))
	expected := make([]float64, 0, len(weights))
	for v, w := range weights {
		observed = append(observed, float64(counts[v]))
		expected = append(expected, w/totalW*float64(N))
	}
	// Verify no out-of-range values.
	for v, c := range counts {
		if _, ok := weights[v]; !ok {
			t.Errorf("unexpected bin value %d (count=%d) — preset emitted off-spec value", v, c)
		}
	}
	x2 := chiSquare(observed, expected)
	return chiSquarePValue(x2, len(weights)-1)
}

func TestPreset_Chrome_StatisticalSignature(t *testing.T) {
	weights := map[int]float64{
		60:   0.20,
		180:  0.25,
		500:  0.20,
		900:  0.15,
		1300: 0.15,
		1400: 0.05,
	}
	s, err := ByName(PresetChromeBrowsing, 12345)
	if err != nil {
		t.Fatal(err)
	}
	p := histogramFit(t, s, shaper.DirectionDown, weights, 100_000)
	if p < 0.05 {
		t.Fatalf("chrome_browsing χ² p=%.4g < 0.05; empirical histogram diverges from spec", p)
	}
	t.Logf("chrome_browsing p-value = %.4g", p)
}

func TestPreset_YouTube_StatisticalSignature(t *testing.T) {
	weights := map[int]float64{
		1300: 0.20,
		1400: 0.30,
		1450: 0.40,
		600:  0.05,
		100:  0.05,
	}
	s, err := ByName(PresetYouTubeStreaming, 12345)
	if err != nil {
		t.Fatal(err)
	}
	p := histogramFit(t, s, shaper.DirectionDown, weights, 100_000)
	if p < 0.05 {
		t.Fatalf("youtube_streaming χ² p=%.4g < 0.05", p)
	}
	t.Logf("youtube_streaming p-value = %.4g", p)
}

func TestPreset_BitTorrent_StatisticalSignature(t *testing.T) {
	weights := map[int]float64{
		68:   0.40,
		144:  0.25,
		320:  0.20,
		600:  0.10,
		1200: 0.05,
	}
	s, err := ByNameAllowAny(PresetBitTorrentIdle, 12345)
	if err != nil {
		t.Fatal(err)
	}
	p := histogramFit(t, s, shaper.DirectionDown, weights, 100_000)
	if p < 0.05 {
		t.Fatalf("bittorrent_idle χ² p=%.4g < 0.05", p)
	}
	t.Logf("bittorrent_idle p-value = %.4g", p)
}

// TestPreset_RandomPerSession_VariesAcrossSeeds checks that distinct seeds
// produce distinguishable distributions. We compute pairwise χ² statistics on
// empirical histograms and require most pairs to be statistically distinct
// (p < 0.01) — i.e. the random_per_session preset really does randomize.
//
// We bin onto a coarse grid that covers all three basis presets so that any
// shift across base preset / jittered bins shows up as separation.
func TestPreset_RandomPerSession_VariesAcrossSeeds(t *testing.T) {
	const (
		nSeeds  = 10
		samples = 5000
	)
	// Coarse 10-bucket grid over [1, MTU] so every emitted size lands in a
	// bucket regardless of which basis preset is picked.
	const buckets = 10
	bucket := func(v int) int {
		b := (v - 1) * buckets / defaultMTU
		if b < 0 {
			b = 0
		}
		if b >= buckets {
			b = buckets - 1
		}
		return b
	}
	histograms := make([][buckets]float64, nSeeds)
	for i := range nSeeds {
		s, err := ByName(PresetRandomPerSession, int64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		for range samples {
			histograms[i][bucket(s.NextPacketSize(shaper.DirectionDown))]++
		}
	}
	// Pairwise χ² between empirical histograms with pooled expected counts.
	distinct := 0
	pairs := 0
	for i := range nSeeds {
		for j := i + 1; j < nSeeds; j++ {
			obs := make([]float64, 0, buckets)
			exp := make([]float64, 0, buckets)
			for k := range buckets {
				a := histograms[i][k]
				b := histograms[j][k]
				if a+b == 0 {
					continue
				}
				// Two-sample χ²: each cell uses pooled mean as expected.
				m := (a + b) / 2
				obs = append(obs, a, b)
				exp = append(exp, m, m)
			}
			df := len(obs)/2 - 1
			if df < 1 {
				continue
			}
			x2 := chiSquare(obs, exp)
			p := chiSquarePValue(x2, df)
			pairs++
			if p < 0.01 {
				distinct++
			}
		}
	}
	// Require >= 40% of pairs to be distinguishable. With 2 data-plane-safe
	// base presets and 15% jitter, ~half the pairs share a base preset and
	// are inherently similar — only cross-base pairs are reliably distinct.
	if float64(distinct)/float64(pairs) < 0.4 {
		t.Fatalf("random_per_session: only %d/%d pairs distinguishable (want ≥ 40%%)", distinct, pairs)
	}
	t.Logf("random_per_session: %d/%d distinct pairs", distinct, pairs)
}
