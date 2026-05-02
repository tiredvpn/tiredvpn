package dist

import (
	"fmt"
	"math/rand/v2"
)

// HistogramBin describes a single bucket of a discrete weighted distribution.
type HistogramBin struct {
	Value  float64
	Weight float64
}

// Histogram is a discrete weighted distribution. Each Next call picks a bin
// proportionally to its weight and returns the bin's Value, optionally jittered
// by ±RandomizationRange (a fraction in [0, 1)).
type Histogram struct {
	bins   []HistogramBin
	cdf    []float64
	totalW float64
	jitter float64
	seed1  uint64
	seed2  uint64
	pcg    *rand.PCG
	rng    *rand.Rand
}

// NewHistogram constructs a Histogram from a non-empty slice of bins. All
// weights must be non-negative and at least one must be strictly positive.
func NewHistogram(bins []HistogramBin, seed int64) (*Histogram, error) {
	if len(bins) == 0 {
		return nil, fmt.Errorf("dist: histogram requires at least one bin")
	}

	cdf := make([]float64, len(bins))
	var total float64
	for i, b := range bins {
		if b.Weight < 0 {
			return nil, fmt.Errorf("dist: bin %d has negative weight %v", i, b.Weight)
		}
		total += b.Weight
		cdf[i] = total
	}
	if total == 0 {
		return nil, fmt.Errorf("dist: histogram total weight is zero")
	}

	binsCopy := make([]HistogramBin, len(bins))
	copy(binsCopy, bins)

	s1, s2 := splitSeed(seed)
	pcg := rand.NewPCG(s1, s2)
	return &Histogram{
		bins:   binsCopy,
		cdf:    cdf,
		totalW: total,
		seed1:  s1,
		seed2:  s2,
		pcg:    pcg,
		rng:    rand.New(pcg),
	}, nil
}

// SetRandomizationRange enables ±r jitter on the emitted value. r must be in
// [0, 1).
func (h *Histogram) SetRandomizationRange(r float64) error {
	if r < 0 || r >= 1 {
		return fmt.Errorf("dist: randomization range must be in [0,1), got %v", r)
	}
	h.jitter = r
	return nil
}

// Next returns the next sample.
func (h *Histogram) Next() float64 {
	u := h.rng.Float64() * h.totalW
	idx := len(h.cdf) - 1
	for i, c := range h.cdf {
		if u <= c {
			idx = i
			break
		}
	}
	v := h.bins[idx].Value
	if h.jitter > 0 {
		v *= 1 + (h.rng.Float64()*2-1)*h.jitter
	}
	return v
}

// Reset rewinds the RNG to the initial seed state.
func (h *Histogram) Reset() {
	h.pcg.Seed(h.seed1, h.seed2)
}
