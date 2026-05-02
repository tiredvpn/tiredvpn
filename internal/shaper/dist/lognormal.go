package dist

import (
	"math"
	"math/rand/v2"
)

// LogNormal samples X = exp(Mu + Sigma*Z) where Z ~ N(0, 1).
type LogNormal struct {
	Mu    float64
	Sigma float64

	seed1 uint64
	seed2 uint64
	pcg   *rand.PCG
	rng   *rand.Rand
}

// NewLogNormal constructs a LogNormal sampler. Sigma must be non-negative.
func NewLogNormal(mu, sigma float64, seed int64) *LogNormal {
	s1, s2 := splitSeed(seed)
	pcg := rand.NewPCG(s1, s2)
	return &LogNormal{
		Mu:    mu,
		Sigma: sigma,
		seed1: s1,
		seed2: s2,
		pcg:   pcg,
		rng:   rand.New(pcg),
	}
}

// Next returns the next sample.
func (l *LogNormal) Next() float64 {
	z := l.rng.NormFloat64()
	return math.Exp(l.Mu + l.Sigma*z)
}

// Reset rewinds the RNG to the initial seed state.
func (l *LogNormal) Reset() {
	l.pcg.Seed(l.seed1, l.seed2)
}
