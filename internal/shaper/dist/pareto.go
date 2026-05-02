package dist

import (
	"math"
	"math/rand/v2"
)

// Pareto samples a Type-I Pareto distribution with scale Xm > 0 and shape
// Alpha > 0 via inverse CDF: X = Xm / U^(1/Alpha) where U ~ Uniform(0, 1].
type Pareto struct {
	Xm    float64
	Alpha float64

	seed1 uint64
	seed2 uint64
	pcg   *rand.PCG
	rng   *rand.Rand
}

// NewPareto constructs a Pareto sampler.
func NewPareto(xm, alpha float64, seed int64) *Pareto {
	s1, s2 := splitSeed(seed)
	pcg := rand.NewPCG(s1, s2)
	return &Pareto{
		Xm:    xm,
		Alpha: alpha,
		seed1: s1,
		seed2: s2,
		pcg:   pcg,
		rng:   rand.New(pcg),
	}
}

// Next returns the next sample.
func (p *Pareto) Next() float64 {
	u := 1.0 - p.rng.Float64()
	return p.Xm / math.Pow(u, 1.0/p.Alpha)
}

// Reset rewinds the RNG to the initial seed state.
func (p *Pareto) Reset() {
	p.pcg.Seed(p.seed1, p.seed2)
}
