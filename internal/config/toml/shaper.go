package toml

import (
	"fmt"
	"math"
)

// DistType enumerates supported distribution kinds for shaper parameters.
type DistType string

const (
	DistHistogram DistType = "histogram"
	DistLogNormal DistType = "lognormal"
	DistPareto    DistType = "pareto"
	DistMarkov    DistType = "markov"
)

// ShaperConfig holds the [shaper] section common to client and server.
//
// Either Preset (a named profile, resolved by a separate registry) or Custom
// (inline distributions) must be provided, but not both. RandomizationRange
// is forwarded to per-distribution jitter where supported, in [0, 1).
type ShaperConfig struct {
	Preset             string        `toml:"preset,omitempty"`
	Custom             *ShaperCustom `toml:"custom,omitempty"`
	Seed               *int64        `toml:"seed,omitempty"`
	RandomizationRange float64       `toml:"randomization_range,omitempty"`
}

// ShaperCustom collects per-feature distributions to drive the shaper directly
// from config. Each field is optional; nil leaves the default behavior.
type ShaperCustom struct {
	PacketSize   *DistConfig `toml:"packet_size,omitempty"`
	InterArrival *DistConfig `toml:"inter_arrival,omitempty"`
	Burst        *DistConfig `toml:"burst,omitempty"`
}

// DistConfig is a tagged union of supported distributions. Exactly one of the
// inline structs (matching Type) must be populated.
type DistConfig struct {
	Type      DistType        `toml:"type"`
	Histogram *HistogramDist  `toml:"histogram,omitempty"`
	LogNormal *LogNormalDist  `toml:"lognormal,omitempty"`
	Pareto    *ParetoDist     `toml:"pareto,omitempty"`
	Markov    *MarkovDist     `toml:"markov,omitempty"`
}

// HistogramDist describes a discrete weighted distribution. Bins must be
// non-empty and contain at least one strictly positive weight.
type HistogramDist struct {
	Bins []HistogramBin `toml:"bins"`
}

// HistogramBin is a single weighted bucket.
type HistogramBin struct {
	Value  float64 `toml:"value"`
	Weight float64 `toml:"weight"`
}

// LogNormalDist describes X = exp(Mu + Sigma*Z), Z ~ N(0,1). Sigma >= 0.
type LogNormalDist struct {
	Mu    float64 `toml:"mu"`
	Sigma float64 `toml:"sigma"`
}

// ParetoDist describes the Type-I Pareto distribution. Xm > 0, Alpha > 0.
type ParetoDist struct {
	Xm    float64 `toml:"xm"`
	Alpha float64 `toml:"alpha"`
}

// MarkovDist describes a discrete-time Markov chain over named states.
// Transitions is a square stochastic matrix sized len(States)×len(States).
type MarkovDist struct {
	States      []MarkovState `toml:"states"`
	Transitions [][]float64   `toml:"transitions"`
}

// MarkovState is a single state of the Markov chain.
type MarkovState struct {
	Name  string  `toml:"name"`
	Value float64 `toml:"value"`
}

func (s *ShaperConfig) validate() error {
	if s == nil {
		return nil
	}
	if s.RandomizationRange < 0 || s.RandomizationRange >= 1 {
		return fmt.Errorf("shaper.randomization_range must be in [0, 1), got %v", s.RandomizationRange)
	}
	hasPreset := s.Preset != ""
	hasCustom := s.Custom != nil
	if !hasPreset && !hasCustom {
		return fmt.Errorf("shaper: either preset or custom must be set")
	}
	if hasPreset && hasCustom {
		return fmt.Errorf("shaper: preset and custom are mutually exclusive")
	}
	if hasCustom {
		if err := s.Custom.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *ShaperCustom) validate() error {
	for name, d := range map[string]*DistConfig{
		"packet_size":   c.PacketSize,
		"inter_arrival": c.InterArrival,
		"burst":         c.Burst,
	} {
		if d == nil {
			continue
		}
		if err := d.validate(); err != nil {
			return fmt.Errorf("shaper.custom.%s: %w", name, err)
		}
	}
	return nil
}

func (d *DistConfig) validate() error {
	switch d.Type {
	case DistHistogram:
		if d.Histogram == nil {
			return fmt.Errorf("type=histogram requires [histogram] block")
		}
		return d.Histogram.validate()
	case DistLogNormal:
		if d.LogNormal == nil {
			return fmt.Errorf("type=lognormal requires [lognormal] block")
		}
		return d.LogNormal.validate()
	case DistPareto:
		if d.Pareto == nil {
			return fmt.Errorf("type=pareto requires [pareto] block")
		}
		return d.Pareto.validate()
	case DistMarkov:
		if d.Markov == nil {
			return fmt.Errorf("type=markov requires [markov] block")
		}
		return d.Markov.validate()
	case "":
		return fmt.Errorf("missing type")
	default:
		return fmt.Errorf("unknown distribution type %q", d.Type)
	}
}

func (h *HistogramDist) validate() error {
	if len(h.Bins) == 0 {
		return fmt.Errorf("histogram.bins is empty")
	}
	var positive int
	for i, b := range h.Bins {
		if b.Weight < 0 {
			return fmt.Errorf("histogram.bins[%d].weight is negative", i)
		}
		if b.Weight > 0 {
			positive++
		}
	}
	if positive == 0 {
		return fmt.Errorf("histogram.bins must contain at least one positive weight")
	}
	return nil
}

func (l *LogNormalDist) validate() error {
	if l.Sigma < 0 {
		return fmt.Errorf("lognormal.sigma must be non-negative, got %v", l.Sigma)
	}
	return nil
}

func (p *ParetoDist) validate() error {
	if p.Xm <= 0 {
		return fmt.Errorf("pareto.xm must be > 0, got %v", p.Xm)
	}
	if p.Alpha <= 0 {
		return fmt.Errorf("pareto.alpha must be > 0, got %v", p.Alpha)
	}
	return nil
}

func (m *MarkovDist) validate() error {
	n := len(m.States)
	if n == 0 {
		return fmt.Errorf("markov.states is empty")
	}
	if len(m.Transitions) != n {
		return fmt.Errorf("markov.transitions has %d rows, want %d", len(m.Transitions), n)
	}
	for i, row := range m.Transitions {
		if len(row) != n {
			return fmt.Errorf("markov.transitions[%d] has %d entries, want %d", i, len(row), n)
		}
		var sum float64
		for j, p := range row {
			if p < 0 {
				return fmt.Errorf("markov.transitions[%d][%d] is negative", i, j)
			}
			sum += p
		}
		if math.Abs(sum-1.0) > 0.001 {
			return fmt.Errorf("markov.transitions[%d] sums to %v, want 1±0.001", i, sum)
		}
	}
	return nil
}
