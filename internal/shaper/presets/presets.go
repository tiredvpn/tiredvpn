// Package presets provides ready-to-use Shaper profiles built on top of
// internal/shaper/dist primitives. Presets are referenced by name from the
// TOML config (`shaper.preset = "..."`) and constructed via ByName.
//
// Each preset bundles two Distribution engines per direction (size + delay)
// driven by a single seed, so that two Shapers built with the same name and
// seed reproduce the same packet/delay sequence — a property exercised by
// tests and required by the Hybrid handshake design (see ADR shaper-handshake).
//
// Presets carry a DataPlaneSafe flag distinguishing profiles fit for the VPN
// data plane (sub-second delays, bounded fragmentation) from cover-traffic
// generators that intentionally idle for seconds. Data-plane entry points
// (FromConfig, ByName) reject unsafe presets; cover-traffic callers must use
// ByNameAllowAny explicitly.
package presets

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/dist"
)

// ErrUnknownPreset is returned when the requested preset is not registered.
var ErrUnknownPreset = errors.New("presets: unknown preset")

// ErrPresetNotDataPlaneSafe is returned by FromConfig and ByName when the
// requested preset is a cover-traffic profile (e.g. multi-second idle gaps)
// and therefore unsuitable for tunneling user payload. Cover-traffic emitters
// must call ByNameAllowAny explicitly.
var ErrPresetNotDataPlaneSafe = errors.New("presets: preset is not safe for data plane")

// presetBuilder is the constructor signature every preset file registers.
type presetBuilder func(seed int64) (shaper.Shaper, error)

// presetMeta carries both the constructor and metadata used by gating logic.
// DataPlaneSafe == true means delays are bounded enough (sub-second median)
// that the preset can carry user traffic without throughput collapse.
type presetMeta struct {
	Name          string
	DataPlaneSafe bool
	Build         presetBuilder
}

// registry holds all built-in presets. Populated by init() in each preset
// file so that adding a new preset is a single-file change.
var registry = map[string]presetMeta{}

func register(name string, dataPlaneSafe bool, b presetBuilder) {
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("presets: duplicate registration for %q", name))
	}
	registry[name] = presetMeta{Name: name, DataPlaneSafe: dataPlaneSafe, Build: b}
}

// IsDataPlaneSafe reports whether the named preset is suitable for the VPN
// data plane (sub-second delays, bounded fragmentation). Returns
// ErrUnknownPreset for unknown names.
func IsDataPlaneSafe(name string) (bool, error) {
	m, ok := registry[name]
	if !ok {
		return false, fmt.Errorf("%w: %q", ErrUnknownPreset, name)
	}
	return m.DataPlaneSafe, nil
}

// ByName returns a Shaper configured for the named preset. It rejects presets
// flagged as not data-plane-safe with ErrPresetNotDataPlaneSafe — use
// ByNameAllowAny for cover-traffic generation.
func ByName(name string, seed int64) (shaper.Shaper, error) {
	m, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, name)
	}
	if !m.DataPlaneSafe {
		return nil, fmt.Errorf("%w: %q", ErrPresetNotDataPlaneSafe, name)
	}
	return m.Build(seed)
}

// ByNameAllowAny is like ByName but does not enforce DataPlaneSafe. Use only
// for cover-traffic generation, never for data tunneling. Returns
// ErrUnknownPreset for unknown names.
func ByNameAllowAny(name string, seed int64) (shaper.Shaper, error) {
	m, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, name)
	}
	return m.Build(seed)
}

// List returns all available preset names in deterministic (sorted) order.
func List() []string {
	names := make([]string, 0, len(registry))
	for k := range registry {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

// FromConfig builds a Shaper from a parsed TOML [shaper] section. Either
// cfg.Preset or cfg.Custom must be set, not both. cfg.RandomizationRange is
// applied to histogram bins where supported. cfg.Seed, when nil, is replaced
// by a freshly drawn cryptographic seed. Non-data-plane-safe presets are
// rejected here so that misconfiguration cannot collapse tunnel throughput.
func FromConfig(cfg toml.ShaperConfig) (shaper.Shaper, error) {
	if cfg.Preset != "" && cfg.Custom != nil {
		return nil, errors.New("presets: preset and custom are mutually exclusive")
	}
	if cfg.Preset == "" && cfg.Custom == nil {
		return nil, errors.New("presets: either preset or custom must be set")
	}

	seed := resolveSeed(cfg.Seed)

	if cfg.Preset != "" {
		// ByName already enforces DataPlaneSafe; relying on it keeps the gate
		// in a single place.
		s, err := ByName(cfg.Preset, seed)
		if err != nil {
			return nil, err
		}
		if cfg.RandomizationRange > 0 {
			if ds, ok := s.(*distShaper); ok {
				ds.applyRandomization(cfg.RandomizationRange)
			}
		}
		return s, nil
	}

	return buildCustom(cfg.Custom, seed, cfg.RandomizationRange)
}

func resolveSeed(s *int64) int64 {
	if s != nil {
		return *s
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure on Linux is essentially impossible; fall back
		// to a fixed sentinel so behavior remains deterministic for tests
		// that intercept this path.
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b[:])) //nolint:gosec // intentional cast
}

func buildCustom(c *toml.ShaperCustom, seed int64, rr float64) (shaper.Shaper, error) {
	ds := &distShaper{mtu: defaultMTU}

	if c.PacketSize != nil {
		d, err := buildDistribution(c.PacketSize, seed, rr)
		if err != nil {
			return nil, fmt.Errorf("packet_size: %w", err)
		}
		ds.sizeUp = d
		ds.sizeDown = d
	} else {
		ds.sizeUp = constDist(defaultPacketSize)
		ds.sizeDown = constDist(defaultPacketSize)
	}

	if c.InterArrival != nil {
		d, err := buildDistribution(c.InterArrival, seed^seedSaltDelay, rr)
		if err != nil {
			return nil, fmt.Errorf("inter_arrival: %w", err)
		}
		ds.delayUp = d
		ds.delayDown = d
	} else {
		ds.delayUp = constDist(0)
		ds.delayDown = constDist(0)
	}

	// Burst is currently treated as an additional size mixer; if present, it
	// overrides per-direction size on Down (downloads tend to burst).
	if c.Burst != nil {
		d, err := buildDistribution(c.Burst, seed^seedSaltBurst, rr)
		if err != nil {
			return nil, fmt.Errorf("burst: %w", err)
		}
		ds.sizeDown = d
	}

	return ds, nil
}

func buildDistribution(d *toml.DistConfig, seed int64, rr float64) (dist.Distribution, error) {
	switch d.Type {
	case toml.DistHistogram:
		bins := make([]dist.HistogramBin, len(d.Histogram.Bins))
		for i, b := range d.Histogram.Bins {
			bins[i] = dist.HistogramBin{Value: b.Value, Weight: b.Weight}
		}
		h, err := dist.NewHistogram(bins, seed)
		if err != nil {
			return nil, err
		}
		if rr > 0 {
			if err := h.SetRandomizationRange(rr); err != nil {
				return nil, err
			}
		}
		return h, nil
	case toml.DistLogNormal:
		return dist.NewLogNormal(d.LogNormal.Mu, d.LogNormal.Sigma, seed), nil
	case toml.DistPareto:
		return dist.NewPareto(d.Pareto.Xm, d.Pareto.Alpha, seed), nil
	case toml.DistMarkov:
		states := make([]dist.MarkovState, len(d.Markov.States))
		for i, s := range d.Markov.States {
			states[i] = dist.MarkovState{Name: s.Name, Value: s.Value}
		}
		return dist.NewMarkovBurst(states, d.Markov.Transitions, seed)
	default:
		return nil, fmt.Errorf("unknown distribution type %q", d.Type)
	}
}
