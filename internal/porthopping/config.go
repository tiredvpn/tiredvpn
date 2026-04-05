package porthopping

import "time"

// Strategy defines the port hopping algorithm
type Strategy string

const (
	// StrategyRandom selects random ports from the range
	StrategyRandom Strategy = "random"
	// StrategySequential increments port by 1 (wraps around)
	StrategySequential Strategy = "sequential"
	// StrategyFibonacci uses Fibonacci sequence for port offsets
	StrategyFibonacci Strategy = "fibonacci"
)

// Config holds port hopping configuration
type Config struct {
	// Enabled turns port hopping on/off
	Enabled bool

	// PortRangeStart is the beginning of the port range (default: 47000)
	// High ports (47000+) are less analyzed by DPI systems
	PortRangeStart int

	// PortRangeEnd is the end of the port range (default: 65535)
	PortRangeEnd int

	// HopInterval is the base interval between port changes
	// Actual interval will be randomized +/-30% around this value
	// Default: random between 30s and 120s
	HopInterval time.Duration

	// Strategy determines how the next port is selected
	// Options: "random", "sequential", "fibonacci"
	Strategy Strategy

	// Seed is used for deterministic port generation
	// When non-nil, allows client-server synchronization
	Seed []byte
}

// DefaultConfig returns sensible defaults for port hopping
// These settings are optimized for DPI evasion based on TSPU intelligence
func DefaultConfig() *Config {
	return &Config{
		Enabled:        true,
		PortRangeStart: 47000, // High ports less analyzed by DPI
		PortRangeEnd:   65535,
		HopInterval:    60 * time.Second, // Will be randomized 30-120s
		Strategy:       StrategyRandom,
		Seed:           nil, // Random mode by default
	}
}

// Validate checks if the config is valid
func (c *Config) Validate() error {
	if c.PortRangeStart < 1 || c.PortRangeStart > 65535 {
		return ErrInvalidPortRange
	}
	if c.PortRangeEnd < 1 || c.PortRangeEnd > 65535 {
		return ErrInvalidPortRange
	}
	if c.PortRangeStart >= c.PortRangeEnd {
		return ErrInvalidPortRange
	}
	if c.HopInterval < 0 {
		return ErrInvalidHopInterval
	}

	switch c.Strategy {
	case StrategyRandom, StrategySequential, StrategyFibonacci:
		// Valid strategies
	default:
		return ErrInvalidStrategy
	}

	return nil
}

// PortRange returns the number of ports in the range
func (c *Config) PortRange() int {
	return c.PortRangeEnd - c.PortRangeStart + 1
}

// Clone creates a deep copy of the config
func (c *Config) Clone() *Config {
	clone := &Config{
		Enabled:        c.Enabled,
		PortRangeStart: c.PortRangeStart,
		PortRangeEnd:   c.PortRangeEnd,
		HopInterval:    c.HopInterval,
		Strategy:       c.Strategy,
	}
	if c.Seed != nil {
		clone.Seed = make([]byte, len(c.Seed))
		copy(clone.Seed, c.Seed)
	}
	return clone
}
