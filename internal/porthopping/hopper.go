package porthopping

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// PortHopper manages port hopping for DPI evasion
// It supports multiple strategies and provides deterministic port generation
// when a seed is provided (for client-server synchronization)
type PortHopper struct {
	config *Config

	mu          sync.RWMutex
	currentPort int
	lastHop     time.Time
	hopCount    uint64

	// Fibonacci state for StrategyFibonacci
	fibPrev int
	fibCurr int

	// Deterministic RNG for synchronized port generation
	rng *mathrand.Rand

	// Jittered interval for current hop cycle
	jitteredInterval time.Duration

	// Callback when port changes
	onHop func(oldPort, newPort int)
}

// NewPortHopper creates a new port hopper with the given configuration
func NewPortHopper(config *Config) (*PortHopper, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	ph := &PortHopper{
		config:      config.Clone(),
		lastHop:     time.Now(),
		fibPrev:     0,
		fibCurr:     1,
		currentPort: config.PortRangeStart,
	}

	// Initialize RNG based on seed
	if config.Seed != nil && len(config.Seed) > 0 {
		// Deterministic RNG from seed for client-server sync
		h := sha256.Sum256(config.Seed)
		seed := int64(binary.BigEndian.Uint64(h[:8]))
		ph.rng = mathrand.New(mathrand.NewSource(seed))
	} else {
		// Cryptographically secure random seed
		var seedBytes [8]byte
		if _, err := rand.Read(seedBytes[:]); err != nil {
			// Fallback to time-based seed
			ph.rng = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		} else {
			ph.rng = mathrand.New(mathrand.NewSource(int64(binary.BigEndian.Uint64(seedBytes[:]))))
		}
	}

	// Calculate initial port
	ph.currentPort = ph.calculateNextPort()
	ph.jitteredInterval = ph.randomizeInterval()

	log.Debug("PortHopper created (strategy=%s, range=%d-%d, interval=%v, initial_port=%d)",
		config.Strategy, config.PortRangeStart, config.PortRangeEnd,
		config.HopInterval, ph.currentPort)

	return ph, nil
}

// CurrentPort returns the current port being used
func (ph *PortHopper) CurrentPort() int {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.currentPort
}

// ShouldHop checks if it's time to switch to a new port
func (ph *PortHopper) ShouldHop() bool {
	if !ph.config.Enabled {
		return false
	}

	ph.mu.RLock()
	defer ph.mu.RUnlock()

	elapsed := time.Since(ph.lastHop)
	return elapsed >= ph.jitteredInterval
}

// NextPort performs a port hop and returns the new port
// It returns the current port if hopping is disabled
func (ph *PortHopper) NextPort() int {
	if !ph.config.Enabled {
		ph.mu.RLock()
		defer ph.mu.RUnlock()
		return ph.currentPort
	}

	ph.mu.Lock()
	defer ph.mu.Unlock()

	oldPort := ph.currentPort
	newPort := ph.calculateNextPort()

	ph.currentPort = newPort
	ph.lastHop = time.Now()
	ph.hopCount++
	ph.jitteredInterval = ph.randomizeInterval()

	log.Debug("Port hop #%d: %d -> %d (next hop in %v)",
		ph.hopCount, oldPort, newPort, ph.jitteredInterval)

	// Trigger callback if set
	if ph.onHop != nil {
		go ph.onHop(oldPort, newPort)
	}

	return newPort
}

// TimeUntilNextHop returns the duration until the next port hop
func (ph *PortHopper) TimeUntilNextHop() time.Duration {
	if !ph.config.Enabled {
		return 0
	}

	ph.mu.RLock()
	defer ph.mu.RUnlock()

	elapsed := time.Since(ph.lastHop)
	if elapsed >= ph.jitteredInterval {
		return 0
	}
	return ph.jitteredInterval - elapsed
}

// OnHop sets a callback function to be called when port changes
func (ph *PortHopper) OnHop(callback func(oldPort, newPort int)) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.onHop = callback
}

// Stats returns current hopper statistics
func (ph *PortHopper) Stats() Stats {
	ph.mu.RLock()
	defer ph.mu.RUnlock()

	timeUntilHop := ph.jitteredInterval - time.Since(ph.lastHop)
	if timeUntilHop < 0 {
		timeUntilHop = 0
	}

	return Stats{
		Enabled:          ph.config.Enabled,
		CurrentPort:      ph.currentPort,
		HopCount:         ph.hopCount,
		LastHop:          ph.lastHop,
		TimeUntilNextHop: timeUntilHop,
		Strategy:         ph.config.Strategy,
		PortRangeStart:   ph.config.PortRangeStart,
		PortRangeEnd:     ph.config.PortRangeEnd,
	}
}

// GetConfig returns a copy of the current configuration
func (ph *PortHopper) GetConfig() *Config {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.config.Clone()
}

// Reset resets the hopper to initial state
// With a deterministic seed, this will restart the same port sequence
func (ph *PortHopper) Reset() {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.hopCount = 0
	ph.lastHop = time.Now()
	ph.fibPrev = 0
	ph.fibCurr = 1

	// Reset RNG to initial state if using deterministic seed
	if ph.config.Seed != nil && len(ph.config.Seed) > 0 {
		h := sha256.Sum256(ph.config.Seed)
		seed := int64(binary.BigEndian.Uint64(h[:8]))
		ph.rng = mathrand.New(mathrand.NewSource(seed))
	}

	// Recalculate initial port (same as NewPortHopper would)
	ph.currentPort = ph.calculateNextPort()
	ph.jitteredInterval = ph.randomizeInterval()

	log.Debug("PortHopper reset (port=%d)", ph.currentPort)
}

// calculateNextPort computes the next port based on strategy
// Must be called with lock held
func (ph *PortHopper) calculateNextPort() int {
	rangeSize := ph.config.PortRangeEnd - ph.config.PortRangeStart + 1

	switch ph.config.Strategy {
	case StrategyRandom:
		offset := ph.rng.Intn(rangeSize)
		return ph.config.PortRangeStart + offset

	case StrategySequential:
		next := ph.currentPort + 1
		if next > ph.config.PortRangeEnd {
			next = ph.config.PortRangeStart
		}
		return next

	case StrategyFibonacci:
		// Calculate next Fibonacci number
		next := ph.fibPrev + ph.fibCurr
		ph.fibPrev = ph.fibCurr
		ph.fibCurr = next

		// Reset Fibonacci if it gets too large
		if ph.fibCurr > rangeSize*10 {
			ph.fibPrev = 0
			ph.fibCurr = 1
		}

		// Map to port range
		offset := ph.fibCurr % rangeSize
		return ph.config.PortRangeStart + offset

	default:
		// Fallback to start of range
		return ph.config.PortRangeStart
	}
}

// randomizeInterval returns the hop interval with +/-30% jitter
func (ph *PortHopper) randomizeInterval() time.Duration {
	base := ph.config.HopInterval

	// If base is 0, generate random interval between 30-120s
	if base == 0 {
		base = time.Duration(30+ph.rng.Intn(91)) * time.Second
	}

	// Apply jitter: -30% to +30%
	jitterFactor := 0.7 + ph.rng.Float64()*0.6 // 0.7 to 1.3
	return time.Duration(float64(base) * jitterFactor)
}

// cryptoRandomInt returns a cryptographically random int in [0, n)
func cryptoRandomInt(n int) int {
	if n <= 0 {
		return 0
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// Fallback to time-based random
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(nBig.Int64())
}

// Stats contains port hopper statistics
type Stats struct {
	Enabled          bool
	CurrentPort      int
	HopCount         uint64
	LastHop          time.Time
	TimeUntilNextHop time.Duration
	Strategy         Strategy
	PortRangeStart   int
	PortRangeEnd     int
}

// PortList generates a list of ports that the hopper will use
// This is useful for server-side pre-allocation of listeners
// Returns at most maxPorts ports
func (ph *PortHopper) PortList(maxPorts int) []int {
	if maxPorts <= 0 {
		maxPorts = 100
	}

	ph.mu.RLock()
	config := ph.config.Clone()
	ph.mu.RUnlock()

	// Create a temporary hopper with the same seed for deterministic sequence
	tempHopper, err := NewPortHopper(config)
	if err != nil {
		return nil
	}

	ports := make([]int, 0, maxPorts)
	seen := make(map[int]bool)

	for i := 0; i < maxPorts; i++ {
		port := tempHopper.NextPort()
		if !seen[port] {
			ports = append(ports, port)
			seen[port] = true
		}
	}

	return ports
}
