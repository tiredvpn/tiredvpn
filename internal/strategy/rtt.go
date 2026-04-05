package strategy

import (
	"crypto/rand"
	"math"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Flusher interface for connections that buffer data
type Flusher interface {
	Flush() error
}

// RTTMaskingConfig configures RTT masking behavior
type RTTMaskingConfig struct {
	// Enabled turns RTT masking on/off
	Enabled bool

	// BaseDelay is the minimum artificial delay added to each packet
	// This helps mask the transport RTT vs application RTT discrepancy
	BaseDelay time.Duration

	// JitterRange is the random jitter added on top of BaseDelay
	// Actual delay = BaseDelay + random(0, JitterRange)
	JitterRange time.Duration

	// AdaptiveMode learns from observed RTT patterns
	// When true, delays are adjusted based on real traffic patterns
	AdaptiveMode bool

	// TargetRTT is the RTT we're trying to simulate (e.g., Moscow to Yandex)
	// Only used in AdaptiveMode
	TargetRTT time.Duration

	// BurstMode groups packets and delays them together
	// This mimics natural burst patterns in video streaming
	BurstMode bool

	// BurstSize is number of packets to group in a burst
	BurstSize int

	// BurstInterval is the interval between bursts
	BurstInterval time.Duration

	// Profile is a predefined RTT profile (optional)
	Profile *RTTProfile
}

// RTTProfile defines RTT characteristics for a typical connection
type RTTProfile struct {
	Name           string
	MeanDelay      time.Duration
	StdDev         time.Duration
	MinDelay       time.Duration
	MaxDelay       time.Duration
	BurstSize      int
	BurstInterval  time.Duration
	Description    string
}

// Predefined RTT profiles for different "cover" scenarios
var (
	// MoscowToYandexProfile mimics RTT from Moscow to Yandex datacenter (~5-15ms)
	MoscowToYandexProfile = &RTTProfile{
		Name:          "moscow-yandex",
		MeanDelay:     10 * time.Millisecond,
		StdDev:        3 * time.Millisecond,
		MinDelay:      5 * time.Millisecond,
		MaxDelay:      25 * time.Millisecond,
		BurstSize:     8,
		BurstInterval: 50 * time.Millisecond,
		Description:   "Moscow to Yandex datacenter (domestic)",
	}

	// MoscowToVKProfile mimics RTT from Moscow to VK (~8-20ms)
	MoscowToVKProfile = &RTTProfile{
		Name:          "moscow-vk",
		MeanDelay:     12 * time.Millisecond,
		StdDev:        4 * time.Millisecond,
		MinDelay:      6 * time.Millisecond,
		MaxDelay:      30 * time.Millisecond,
		BurstSize:     10,
		BurstInterval: 40 * time.Millisecond,
		Description:   "Moscow to VK datacenter (domestic)",
	}

	// RegionalRussiaProfile mimics RTT from regions to Moscow (~20-50ms)
        // BeijingToBaiduProfile mimics RTT from Beijing to Baidu (~5-15ms)
        BeijingToBaiduProfile = &RTTProfile{
                Name:          "beijing-baidu",
                MeanDelay:     10 * time.Millisecond,
                StdDev:        3 * time.Millisecond,
                MinDelay:      5 * time.Millisecond,
                MaxDelay:      25 * time.Millisecond,
                BurstSize:     8,
                BurstInterval: 50 * time.Millisecond,
                Description:   "Beijing to Baidu datacenter (domestic)",
        }

        // TehranToAparatProfile mimics RTT from Tehran to Aparat (~10-25ms)
        TehranToAparatProfile = &RTTProfile{
                Name:          "tehran-aparat",
                MeanDelay:     15 * time.Millisecond,
                StdDev:        5 * time.Millisecond,
                MinDelay:      8 * time.Millisecond,
                MaxDelay:      35 * time.Millisecond,
                BurstSize:     6,
                BurstInterval: 60 * time.Millisecond,
                Description:   "Tehran to Aparat datacenter (domestic)",
        }

	RegionalRussiaProfile = &RTTProfile{
		Name:          "regional-russia",
		MeanDelay:     35 * time.Millisecond,
		StdDev:        10 * time.Millisecond,
		MinDelay:      20 * time.Millisecond,
		MaxDelay:      80 * time.Millisecond,
		BurstSize:     6,
		BurstInterval: 100 * time.Millisecond,
		Description:   "Regional Russia to Moscow datacenter",
	}

	// SiberiaProfile mimics RTT from Siberia to Moscow (~60-120ms)
	SiberiaProfile = &RTTProfile{
		Name:          "siberia",
		MeanDelay:     80 * time.Millisecond,
		StdDev:        20 * time.Millisecond,
		MinDelay:      50 * time.Millisecond,
		MaxDelay:      150 * time.Millisecond,
		BurstSize:     4,
		BurstInterval: 150 * time.Millisecond,
		Description:   "Siberia/Far East to Moscow (high latency domestic)",
	}

	// CDNProfile mimics CDN-like RTT (very low, consistent)
	CDNProfile = &RTTProfile{
		Name:          "cdn",
		MeanDelay:     3 * time.Millisecond,
		StdDev:        1 * time.Millisecond,
		MinDelay:      1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BurstSize:     16,
		BurstInterval: 20 * time.Millisecond,
		Description:   "CDN edge (very low latency)",
	}
)

// AllRTTProfiles returns all available profiles
func AllRTTProfiles() []*RTTProfile {
	return []*RTTProfile{
		MoscowToYandexProfile,
		MoscowToVKProfile,
		RegionalRussiaProfile,
		SiberiaProfile,
		CDNProfile,
                BeijingToBaiduProfile,
                TehranToAparatProfile,
	}
}

// GetRTTProfile returns profile by name
func GetRTTProfile(name string) *RTTProfile {
	for _, p := range AllRTTProfiles() {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// DefaultRTTMaskingConfig returns sensible defaults
func DefaultRTTMaskingConfig() RTTMaskingConfig {
	return RTTMaskingConfig{
		Enabled:       true,
		BaseDelay:     5 * time.Millisecond,
		JitterRange:   10 * time.Millisecond,
		AdaptiveMode:  false,
		TargetRTT:     0,
		BurstMode:     true,
		BurstSize:     8,
		BurstInterval: 50 * time.Millisecond,
		Profile:       MoscowToYandexProfile,
	}
}

// RTTMaskingConn wraps a connection with RTT masking
type RTTMaskingConn struct {
	net.Conn
	config RTTMaskingConfig

	mu            sync.Mutex
	burstBuffer   [][]byte
	lastBurstTime time.Time

	// Adaptive stats
	observedRTTs  []time.Duration
	avgObservedRTT time.Duration
}

// NewRTTMaskingConn wraps a connection with RTT masking
func NewRTTMaskingConn(conn net.Conn, config RTTMaskingConfig) *RTTMaskingConn {
	return &RTTMaskingConn{
		Conn:          conn,
		config:        config,
		burstBuffer:   make([][]byte, 0, config.BurstSize),
		lastBurstTime: time.Now(),
		observedRTTs:  make([]time.Duration, 0, 100),
	}
}

// Write implements net.Conn with RTT masking
func (c *RTTMaskingConn) Write(p []byte) (int, error) {
	if !c.config.Enabled {
		return c.Conn.Write(p)
	}

	// Calculate delay based on profile or config
	delay := c.calculateDelay()

	if c.config.BurstMode {
		return c.writeWithBurst(p, delay)
	}

	// Simple delay mode
	if delay > 0 {
		time.Sleep(delay)
	}

	return c.Conn.Write(p)
}

// writeWithBurst groups packets into bursts
func (c *RTTMaskingConn) writeWithBurst(p []byte, delay time.Duration) (int, error) {
	c.mu.Lock()

	// Copy data to buffer
	data := make([]byte, len(p))
	copy(data, p)
	c.burstBuffer = append(c.burstBuffer, data)

	// Check if we should flush the burst
	shouldFlush := len(c.burstBuffer) >= c.config.BurstSize ||
		time.Since(c.lastBurstTime) >= c.config.BurstInterval

	if !shouldFlush {
		c.mu.Unlock()
		return len(p), nil // Buffered, will be sent with burst
	}

	// Flush burst
	buffer := c.burstBuffer
	c.burstBuffer = make([][]byte, 0, c.config.BurstSize)
	c.lastBurstTime = time.Now()
	c.mu.Unlock()

	// Apply inter-burst delay
	if delay > 0 {
		time.Sleep(delay)
	}

	// Send all buffered packets quickly (simulating burst)
	totalWritten := 0
	for _, data := range buffer {
		n, err := c.Conn.Write(data)
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
		// Tiny delay between packets in burst (0.5-2ms)
		inBurstDelay := c.randomDuration(500*time.Microsecond, 2*time.Millisecond)
		time.Sleep(inBurstDelay)
	}

	return len(p), nil
}

// calculateDelay computes the delay based on config and profile
func (c *RTTMaskingConn) calculateDelay() time.Duration {
	if c.config.Profile != nil {
		return c.gaussianDelay(c.config.Profile)
	}

	// Simple uniform jitter
	jitter := c.randomDuration(0, c.config.JitterRange)
	return c.config.BaseDelay + jitter
}

// gaussianDelay generates delay with Gaussian distribution
func (c *RTTMaskingConn) gaussianDelay(profile *RTTProfile) time.Duration {
	// Box-Muller transform for Gaussian distribution
	u1 := c.randomFloat()
	u2 := c.randomFloat()

	// Avoid log(0)
	if u1 < 0.0001 {
		u1 = 0.0001
	}

	// Standard normal
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)

	// Scale to our distribution
	delay := float64(profile.MeanDelay) + z*float64(profile.StdDev)

	// Clamp to min/max
	if delay < float64(profile.MinDelay) {
		delay = float64(profile.MinDelay)
	}
	if delay > float64(profile.MaxDelay) {
		delay = float64(profile.MaxDelay)
	}

	return time.Duration(delay)
}

// randomDuration returns random duration in [min, max)
func (c *RTTMaskingConn) randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}

	rangeNs := int64(max - min)
	n, err := rand.Int(rand.Reader, big.NewInt(rangeNs))
	if err != nil {
		return min
	}

	return min + time.Duration(n.Int64())
}

// randomFloat returns random float in [0, 1)
func (c *RTTMaskingConn) randomFloat() float64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0.5
	}
	return float64(n.Int64()) / float64(1<<53)
}

// Read implements net.Conn (no masking on read, just pass through)
func (c *RTTMaskingConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}

// Flush sends any buffered data immediately without waiting for burst
func (c *RTTMaskingConn) Flush() error {
	c.mu.Lock()
	buffer := c.burstBuffer
	c.burstBuffer = make([][]byte, 0, c.config.BurstSize)
	c.lastBurstTime = time.Now()
	c.mu.Unlock()

	for _, data := range buffer {
		if _, err := c.Conn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes any pending burst and closes connection
func (c *RTTMaskingConn) Close() error {
	// Flush remaining burst buffer
	c.Flush()
	return c.Conn.Close()
}

// UpdateConfig allows runtime config updates
func (c *RTTMaskingConn) UpdateConfig(config RTTMaskingConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
}

// GetStats returns RTT masking statistics
func (c *RTTMaskingConn) GetStats() RTTMaskingStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	return RTTMaskingStats{
		Enabled:        c.config.Enabled,
		ProfileName:    c.getProfileName(),
		AvgObservedRTT: c.avgObservedRTT,
		BurstBuffered:  len(c.burstBuffer),
	}
}

func (c *RTTMaskingConn) getProfileName() string {
	if c.config.Profile != nil {
		return c.config.Profile.Name
	}
	return "custom"
}

// RTTMaskingStats contains runtime statistics
type RTTMaskingStats struct {
	Enabled        bool
	ProfileName    string
	AvgObservedRTT time.Duration
	BurstBuffered  int
}

// WrapWithRTTMasking is a convenience function to wrap connection
func WrapWithRTTMasking(conn net.Conn, profile *RTTProfile) net.Conn {
	if profile == nil {
		profile = MoscowToYandexProfile
	}

	config := RTTMaskingConfig{
		Enabled:       true,
		BurstMode:     true,
		BurstSize:     profile.BurstSize,
		BurstInterval: profile.BurstInterval,
		Profile:       profile,
	}

	log.Debug("Wrapping connection with RTT masking (profile=%s, mean=%v, stddev=%v)",
		profile.Name, profile.MeanDelay, profile.StdDev)

	return NewRTTMaskingConn(conn, config)
}

// Ensure interface compliance
var _ net.Conn = (*RTTMaskingConn)(nil)
