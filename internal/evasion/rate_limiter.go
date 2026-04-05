package evasion

import (
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

// AdaptiveRateLimiter implements token bucket with jitter to avoid TSPU detection
// TSPU detects bulk data transfers by:
// 1. Consistent high bandwidth usage
// 2. Regular packet timing patterns
// 3. Sustained throughput above thresholds
//
// Our countermeasures:
// 1. Rate limit to stay below detection threshold (~100-200 KB/s base)
// 2. Add random jitter to timing (±30%)
// 3. Variable "micro-pauses" that mimic buffering/rebuffering
// 4. Adaptive rate based on connection health
type AdaptiveRateLimiter struct {
	// Base rate in bytes per second
	bytesPerSecond int64

	// Jitter percentage (0.0 - 1.0)
	jitterPercent float64

	// Token bucket state
	tokens    float64
	lastCheck time.Time
	mu        sync.Mutex

	// Adaptive parameters
	consecutiveSuccesses int
	consecutiveFailures  int
	currentMultiplier    float64 // 0.5 - 2.0, adjusts rate based on health

	// Micro-pause simulation (mimics video buffering)
	microPauseChance   float64       // Probability of micro-pause (0.01 = 1%)
	microPauseMin      time.Duration // Minimum pause duration
	microPauseMax      time.Duration // Maximum pause duration
	lastMicroPause     time.Time
	microPauseCooldown time.Duration // Minimum time between pauses

	// Stats
	bytesSent        int64
	bytesThrottled   int64
	microPausesCount int64

	// RNG (use separate instance to avoid contention)
	rng *rand.Rand
}

// RateLimiterConfig configures the rate limiter
type RateLimiterConfig struct {
	// Base rate in bytes per second (default: 150KB/s)
	BytesPerSecond int64

	// Jitter percentage (default: 0.3 = 30%)
	JitterPercent float64

	// Micro-pause settings
	MicroPauseChance   float64       // Default: 0.02 (2%)
	MicroPauseMin      time.Duration // Default: 50ms
	MicroPauseMax      time.Duration // Default: 300ms
	MicroPauseCooldown time.Duration // Default: 2s
}

// DefaultRateLimiterConfig returns conservative config for TSPU evasion
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		BytesPerSecond:     150 * 1024, // 150 KB/s - conservative for Russia
		JitterPercent:      0.30,       // ±30% timing variation
		MicroPauseChance:   0.02,       // 2% chance per write
		MicroPauseMin:      50 * time.Millisecond,
		MicroPauseMax:      300 * time.Millisecond,
		MicroPauseCooldown: 2 * time.Second,
	}
}

// AggressiveRateLimiterConfig returns higher throughput config
func AggressiveRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		BytesPerSecond:     300 * 1024, // 300 KB/s
		JitterPercent:      0.25,
		MicroPauseChance:   0.01,
		MicroPauseMin:      30 * time.Millisecond,
		MicroPauseMax:      150 * time.Millisecond,
		MicroPauseCooldown: 3 * time.Second,
	}
}

// StealthRateLimiterConfig returns very conservative config for heavy DPI
func StealthRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		BytesPerSecond:     80 * 1024, // 80 KB/s - very conservative
		JitterPercent:      0.40,      // ±40% timing variation
		MicroPauseChance:   0.05,      // 5% chance
		MicroPauseMin:      100 * time.Millisecond,
		MicroPauseMax:      500 * time.Millisecond,
		MicroPauseCooldown: 1 * time.Second,
	}
}

// NewAdaptiveRateLimiter creates a new rate limiter
func NewAdaptiveRateLimiter(config *RateLimiterConfig) *AdaptiveRateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	return &AdaptiveRateLimiter{
		bytesPerSecond:     config.BytesPerSecond,
		jitterPercent:      config.JitterPercent,
		tokens:             float64(config.BytesPerSecond), // Start with full bucket
		lastCheck:          time.Now(),
		currentMultiplier:  1.0,
		microPauseChance:   config.MicroPauseChance,
		microPauseMin:      config.MicroPauseMin,
		microPauseMax:      config.MicroPauseMax,
		microPauseCooldown: config.MicroPauseCooldown,
		rng:                rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Wait blocks until n bytes can be sent, applying jitter
// Small packets (<1KB) are allowed through without rate limiting to avoid
// breaking handshakes and control traffic
func (r *AdaptiveRateLimiter) Wait(n int) {
	// Allow small packets through immediately - these are usually control/handshake
	// TSPU focuses on bulk transfers, not small packets
	if n < 1024 {
		r.mu.Lock()
		r.bytesSent += int64(n)
		r.mu.Unlock()
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Refill tokens based on elapsed time
	elapsed := now.Sub(r.lastCheck).Seconds()
	r.lastCheck = now

	effectiveRate := float64(r.bytesPerSecond) * r.currentMultiplier
	r.tokens += elapsed * effectiveRate

	// Cap tokens at 2 seconds worth (allows small bursts)
	maxTokens := effectiveRate * 2.0
	if r.tokens > maxTokens {
		r.tokens = maxTokens
	}

	// Check if we need to wait
	needed := float64(n)
	if r.tokens >= needed {
		r.tokens -= needed
		r.bytesSent += int64(n)

		// Maybe do micro-pause (mimics buffering)
		r.maybeDoMicroPause()
		return
	}

	// Calculate wait time with jitter
	deficit := needed - r.tokens
	baseWait := deficit / effectiveRate

	// Add jitter (±jitterPercent)
	jitter := (r.rng.Float64()*2 - 1) * r.jitterPercent
	waitTime := time.Duration(baseWait*(1+jitter)*1e9) * time.Nanosecond

	r.bytesThrottled += int64(n)

	// Release lock during sleep
	r.mu.Unlock()
	time.Sleep(waitTime)
	r.mu.Lock()

	// After waiting, consume tokens
	r.tokens = 0 // We've waited for all needed tokens
	r.bytesSent += int64(n)

	// Maybe do micro-pause
	r.maybeDoMicroPause()
}

// maybeDoMicroPause randomly pauses to mimic video buffering
// Must be called with lock held
func (r *AdaptiveRateLimiter) maybeDoMicroPause() {
	// Check cooldown
	if time.Since(r.lastMicroPause) < r.microPauseCooldown {
		return
	}

	// Random chance
	if r.rng.Float64() > r.microPauseChance {
		return
	}

	// Calculate pause duration
	pauseRange := r.microPauseMax - r.microPauseMin
	pause := r.microPauseMin + time.Duration(r.rng.Int63n(int64(pauseRange)))

	r.lastMicroPause = time.Now()
	r.microPausesCount++

	// Release lock during sleep
	r.mu.Unlock()
	time.Sleep(pause)
	r.mu.Lock()
}

// RecordSuccess indicates successful data transfer, may increase rate
func (r *AdaptiveRateLimiter) RecordSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.consecutiveSuccesses++
	r.consecutiveFailures = 0

	// Slowly increase rate after 10 consecutive successes
	if r.consecutiveSuccesses >= 10 && r.currentMultiplier < 2.0 {
		r.currentMultiplier *= 1.1
		if r.currentMultiplier > 2.0 {
			r.currentMultiplier = 2.0
		}
		r.consecutiveSuccesses = 0
	}
}

// RecordFailure indicates throttling detected, decreases rate
func (r *AdaptiveRateLimiter) RecordFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.consecutiveFailures++
	r.consecutiveSuccesses = 0

	// Quickly decrease rate on failure
	if r.consecutiveFailures >= 2 && r.currentMultiplier > 0.5 {
		r.currentMultiplier *= 0.7
		if r.currentMultiplier < 0.5 {
			r.currentMultiplier = 0.5
		}
	}
}

// Stats returns rate limiter statistics
func (r *AdaptiveRateLimiter) Stats() (bytesSent, bytesThrottled, microPauses int64, multiplier float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytesSent, r.bytesThrottled, r.microPausesCount, r.currentMultiplier
}

// GetEffectiveRate returns current effective rate in bytes/sec
func (r *AdaptiveRateLimiter) GetEffectiveRate() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int64(float64(r.bytesPerSecond) * r.currentMultiplier)
}

// RateLimitedConn wraps a connection with rate limiting
type RateLimitedConn struct {
	net.Conn
	limiter   *AdaptiveRateLimiter
	direction string // "upload", "download", or "both"
}

// NewRateLimitedConn wraps a connection with rate limiting
func NewRateLimitedConn(conn net.Conn, config *RateLimiterConfig, direction string) *RateLimitedConn {
	return &RateLimitedConn{
		Conn:      conn,
		limiter:   NewAdaptiveRateLimiter(config),
		direction: direction,
	}
}

// Write writes data with rate limiting (for uploads)
func (c *RateLimitedConn) Write(p []byte) (int, error) {
	if c.direction == "upload" || c.direction == "both" {
		c.limiter.Wait(len(p))
	}
	return c.Conn.Write(p)
}

// Read reads data with rate limiting (for downloads)
func (c *RateLimitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		return n, err
	}

	if c.direction == "download" || c.direction == "both" {
		c.limiter.Wait(n)
	}
	return n, nil
}

// RecordSuccess delegates to limiter
func (c *RateLimitedConn) RecordSuccess() {
	c.limiter.RecordSuccess()
}

// RecordFailure delegates to limiter
func (c *RateLimitedConn) RecordFailure() {
	c.limiter.RecordFailure()
}

// Stats returns rate limiter stats
func (c *RateLimitedConn) Stats() (bytesSent, bytesThrottled, microPauses int64, multiplier float64) {
	return c.limiter.Stats()
}

// Ensure interface compliance
var _ net.Conn = (*RateLimitedConn)(nil)
var _ io.ReadWriter = (*RateLimitedConn)(nil)
