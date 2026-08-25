package mux

import (
	"time"

	"github.com/xtaci/smux"
)

// Config holds configuration for the mux layer
type Config struct {
	// KeepAliveInterval is how often to send keepalive pings
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is how long to wait for keepalive response
	KeepAliveTimeout time.Duration

	// MaxFrameSize is the maximum size of a single frame
	// Larger frames reduce overhead but increase latency
	MaxFrameSize int

	// MaxReceiveBuffer is the total receive buffer size for all streams
	MaxReceiveBuffer int

	// MaxStreams is the maximum number of concurrent streams (0 = unlimited)
	MaxStreams int

	// CarrierBudgetBytes is the per-session byte budget before the carrier
	// connection is considered exhausted (0 = disabled).
	// Recommended value when enabled: 12288 (12KB).
	CarrierBudgetBytes int64

	// CarrierBudgetJitter randomizes the effective budget by ±jitter fraction
	// (0.0-1.0). Applied once per client at creation. Recommended: 0.2 (±20%).
	CarrierBudgetJitter float64
}

// DefaultConfig returns sensible defaults optimized for DPI evasion
// These settings balance:
// - Low latency (small keepalive interval)
// - Good throughput (large buffers)
// - DPI confusion (reasonable frame sizes)
func DefaultConfig() *Config {
	return &Config{
		KeepAliveInterval: 10 * time.Second, // Fast detection of dead connections
		KeepAliveTimeout:  30 * time.Second, // Allow for network jitter
		MaxFrameSize:      32768,            // 32KB frames - good balance
		MaxReceiveBuffer:  4194304,          // 4MB total receive buffer
		MaxStreams:        0,                // Unlimited streams
		// CarrierBudgetBytes left at 0 (disabled by default).
		// Enabled via strategy; recommended value is 12288 (12KB) with
		// CarrierBudgetJitter 0.2 (±20%).
	}
}

// HighThroughputConfig returns config optimized for high throughput
// Use this for bulk data transfer scenarios
func HighThroughputConfig() *Config {
	return &Config{
		KeepAliveInterval: 15 * time.Second,
		KeepAliveTimeout:  45 * time.Second,
		MaxFrameSize:      65535,    // Maximum frame size
		MaxReceiveBuffer:  16777216, // 16MB total buffer
		MaxStreams:        0,
	}
}

// LowLatencyConfig returns config optimized for low latency
// Use this for interactive applications (SSH, gaming, etc.)
func LowLatencyConfig() *Config {
	return &Config{
		KeepAliveInterval: 5 * time.Second, // Very fast keepalive
		KeepAliveTimeout:  15 * time.Second,
		MaxFrameSize:      16384,   // Smaller frames for lower latency
		MaxReceiveBuffer:  2097152, // 2MB total buffer
		MaxStreams:        0,
	}
}

// MobileConfig returns config optimized for mobile networks
// Handles network transitions and high latency
func MobileConfig() *Config {
	return &Config{
		KeepAliveInterval: 20 * time.Second, // Less aggressive keepalive for battery
		KeepAliveTimeout:  60 * time.Second, // More tolerance for mobile latency
		MaxFrameSize:      32768,            // Standard frames
		MaxReceiveBuffer:  2097152,          // 2MB - conserve memory
		MaxStreams:        100,              // Limit streams on mobile
	}
}

// Validate checks if the config values are valid
func (c *Config) Validate() error {
	if c.KeepAliveInterval <= 0 {
		return ErrMuxInvalidConfig
	}
	if c.KeepAliveTimeout <= c.KeepAliveInterval {
		return ErrMuxInvalidConfig
	}
	if c.MaxFrameSize < 1024 || c.MaxFrameSize > 65535 {
		return ErrMuxInvalidConfig
	}
	if c.MaxReceiveBuffer < c.MaxFrameSize {
		return ErrMuxInvalidConfig
	}
	return nil
}

// Clone creates a deep copy of the config
func (c *Config) Clone() *Config {
	return &Config{
		KeepAliveInterval:   c.KeepAliveInterval,
		KeepAliveTimeout:    c.KeepAliveTimeout,
		MaxFrameSize:        c.MaxFrameSize,
		MaxReceiveBuffer:    c.MaxReceiveBuffer,
		MaxStreams:          c.MaxStreams,
		CarrierBudgetBytes:  c.CarrierBudgetBytes,
		CarrierBudgetJitter: c.CarrierBudgetJitter,
	}
}

// SmuxSilentConfig returns an smux configuration that neither sends keepalives
// nor kills a session for the lack of them.
//
// smux's default sends a NOP every ten seconds from a plain time.Ticker with no
// jitter (session.go, keepalive). On the wire that is a perfectly periodic
// pulse repeating without end: of 772 idle gaps longer than five seconds in one
// capture, 706 were exactly ten. Recovering it needs an autocorrelation over
// packet timestamps and nothing else - no model, no centroids, no payload. A
// browser's PING follows events; only a metronome ticks.
//
// Jitter is the wrong fix and we have already made that mistake once today, on
// the binding record's padding: uniform jitter produces a uniform distribution
// of intervals, which is its own signature moved into the time axis. Silence
// has no distribution.
//
// It is safe because the pings were never load-bearing. Measurement showed
// sessions surviving sixty seconds of idleness without a single packet; the
// pings exist to notice a dead peer, and noticing a dead peer belongs to an
// active health check rather than to a metronome on every connection.
//
// smux rejects a zero interval outright and requires the timeout to be at least
// the interval, so "disabled" is expressed as durations no session will ever
// reach. Both matter: silencing the sender alone would leave the receiver
// killing the session after thirty seconds of the quiet we just created.
func SmuxSilentConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = smuxSilentInterval
	c.KeepAliveTimeout = smuxSilentTimeout
	return c
}

const (
	// smuxSilentInterval is far beyond any session's life, which is how a
	// library that refuses to be told "never" is told never.
	smuxSilentInterval = 24 * time.Hour
	smuxSilentTimeout  = 48 * time.Hour
)
