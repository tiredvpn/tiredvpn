package mux

import "time"

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
		KeepAliveInterval: c.KeepAliveInterval,
		KeepAliveTimeout:  c.KeepAliveTimeout,
		MaxFrameSize:      c.MaxFrameSize,
		MaxReceiveBuffer:  c.MaxReceiveBuffer,
		MaxStreams:        c.MaxStreams,
	}
}
