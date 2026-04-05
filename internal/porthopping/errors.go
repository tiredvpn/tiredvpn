package porthopping

import "errors"

var (
	// ErrInvalidPortRange indicates invalid port range configuration
	ErrInvalidPortRange = errors.New("invalid port range: must be 1-65535 and start < end")

	// ErrInvalidHopInterval indicates invalid hop interval
	ErrInvalidHopInterval = errors.New("invalid hop interval: must be non-negative")

	// ErrInvalidStrategy indicates unknown port hopping strategy
	ErrInvalidStrategy = errors.New("invalid strategy: must be random, sequential, or fibonacci")

	// ErrHopperDisabled indicates the hopper is disabled
	ErrHopperDisabled = errors.New("port hopper is disabled")

	// ErrNilConfig indicates nil configuration was provided
	ErrNilConfig = errors.New("config cannot be nil")
)
