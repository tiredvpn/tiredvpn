package mux

import "errors"

// Mux layer errors
var (
	// ErrMuxClosed indicates the mux session is closed
	ErrMuxClosed = errors.New("mux: session is closed")

	// ErrMuxSessionFailed indicates session creation failed
	ErrMuxSessionFailed = errors.New("mux: session creation failed")

	// ErrMuxStreamFailed indicates stream creation failed
	ErrMuxStreamFailed = errors.New("mux: stream creation failed")

	// ErrMuxNoSession indicates no active session exists
	ErrMuxNoSession = errors.New("mux: no active session")

	// ErrMuxInvalidConfig indicates invalid configuration
	ErrMuxInvalidConfig = errors.New("mux: invalid configuration")

	// ErrMuxMaxStreamsReached indicates max streams limit reached
	ErrMuxMaxStreamsReached = errors.New("mux: max streams limit reached")
)
