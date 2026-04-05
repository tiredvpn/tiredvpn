package strategy

import (
	"math"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	// CircuitClosed - normal operation, requests flow through
	CircuitClosed CircuitState = iota
	// CircuitOpen - circuit is tripped, requests are blocked
	CircuitOpen
	// CircuitHalfOpen - testing if service recovered
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// outcomeType classifies a request outcome for the sliding window
type outcomeType int

const (
	outcomeSuccess outcomeType = iota
	outcomeFailure
	outcomeTimeout
)

// windowEntry records a single outcome with its timestamp and optional RTT
type windowEntry struct {
	outcome   outcomeType
	timestamp time.Time
	rtt       time.Duration // zero if not measured
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	FailureThreshold int           // Base number of failures before opening circuit
	ResetTimeout     time.Duration // Initial timeout before trying half-open (exponential backoff from here)
	HalfOpenMax      int           // Max test requests allowed in half-open state

	// Adaptive settings (zero values use sensible defaults)
	WindowSize         int           // Max entries in sliding window (default 20)
	WindowDuration     time.Duration // How far back to look (default 2 min)
	MinFailureRate     float64       // Min failure rate in window to open on stable network (default 0.7)
	UnstableFailRate   float64       // Min failure rate on unstable network (default 0.85)
	MinSamples         int           // Minimum samples in window before circuit can open (default 5)
	HalfOpenSuccessReq int           // Successes needed in half-open to close (default 2 out of HalfOpenMax)
	MaxResetTimeout    time.Duration // Cap for exponential backoff (default 5 min)
}

// DefaultCircuitBreakerConfig returns sensible defaults
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:   5,
		ResetTimeout:       30 * time.Second,
		HalfOpenMax:        3,
		WindowSize:         20,
		WindowDuration:     2 * time.Minute,
		MinFailureRate:     0.7,
		UnstableFailRate:   0.85,
		MinSamples:         5,
		HalfOpenSuccessReq: 2,
		MaxResetTimeout:    5 * time.Minute,
	}
}

// CircuitBreaker implements the circuit breaker pattern with adaptive thresholds.
//
// Key behaviors:
//   - Sliding window tracks outcomes over time (not just consecutive failures)
//   - RTT variance detects network instability (WiFi roaming, cell handoff)
//   - Unstable networks get higher failure rate threshold (85% vs 70%)
//   - Minimum 5 samples required before circuit can open
//   - Graduated half-open recovery: 3 test requests, 2/3 must succeed
//   - Exponential backoff on ResetTimeout: 30s -> 1m -> 2m -> 5m (capped)
type CircuitBreaker struct {
	config CircuitBreakerConfig

	mu                 sync.RWMutex
	state              CircuitState
	consecutiveFail    int
	consecutiveTimeout int
	lastFailure        time.Time
	lastStateChange    time.Time

	// Half-open graduated recovery
	halfOpenCount      int // requests attempted in half-open
	halfOpenSuccess    int // successes in half-open

	// Exponential backoff
	currentResetTimeout time.Duration // grows with each re-open
	openCount           int           // how many times circuit has opened (for backoff)

	// Sliding window for adaptive thresholds
	window []windowEntry

	// RTT tracking for network stability detection
	rttSamples    []time.Duration
	rttMean       time.Duration
	rttVariance   float64 // in nanoseconds^2
	networkStable bool    // cached stability assessment

	// Network-down suppression (set by manager)
	networkDown bool
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	// Apply defaults for zero-valued settings
	if config.WindowSize == 0 {
		config.WindowSize = 20
	}
	if config.WindowDuration == 0 {
		config.WindowDuration = 2 * time.Minute
	}
	if config.MinFailureRate == 0 {
		config.MinFailureRate = 0.7
	}
	if config.UnstableFailRate == 0 {
		config.UnstableFailRate = 0.85
	}
	if config.MinSamples == 0 {
		config.MinSamples = 5
	}
	if config.HalfOpenMax == 0 {
		config.HalfOpenMax = 3
	}
	if config.HalfOpenSuccessReq == 0 {
		config.HalfOpenSuccessReq = 2
	}
	if config.MaxResetTimeout == 0 {
		config.MaxResetTimeout = 5 * time.Minute
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = 30 * time.Second
	}
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}

	return &CircuitBreaker{
		config:              config,
		state:               CircuitClosed,
		lastStateChange:     time.Now(),
		currentResetTimeout: config.ResetTimeout,
		window:              make([]windowEntry, 0, config.WindowSize),
		rttSamples:          make([]time.Duration, 0, config.WindowSize),
		networkStable:       true,
	}
}

// State returns current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.getStateWithTimeCheck()
}

// getStateWithTimeCheck checks if Open circuit should transition to HalfOpen.
// Uses currentResetTimeout which grows with exponential backoff.
// Must be called with at least read lock held.
func (cb *CircuitBreaker) getStateWithTimeCheck() CircuitState {
	if cb.state == CircuitOpen {
		if time.Since(cb.lastStateChange) >= cb.currentResetTimeout {
			return CircuitHalfOpen
		}
	}
	return cb.state
}

// Allow checks if a request should be allowed through
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := cb.getStateWithTimeCheck()

	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		return false
	case CircuitHalfOpen:
		// Transition to half-open if coming from open
		if cb.state == CircuitOpen {
			cb.state = CircuitHalfOpen
			cb.halfOpenCount = 0
			cb.halfOpenSuccess = 0
			cb.lastStateChange = time.Now()
			log.Info("Circuit breaker transitioning to half-open (allowing %d test requests)", cb.config.HalfOpenMax)
		}
		// Allow limited test requests in half-open
		if cb.halfOpenCount < cb.config.HalfOpenMax {
			cb.halfOpenCount++
			return true
		}
		return false
	}
	return true
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFail = 0
	cb.consecutiveTimeout = 0

	cb.addWindowEntry(outcomeSuccess, 0)

	cb.handleHalfOpenSuccess()
}

// RecordSuccessWithRTT records a successful request with RTT measurement.
// The RTT is used to track network stability and adjust failure thresholds.
func (cb *CircuitBreaker) RecordSuccessWithRTT(rtt time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFail = 0
	cb.consecutiveTimeout = 0

	cb.addWindowEntry(outcomeSuccess, rtt)
	if rtt > 0 {
		cb.addRTTSample(rtt)
	}

	cb.handleHalfOpenSuccess()
}

// handleHalfOpenSuccess handles graduated recovery in half-open state.
// Requires HalfOpenSuccessReq successes out of HalfOpenMax attempts.
// Must be called with lock held.
func (cb *CircuitBreaker) handleHalfOpenSuccess() {
	if cb.state != CircuitHalfOpen {
		return
	}

	cb.halfOpenSuccess++

	if cb.halfOpenSuccess >= cb.config.HalfOpenSuccessReq {
		// Graduated recovery: enough successes to close
		cb.state = CircuitClosed
		cb.lastStateChange = time.Now()
		// Reset backoff on successful recovery
		cb.currentResetTimeout = cb.config.ResetTimeout
		cb.openCount = 0
		log.Info("Circuit breaker closed - graduated recovery (%d/%d successes)",
			cb.halfOpenSuccess, cb.halfOpenCount)
	} else {
		log.Debug("Circuit breaker half-open: %d/%d successes so far (need %d)",
			cb.halfOpenSuccess, cb.halfOpenCount, cb.config.HalfOpenSuccessReq)
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFail++
	cb.consecutiveTimeout = 0
	cb.lastFailure = time.Now()

	cb.addWindowEntry(outcomeFailure, 0)

	switch cb.state {
	case CircuitClosed:
		if cb.shouldOpen() {
			cb.openCircuit()
		}
	case CircuitHalfOpen:
		cb.handleHalfOpenFailure()
	}
}

// RecordTimeout records a timeout error (treated more aggressively)
func (cb *CircuitBreaker) RecordTimeout() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFail++
	cb.consecutiveTimeout++
	cb.lastFailure = time.Now()

	cb.addWindowEntry(outcomeTimeout, 0)

	switch cb.state {
	case CircuitClosed:
		if cb.shouldOpen() {
			cb.openCircuit()
		}
	case CircuitHalfOpen:
		cb.handleHalfOpenFailure()
	}
}

// openCircuit transitions to Open with exponential backoff on ResetTimeout.
// Must be called with lock held.
func (cb *CircuitBreaker) openCircuit() {
	cb.state = CircuitOpen
	cb.lastStateChange = time.Now()
	cb.openCount++

	// Exponential backoff: 30s -> 1m -> 2m -> 4m -> 5m (capped)
	cb.currentResetTimeout = cb.config.ResetTimeout
	for i := 1; i < cb.openCount; i++ {
		cb.currentResetTimeout *= 2
		if cb.currentResetTimeout > cb.config.MaxResetTimeout {
			cb.currentResetTimeout = cb.config.MaxResetTimeout
			break
		}
	}

	failRate := cb.windowFailureRate()
	log.Warn("Circuit breaker opened (consecutive=%d, timeouts=%d, window_fail_rate=%.0f%%, stable=%v, backoff=%v, open_count=%d)",
		cb.consecutiveFail, cb.consecutiveTimeout, failRate*100, cb.networkStable,
		cb.currentResetTimeout, cb.openCount)
}

// handleHalfOpenFailure handles failure during half-open state.
// If all test requests have been exhausted without enough successes, re-open.
// Otherwise, just record the failure and let remaining test requests continue.
// Must be called with lock held.
func (cb *CircuitBreaker) handleHalfOpenFailure() {
	remaining := cb.config.HalfOpenMax - cb.halfOpenCount
	needed := cb.config.HalfOpenSuccessReq - cb.halfOpenSuccess

	// If it's impossible to reach the success threshold with remaining attempts, re-open
	if remaining < needed {
		cb.state = CircuitOpen
		cb.lastStateChange = time.Now()
		cb.openCount++

		// Exponential backoff
		cb.currentResetTimeout = cb.config.ResetTimeout
		for i := 1; i < cb.openCount; i++ {
			cb.currentResetTimeout *= 2
			if cb.currentResetTimeout > cb.config.MaxResetTimeout {
				cb.currentResetTimeout = cb.config.MaxResetTimeout
				break
			}
		}

		log.Warn("Circuit breaker re-opened - half-open recovery failed (%d/%d successes, backoff=%v)",
			cb.halfOpenSuccess, cb.halfOpenCount, cb.currentResetTimeout)
	} else {
		log.Debug("Circuit breaker half-open: failure recorded, but recovery still possible (%d successes, %d remaining)",
			cb.halfOpenSuccess, remaining)
	}
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitClosed
	cb.consecutiveFail = 0
	cb.consecutiveTimeout = 0
	cb.halfOpenCount = 0
	cb.halfOpenSuccess = 0
	cb.lastStateChange = time.Now()
	cb.currentResetTimeout = cb.config.ResetTimeout
	cb.openCount = 0
	cb.window = cb.window[:0]
	cb.rttSamples = cb.rttSamples[:0]
	cb.rttMean = 0
	cb.rttVariance = 0
	cb.networkStable = true
	cb.networkDown = false
}

// Stats returns current circuit breaker statistics
func (cb *CircuitBreaker) Stats() CircuitStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	failRate := cb.windowFailureRate()
	return CircuitStats{
		State:               cb.getStateWithTimeCheck(),
		ConsecutiveFail:     cb.consecutiveFail,
		ConsecutiveTimeout:  cb.consecutiveTimeout,
		LastFailure:         cb.lastFailure,
		LastStateChange:     cb.lastStateChange,
		NetworkStable:       cb.networkStable,
		EffectiveThreshold:  cb.config.FailureThreshold,
		WindowFailureRate:   failRate,
		WindowSamples:       len(cb.window),
		RTTMean:             cb.rttMean,
		RTTVariance:         cb.rttVariance,
		CurrentResetTimeout: cb.currentResetTimeout,
		OpenCount:           cb.openCount,
		NetworkDown:         cb.networkDown,
	}
}

// CircuitStats holds circuit breaker statistics
type CircuitStats struct {
	State              CircuitState
	ConsecutiveFail    int
	ConsecutiveTimeout int
	LastFailure        time.Time
	LastStateChange    time.Time
	// Adaptive stats
	NetworkStable       bool
	EffectiveThreshold  int
	WindowFailureRate   float64
	WindowSamples       int
	RTTMean             time.Duration
	RTTVariance         float64
	CurrentResetTimeout time.Duration
	OpenCount           int
	NetworkDown         bool
}

// --- Adaptive internals (must be called with lock held) ---

// addWindowEntry appends an outcome and trims the window
func (cb *CircuitBreaker) addWindowEntry(oc outcomeType, rtt time.Duration) {
	now := time.Now()
	cb.window = append(cb.window, windowEntry{
		outcome:   oc,
		timestamp: now,
		rtt:       rtt,
	})
	cb.trimWindow(now)
}

// trimWindow removes entries older than WindowDuration and caps size
func (cb *CircuitBreaker) trimWindow(now time.Time) {
	cutoff := now.Add(-cb.config.WindowDuration)

	// Remove old entries from the front
	start := 0
	for start < len(cb.window) && cb.window[start].timestamp.Before(cutoff) {
		start++
	}
	if start > 0 {
		copy(cb.window, cb.window[start:])
		cb.window = cb.window[:len(cb.window)-start]
	}

	// Cap at WindowSize (keep most recent)
	if len(cb.window) > cb.config.WindowSize {
		excess := len(cb.window) - cb.config.WindowSize
		copy(cb.window, cb.window[excess:])
		cb.window = cb.window[:cb.config.WindowSize]
	}
}

// windowFailureRate returns the fraction of failures+timeouts in the current window
func (cb *CircuitBreaker) windowFailureRate() float64 {
	if len(cb.window) == 0 {
		return 0
	}
	failures := 0
	for _, e := range cb.window {
		if e.outcome == outcomeFailure || e.outcome == outcomeTimeout {
			failures++
		}
	}
	return float64(failures) / float64(len(cb.window))
}

// addRTTSample adds an RTT measurement and recomputes variance
func (cb *CircuitBreaker) addRTTSample(rtt time.Duration) {
	cb.rttSamples = append(cb.rttSamples, rtt)

	// Keep only last WindowSize samples
	if len(cb.rttSamples) > cb.config.WindowSize {
		excess := len(cb.rttSamples) - cb.config.WindowSize
		copy(cb.rttSamples, cb.rttSamples[excess:])
		cb.rttSamples = cb.rttSamples[:cb.config.WindowSize]
	}

	cb.recomputeRTTStats()
}

// recomputeRTTStats calculates mean and variance of RTT samples
func (cb *CircuitBreaker) recomputeRTTStats() {
	n := len(cb.rttSamples)
	if n == 0 {
		cb.rttMean = 0
		cb.rttVariance = 0
		cb.networkStable = true
		return
	}

	// Mean
	var sum float64
	for _, s := range cb.rttSamples {
		sum += float64(s)
	}
	mean := sum / float64(n)
	cb.rttMean = time.Duration(mean)

	// Variance
	if n < 2 {
		cb.rttVariance = 0
		cb.networkStable = true
		return
	}

	var varSum float64
	for _, s := range cb.rttSamples {
		diff := float64(s) - mean
		varSum += diff * diff
	}
	cb.rttVariance = varSum / float64(n-1)

	// Coefficient of variation: stddev / mean
	stddev := math.Sqrt(cb.rttVariance)
	if mean > 0 {
		cv := stddev / mean
		// CV > 0.5 means RTT varies by more than 50% around the mean => unstable
		// stddev > 200ms is also a strong signal of instability
		cb.networkStable = cv < 0.5 && stddev < float64(200*time.Millisecond)
	} else {
		cb.networkStable = true
	}
}

// effectiveFailureRate returns the failure rate threshold based on network stability.
// Unstable networks get a higher threshold (85%) to be more tolerant.
func (cb *CircuitBreaker) effectiveFailureRate() float64 {
	if !cb.networkStable {
		return cb.config.UnstableFailRate
	}
	return cb.config.MinFailureRate
}

// shouldOpen decides whether the circuit should transition to Open.
// Requires: minimum samples AND failure rate above threshold AND consecutive failures above threshold.
// Network-down suppression: if manager set networkDown=true, never open.
func (cb *CircuitBreaker) shouldOpen() bool {
	// Network-down suppression: don't open individual circuits during global outage
	if cb.networkDown {
		log.Debug("Circuit breaker: suppressing open (network-down detected)")
		return false
	}

	// Must have minimum samples before making a decision
	if len(cb.window) < cb.config.MinSamples {
		log.Debug("Circuit breaker: only %d samples (need %d), staying closed",
			len(cb.window), cb.config.MinSamples)
		return false
	}

	// Must exceed consecutive-failure threshold
	if cb.consecutiveFail < cb.config.FailureThreshold {
		return false
	}

	// Check sliding window failure rate against adaptive threshold
	failRate := cb.windowFailureRate()
	threshold := cb.effectiveFailureRate()
	if failRate < threshold {
		log.Debug("Circuit breaker: %d consecutive failures but window failure rate %.0f%% < %.0f%%, staying closed",
			cb.consecutiveFail, failRate*100, threshold*100)
		return false
	}

	return true
}

// IsNetworkStable returns the current network stability assessment
func (cb *CircuitBreaker) IsNetworkStable() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.networkStable
}

// setNetworkDown sets the network-down flag (called by manager).
// When networkDown=true, failures don't open the circuit.
func (cb *CircuitBreaker) setNetworkDown(down bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.networkDown = down
}

// CircuitBreakerManager manages circuit breakers for multiple strategies
type CircuitBreakerManager struct {
	config   CircuitBreakerConfig
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex

	// Network-down detection
	networkDown     bool
	lastFailureTime map[string]time.Time // strategyID -> last failure timestamp
}

// NewCircuitBreakerManager creates a manager for multiple circuit breakers
func NewCircuitBreakerManager(config CircuitBreakerConfig) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		config:          config,
		breakers:        make(map[string]*CircuitBreaker),
		lastFailureTime: make(map[string]time.Time),
	}
}

// Get returns circuit breaker for strategy, creating if needed
func (m *CircuitBreakerManager) Get(strategyID string) *CircuitBreaker {
	m.mu.RLock()
	cb, exists := m.breakers[strategyID]
	m.mu.RUnlock()

	if exists {
		return cb
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists = m.breakers[strategyID]; exists {
		return cb
	}

	cb = NewCircuitBreaker(m.config)
	m.breakers[strategyID] = cb
	return cb
}

// Allow checks if strategy is allowed to be used
func (m *CircuitBreakerManager) Allow(strategyID string) bool {
	return m.Get(strategyID).Allow()
}

// RecordSuccess records success for strategy and clears network-down
func (m *CircuitBreakerManager) RecordSuccess(strategyID string) {
	m.Get(strategyID).RecordSuccess()
	m.clearNetworkDown()
}

// RecordSuccessWithRTT records success with RTT for strategy and clears network-down
func (m *CircuitBreakerManager) RecordSuccessWithRTT(strategyID string, rtt time.Duration) {
	m.Get(strategyID).RecordSuccessWithRTT(rtt)
	m.clearNetworkDown()
}

// RecordFailure records failure for strategy and checks for network-down
func (m *CircuitBreakerManager) RecordFailure(strategyID string) {
	m.Get(strategyID).RecordFailure()
	m.checkNetworkDown(strategyID)
}

// RecordTimeout records timeout for strategy and checks for network-down
func (m *CircuitBreakerManager) RecordTimeout(strategyID string) {
	m.Get(strategyID).RecordTimeout()
	m.checkNetworkDown(strategyID)
}

// checkNetworkDown detects if all breakers failed within a 10-second window.
// If so, sets networkDown=true on all breakers to suppress individual circuit opens.
func (m *CircuitBreakerManager) checkNetworkDown(failedID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.lastFailureTime[failedID] = now

	// Need at least 2 strategies to detect network-down
	if len(m.breakers) < 2 {
		return
	}

	// Check if ALL registered breakers have failed within 10 seconds
	cutoff := now.Add(-10 * time.Second)
	allFailed := true
	for id := range m.breakers {
		lastFail, has := m.lastFailureTime[id]
		if !has || lastFail.Before(cutoff) {
			allFailed = false
			break
		}
	}

	if allFailed && !m.networkDown {
		m.networkDown = true
		log.Warn("Network-down detected: all %d strategies failed within 10s, suppressing circuit opens", len(m.breakers))
		for _, cb := range m.breakers {
			cb.setNetworkDown(true)
		}
	}
}

// clearNetworkDown clears network-down state when any strategy succeeds
func (m *CircuitBreakerManager) clearNetworkDown() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.networkDown {
		return
	}

	m.networkDown = false
	log.Info("Network recovered: clearing network-down state")
	for _, cb := range m.breakers {
		cb.setNetworkDown(false)
	}
	// Clear failure timestamps
	for id := range m.lastFailureTime {
		delete(m.lastFailureTime, id)
	}
}

// IsNetworkDown returns whether the manager detects a global network outage
func (m *CircuitBreakerManager) IsNetworkDown() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.networkDown
}

// GetAllStats returns stats for all managed circuit breakers
func (m *CircuitBreakerManager) GetAllStats() map[string]CircuitStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]CircuitStats, len(m.breakers))
	for id, cb := range m.breakers {
		stats[id] = cb.Stats()
	}
	return stats
}

// GetAvailableStrategies returns IDs of strategies with closed/half-open circuits
func (m *CircuitBreakerManager) GetAvailableStrategies() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var available []string
	for id, cb := range m.breakers {
		state := cb.State()
		if state != CircuitOpen {
			available = append(available, id)
		}
	}
	return available
}
