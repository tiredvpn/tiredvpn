package strategy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/mux"
	"github.com/tiredvpn/tiredvpn/internal/porthopping"
)

// Strategy defines interface for DPI evasion techniques
type Strategy interface {
	// Name returns human-readable strategy name
	Name() string

	// ID returns unique strategy identifier
	ID() string

	// Priority returns execution priority (lower = try first)
	Priority() int

	// Probe tests if this strategy works in current network conditions
	// Returns nil if strategy is likely to work
	Probe(ctx context.Context, target string) error

	// Connect establishes connection using this strategy
	Connect(ctx context.Context, target string) (net.Conn, error)

	// RequiresServer returns true if strategy needs special server support
	RequiresServer() bool

	// Description returns detailed description
	Description() string
}

// Result holds strategy execution result with extended statistics
type Result struct {
	Strategy   Strategy
	Success    bool
	Latency    time.Duration
	Error      error
	TestedAt   time.Time
	Confidence float64 // 0.0 - 1.0, based on historical success

	// Extended statistics for adaptive scoring
	SuccessCount    int64
	FailureCount    int64
	ConsecutiveFail int
	LastSuccess     time.Time
	LastFailure     time.Time
	AvgLatency      time.Duration
	LatencySum      time.Duration // for calculating average
	LatencyCount    int64
}

// Manager manages multiple strategies and performs auto-fallback
type Manager struct {
	strategies []Strategy
	results    map[string]*Result
	mu         sync.RWMutex

	// Config
	probeTimeout   time.Duration
	connectTimeout time.Duration
	maxRetries     int
	parallelProbes int
	adaptiveOrder  bool // Reorder strategies based on success rate

	// Circuit breaker
	circuitBreakers *CircuitBreakerManager

	// Periodic re-probe
	reprobeInterval time.Duration
	reprobeTarget   string
	stopReprobe     chan struct{}
	reprobeRunning  bool

	// Emergency re-probe (for network recovery)
	emergencyReprobeRunning bool
	emergencyReprobeStop    chan struct{}
	lastEmergencyReprobe    time.Time

	// RTT Masking
	rttMaskingEnabled bool
	rttProfile        *RTTProfile

	// Mux configuration
	muxEnabled bool
	muxConfig  *mux.Config
	muxClient  *mux.Client
	muxConn    net.Conn   // underlying connection for mux
	muxMu      sync.Mutex // separate mutex for mux operations

	// Last successful strategy for fast reconnect
	lastSuccessfulStrategy Strategy
	lastSuccessfulTime     time.Time // When the last successful connection was made

	// Connectivity checker for pre-flight checks
	connectivityChecker  *ConnectivityChecker
	excludeUDPStrategies bool // Temporarily exclude UDP-based strategies if UDP is blocked

	// Android mode - deprioritize QUIC/UDP strategies
	androidMode bool

	// Android adaptive strategy selection
	consecutiveTCPTimeouts int // Count of consecutive TCP strategy timeouts
	tcpFailuresBeforeQUIC  int // Threshold before fast-switching to QUIC (default: 3)

	// Last connection info (for Android UI and metrics)
	lastConnectionLatency    time.Duration
	lastConnectionAttempts   int
	lastConnectionStrategy   string
	lastConnectionStrategyID string

	// Port hopping for DPI evasion
	portHopper        *porthopping.PortHopper
	portHopperStop    chan struct{}
	portHopperMu      sync.Mutex
	portHopCallback   func(oldPort, newPort int) // External callback for port hop events (e.g., VPN reconnect)
	portHopCallbackMu sync.Mutex

	// IPv6 Transport Layer
	serverAddrV6    string // IPv6 server address
	serverAddrV4    string // IPv4 server address
	preferIPv6      bool   // Prefer IPv6 if available
	fallbackToV4    bool   // Fallback to IPv4 if IPv6 fails
	ipv6Available   bool   // Cached IPv6 availability
	ipv6CheckedOnce bool   // Whether we've checked IPv6 availability
	ipv6Mu          sync.Mutex
}

// NewManager creates a new strategy manager
func NewManager() *Manager {
	m := &Manager{
		strategies:            make([]Strategy, 0),
		results:               make(map[string]*Result),
		probeTimeout:          10 * time.Second,
		connectTimeout:        30 * time.Second,
		maxRetries:            2,
		parallelProbes:        3,
		adaptiveOrder:         true,
		circuitBreakers:       NewCircuitBreakerManager(DefaultCircuitBreakerConfig()),
		reprobeInterval:       5 * time.Minute,
		stopReprobe:           make(chan struct{}),
		tcpFailuresBeforeQUIC: 3, // Switch to QUIC after 3 TCP timeouts
	}
	log.Debug("Strategy Manager created (probeTimeout=%v, connectTimeout=%v, maxRetries=%d)",
		m.probeTimeout, m.connectTimeout, m.maxRetries)
	return m
}

// Register adds a strategy to the manager
func (m *Manager) Register(s Strategy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.strategies = append(m.strategies, s)
	m.results[s.ID()] = &Result{
		Strategy:   s,
		Confidence: 0.5, // Initial neutral confidence
	}

	log.Debug("Registered strategy: %s (id=%s, priority=%d, requiresServer=%v)",
		s.Name(), s.ID(), s.Priority(), s.RequiresServer())

	// Sort by priority
	m.sortStrategies()
}

// SetConnectivityChecker sets the connectivity checker for pre-flight checks
func (m *Manager) SetConnectivityChecker(checker *ConnectivityChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectivityChecker = checker
	if checker != nil {
		log.Debug("Connectivity checker set for server: %s", checker.ServerAddr())
	}
}

// isTimeoutError checks if an error is a timeout
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// net.Error with Timeout()
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// String checks for QUIC and other protocols
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "no recent network activity") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "i/o timeout")
}

// isUDPBasedStrategy checks if a strategy uses UDP (like QUIC)
func isUDPBasedStrategy(s Strategy) bool {
	id := s.ID()
	return strings.HasPrefix(id, "quic") ||
		strings.Contains(id, "quic") ||
		strings.Contains(strings.ToLower(s.Name()), "quic")
}

// sortStrategies sorts by priority and confidence
func (m *Manager) sortStrategies() {
	// Simple bubble sort (small list)
	for i := 0; i < len(m.strategies)-1; i++ {
		for j := 0; j < len(m.strategies)-i-1; j++ {
			s1, s2 := m.strategies[j], m.strategies[j+1]
			r1, r2 := m.results[s1.ID()], m.results[s2.ID()]

			// Compare by adjusted priority (priority - confidence bonus)
			score1 := float64(s1.Priority()) - r1.Confidence*10
			score2 := float64(s2.Priority()) - r2.Confidence*10

			// Android mode: adaptive penalty for UDP/QUIC strategies
			// Base penalty is 50, but decreases with each TCP timeout
			// After tcpFailuresBeforeQUIC TCP timeouts, penalty becomes 0
			if m.androidMode {
				// Calculate adaptive penalty: starts at 10, decreases by 5 per TCP timeout
				// 0 timeouts: +10, 1: +5, 2+: 0
				// Reduced from 50 to avoid 4x TCP timeout delay (~20s) before trying QUIC
				basePenalty := 10.0
				penaltyReduction := float64(m.consecutiveTCPTimeouts) * 5.0
				adaptivePenalty := basePenalty - penaltyReduction
				if adaptivePenalty < 0 {
					adaptivePenalty = 0
				}

				if isUDPBasedStrategy(s1) {
					score1 += adaptivePenalty
				}
				if isUDPBasedStrategy(s2) {
					score2 += adaptivePenalty
				}
			}

			if score1 > score2 {
				m.strategies[j], m.strategies[j+1] = m.strategies[j+1], m.strategies[j]
			}
		}
	}
}

// ForceStrategy keeps only matching strategy (by ID prefix)
func (m *Manager) ForceStrategy(idPrefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var matched []Strategy
	for _, s := range m.strategies {
		// Match by prefix (e.g., "morph" matches "morph_YouTube 1080p")
		if len(s.ID()) >= len(idPrefix) && s.ID()[:len(idPrefix)] == idPrefix {
			matched = append(matched, s)
		}
		// Also match by full ID
		if s.ID() == idPrefix {
			matched = []Strategy{s}
			break
		}
	}

	if len(matched) == 0 {
		return fmt.Errorf("no strategy matching: %s", idPrefix)
	}

	m.strategies = matched
	log.Info("Forced %d strategies matching '%s'", len(matched), idPrefix)
	return nil
}

// ListStrategyIDs returns comma-separated list of all strategy IDs
func (m *Manager) ListStrategyIDs() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect unique base IDs (without variant suffixes)
	seen := make(map[string]bool)
	var ids []string
	for _, s := range m.strategies {
		id := s.ID()
		// Extract base ID (e.g., "morph" from "morph_YouTube 1080p")
		baseID := id
		if idx := strings.Index(id, "_"); idx > 0 {
			// Keep full ID for strategies like geneva_russia
			if !strings.HasPrefix(id, "geneva") && !strings.HasPrefix(id, "quic") {
				baseID = id[:idx]
			}
		}
		if !seen[baseID] {
			seen[baseID] = true
			ids = append(ids, baseID)
		}
	}
	return strings.Join(ids, ", ")
}

// ProbeAll tests all strategies in parallel
func (m *Manager) ProbeAll(ctx context.Context, target string) []Result {
	// IPv6 Transport Layer: select IPv6 or IPv4 address for probing
	if m.serverAddrV6 != "" && m.preferIPv6 {
		target = m.GetServerAddr(ctx)
		log.Debug("Probing with effective server address: %s", target)
	}

	m.mu.RLock()
	// Filter out disabled strategies (priority <= 0)
	var strategies []Strategy
	for _, s := range m.strategies {
		if s.Priority() > 0 {
			strategies = append(strategies, s)
		} else {
			log.Debug("Skipping probe for disabled strategy: %s (priority=%d)", s.Name(), s.Priority())
		}
	}
	m.mu.RUnlock()

	log.Info("Probing %d strategies for target: %s", len(strategies), target)

	results := make([]Result, len(strategies))
	var wg sync.WaitGroup

	// Limit parallel probes
	sem := make(chan struct{}, m.parallelProbes)

	for i, s := range strategies {
		wg.Add(1)
		go func(idx int, strat Strategy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			log.Debug("Probing strategy: %s", strat.Name())
			start := time.Now()
			probeCtx, cancel := context.WithTimeout(ctx, m.probeTimeout)
			defer cancel()

			err := strat.Probe(probeCtx, target)
			latency := time.Since(start)

			result := Result{
				Strategy: strat,
				Success:  err == nil,
				Latency:  latency,
				Error:    err,
				TestedAt: time.Now(),
			}

			if err == nil {
				log.Debug("Probe SUCCESS: %s (latency=%v)", strat.Name(), latency)
			} else {
				log.Debug("Probe FAILED: %s (error=%v, latency=%v)", strat.Name(), err, latency)
			}

			results[idx] = result

			// Update stored results
			m.mu.Lock()
			m.updateConfidence(strat.ID(), err == nil)
			m.mu.Unlock()
		}(i, s)
	}

	wg.Wait()

	// Re-sort based on new confidence scores
	if m.adaptiveOrder {
		m.mu.Lock()
		m.sortStrategies()
		m.mu.Unlock()
	}

	// Log summary
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	log.Info("Probe complete: %d/%d strategies available", successCount, len(results))

	return results
}

// updateConfidence adjusts confidence based on result with adaptive scoring
func (m *Manager) updateConfidence(id string, success bool) {
	m.updateConfidenceWithLatency(id, success, 0)
}

// updateConfidenceWithLatency adjusts confidence with latency tracking
func (m *Manager) updateConfidenceWithLatency(id string, success bool, latency time.Duration) {
	r, ok := m.results[id]
	if !ok {
		return
	}

	now := time.Now()

	// Update statistics
	if success {
		r.SuccessCount++
		r.ConsecutiveFail = 0
		r.LastSuccess = now
		if latency > 0 {
			r.LatencySum += latency
			r.LatencyCount++
			r.AvgLatency = r.LatencySum / time.Duration(r.LatencyCount)
		}
		// Record success in circuit breaker (with RTT for adaptive thresholds)
		if latency > 0 {
			m.circuitBreakers.RecordSuccessWithRTT(id, latency)
		} else {
			m.circuitBreakers.RecordSuccess(id)
		}
	} else {
		r.FailureCount++
		r.ConsecutiveFail++
		r.LastFailure = now
		// Record failure in circuit breaker
		m.circuitBreakers.RecordFailure(id)
	}

	// Base: Exponential moving average
	alpha := 0.3
	baseConfidence := r.Confidence
	if success {
		baseConfidence = baseConfidence*(1-alpha) + 1.0*alpha
	} else {
		baseConfidence = baseConfidence*(1-alpha) + 0.0*alpha
	}

	// Bonus: +0.1 if successful in last 5 minutes
	bonus := 0.0
	if !r.LastSuccess.IsZero() && time.Since(r.LastSuccess) < 5*time.Minute {
		bonus = 0.1
	}

	// Penalty: -0.15 for each consecutive failure (up to 3)
	penalty := 0.0
	if r.ConsecutiveFail > 0 {
		penalty = float64(min(r.ConsecutiveFail, 3)) * 0.15
	}

	// Recovery: if unused for 10+ minutes and was failing, give small boost
	recovery := 0.0
	if r.ConsecutiveFail > 0 && !r.LastFailure.IsZero() && time.Since(r.LastFailure) > 10*time.Minute {
		recovery = 0.1
	}

	// Calculate final confidence
	r.Confidence = baseConfidence + bonus - penalty + recovery

	// Clamp to 0.05-0.95 to never completely exclude
	if r.Confidence < 0.05 {
		r.Confidence = 0.05
	}
	if r.Confidence > 0.95 {
		r.Confidence = 0.95
	}

	log.Debug("Strategy %s confidence updated: %.2f (base=%.2f, bonus=%.2f, penalty=%.2f, recovery=%.2f, consecutive_fail=%d)",
		id, r.Confidence, baseConfidence, bonus, penalty, recovery, r.ConsecutiveFail)
}

// UpdateStrategyConfidence updates a strategy's confidence (public wrapper)
func (m *Manager) UpdateStrategyConfidence(id string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateConfidence(id, success)
	m.sortStrategies()
}

// Connect tries strategies in order until one succeeds
func (m *Manager) Connect(ctx context.Context, target string) (net.Conn, Strategy, error) {
	// IPv6 Transport Layer: select IPv6 or IPv4 address
	// This overrides the target parameter if IPv6 is configured and available
	if m.serverAddrV6 != "" && m.preferIPv6 {
		target = m.GetServerAddr(ctx)
		log.Debug("Using effective server address: %s", target)
	}

	// Apply port hopping if enabled
	if m.portHopper != nil {
		target = m.replacePort(target, m.portHopper.CurrentPort())
	}

	// Pre-flight connectivity check
	m.mu.RLock()
	checker := m.connectivityChecker
	m.mu.RUnlock()

	if checker != nil {
		result := checker.Check(ctx)

		if !result.TCP {
			// No TCP connectivity - wait in loop until it's restored
			log.Warn("No TCP connectivity to server, waiting for network...")
			result = checker.WaitForConnectivity(ctx, 5*time.Second)

			if !result.TCP {
				return nil, nil, fmt.Errorf("no connectivity to server: %w", result.Error)
			}
		}

		// Check UDP connectivity for QUIC strategies
		m.mu.Lock()
		if !result.UDP {
			if !m.excludeUDPStrategies {
				log.Info("UDP not working, temporarily excluding QUIC strategies")
			}
			m.excludeUDPStrategies = true
		} else {
			if m.excludeUDPStrategies {
				log.Info("UDP connectivity restored, QUIC strategies enabled")
			}
			m.excludeUDPStrategies = false
		}
		m.mu.Unlock()
	}

	// Connect through strategy
	conn, strategy, err := m.ConnectExcluding(ctx, target, nil)
	if err != nil {
		return nil, nil, err
	}

	// Wrap with mux if enabled (BEFORE RTT masking in the chain)
	// Architecture: [Application] -> [RTT Camouflage] -> [Mux Layer] -> [Transport]
	m.muxMu.Lock()
	muxEnabled := m.muxEnabled
	muxConfig := m.muxConfig
	m.muxMu.Unlock()

	if muxEnabled {
		muxConn, muxErr := m.wrapWithMux(conn, muxConfig)
		if muxErr != nil {
			log.Warn("Mux wrap failed, using direct connection: %v", muxErr)
			// Fallback to direct connection without mux
			return conn, strategy, nil
		}
		log.Debug("Connection wrapped with mux layer")
		return muxConn, strategy, nil
	}

	return conn, strategy, nil
}

// ConnectExcluding tries strategies excluding specified ones (for fallback)
func (m *Manager) ConnectExcluding(ctx context.Context, target string, excludeIDs []string) (net.Conn, Strategy, error) {
	// First pass: try all strategies WITHOUT RTT masking
	conn, strategy, err := m.connectWithRTT(ctx, target, excludeIDs, false)
	if err == nil {
		return conn, strategy, nil
	}

	// Second pass: if RTT masking is enabled, retry all strategies WITH RTT masking
	m.mu.RLock()
	rttEnabled := m.rttMaskingEnabled
	m.mu.RUnlock()

	if rttEnabled {
		log.Info("All strategies failed, retrying with RTT masking enabled...")
		return m.connectWithRTT(ctx, target, excludeIDs, true)
	}

	return nil, nil, err
}

// connectWithRTT is the internal connect method with optional RTT masking
func (m *Manager) connectWithRTT(ctx context.Context, target string, excludeIDs []string, useRTTMasking bool) (net.Conn, Strategy, error) {
	m.mu.RLock()
	// Check if we have a recent successful strategy to try first (for fast reconnect)
	lastSuccessful := m.lastSuccessfulStrategy
	lastSuccessfulTime := m.lastSuccessfulTime
	androidMode := m.androidMode
	tcpFailuresThreshold := m.tcpFailuresBeforeQUIC
	m.mu.RUnlock()

	// Try last successful strategy first if it was recent (within 5 minutes)
	if lastSuccessful != nil && time.Since(lastSuccessfulTime) < 5*time.Minute {
		log.Info("Trying last successful strategy first: %s", lastSuccessful.Name())

		connectCtx, cancel := context.WithTimeout(ctx, m.connectTimeout)
		start := time.Now()
		conn, err := lastSuccessful.Connect(connectCtx, target)
		latency := time.Since(start)
		cancel()

		if err == nil {
			// Success - update stats
			m.mu.Lock()
			m.lastSuccessfulTime = time.Now()
			m.consecutiveTCPTimeouts = 0 // Reset TCP timeout counter on success
			m.updateConfidenceWithLatency(lastSuccessful.ID(), true, latency)
			m.mu.Unlock()

			optimizeTCPConn(conn)
			if useRTTMasking {
				m.mu.RLock()
				rttProfile := m.rttProfile
				m.mu.RUnlock()
				conn = WrapWithRTTMasking(conn, rttProfile)
			}

			log.Info("Fast reconnect via %s (latency=%v)", lastSuccessful.Name(), latency)
			return conn, lastSuccessful, nil
		}
		log.Debug("Last successful strategy failed: %v, falling back to full strategy list", err)
	}

	m.mu.RLock()
	// Filter out disabled strategies (priority <= 0) and excluded strategies
	excludeMap := make(map[string]bool)
	for _, id := range excludeIDs {
		excludeMap[id] = true
	}

	excludeUDP := m.excludeUDPStrategies

	var strategies []Strategy
	var quicStrategies []Strategy // Collect QUIC strategies separately for fast fallback

	for _, s := range m.strategies {
		if s.Priority() <= 0 {
			log.Debug("Skipping disabled strategy: %s (priority=%d)", s.Name(), s.Priority())
			continue
		}
		if excludeMap[s.ID()] {
			log.Debug("Skipping excluded strategy: %s", s.Name())
			continue
		}
		// Check circuit breaker
		if !m.circuitBreakers.Allow(s.ID()) {
			log.Debug("Skipping strategy %s (circuit breaker open)", s.Name())
			continue
		}
		// Skip UDP-based strategies (like QUIC) if UDP is not working
		if excludeUDP && isUDPBasedStrategy(s) {
			log.Debug("Skipping UDP strategy %s (UDP connectivity issue)", s.Name())
			continue
		}

		// Separate QUIC strategies for fast fallback
		if isUDPBasedStrategy(s) {
			quicStrategies = append(quicStrategies, s)
		}
		strategies = append(strategies, s)
	}
	rttProfile := m.rttProfile
	m.mu.RUnlock()

	if len(strategies) == 0 {
		return nil, nil, fmt.Errorf("no available strategies (all excluded or circuit-broken)")
	}

	modeStr := ""
	if useRTTMasking {
		modeStr = " [RTT masking]"
	}
	log.Info("Connecting to %s (trying %d strategies)%s", target, len(strategies), modeStr)

	var lastErr error
	attemptCount := 0
	tcpTimeoutCount := 0 // Track consecutive TCP timeouts in this connection attempt

	for i, s := range strategies {
		// Android fast QUIC fallback: after N TCP timeouts, skip remaining TCP and try QUIC
		if androidMode && tcpTimeoutCount >= tcpFailuresThreshold && !isUDPBasedStrategy(s) {
			log.Info("Fast QUIC fallback: %d TCP timeouts, skipping remaining TCP strategies", tcpTimeoutCount)
			// Jump to QUIC strategies
			for _, qs := range quicStrategies {
				if excludeMap[qs.ID()] || !m.circuitBreakers.Allow(qs.ID()) {
					continue
				}

				log.Debug("Trying QUIC fallback: %s", qs.Name())
				connectCtx, cancel := context.WithTimeout(ctx, m.connectTimeout)
				start := time.Now()
				conn, err := qs.Connect(connectCtx, target)
				latency := time.Since(start)
				cancel()

				if err == nil {
					m.mu.Lock()
					m.lastSuccessfulStrategy = qs
					m.lastSuccessfulTime = time.Now()
					m.consecutiveTCPTimeouts = 0
					m.updateConfidenceWithLatency(qs.ID(), true, latency)
					m.sortStrategies()
					m.lastConnectionLatency = latency
					m.lastConnectionAttempts = attemptCount
					m.lastConnectionStrategy = qs.Name()
					m.lastConnectionStrategyID = qs.ID()
					m.mu.Unlock()

					optimizeTCPConn(conn)
					if useRTTMasking {
						conn = WrapWithRTTMasking(conn, rttProfile)
					}

					log.Info("Connected via QUIC fallback %s (latency=%v)", qs.Name(), latency)
					return conn, qs, nil
				}
				lastErr = fmt.Errorf("%s: %w", qs.Name(), err)
			}
			// All QUIC failed too, continue with remaining strategies
			break
		}

		m.mu.RLock()
		confidence := m.results[s.ID()].Confidence
		m.mu.RUnlock()

		log.Debug("Trying strategy %d/%d: %s (confidence=%.2f)%s",
			i+1, len(strategies), s.Name(), confidence, modeStr)

		for retry := 0; retry < m.maxRetries; retry++ {
			attemptCount++
			log.Debug("  Attempt %d/%d for %s", retry+1, m.maxRetries, s.Name())

			connectCtx, cancel := context.WithTimeout(ctx, m.connectTimeout)
			start := time.Now()

			conn, err := s.Connect(connectCtx, target)
			latency := time.Since(start)
			cancel()

			if err == nil {
				// Success - update confidence with latency and save for fast reconnect
				m.mu.Lock()
				m.lastSuccessfulStrategy = s
				m.lastSuccessfulTime = time.Now()
				m.consecutiveTCPTimeouts = 0 // Reset on success
				m.updateConfidenceWithLatency(s.ID(), true, latency)
				m.sortStrategies()
				m.mu.Unlock()

				// Optimize TCP connection for low latency
				optimizeTCPConn(conn)

				// Apply RTT masking if this pass uses it
				if useRTTMasking {
					conn = WrapWithRTTMasking(conn, rttProfile)
				}

				// Store connection info for Android UI
				m.mu.Lock()
				m.lastConnectionLatency = latency
				m.lastConnectionAttempts = attemptCount
				m.lastConnectionStrategy = s.Name()
				m.lastConnectionStrategyID = s.ID()
				m.mu.Unlock()

				log.Info("Connected via %s (latency=%v, attempts=%d, rtt_masking=%v)", s.Name(), latency, attemptCount, useRTTMasking)
				return conn, s, nil
			}

			lastErr = fmt.Errorf("%s: %w", s.Name(), err)

			// Distinguish between timeout and regular errors
			if isTimeoutError(err) {
				log.Debug("  Failed: %s TIMEOUT (latency=%v)", s.Name(), latency)
				m.circuitBreakers.RecordTimeout(s.ID())

				// Track TCP timeouts for Android fast fallback
				if androidMode && !isUDPBasedStrategy(s) {
					tcpTimeoutCount++
					m.mu.Lock()
					m.consecutiveTCPTimeouts++
					// Re-sort strategies with updated penalty
					m.sortStrategies()
					m.mu.Unlock()
					log.Debug("TCP timeout count: %d/%d (adaptive penalty adjusted)", tcpTimeoutCount, tcpFailuresThreshold)
				}
			} else {
				log.Debug("  Failed: %v (latency=%v)", err, latency)
				m.circuitBreakers.RecordFailure(s.ID())
			}

			// Brief pause before retry
			select {
			case <-ctx.Done():
				log.Warn("Connection cancelled by context")
				return nil, nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}

		// Strategy exhausted all retries - update confidence
		m.mu.Lock()
		m.updateConfidence(s.ID(), false)
		m.mu.Unlock()

		log.Debug("Strategy %s exhausted, moving to next", s.Name())
	}

	log.Error("All %d strategies failed after %d attempts%s", len(strategies), attemptCount, modeStr)

	// Trigger emergency reprobe to recover from network outage
	go m.TriggerEmergencyReprobe(context.Background())

	return nil, nil, fmt.Errorf("all strategies failed, last error: %w", lastErr)
}

// GetStats returns current strategy statistics
func (m *Manager) GetStats() map[string]Result {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]Result)
	for id, r := range m.results {
		stats[id] = *r
	}
	return stats
}

// GetOrderedStrategies returns strategies in current priority order
func (m *Manager) GetOrderedStrategies() []Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Strategy, len(m.strategies))
	copy(result, m.strategies)
	return result
}

// ConnectionInfo holds last connection metadata for Android UI
type ConnectionInfo struct {
	StrategyID string
	Strategy   string
	Latency    time.Duration
	Attempts   int
}

// GetLastConnectionInfo returns info about the last successful connection
func (m *Manager) GetLastConnectionInfo() ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ConnectionInfo{
		StrategyID: m.lastConnectionStrategyID,
		Strategy:   m.lastConnectionStrategy,
		Latency:    m.lastConnectionLatency,
		Attempts:   m.lastConnectionAttempts,
	}
}

// StrategyConn wraps connection with strategy info
type StrategyConn struct {
	net.Conn
	strategy Strategy
}

// Strategy returns the strategy used for this connection
func (sc *StrategyConn) Strategy() Strategy {
	return sc.strategy
}

// Ensure interface compliance
var _ io.ReadWriteCloser = (*StrategyConn)(nil)

// DefaultManagerConfig contains configuration for default manager
type DefaultManagerConfig struct {
	ServerAddr string       // Server address for server-based strategies
	Secret     []byte       // Shared secret for authentication
	RelayNodes []*RelayNode // Mesh relay nodes (optional)
	CoverHost  string       // Host to impersonate for HTTP/2 stego

	// IPv6 Transport Layer
	ServerAddrV6 string // IPv6 server address (e.g., "[2001:db8::100]:995")
	PreferIPv6   bool   // Prefer IPv6 transport if available (default: false)
	FallbackToV4 bool   // Fallback to IPv4 if IPv6 fails (default: true)

	// RTT Masking configuration
	RTTMaskingEnabled bool        // Enable RTT masking on connections
	RTTProfile        *RTTProfile // RTT profile to use (nil = auto-select)

	// Mux configuration (99.5% success rate with VLESS+Reality+mux)
	MuxEnabled bool        // Enable connection multiplexing (default: true)
	MuxConfig  *mux.Config // Mux configuration (nil = use default)

	// QUIC configuration
	QUICEnabled           bool // Enable QUIC strategy
	QUICPort              int  // QUIC server port (default: 443)
	QUICSalamanderEnabled bool // Enable QUIC with Salamander obfuscation
	QUICSalamanderPort    int  // QUIC Salamander port (default: 8443)

	// REALITY configuration
	REALITYEnabled bool // Enable REALITY protocol (99.5% success rate)

	// WebSocket Padded configuration
	WebSocketPaddedEnabled bool // Enable WebSocket with Salamander padding

	// ECH (Encrypted Client Hello) configuration
	ECHEnabled    bool   // Enable ECH to hide SNI from DPI
	ECHConfigList []byte // ECHConfigList from server (base64 decoded)
	ECHPublicName string // Outer SNI visible to network (e.g. "cloudflare-ech.com")

	// QUIC SNI fragmentation for GFW bypass
	QUICSNIFragEnabled bool // Enable SNI fragmentation in QUIC CRYPTO frames

	// Post-Quantum crypto for REALITY
	PQEnabled         bool   // Enable post-quantum crypto (ML-KEM-768 + ML-DSA-65)
	PQServerKemPubB64 string // Server's Kyber768 public key in base64

	// Android-specific optimizations
	AndroidMode bool // Running on Android - use shorter timeouts, fewer retries, TCP-first

	// Port hopping for DPI evasion
	// High ports (47000+) are less analyzed by DPI, periodic port changes complicate blocking
	PortHopping *porthopping.Config
}

// NewDefaultManager creates a manager with all strategies pre-registered
func NewDefaultManager(cfg DefaultManagerConfig) *Manager {
	m := NewManager()

	// Initialize IPv6 Transport Layer
	m.serverAddrV4 = cfg.ServerAddr
	m.serverAddrV6 = cfg.ServerAddrV6
	m.preferIPv6 = cfg.PreferIPv6
	m.fallbackToV4 = cfg.FallbackToV4
	if cfg.ServerAddrV6 != "" && cfg.PreferIPv6 {
		log.Info("IPv6 transport enabled (IPv6=%s, IPv4=%s, fallback=%v)",
			cfg.ServerAddrV6, cfg.ServerAddr, cfg.FallbackToV4)
	}

	// Initialize port hopper if configured
	if cfg.PortHopping != nil && cfg.PortHopping.Enabled {
		hopper, err := porthopping.NewPortHopper(cfg.PortHopping)
		if err != nil {
			log.Warn("Port hopping disabled: %v", err)
		} else {
			m.portHopper = hopper
			// Set callback for port change - triggers reconnect
			hopper.OnHop(func(oldPort, newPort int) {
				log.Info("Port hop: %d -> %d, triggering reconnect", oldPort, newPort)
				m.triggerReconnect()
			})
			log.Info("Port hopping enabled (range=%d-%d, interval=%v, strategy=%s)",
				cfg.PortHopping.PortRangeStart, cfg.PortHopping.PortRangeEnd,
				cfg.PortHopping.HopInterval, cfg.PortHopping.Strategy)
		}
	}

	// Android-specific optimizations: shorter timeouts, fewer retries, TCP-first
	if cfg.AndroidMode {
		m.probeTimeout = 3 * time.Second    // 10s -> 3s
		m.connectTimeout = 10 * time.Second // 30s -> 10s
		m.maxRetries = 1                    // 2 -> 1
		m.androidMode = true                // Deprioritize QUIC/UDP strategies
		log.Info("Android mode: using optimized timeouts (probe=%v, connect=%v, retries=%d, TCP-first)",
			m.probeTimeout, m.connectTimeout, m.maxRetries)
	}

	// Configure Mux - ENABLED BY DEFAULT (99.5% success rate with VLESS+Reality+mux)
	// Mux is critical for DPI evasion: interleaved frames confuse traffic analysis
	if cfg.MuxEnabled {
		muxConfig := cfg.MuxConfig
		if muxConfig == nil {
			// Use mobile config for Android, default otherwise
			if cfg.AndroidMode {
				muxConfig = mux.MobileConfig()
			} else {
				muxConfig = mux.DefaultConfig()
			}
		}
		m.EnableMux(muxConfig)
	}

	// Configure RTT masking if enabled
	if cfg.RTTMaskingEnabled {
		profile := cfg.RTTProfile
		if profile == nil {
			profile = MoscowToYandexProfile // Default to Moscow-Yandex profile
		}
		m.EnableRTTMasking(profile)
	}

	// 1. QUIC Strategy - hardest to block, new protocol
	if cfg.QUICEnabled && cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		port := cfg.QUICPort
		if port == 0 {
			port = 443
		}
		quicStrat := NewQUICStrategy(m, cfg.Secret, port)
		// Enable SNI fragmentation for GFW bypass if configured
		if cfg.QUICSNIFragEnabled {
			quicStrat.SetSNIFragmentation(true, nil)
		}
		m.Register(quicStrat)
	}

	// 1.3. QUIC Salamander - QUIC with cryptographic obfuscation
	// NOT registered when SNI fragmentation is enabled (they are mutually exclusive)
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 && !cfg.QUICSNIFragEnabled {
		port := cfg.QUICSalamanderPort
		if port == 0 {
			// Extract port from server address, default to 443 if not specified
			if _, portStr, err := net.SplitHostPort(cfg.ServerAddr); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil {
					port = p
				}
			}
			if port == 0 {
				port = 443
			}
		}
		salamanderStrat := NewQUICSalamanderStrategy(m, cfg.Secret, port)
		m.Register(salamanderStrat)
	}

	// 1.5. REALITY Protocol - 99.5% success rate (ALWAYS enabled if server present)
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		reality := NewREALITYStrategy(m, cfg.Secret)
		// Enable post-quantum crypto if configured
		if cfg.PQEnabled && cfg.PQServerKemPubB64 != "" {
			kemPub, err := base64.StdEncoding.DecodeString(cfg.PQServerKemPubB64)
			if err == nil && len(kemPub) > 0 {
				if err := reality.SetPostQuantum(kemPub); err != nil {
					// Log but don't fail - fallback to classical
					log.Warn("REALITY: PQ init failed, using classical: %v", err)
				}
			}
		}
		m.Register(reality)
	}

	// 1.7. WebSocket Salamander Padding - High priority (ALWAYS enabled if server present)
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		m.Register(NewWebSocketPaddedStrategy(m, cfg.Secret))
	}

	// 1.8. HTTP Polling (meek-style) - bypasses long-connection throttling
	// Uses multiple short-lived HTTP/1.1 requests instead of persistent connections
	// Effective against TSPU that blocks HTTP/2 but allows HTTP/1.1
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		m.Register(NewHTTPPollingStrategy(m, cfg.Secret))
	}

	// 2. HTTP/2 Steganography - highest priority, looks most legitimate
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		stego := NewHTTP2StegoStrategy(m, cfg.Secret, cfg.CoverHost)
		// Enable ECH if configured
		if cfg.ECHEnabled && len(cfg.ECHConfigList) > 0 {
			stego.SetECH(cfg.ECHConfigList, cfg.ECHPublicName)
		}
		m.Register(stego)
	}

	// 3. Traffic Morphing (Yandex profile) - Russian video service (primary)
	if len(cfg.Secret) > 0 {
		m.Register(NewTrafficMorphStrategy(m, YandexVideoProfile, nil, cfg.Secret))
	}

	// 4. Traffic Morphing (VK profile) - VK video streaming
	if len(cfg.Secret) > 0 {
		m.Register(NewTrafficMorphStrategy(m, VKVideoProfile, nil, cfg.Secret))

		// 5. Traffic Morphing (Baidu profile) - Chinese video streaming
		if len(cfg.Secret) > 0 {
			m.Register(NewTrafficMorphStrategy(m, BaiduVideoProfile, nil, cfg.Secret))
		}

		// 6. Traffic Morphing (Aparat profile) - Iranian video streaming
		if len(cfg.Secret) > 0 {
			m.Register(NewTrafficMorphStrategy(m, AparatVideoProfile, nil, cfg.Secret))
		}
	}

	// 5. Mesh Relay - route through Russian IPs
	if cfg.ServerAddr != "" && len(cfg.RelayNodes) > 0 {
		mesh := NewMeshRelayStrategy(cfg.ServerAddr)
		mesh.AddRelays(cfg.RelayNodes)
		m.Register(mesh)
	}

	// 6. Anti-Probe Resistance
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		antiprobe := NewAntiProbeStrategy(m, cfg.Secret)
		if cfg.ECHEnabled && len(cfg.ECHConfigList) > 0 {
			antiprobe.SetECH(cfg.ECHConfigList, cfg.ECHPublicName)
		}
		m.Register(antiprobe)
	}

	// 7. Protocol Confusion strategies
	for _, confStrat := range AllConfusionTypes(m) {
		m.Register(confStrat)
	}

	// 8. State Table Exhaustion - more aggressive, lower priority
	m.Register(NewStateExhaustionStrategy(m))

	// 9. Geneva strategies for different countries
	// Now using Manager reference for IPv6/IPv4 transport layer support
	if cfg.ServerAddr != "" && len(cfg.Secret) > 0 {
		// Russia TSPU - most relevant for Russian users
		m.Register(NewGenevaStrategy(m, cfg.Secret, "russia"))
		// China GFW
		m.Register(NewGenevaStrategy(m, cfg.Secret, "china"))
		// Iran DPI
		m.Register(NewGenevaStrategy(m, cfg.Secret, "iran"))
	}

	return m
}

// ConnectWithFallback is a convenience function for one-shot connection
func ConnectWithFallback(ctx context.Context, target string, cfg DefaultManagerConfig) (net.Conn, Strategy, error) {
	m := NewDefaultManager(cfg)
	return m.Connect(ctx, target)
}

// PrintStrategySummary prints current strategy order and stats
func (m *Manager) PrintStrategySummary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result string
	result += "=== Strategy Summary ===\n"
	result += fmt.Sprintf("Registered strategies: %d\n\n", len(m.strategies))

	for i, s := range m.strategies {
		r := m.results[s.ID()]
		status := "untested"
		if r.TestedAt.Unix() > 0 {
			if r.Success {
				status = "✓ working"
			} else {
				status = "✗ failed"
			}
		}

		// Get circuit breaker state
		cbStats := m.circuitBreakers.Get(s.ID()).Stats()
		cbState := cbStats.State.String()

		result += fmt.Sprintf("%d. [%s] %s\n", i+1, s.ID(), s.Name())
		result += fmt.Sprintf("   Priority: %d | Confidence: %.2f | Status: %s | Circuit: %s\n",
			s.Priority(), r.Confidence, status, cbState)
		result += fmt.Sprintf("   Success: %d | Failures: %d | ConsecFail: %d | AvgLatency: %v\n",
			r.SuccessCount, r.FailureCount, r.ConsecutiveFail, r.AvgLatency)
		result += fmt.Sprintf("   Requires Server: %v\n", s.RequiresServer())
		result += fmt.Sprintf("   %s\n\n", s.Description())
	}

	return result
}

// StartPeriodicReprobe starts background re-probing of strategies
func (m *Manager) StartPeriodicReprobe(ctx context.Context, target string) {
	m.mu.Lock()
	if m.reprobeRunning {
		m.mu.Unlock()
		log.Debug("Periodic reprobe already running")
		return
	}
	m.reprobeRunning = true
	m.reprobeTarget = target
	m.stopReprobe = make(chan struct{})
	m.mu.Unlock()

	log.Info("Starting periodic reprobe (interval=%v, target=%s)", m.reprobeInterval, target)

	go func() {
		ticker := time.NewTicker(m.reprobeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Periodic reprobe stopped (context cancelled)")
				return
			case <-m.stopReprobe:
				log.Info("Periodic reprobe stopped")
				return
			case <-ticker.C:
				m.doPeriodicReprobe(ctx)
			}
		}
	}()
}

// StopPeriodicReprobe stops background re-probing
func (m *Manager) StopPeriodicReprobe() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reprobeRunning {
		close(m.stopReprobe)
		m.reprobeRunning = false
	}
}

// doPeriodicReprobe performs a single reprobe cycle
func (m *Manager) doPeriodicReprobe(ctx context.Context) {
	m.mu.RLock()
	target := m.reprobeTarget
	m.mu.RUnlock()

	if target == "" {
		log.Warn("No reprobe target set")
		return
	}

	log.Info("Running periodic reprobe...")

	// Create a timeout context for the reprobe
	reprobeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	results := m.ProbeAll(reprobeCtx, target)

	// Log summary
	available := 0
	for _, r := range results {
		if r.Success {
			available++
		}
	}
	log.Info("Periodic reprobe complete: %d/%d strategies available", available, len(results))
}

// SetReprobeInterval changes the reprobe interval
func (m *Manager) SetReprobeInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reprobeInterval = interval
}

// EnableRTTMasking enables RTT masking on all connections
func (m *Manager) EnableRTTMasking(profile *RTTProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rttMaskingEnabled = true
	m.rttProfile = profile
	if profile != nil {
		log.Info("RTT masking enabled (profile=%s, mean=%v)", profile.Name, profile.MeanDelay)
	} else {
		log.Info("RTT masking enabled (default profile)")
	}
}

// DisableRTTMasking disables RTT masking
func (m *Manager) DisableRTTMasking() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rttMaskingEnabled = false
	m.rttProfile = nil
	log.Info("RTT masking disabled")
}

// IsRTTMaskingEnabled returns RTT masking status
func (m *Manager) IsRTTMaskingEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rttMaskingEnabled
}

// EnableMux enables connection multiplexing for DPI evasion
// According to research data, VLESS+Reality+mux shows 99.5% success rate
func (m *Manager) EnableMux(config *mux.Config) {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	m.muxEnabled = true
	if config != nil {
		m.muxConfig = config
		log.Info("Mux enabled (version=%d, keepalive=%v)", config.Version, config.KeepAliveInterval)
	} else {
		m.muxConfig = mux.DefaultConfig()
		log.Info("Mux enabled (default config)")
	}
}

// DisableMux disables connection multiplexing
func (m *Manager) DisableMux() {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	m.muxEnabled = false

	// Close existing mux client if any
	if m.muxClient != nil {
		m.muxClient.Close()
		m.muxClient = nil
	}
	if m.muxConn != nil {
		m.muxConn.Close()
		m.muxConn = nil
	}

	log.Info("Mux disabled")
}

// IsMuxEnabled returns whether mux is enabled
func (m *Manager) IsMuxEnabled() bool {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()
	return m.muxEnabled
}

// wrapWithMux wraps a connection with mux layer and opens a stream
// If an existing mux session is available and not closed, reuse it
func (m *Manager) wrapWithMux(conn net.Conn, config *mux.Config) (net.Conn, error) {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	// Reuse existing mux session if available and not closed
	if m.muxClient != nil && !m.muxClient.IsClosed() {
		stream, err := m.muxClient.OpenStream()
		if err == nil {
			log.Debug("Mux stream opened on existing session (active=%d)", m.muxClient.NumStreams())
			return stream, nil
		}
		// Session is dead, close it
		log.Debug("Existing mux session failed, recreating: %v", err)
		m.muxClient.Close()
		m.muxClient = nil
		if m.muxConn != nil {
			m.muxConn.Close()
			m.muxConn = nil
		}
	}

	// Create new mux client
	if config == nil {
		config = mux.DefaultConfig()
	}

	client, err := mux.NewClient(conn, config)
	if err != nil {
		return nil, fmt.Errorf("mux client creation failed: %w", err)
	}

	m.muxClient = client
	m.muxConn = conn

	// Open first stream
	stream, err := client.OpenStream()
	if err != nil {
		client.Close()
		m.muxClient = nil
		m.muxConn = nil
		return nil, fmt.Errorf("mux stream open failed: %w", err)
	}

	log.Debug("Mux client created and stream opened (version=%d)", config.Version)
	return stream, nil
}

// GetMuxMetrics returns current mux metrics (if mux is active)
func (m *Manager) GetMuxMetrics() *mux.MetricsSnapshot {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	if m.muxClient == nil {
		return nil
	}
	snapshot := m.muxClient.GetMetrics()
	return &snapshot
}

// CloseMuxSession closes the current mux session (forces reconnection on next Connect)
func (m *Manager) CloseMuxSession() {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	if m.muxClient != nil {
		m.muxClient.Close()
		m.muxClient = nil
	}
	if m.muxConn != nil {
		m.muxConn.Close()
		m.muxConn = nil
	}
	log.Debug("Mux session closed")
}

// GetCircuitBreakerStats returns circuit breaker statistics
func (m *Manager) GetCircuitBreakerStats() map[string]CircuitStats {
	return m.circuitBreakers.GetAllStats()
}

// tcpConnExtractor is an interface for connections that wrap TCP
type tcpConnExtractor interface {
	NetConn() net.Conn
}

// extractTCPConn recursively unwraps connection wrappers to find the underlying TCP connection
func extractTCPConn(conn net.Conn) *net.TCPConn {
	// Direct TCP connection
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc
	}

	// Connection with NetConn() method (TLS, MorphedConn, etc)
	if extractor, ok := conn.(tcpConnExtractor); ok {
		return extractTCPConn(extractor.NetConn())
	}

	return nil
}

// optimizeTCPConn sets TCP_NODELAY and buffer sizes on the underlying TCP connection
// This is critical for low-latency proxy operations
func optimizeTCPConn(conn net.Conn) {
	// Recursively unwrap to find the underlying TCP connection
	// Chain: MorphedConn -> TLS -> TCP
	tcpConn := extractTCPConn(conn)

	if tcpConn == nil {
		log.Debug("Cannot optimize connection: not a TCP connection (type=%T)", conn)
		return
	}

	// Disable Nagle's algorithm - critical for interactive traffic
	// Without this, small packets are delayed up to 40ms waiting for more data
	if err := tcpConn.SetNoDelay(true); err != nil {
		log.Debug("Failed to set TCP_NODELAY: %v", err)
	}

	// Increase socket buffers for throughput
	if err := tcpConn.SetReadBuffer(64 * 1024); err != nil {
		log.Debug("Failed to set read buffer: %v", err)
	}
	if err := tcpConn.SetWriteBuffer(64 * 1024); err != nil {
		log.Debug("Failed to set write buffer: %v", err)
	}

	log.Debug("TCP connection optimized: NoDelay=true, buffers=64KB")
}

// TriggerEmergencyReprobe starts aggressive re-probing when all strategies fail
// This helps recover from network outages by periodically retrying with short intervals
func (m *Manager) TriggerEmergencyReprobe(ctx context.Context) {
	m.mu.Lock()

	// Check if already running
	if m.emergencyReprobeRunning {
		m.mu.Unlock()
		return
	}

	// Don't trigger too frequently (at most once per minute)
	if time.Since(m.lastEmergencyReprobe) < 1*time.Minute {
		m.mu.Unlock()
		log.Debug("Emergency reprobe throttled (last: %v ago)", time.Since(m.lastEmergencyReprobe))
		return
	}

	m.emergencyReprobeRunning = true
	m.lastEmergencyReprobe = time.Now()
	m.emergencyReprobeStop = make(chan struct{})
	target := m.reprobeTarget
	m.mu.Unlock()

	log.Warn("EMERGENCY REPROBE: All strategies failed, entering aggressive recovery mode")

	go func() {
		defer func() {
			m.mu.Lock()
			m.emergencyReprobeRunning = false
			m.mu.Unlock()
			log.Info("Emergency reprobe stopped")
		}()

		ticker := time.NewTicker(30 * time.Second) // Aggressive: every 30 seconds
		defer ticker.Stop()

		maxAttempts := 10 // Try for 5 minutes max
		attempt := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.emergencyReprobeStop:
				return
			case <-ticker.C:
				attempt++
				if attempt > maxAttempts {
					log.Warn("Emergency reprobe giving up after %d attempts", maxAttempts)
					return
				}

				log.Info("Emergency reprobe attempt %d/%d...", attempt, maxAttempts)

				// Reset all circuit breakers to give strategies a fresh chance
				m.mu.Lock()
				for _, s := range m.strategies {
					cb := m.circuitBreakers.Get(s.ID())
					cb.Reset()
				}
				m.mu.Unlock()

				// Probe all strategies
				reprobeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				results := m.ProbeAll(reprobeCtx, target)
				cancel()

				// Check if any succeeded
				available := 0
				for _, r := range results {
					if r.Success {
						available++
					}
				}

				log.Info("Emergency reprobe result: %d/%d strategies available", available, len(results))

				// If at least one strategy works, we're recovered
				if available > 0 {
					log.Info("Network recovered! %d strategies now available", available)
					return
				}
			}
		}
	}()
}

// StopEmergencyReprobe stops the emergency reprobe process
func (m *Manager) StopEmergencyReprobe() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.emergencyReprobeRunning && m.emergencyReprobeStop != nil {
		close(m.emergencyReprobeStop)
	}
}

// ResetForNetworkChange resets all circuit breakers and strategy confidences
// This is called when Android detects a network change (WiFi→LTE, cell handoff)
// After a network change, old connection state is meaningless - we need fresh start
func (m *Manager) ResetForNetworkChange() {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Info("Network change detected - resetting all circuit breakers and confidences")

	// Reset all circuit breakers
	for _, s := range m.strategies {
		cb := m.circuitBreakers.Get(s.ID())
		cb.Reset()

		// Reset confidence to neutral (0.5) - don't punish strategies for old network failures
		if result, exists := m.results[s.ID()]; exists {
			result.Confidence = 0.5
			result.ConsecutiveFail = 0
			result.LastFailure = time.Time{}
		}
	}

	// Stop any running emergency reprobe
	if m.emergencyReprobeRunning && m.emergencyReprobeStop != nil {
		close(m.emergencyReprobeStop)
		m.emergencyReprobeRunning = false
	}

	// Re-sort strategies by priority (confidence is now neutral for all)
	m.sortStrategies()
}

// ConnectForReconnect is optimized for network change scenarios
// It skips circuit breaker checks since we just reset them
// and uses shorter timeouts for faster reconnection
// For Android: first tries the last successful strategy multiple times before fallback
func (m *Manager) ConnectForReconnect(ctx context.Context, target string) (net.Conn, Strategy, error) {
	// IPv6 Transport Layer: select IPv6 or IPv4 address
	// Network change might affect IPv6 availability, so re-check
	if m.serverAddrV6 != "" && m.preferIPv6 {
		m.ResetIPv6Check() // Force re-check after network change
		target = m.GetServerAddr(ctx)
		log.Debug("Reconnect: using effective server address: %s", target)
	}

	m.mu.RLock()
	lastStrategy := m.lastSuccessfulStrategy
	strategies := make([]Strategy, 0, len(m.strategies))
	for _, s := range m.strategies {
		if s.Priority() > 0 {
			strategies = append(strategies, s)
		}
	}
	m.mu.RUnlock()

	if len(strategies) == 0 {
		return nil, nil, fmt.Errorf("no strategies available")
	}

	// Use shorter timeout for reconnect (5s per attempt)
	reconnectTimeout := 5 * time.Second
	var lastErr error

	// Phase 1: Try last successful strategy up to 5 times
	// This is optimized for Android network handoff where the network needs time to stabilize
	if lastStrategy != nil {
		log.Info("Reconnecting to %s: trying last successful strategy %s (up to 5 attempts)", target, lastStrategy.Name())

		for attempt := 1; attempt <= 5; attempt++ {
			// Wait a bit before each attempt for network to stabilize
			if attempt > 1 {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(300 * time.Millisecond):
				}
			}

			log.Debug("Reconnect: attempt %d/5 with %s", attempt, lastStrategy.Name())

			connectCtx, cancel := context.WithTimeout(ctx, reconnectTimeout)
			start := time.Now()

			conn, err := lastStrategy.Connect(connectCtx, target)
			latency := time.Since(start)
			cancel()

			if err == nil {
				// Success
				m.mu.Lock()
				m.updateConfidenceWithLatency(lastStrategy.ID(), true, latency)
				m.sortStrategies()
				m.mu.Unlock()

				optimizeTCPConn(conn)
				log.Info("Reconnected via %s (attempt %d, latency=%v)", lastStrategy.Name(), attempt, latency)
				return conn, lastStrategy, nil
			}

			lastErr = err
			log.Debug("Reconnect attempt %d with %s failed: %v", attempt, lastStrategy.Name(), err)
		}

		log.Info("Last successful strategy %s failed after 5 attempts, falling back to full scan", lastStrategy.Name())
	}

	// Phase 2: Try all strategies (excluding the one we just tried)
	log.Info("Reconnecting to %s (trying %d strategies with fast timeout)", target, len(strategies))

	for i, s := range strategies {
		// Skip the strategy we already tried 5 times
		if lastStrategy != nil && s.ID() == lastStrategy.ID() {
			continue
		}

		log.Debug("Reconnect: trying strategy %d/%d: %s", i+1, len(strategies), s.Name())

		connectCtx, cancel := context.WithTimeout(ctx, reconnectTimeout)
		start := time.Now()

		conn, err := s.Connect(connectCtx, target)
		latency := time.Since(start)
		cancel()

		if err == nil {
			// Success - update last successful strategy
			m.mu.Lock()
			m.lastSuccessfulStrategy = s
			m.updateConfidenceWithLatency(s.ID(), true, latency)
			m.sortStrategies()
			m.mu.Unlock()

			optimizeTCPConn(conn)
			log.Info("Reconnected via %s (latency=%v)", s.Name(), latency)
			return conn, s, nil
		}

		lastErr = fmt.Errorf("%s: %w", s.Name(), err)
		log.Debug("Reconnect strategy %s failed: %v", s.Name(), err)

		// Short pause between attempts
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	return nil, nil, fmt.Errorf("all strategies failed during reconnect, last error: %w", lastErr)
}

// HasAvailableStrategies checks if any strategy is currently available
func (m *Manager) HasAvailableStrategies() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.strategies {
		// Check circuit breaker
		if !m.circuitBreakers.Allow(s.ID()) {
			continue
		}

		// Check if strategy has been tested and is working
		if result, exists := m.results[s.ID()]; exists {
			if result.Success || result.Confidence > 0.3 {
				return true
			}
		}
	}

	return false
}

// replacePort replaces the port in a host:port string with newPort
func (m *Manager) replacePort(target string, newPort int) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// Target may not have a port, just return as-is
		return target
	}
	return fmt.Sprintf("%s:%d", host, newPort)
}

// triggerReconnect is called when port hopping changes the port
// Uses "make before break" approach: establish new connection first, then swap
func (m *Manager) triggerReconnect() {
	m.portHopperMu.Lock()
	defer m.portHopperMu.Unlock()

	// Get new target with updated port
	newPort := m.portHopper.CurrentPort()

	// Get current target (we need the host part)
	m.mu.Lock()
	currentStrategy := m.lastSuccessfulStrategy
	m.mu.Unlock()

	if currentStrategy == nil {
		// No active connection, just close and let next Connect() handle it
		m.CloseMuxSession()
		log.Debug("Port hop: no active strategy, will reconnect on next request")
		return
	}

	// Try to establish new connection in background
	go m.performMakeBeforeBreak(newPort)
}

// performMakeBeforeBreak establishes new connection before closing old one
func (m *Manager) performMakeBeforeBreak(newPort int) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Get target address for reconnect
	m.mu.Lock()
	target := m.reprobeTarget // This contains the server address
	lastStrategy := m.lastSuccessfulStrategy
	m.mu.Unlock()

	if target == "" || lastStrategy == nil {
		log.Debug("Port hop: no target/strategy available, forcing hard reconnect")
		m.CloseMuxSession()
		return
	}

	// Build new target with new port
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	newTarget := fmt.Sprintf("%s:%d", host, newPort)

	log.Debug("Port hop: establishing new connection to %s (make before break)", newTarget)

	// Try to connect using the last successful strategy
	conn, err := lastStrategy.Connect(ctx, newTarget)
	if err != nil {
		log.Warn("Port hop: new connection failed (%v), forcing hard reconnect", err)
		m.CloseMuxSession()
		return
	}

	// Create new mux client on the new connection
	m.muxMu.Lock()

	// Store old client/conn for cleanup
	oldClient := m.muxClient
	oldConn := m.muxConn

	// Create new mux client
	config := m.muxConfig
	if config == nil {
		config = mux.DefaultConfig()
	}

	newClient, err := mux.NewClient(conn, config)
	if err != nil {
		m.muxMu.Unlock()
		conn.Close()
		log.Warn("Port hop: mux client creation failed (%v), forcing hard reconnect", err)
		m.CloseMuxSession()
		return
	}

	// Test new connection by opening a stream
	stream, err := newClient.OpenStream()
	if err != nil {
		m.muxMu.Unlock()
		newClient.Close()
		conn.Close()
		log.Warn("Port hop: stream open failed (%v), forcing hard reconnect", err)
		m.CloseMuxSession()
		return
	}
	stream.Close() // Just testing, close it

	// Atomic swap: new connection is ready
	m.muxClient = newClient
	m.muxConn = conn
	m.muxMu.Unlock()

	// Now close old connection (traffic already switched to new one)
	if oldClient != nil {
		oldClient.Close()
	}
	if oldConn != nil {
		oldConn.Close()
	}

	log.Info("Port hop: seamless switch to port %d completed", newPort)

	// Notify external callback (e.g., VPN client) about port hop
	m.portHopCallbackMu.Lock()
	callback := m.portHopCallback
	m.portHopCallbackMu.Unlock()
	if callback != nil {
		// Run callback in goroutine to avoid blocking
		go callback(0, newPort) // oldPort not tracked, just pass newPort
	}
}

// SetPortHopCallback sets a callback function that will be called when port hop occurs
// This allows external components (like VPN client) to react to port changes
func (m *Manager) SetPortHopCallback(callback func(oldPort, newPort int)) {
	m.portHopCallbackMu.Lock()
	defer m.portHopCallbackMu.Unlock()
	m.portHopCallback = callback
}

// StartPortHopChecker starts background goroutine that checks for port hops
func (m *Manager) StartPortHopChecker(ctx context.Context) {
	if m.portHopper == nil {
		return
	}

	m.portHopperMu.Lock()
	if m.portHopperStop != nil {
		m.portHopperMu.Unlock()
		return // Already running
	}
	m.portHopperStop = make(chan struct{})
	stopCh := m.portHopperStop
	m.portHopperMu.Unlock()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				if m.portHopper.ShouldHop() {
					m.portHopper.NextPort() // Triggers OnHop callback
				}
			}
		}
	}()

	log.Debug("Port hop checker started")
}

// StopPortHopChecker stops the port hop checker goroutine
func (m *Manager) StopPortHopChecker() {
	m.portHopperMu.Lock()
	defer m.portHopperMu.Unlock()

	if m.portHopperStop != nil {
		close(m.portHopperStop)
		m.portHopperStop = nil
		log.Debug("Port hop checker stopped")
	}
}

// GetPortHopperStats returns current port hopper statistics
func (m *Manager) GetPortHopperStats() *porthopping.Stats {
	if m.portHopper == nil {
		return nil
	}
	stats := m.portHopper.Stats()
	return &stats
}

// GetCurrentPort returns current port being used (for port hopping)
// Returns 0 if port hopping is disabled
func (m *Manager) GetCurrentPort() int {
	if m.portHopper == nil {
		return 0
	}
	return m.portHopper.CurrentPort()
}

// EnablePortHopping enables port hopping dynamically (e.g., from server capabilities)
// Returns true if port hopping was enabled, false if already enabled or error
func (m *Manager) EnablePortHopping(cfg *porthopping.Config) bool {
	m.portHopperMu.Lock()
	defer m.portHopperMu.Unlock()

	// Already enabled
	if m.portHopper != nil {
		log.Debug("Port hopping already enabled, ignoring auto-enable")
		return false
	}

	if cfg == nil || !cfg.Enabled {
		return false
	}

	hopper, err := porthopping.NewPortHopper(cfg)
	if err != nil {
		log.Warn("Failed to enable port hopping: %v", err)
		return false
	}

	m.portHopper = hopper
	// Set callback for port change - triggers reconnect
	hopper.OnHop(func(oldPort, newPort int) {
		log.Info("Port hop: %d -> %d, triggering reconnect", oldPort, newPort)
		m.triggerReconnect()
	})

	log.Info("Port hopping auto-enabled from server (range=%d-%d, interval=%v, strategy=%s)",
		cfg.PortRangeStart, cfg.PortRangeEnd, cfg.HopInterval, cfg.Strategy)

	return true
}

// IsPortHoppingEnabled returns true if port hopping is enabled
func (m *Manager) IsPortHoppingEnabled() bool {
	return m.portHopper != nil
}

// GetServerAddr returns the effective server address considering IPv6/IPv4 preferences
// This method implements IPv6 Transport Layer with automatic fallback
func (m *Manager) GetServerAddr(ctx context.Context) string {
	m.ipv6Mu.Lock()
	defer m.ipv6Mu.Unlock()

	// If IPv6 is not configured, return IPv4
	if m.serverAddrV6 == "" || !m.preferIPv6 {
		return m.serverAddrV4
	}

	// Check IPv6 availability on first call
	if !m.ipv6CheckedOnce {
		m.ipv6CheckedOnce = true
		m.ipv6Available = m.checkIPv6Connectivity(ctx)
		if m.ipv6Available {
			log.Info("IPv6 connectivity check passed, using IPv6 transport")
		} else {
			log.Warn("IPv6 connectivity check failed, falling back to IPv4")
		}
	}

	// Return IPv6 if available, otherwise fallback to IPv4
	if m.ipv6Available {
		return m.serverAddrV6
	}

	if m.fallbackToV4 {
		return m.serverAddrV4
	}

	// IPv6 preferred but not available, fallback disabled
	// Return IPv6 anyway and let it fail
	return m.serverAddrV6
}

// checkIPv6Connectivity performs a quick check if IPv6 is available
func (m *Manager) checkIPv6Connectivity(ctx context.Context) bool {
	if m.serverAddrV6 == "" {
		return false
	}

	// Try to dial IPv6 server with short timeout
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	conn, err := dialer.DialContext(checkCtx, "tcp6", m.serverAddrV6)
	if err != nil {
		log.Debug("IPv6 connectivity check failed: %v", err)
		return false
	}

	conn.Close()
	return true
}

// ResetIPv6Check forces a re-check of IPv6 connectivity on next GetServerAddr call
// Useful after network changes (WiFi -> LTE, etc.)
func (m *Manager) ResetIPv6Check() {
	m.ipv6Mu.Lock()
	defer m.ipv6Mu.Unlock()
	m.ipv6CheckedOnce = false
	log.Debug("IPv6 connectivity check reset, will re-check on next connection")
}
