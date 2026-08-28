package strategy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/mux"
	"github.com/tiredvpn/tiredvpn/internal/porthopping"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// clientSocketBufferBytes is the SO_RCVBUF/SO_SNDBUF size applied to client TCP
// sockets in optimizeTCPConn. On high-RTT censored links (150-300ms) the BDP far
// exceeds the old 64KB default, which capped the TCP window and throughput. This
// matches the 4MB the server already uses (server/upstream.go, server/server.go).
const clientSocketBufferBytes = 4 * 1024 * 1024

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

	// burstReshape configures the nudge/ack exchange that splits the inner
	// handshake. Off unless the operator turns it on, and it must be on at both
	// ends - see internal/strategy/burst_reshape.go.
	burstReshape BurstReshapeConfig

	// Circuit breaker
	circuitBreakers *CircuitBreakerManager

	// Storm detector: catches strategies that connect successfully but whose
	// sessions are repeatedly torn down (e.g. DPI killing a REALITY pattern
	// after a few seconds). The circuit breaker cannot see this because every
	// connect() succeeds.
	stormDetector *StormDetector

	// forced is true when ForceStrategy() was called (user passed -strategy X).
	// In forced mode storms are logged loudly but never trigger a switch.
	forced bool

	// Periodic re-probe. There is deliberately no cached target here: the
	// reprobe must follow whichever candidate is pinned right now, and a copy
	// written once at start-up cannot. All four consumers call GetServerAddr.
	reprobeInterval time.Duration
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
	muxEnabled          bool
	muxConfig           *mux.Config
	muxClient           *mux.Client
	muxConn             net.Conn   // underlying connection for mux
	muxMu               sync.Mutex // separate mutex for mux operations
	recyclingInProgress bool       // true while budget recycling goroutine is running (under muxMu)

	// Last successful strategy for fast reconnect
	lastSuccessfulStrategy Strategy
	lastSuccessfulTime     time.Time // When the last successful connection was made

	// Fast-reconnect loop guard. connectWithRTT re-uses lastSuccessfulStrategy on
	// a "fast reconnect" path while it is not parked. A strategy that connects
	// fine but whose tunnel dies seconds later (meek under DPI) can ride that path
	// in a tight loop without the storm detector ever parking it (the storm
	// detector keys on session lifetime; these sessions can outlive the short
	// threshold). These fields count consecutive fast reconnects of one strategy
	// inside fastReconnectWindow; past the limit the fast path is skipped so a
	// full scan gives other strategies (and the detector) a turn. Guarded by m.mu.
	fastReconnectStrategy string
	fastReconnectCount    int
	fastReconnectFirst    time.Time

	// Connectivity checker for pre-flight checks
	connectivityChecker  *ConnectivityChecker
	excludeUDPStrategies bool // Temporarily exclude UDP-based strategies if UDP is blocked

	// consecutiveConnectFailures counts back-to-back failed Connect() calls. The
	// blocking pre-flight connectivity check is skipped on the hot reconnect path
	// (a brief server-side RST/EOF should not cost a full check) and only re-armed
	// after this many failures in a row, which is the real "network is down"
	// signal rather than a one-off reset. Reset on any successful connect.
	// Guarded by m.mu.
	consecutiveConnectFailures int

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

	// Endpoint selection: which server, on which address family, we currently
	// dial. Replaces the old serverAddrV4/serverAddrV6 pair together with the
	// one-shot ipv6CheckedOnce verdict, which was decided once per process and
	// never revisited outside the Android control socket. Guarded by m.mu; the
	// selector itself is safe for concurrent use.
	endpoints *endpoint.Selector

	// secret is the process-wide shared secret: -secret / TIREDVPN_SECRET, or
	// the one value a config file gave every server. It is the fallback for
	// endpoints that do not carry a secret of their own - see secret.go for how
	// the secret in force reaches a strategy. Guarded by m.mu.
	secret []byte

	// Shared TLS client session cache for resumption across reconnects.
	// The adaptive manager reconnects frequently (fallback, reprobe); without a
	// shared cache every stdlib-TLS strategy does a full handshake each time,
	// costing 1-2 extra RTTs. tls.ClientSessionCache is safe for concurrent use,
	// and resumption is keyed by ServerName, so strategies with different SNI
	// never collide. Set once at construction, never mutated => race-free.
	tlsSessionCache tls.ClientSessionCache
}

// Fast-reconnect loop-guard tuning. See Manager.fastReconnectStrategy.
const (
	fastReconnectLimit  = 3               // fast reconnects of one strategy allowed before forcing a full scan
	fastReconnectWindow = 5 * time.Minute // window over which fast reconnects are counted
)

// errStrategyScanFailed marks the one failure mode that says something about
// the ENDPOINT rather than about a strategy: every eligible transport was tried
// against this address and every one of them died. dialEndpoints keys its
// candidate switch on it, so it must not be attached to "context cancelled" or
// "nothing was eligible", which say nothing about the address.
var errStrategyScanFailed = errors.New("all strategies failed")

// errAddrSilent narrows errStrategyScanFailed: the scan was abandoned because
// the address accepted connections and then answered nothing, on one transport
// after another. Every failure was a timeout at connectTimeout - no refusal, no
// reset, no protocol error - which is what a blackholed address looks like and
// what no application-layer disguise can talk its way out of.
//
// Errors carrying it also carry errStrategyScanFailed, so dialEndpoints still
// treats it as an endpoint verdict; the extra sentinel only says the verdict is
// strong enough to act on at once.
var errAddrSilent = errors.New("address answered no transport")

// androidSilentScanAbort is how many consecutive non-UDP strategies must die on
// the connect timeout before an Android scan gives up on the address.
//
// Two rather than the desktop three because the VPN service abandons a connect
// after ~26s and rebuilds the client: with connectTimeout at 10s, a verdict
// reached at 30s is a verdict nobody is left to hear.
const androidSilentScanAbort = 2

// silenceLatency is the share of the connect timeout an attempt has to burn
// before it counts as having heard nothing back, whatever its error says.
//
// Not the full timeout: the deadline fires a hair before the caller measures,
// and a strategy that gives up a moment early on its own inner deadline heard
// just as little. Not much less either - a transport that got an answer and
// disliked it comes back in milliseconds, nowhere near this line.
func silenceLatency(connectTimeout time.Duration) time.Duration {
	return connectTimeout - connectTimeout/10
}

// preflightFailThreshold is how many consecutive failed connects must pile up
// before Connect re-arms the blocking pre-flight connectivity check. See
// Manager.consecutiveConnectFailures.
const preflightFailThreshold = 2

// recordConnectResult tracks the consecutive-failure streak that gates the
// pre-flight connectivity check on reconnect.
func (m *Manager) recordConnectResult(success bool) {
	m.mu.Lock()
	if success {
		m.consecutiveConnectFailures = 0
	} else {
		m.consecutiveConnectFailures++
	}
	m.mu.Unlock()
}

// applyUDPGate flips QUIC/UDP strategy exclusion based on a fresh UDP probe.
func (m *Manager) applyUDPGate(udpOK bool) {
	m.mu.Lock()
	if !udpOK {
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

// shouldSkipFastReconnect records a fast-reconnect attempt for strategyID and
// reports whether the fast path should be skipped in favor of a full scan. A
// strategy that fast-reconnects more than fastReconnectLimit times inside
// fastReconnectWindow is looping on a tunnel that connects but will not hold;
// the full scan then gives the storm detector and other strategies a chance.
// A different strategy, or an expired window, restarts the count.
// Caller must hold m.mu.
func (m *Manager) shouldSkipFastReconnect(strategyID string, now time.Time) bool {
	if m.fastReconnectStrategy != strategyID || now.Sub(m.fastReconnectFirst) > fastReconnectWindow {
		m.fastReconnectStrategy = strategyID
		m.fastReconnectCount = 0
		m.fastReconnectFirst = now
	}
	m.fastReconnectCount++
	return m.fastReconnectCount > fastReconnectLimit
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
		stormDetector:         NewStormDetector(StormConfig{}),
		reprobeInterval:       5 * time.Minute,
		stopReprobe:           make(chan struct{}),
		tcpFailuresBeforeQUIC: 3, // Switch to QUIC after 3 TCP timeouts
		tlsSessionCache:       tls.NewLRUClientSessionCache(64),
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

// ConnectivityChecker returns the pre-flight gate, or nil when none was set.
//
// Exported so the reconnect loop asks the same question the same way the
// connect path does, against the addresses the selector pinned - instead of
// inventing its own probe and, in the process, its own observable signature.
func (m *Manager) ConnectivityChecker() *ConnectivityChecker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connectivityChecker
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
	m.forced = true
	log.Info("Forced %d strategies matching '%s'", len(matched), idPrefix)
	return nil
}

// IsForced reports whether a strategy was explicitly forced via ForceStrategy.
// In forced mode the manager never auto-switches away from a storming strategy.
func (m *Manager) IsForced() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.forced
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
	// Probe the pinned candidate and only the pinned candidate. Sweeping every
	// configured endpoint on a timer would multiply this client's traffic by the
	// size of its server list and hand an observer a periodic fan-out pattern
	// that nothing else on the wire produces.
	if addr := m.GetServerAddr(ctx); addr != "" {
		target = addr
		log.Debug("Probing with effective server address: %s", target)
	}
	// Same endpoint, same key: a probe that authenticates does it against the
	// pinned endpoint, which is the one whose address was just resolved above.
	ctx = m.ensureDialSecret(ctx)

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

// updateConfidenceWithLatency updates the confidence stats/EMA and records the
// outcome in the circuit breaker exactly once.
func (m *Manager) updateConfidenceWithLatency(id string, success bool, latency time.Duration) {
	m.updateConfidenceStats(id, success, latency)
	if success {
		// Record success in circuit breaker (with RTT for adaptive thresholds)
		if latency > 0 {
			m.circuitBreakers.RecordSuccessWithRTT(id, latency)
		} else {
			m.circuitBreakers.RecordSuccess(id)
		}
	} else {
		m.circuitBreakers.RecordFailure(id)
	}
}

// updateConfidenceStats updates the confidence EMA and per-strategy statistics
// WITHOUT recording anything in the circuit breaker. Callers that record the
// circuit-breaker outcome themselves (e.g. the connect retry loop, which counts
// one logical strategy failure once) use this to avoid double-counting.
func (m *Manager) updateConfidenceStats(id string, success bool, latency time.Duration) {
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
	} else {
		r.FailureCount++
		r.ConsecutiveFail++
		r.LastFailure = now
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

// RecordSessionStart marks the moment a tunnel session became usable for the
// given strategy. Pair it with RecordSessionEnd to let the storm detector
// measure how long the session survived.
func (m *Manager) RecordSessionStart(strategyID string) {
	m.stormDetector.SessionOpened(strategyID)
}

// RecordSessionEnd reports that the session for strategyID has ended and
// returns whether the strategy is now storming (repeatedly short-lived
// sessions). On a storm in auto-mode the strategy is parked and excluded from
// selection for the cooldown; the caller should drop the cached fast-reconnect
// strategy so the next Connect picks a fresh one. In forced mode the verdict is
// still returned (for loud logging) but the strategy stays in use.
func (m *Manager) RecordSessionEnd(strategyID string) (storming bool) {
	storming = m.stormDetector.SessionClosed(strategyID)
	if !storming {
		return false
	}

	if m.IsForced() {
		log.Error("STORM on forced strategy %s: sessions keep dying within %v of connecting. "+
			"DPI is likely tearing down this pattern. Consider switching strategy (-strategy ...) "+
			"or running in auto mode.", strategyID, stormShortSession)
		return true
	}

	log.Warn("STORM detected on %s: repeated short-lived sessions, parking for %v and failing over to next strategy",
		strategyID, stormCooldown)

	// Drop the cached fast-reconnect strategy if it is the storming one, so the
	// next reconnect does not immediately retry it.
	m.mu.Lock()
	if m.lastSuccessfulStrategy != nil && m.lastSuccessfulStrategy.ID() == strategyID {
		m.lastSuccessfulStrategy = nil
	}
	m.mu.Unlock()
	return true
}

// maxEndpointAttempts caps how many endpoint candidates a single Connect may
// try. Two, and no more: handleDisconnect gives the whole reconnect 15 seconds,
// and each candidate costs a full strategy scan. A deeper walk would blow that
// budget and turn one dead family into a minutes-long outage.
const maxEndpointAttempts = 2

// Connect tries strategies in order until one succeeds
func (m *Manager) Connect(ctx context.Context, target string) (net.Conn, Strategy, error) {
	// Mux fast-path: if mux is enabled and a live session already exists, open a
	// new stream on it and return immediately - do NOT dial a fresh transport.
	// Without this, every call (e.g. every proxy CONNECT routed through
	// pool.DialTarget) unconditionally completes a full REALITY handshake below,
	// which wrapWithMux then discards in its reuse branch. That orphaned transport
	// is never used nor closed, so it hangs pre-auth on the server (goroutine +
	// peek-buffer + admission slot) until probeReadDeadline, and under a busy
	// client the accumulation outpaces reclamation -> server OOM.
	if stream, strat, ok := m.tryMuxFastPath(); ok {
		return stream, strat, nil
	}

	conn, strategy, err := m.dialEndpoints(ctx, target)
	if err != nil {
		m.recordConnectResult(false)
		return nil, nil, err
	}
	m.recordConnectResult(true)

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

// dialEndpoints walks the endpoint candidates until one of them yields a
// connection.
//
// The loop only ever advances on errStrategyScanFailed - every transport on
// that address was tried and every one of them died. That signal is the useful
// one precisely because it arrives on the hot reconnect path, where the
// pre-flight gate is skipped. A pre-flight that fails outright means the whole
// network is down, not this endpoint, so it stops the loop without touching
// anyone's health: otherwise closing a laptop lid would park every candidate.
func (m *Manager) dialEndpoints(ctx context.Context, target string) (net.Conn, Strategy, error) {
	sel := m.selector()
	if sel == nil {
		if _, err := m.preflightCandidate(ctx, nil, endpoint.Candidate{Addr: target}); err != nil {
			return nil, nil, err
		}
		return m.ConnectExcluding(ctx, m.withHoppedPort(target), nil)
	}

	cand, ok := sel.Reconsider(sel.Now())
	if !ok {
		return nil, nil, fmt.Errorf("no endpoint candidates configured")
	}
	// Without this line a log shows a client dialling the same address over and
	// over and cannot say whether the endpoint layer never condemned it or
	// condemned it and chose it anyway. Those are different bugs and we spent a
	// day telling them apart by hand.
	log.Info("Endpoint choice: %s (%s)", cand, m.endpointRoster(sel))

	budget := min(maxEndpointAttempts, len(sel.Candidates()))
	var lastErr error

	for attempt := range budget {
		if attempt > 0 {
			next, ok := sel.Next(sel.Now())
			if !ok {
				break
			}
			log.Warn("Endpoint %s failed a full strategy scan, switching to %s", cand, next)
			sel.Pin(next)
			cand = next
		}

		gated, err := m.preflightCandidate(ctx, sel, cand)
		if err != nil {
			// The gate found no network at all. That is not this endpoint's
			// fault and nobody has been charged for it - see the comment above.
			return nil, nil, err
		}
		cand = gated

		// Family probe: one dial, at most once per candidate, and only when
		// there is somewhere to fall back to (see Selector.ProbeCurrent). It
		// runs AFTER the gate on purpose. The gate answers the same question
		// for free when it runs at all, and it marks the candidates it resolved
		// as probed, so this is a no-op then. On the hot reconnect path, where
		// the gate is skipped, this is the only thing that notices a dead
		// family - which is exactly what the old one-shot IPv6 check did.
		cand, _ = sel.ProbeCurrent(ctx)

		// Name the secret for THIS candidate, on this dial's own context. The
		// pinned candidate can move underneath us - a concurrent Connect, the
		// pre-flight gate, a health report - so reading the pin again down in a
		// strategy would let a handshake authenticate to one server with another
		// server's key. Here the address and the key are decided together and
		// travel together.
		dialCtx := withDialSecret(ctx, m.secretForCandidate(cand))

		start := time.Now()
		conn, strategy, err := m.ConnectExcluding(dialCtx, m.withHoppedPort(cand.Addr), nil)
		if err == nil {
			sel.Report(cand, true, time.Since(start))
			return conn, strategy, nil
		}
		lastErr = err

		if !errors.Is(err, errStrategyScanFailed) {
			// Context cancelled, or no strategy was even eligible. Neither says
			// anything about this endpoint.
			break
		}
		if errors.Is(err, errAddrSilent) {
			sel.ReportSilent(cand)
		} else {
			sel.Report(cand, false, 0)
		}
		m.logEndpointHealth(sel, cand)
	}

	return nil, nil, lastErr
}

// endpointRoster renders the pool the way a reader of the log needs it: which
// candidates are parked and until when. "6 servers, selection=priority" says
// what was configured; this says what the client currently believes.
func (m *Manager) endpointRoster(sel *endpoint.Selector) string {
	now := sel.Now()
	var parked []string
	total := 0
	for _, st := range sel.Snapshot() {
		total++
		if st.CooldownUntil.IsZero() || !now.Before(st.CooldownUntil) {
			continue
		}
		parked = append(parked, fmt.Sprintf("%s for %s", st.Addr, st.CooldownUntil.Sub(now).Round(time.Second)))
	}
	if len(parked) == 0 {
		return fmt.Sprintf("%d candidates, none parked", total)
	}
	return fmt.Sprintf("%d candidates, parked: %s", total, strings.Join(parked, ", "))
}

// logEndpointHealth reports what a failed cycle did to a candidate, so a log
// can distinguish "not parked" from "parked and picked again".
func (m *Manager) logEndpointHealth(sel *endpoint.Selector, cand endpoint.Candidate) {
	now := sel.Now()
	for _, st := range sel.Snapshot() {
		if st.Addr != cand.Addr {
			continue
		}
		if !st.CooldownUntil.IsZero() && now.Before(st.CooldownUntil) {
			log.Info("Endpoint %s parked for %s after %d consecutive failure(s)",
				cand, st.CooldownUntil.Sub(now).Round(time.Second), st.ConsecutiveFailures)
			return
		}
		log.Info("Endpoint %s failed (%d consecutive), not parked yet", cand, st.ConsecutiveFailures)
		return
	}
}

// withHoppedPort rewrites the port when port hopping is active.
func (m *Manager) withHoppedPort(target string) string {
	if m.portHopper == nil {
		return target
	}
	return m.replacePort(target, m.portHopper.CurrentPort())
}

// preflightCandidate runs the pre-flight connectivity gate for cand and returns
// the candidate to dial - which may differ from the one passed in when the gate
// found the sibling address answering instead.
//
// The skip condition is unchanged: on the hot reconnect path the real connect
// below has its own timeout and would reach a briefly-reset server itself, so
// checking first only adds latency to recovery. The gate runs on the very first
// connect, or once several connects in a row have failed - the signal that the
// network is genuinely down rather than a one-off server RST.
func (m *Manager) preflightCandidate(ctx context.Context, sel *endpoint.Selector, cand endpoint.Candidate) (endpoint.Candidate, error) {
	m.mu.RLock()
	checker := m.connectivityChecker
	connectedBefore := m.lastSuccessfulStrategy != nil
	fails := m.consecutiveConnectFailures
	m.mu.RUnlock()

	if checker == nil {
		return cand, nil
	}
	if connectedBefore && fails < preflightFailThreshold {
		return cand, nil
	}

	if sel != nil {
		// The whole pool, not just this endpoint's other family: the gate
		// decides between dialling and waiting, so a narrow view makes a client
		// wait out its first server while the rest of the pool sits idle.
		checker.SetAddrs(cand.Addr, sel.GateAddrs(cand)...)
	}

	result := checker.Check(ctx)
	if !result.TCP {
		// No TCP connectivity - wait in loop until it's restored
		log.Warn("No TCP connectivity to server, waiting for network...")
		result = checker.WaitForConnectivity(ctx, defaultProbeInterval)
		if !result.TCP {
			return cand, fmt.Errorf("no connectivity to server: %w", result.Error)
		}
	}

	m.applyUDPGate(result.UDP)

	if sel == nil || result.Addr == "" {
		return cand, nil
	}
	if result.Addr == cand.Addr {
		// The pinned address answered. Record it as a probe, not as a connect:
		// a completed TCP handshake is not evidence that the transport works,
		// so this refreshes latency and deliberately leaves both the failure
		// streak and any cooldown alone (see Selector.ReportProbe).
		sel.ReportProbe(cand, true, result.Latency)
		return cand, nil
	}
	other, ok := sel.CandidateForAddr(result.Addr)
	if !ok {
		return cand, nil
	}

	// The gate probes parked candidates on purpose - its question is whether
	// this client has a network at all, and leaving a parked-but-live server
	// out would make it wait when it has somewhere to go. Acting on that answer
	// is a different question, and for a parked candidate the selector has
	// already answered it, on evidence the gate cannot produce: an address that
	// swallowed every transport still completes a TCP handshake. Switching here
	// sent the client straight back to the server a full scan had just
	// condemned, over and over.
	if sel.IsParked(other) {
		log.Debug("Pre-flight: %s answered but is parked - staying on %s", other, cand)
		return cand, nil
	}

	// The gate walked the pool and something other than the pinned address
	// answered - the other family of this server, or another server entirely.
	// That is a free verdict, the packets went out either way, so act on it
	// instead of dialling a silent address through every strategy in turn.
	log.Info("Pre-flight: %s silent, %s answered - switching endpoint", cand, other)
	sel.ReportProbe(cand, false, 0)
	sel.ReportProbe(other, true, result.Latency)
	sel.Pin(other)
	return other, nil
}

// scanState is what one connect cycle learns about the ADDRESS rather than
// about any single transport, carried across both passes ConnectExcluding
// makes over the strategy list.
//
// It has to outlive a pass. Every failure re-sorts the list by confidence, so
// the masked pass sees the same transports in a different order, and a per-pass
// counter would let that reordering manufacture a silence verdict for an
// address that had already answered.
type scanState struct {
	// answered records that some transport got a reply - a refusal, a reset, a
	// rejected handshake. One is enough: whatever is wrong from there on is a
	// property of a transport, which is what the scan exists to work around.
	answered bool
	// timeouts counts non-UDP strategies that died on the connect timeout.
	timeouts int
}

// ConnectExcluding tries strategies excluding specified ones (for fallback)
func (m *Manager) ConnectExcluding(ctx context.Context, target string, excludeIDs []string) (net.Conn, Strategy, error) {
	scan := &scanState{}

	// First pass: try all strategies WITHOUT RTT masking
	conn, strategy, err := m.connectWithRTTScan(ctx, target, excludeIDs, false, scan)
	if err == nil {
		return conn, strategy, nil
	}

	// Second pass: if RTT masking is enabled, retry all strategies WITH RTT masking
	m.mu.RLock()
	rttEnabled := m.rttMaskingEnabled
	m.mu.RUnlock()

	// Two cases where the second pass is pure cost. A cancelled context has
	// nobody left to hand a connection to - on Android the service has already
	// given up and is tearing this client down, and the log still showed a
	// fresh 21-strategy scan starting underneath it. And RTT masking reshapes
	// the timing of an established session; it cannot make an address that
	// answered nothing answer, so repeating the whole scan against a silent
	// address doubles the time before the endpoint layer hears the verdict.
	if ctx.Err() != nil || errors.Is(err, errAddrSilent) {
		return nil, nil, err
	}

	if rttEnabled {
		log.Info("All strategies failed, retrying with RTT masking enabled...")
		return m.connectWithRTTScan(ctx, target, excludeIDs, true, scan)
	}

	return nil, nil, err
}

// connectWithRTT is the internal connect method with optional RTT masking. It
// scans on its own, for callers that make a single pass.
func (m *Manager) connectWithRTT(ctx context.Context, target string, excludeIDs []string, useRTTMasking bool) (net.Conn, Strategy, error) {
	return m.connectWithRTTScan(ctx, target, excludeIDs, useRTTMasking, &scanState{})
}

// connectWithRTTScan is connectWithRTT with the cycle-wide scan state supplied
// by the caller.
func (m *Manager) connectWithRTTScan(ctx context.Context, target string, excludeIDs []string, useRTTMasking bool, scan *scanState) (net.Conn, Strategy, error) {
	// Every path that reaches a strategy's Connect goes through here, so this is
	// where a dial that nobody labelled picks up the pinned endpoint's secret.
	// dialEndpoints labels its own, per candidate, and that label wins.
	ctx = m.ensureDialSecret(ctx)

	m.mu.RLock()
	// Check if we have a recent successful strategy to try first (for fast reconnect)
	lastSuccessful := m.lastSuccessfulStrategy
	lastSuccessfulTime := m.lastSuccessfulTime
	androidMode := m.androidMode
	tcpFailuresThreshold := m.tcpFailuresBeforeQUIC
	m.mu.RUnlock()

	// Try last successful strategy first if it was recent (within 5 minutes).
	// Skip it in auto-mode if it is parked for a storm - that is precisely the
	// strategy we want to move away from. In forced mode there is no
	// alternative, so we still use it.
	if lastSuccessful != nil && time.Since(lastSuccessfulTime) < 5*time.Minute &&
		(m.forced || !m.stormDetector.IsParked(lastSuccessful.ID())) {

		// Loop guard: a strategy that connects but whose tunnel dies seconds later
		// can ride this fast path in a tight reconnect loop without ever being
		// parked. After too many fast reconnects in a short window, fall through
		// to the full scan (forced mode has no alternative, so never skips).
		m.mu.Lock()
		skipFast := !m.forced && m.shouldSkipFastReconnect(lastSuccessful.ID(), time.Now())
		m.mu.Unlock()

		if skipFast {
			log.Warn("Fast reconnect via %s exceeded %d attempts within %v - forcing full strategy scan",
				lastSuccessful.Name(), fastReconnectLimit, fastReconnectWindow)
		} else {
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
		// Skip strategies parked by the storm detector (auto-mode only).
		// Forced mode keeps its single strategy regardless.
		if !m.forced && m.stormDetector.IsParked(s.ID()) {
			log.Debug("Skipping strategy %s (storm cooldown)", s.Name())
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
		// If storm parking emptied the list, unpark everything and retry with
		// the full set: a storming strategy is still better than no tunnel.
		// This guarantees the failover loop converges instead of dead-ending.
		if !m.forced && m.stormDetector.AnyParked() {
			log.Warn("All strategies parked by storm cooldown - unparking to avoid total outage")
			m.stormDetector.Reset()
			return m.connectWithRTTScan(ctx, target, excludeIDs, useRTTMasking, scan)
		}
		return nil, nil, fmt.Errorf("no available strategies (all excluded or circuit-broken)")
	}

	modeStr := ""
	if useRTTMasking {
		modeStr = " [RTT masking]"
	}
	log.Info("Connecting to %s (trying %d strategies)%s", target, len(strategies), modeStr)

	var lastErr error
	attemptCount := 0
	addrSilent := false

	for i, s := range strategies {
		if !scan.answered && scan.timeouts >= tcpFailuresThreshold && !isUDPBasedStrategy(s) {
			// Nothing has come back from this address on any transport. Walking
			// the rest of the list means one connect timeout per strategy for a
			// verdict already in hand, and the endpoint layer is waiting for
			// that verdict to move the client to another server.
			log.Info("Address %s answered nothing on %d transports - abandoning the scan%s",
				target, scan.timeouts, modeStr)
			addrSilent = true

			// QUIC rides UDP, which the TCP verdict says nothing about. Android
			// jumps to it here rather than losing it with the rest of the list.
			if androidMode {
				log.Info("Fast QUIC fallback: %d TCP timeouts, skipping remaining TCP strategies", scan.timeouts)
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
			}
			break
		}

		m.mu.RLock()
		confidence := m.results[s.ID()].Confidence
		m.mu.RUnlock()

		log.Debug("Trying strategy %d/%d: %s (confidence=%.2f)%s",
			i+1, len(strategies), s.Name(), confidence, modeStr)

		// Tracks whether the strategy's final failing attempt was a timeout, so
		// the single circuit-breaker record on exhaustion reflects the right
		// outcome (timeouts are treated more aggressively by the breaker).
		strategyTimedOut := false
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

			// Distinguish between timeout and regular errors. The circuit
			// breaker is NOT recorded per retry here - it is recorded once when
			// the strategy is exhausted, so one logical failure counts once
			// regardless of maxRetries.
			timedOut := isTimeoutError(err)
			// Whether the address said anything is a question about the clock,
			// not about the wording of the error. On the device the same
			// ten-second wait came back as a timeout on one cycle and as
			// "use of closed network connection" on the next - the deadline
			// fired, something closed the socket, and the text stopped
			// containing the word the classifier looks for. A refusal or a
			// reset arrives in milliseconds; only silence costs the whole
			// budget.
			heardNothing := timedOut || latency >= silenceLatency(m.connectTimeout)

			if timedOut {
				log.Debug("  Failed: %s TIMEOUT (latency=%v)", s.Name(), latency)
			} else {
				log.Debug("  Failed: %v (latency=%v)", err, latency)
			}
			strategyTimedOut = timedOut

			if heardNothing {
				if !isUDPBasedStrategy(s) {
					scan.timeouts++
					log.Debug("TCP silence count: %d/%d", scan.timeouts, tcpFailuresThreshold)
				}
				// Track TCP timeouts for Android fast fallback
				if androidMode && !isUDPBasedStrategy(s) {
					m.mu.Lock()
					m.consecutiveTCPTimeouts++
					// Re-sort strategies with updated penalty
					m.sortStrategies()
					m.mu.Unlock()
				}
			} else {
				// A refusal, a reset, a handshake that got an answer it did not
				// like: the address is talking. Whatever is wrong here is a
				// property of this transport, which is precisely the case the
				// full scan exists for, so the address is no longer a candidate
				// for the silence verdict this cycle.
				scan.answered = true
			}

			// Brief pause before retry
			select {
			case <-ctx.Done():
				log.Warn("Connection cancelled by context")
				return nil, nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}

		// Strategy exhausted all retries - update confidence EMA and record
		// exactly one circuit-breaker failure for the whole strategy attempt.
		// The retry loop no longer writes to the breaker, so a single logical
		// strategy failure counts once (as timeout or failure) regardless of
		// maxRetries. Confidence EMA is still updated honestly on every attempt.
		m.mu.Lock()
		m.updateConfidenceStats(s.ID(), false, 0)
		if strategyTimedOut {
			m.circuitBreakers.RecordTimeout(s.ID())
		} else {
			m.circuitBreakers.RecordFailure(s.ID())
		}
		m.mu.Unlock()

		log.Debug("Strategy %s exhausted, moving to next", s.Name())
	}

	if addrSilent {
		// No emergency reprobe here: it exists to find a way back to an address
		// that went dark, and this scan's whole point is that the client should
		// stop asking this one and try another server.
		return nil, nil, fmt.Errorf("%w: %w, last error: %w", errAddrSilent, errStrategyScanFailed, lastErr)
	}

	log.Error("All %d strategies failed after %d attempts%s", len(strategies), attemptCount, modeStr)

	// Trigger emergency reprobe to recover from network outage
	go m.TriggerEmergencyReprobe(context.Background())

	return nil, nil, fmt.Errorf("%w, last error: %w", errStrategyScanFailed, lastErr)
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

	// Endpoints, when non-empty, replaces the single ServerAddr/ServerAddrV6
	// pair above. The legacy fields stay: they are what ControlConfig,
	// tun.VPNConfig, the pool, JNI, macOS and the benchmarks read, and they
	// still describe the first endpoint.
	Endpoints []endpoint.Endpoint

	// EndpointTuning is the [selection] section: which endpoint wins among the
	// healthy ones and how quickly a failing one is parked. Its zero value
	// keeps the historical behaviour - configured order, and the family policy
	// derived from PreferIPv6/FallbackToV4 above.
	EndpointTuning endpoint.Tuning

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

	// ICMP tunnel configuration (backup transport, requires CAP_NET_RAW)
	ICMPTunnelEnabled bool // Enable ICMP tunnel strategy (off by default)

	// Seqovl level-A packet overlap (Linux + CAP_NET_ADMIN, off by default)
	SeqovlPacketEnabled bool // Enable packet-level TCP sequence overlap on top of level-B decoy

	// REALITY configuration
	REALITYEnabled bool // Enable REALITY protocol (99.5% success rate)

	// REALITYServerPubKeyB64 is the server's static X25519 public key, base64.
	// Non-empty switches the REALITY client onto the B1 transport: a real TLS
	// 1.3 handshake with authentication in session_id.
	REALITYServerPubKeyB64 string

	// TLSFingerprint names the uTLS browser profile used for ClientHellos
	// (see internal/tls.FingerprintMap). Empty selects the default profile.
	// It is fixed for the process lifetime on purpose — rotating fingerprints
	// after a censor throttles a SNI escalates the penalty.
	TLSFingerprint string

	// REALITYRequireDataV2 refuses servers that do not confirm the v2 data
	// layer (per-connection X25519 keys + ChaCha20-Poly1305) instead of falling
	// back to v1. Off during the rollout, since clients are upgraded last.
	REALITYRequireDataV2 bool

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

	// Shaper, when non-nil, is injected into Traffic-Morph strategies and
	// drives sizing/inter-arrival in MorphedConn. nil keeps the legacy
	// NoopShaper behaviour (wire-format unchanged).
	Shaper shaper.Shaper

	// BurstReshape configures the nudge/ack exchange. It has to match the
	// server: see internal/strategy/burst_reshape.go.
	BurstReshape BurstReshapeConfig

	// ShaperID is the 1-byte value advertised to the server in the MRPH
	// handshake so it can rebuild the matching framing. 0 (noop) keeps the
	// legacy wire format. Ignored when Shaper is nil.
	ShaperID byte
}

// NewDefaultManager creates a manager with all strategies pre-registered
func NewDefaultManager(cfg DefaultManagerConfig) *Manager {
	m := NewManager()

	// Set before registering: strategies copy this at construction.
	m.SetBurstReshape(cfg.BurstReshape)

	// Set before the selector exists: it is the fallback every endpoint without
	// a secret of its own resolves to, and CurrentSecret must never return nil
	// once a dial can start.
	m.setDefaultSecret(cfg.Secret)

	initManagerTransport(m, cfg)
	initManagerPortHopping(m, cfg)
	initManagerAndroidMode(m, cfg)
	initManagerMux(m, cfg)
	initManagerRTTMasking(m, cfg)
	registerAllStrategies(m, cfg)

	return m
}

// initManagerTransport builds the endpoint selector.
//
// With no explicit Endpoints list it synthesises the single dual-addressed
// server the legacy flags describe, so a unit started with nothing but -server
// keeps working and keeps dialling exactly the same address.
func initManagerTransport(m *Manager, cfg DefaultManagerConfig) {
	eps := cfg.Endpoints
	if len(eps) == 0 {
		if cfg.ServerAddr == "" && cfg.ServerAddrV6 == "" {
			return
		}
		eps = []endpoint.Endpoint{{Name: "server", V4: cfg.ServerAddr, V6: cfg.ServerAddrV6}}
	}

	legacy := endpoint.FamilyPolicyFromLegacy(cfg.PreferIPv6, cfg.FallbackToV4)
	sel, err := endpoint.NewTunedSelector(eps, cfg.EndpointTuning, legacy)
	if err != nil {
		log.Warn("Endpoint selector not configured: %v", err)
		return
	}
	m.endpoints = sel

	if len(eps) > 1 {
		log.Info("Endpoint pool: %d servers, selection=%s, family=%s",
			len(eps), cfg.EndpointTuning.Selection, cfg.EndpointTuning.FamilyOr(legacy))
	}
	if cfg.ServerAddrV6 != "" && cfg.PreferIPv6 {
		log.Info("IPv6 transport enabled (IPv6=%s, IPv4=%s, fallback=%v)",
			cfg.ServerAddrV6, cfg.ServerAddr, cfg.FallbackToV4)
	}
}

// SetEndpoints replaces the endpoint list and the family policy.
//
// Health is discarded only when the new list is genuinely different: selectors
// are process-scoped per configuration, so re-applying the same endpoints hands
// back the same instance rather than forgetting everything it measured. Use
// ResetHealth to discard verdicts deliberately - that is what a network change
// does.
func (m *Manager) SetEndpoints(eps []endpoint.Endpoint, policy endpoint.FamilyPolicy) error {
	return m.SetEndpointsTuned(eps, endpoint.Tuning{Family: &policy})
}

// SetEndpointsTuned is SetEndpoints with the whole [selection] section rather
// than the family policy alone, and with the same health semantics.
func (m *Manager) SetEndpointsTuned(eps []endpoint.Endpoint, tuning endpoint.Tuning) error {
	sel, err := endpoint.NewTunedSelector(eps, tuning, endpoint.PreferV6)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.endpoints = sel
	m.mu.Unlock()
	return nil
}

// selector returns the endpoint selector, or nil when the manager was built
// without one (NewManager, benchmarks, strategy unit tests).
func (m *Manager) selector() *endpoint.Selector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.endpoints
}

// initManagerPortHopping configures the port hopper if enabled.
func initManagerPortHopping(m *Manager, cfg DefaultManagerConfig) {
	if cfg.PortHopping == nil || !cfg.PortHopping.Enabled {
		return
	}
	hopper, err := porthopping.NewPortHopper(cfg.PortHopping)
	if err != nil {
		log.Warn("Port hopping disabled: %v", err)
		return
	}
	m.portHopper = hopper
	hopper.OnHop(func(oldPort, newPort int) {
		log.Info("Port hop: %d -> %d, triggering reconnect", oldPort, newPort)
		m.triggerReconnect()
	})
	log.Info("Port hopping enabled (range=%d-%d, interval=%v, strategy=%s)",
		cfg.PortHopping.PortRangeStart, cfg.PortHopping.PortRangeEnd,
		cfg.PortHopping.HopInterval, cfg.PortHopping.Strategy)
}

// initManagerAndroidMode applies Android-specific timeout and retry optimizations.
func initManagerAndroidMode(m *Manager, cfg DefaultManagerConfig) {
	if !cfg.AndroidMode {
		return
	}
	m.probeTimeout = 3 * time.Second
	m.connectTimeout = 10 * time.Second
	m.maxRetries = 1
	m.androidMode = true
	m.tcpFailuresBeforeQUIC = androidSilentScanAbort
	log.Info("Android mode: using optimized timeouts (probe=%v, connect=%v, retries=%d, TCP-first)",
		m.probeTimeout, m.connectTimeout, m.maxRetries)
}

// initManagerMux enables mux multiplexing if configured.
func initManagerMux(m *Manager, cfg DefaultManagerConfig) {
	if !cfg.MuxEnabled {
		return
	}
	muxConfig := cfg.MuxConfig
	if muxConfig == nil {
		if cfg.AndroidMode {
			muxConfig = mux.MobileConfig()
		} else {
			muxConfig = mux.DefaultConfig()
		}
	}
	m.EnableMux(muxConfig)
}

// initManagerRTTMasking enables RTT masking if configured.
func initManagerRTTMasking(m *Manager, cfg DefaultManagerConfig) {
	if !cfg.RTTMaskingEnabled {
		return
	}
	profile := cfg.RTTProfile
	if profile == nil {
		profile = MoscowToYandexProfile
	}
	m.EnableRTTMasking(profile)
}

// registerAllStrategies registers all transport strategies onto the manager.
func registerAllStrategies(m *Manager, cfg DefaultManagerConfig) {
	// A config that only fills Endpoints has a server just as much as one that
	// fills ServerAddr. Checking ServerAddr alone would register nothing at all
	// for a pure server-list client - every strategy gated out, and the failure
	// mode is "no strategies available" rather than anything that points at the
	// config.
	hasServer := cfg.ServerAddr != "" || cfg.ServerAddrV6 != "" || len(cfg.Endpoints) > 0
	hasSecret := len(cfg.Secret) > 0

	warnEndpointPinnedFlags(cfg)

	registerQUICStrategies(m, cfg, hasServer, hasSecret)
	registerTLSStrategies(m, cfg, hasServer, hasSecret)
	registerMorphStrategies(m, cfg, hasSecret)
	registerMeshAndAntiProbe(m, cfg, hasServer, hasSecret)
	registerConfusionAndExhaustion(m)
	registerSSHCamouflage(m, cfg, hasServer, hasSecret)
	registerIMAPCamouflage(m, cfg, hasServer, hasSecret)
	registerGenevaStrategies(m, cfg, hasServer, hasSecret)
	registerSeqovlStrategy(m, cfg, hasServer, hasSecret)
	registerICMPStrategy(m, cfg, hasServer, hasSecret)
}

// derivedSalamanderPort picks the Salamander port when the flag left it unset:
// the port of ServerAddr, then of the first endpoint, then 443.
//
// The endpoint fallback matters for a client configured only through
// [[servers]], where ServerAddr is empty and the old derivation silently landed
// on 443 - a port the exit is not listening on.
func derivedSalamanderPort(cfg DefaultManagerConfig) int {
	addrs := []string{cfg.ServerAddr}
	if len(cfg.Endpoints) > 0 {
		addrs = append(addrs, cfg.Endpoints[0].V4, cfg.Endpoints[0].V6)
	}
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			return p
		}
	}
	return 443
}

// warnEndpointPinnedFlags reports the settings that a server list silently
// makes wrong, rather than letting them fail as an unexplained dead transport.
//
// The QUIC Salamander port, when not given explicitly, is derived from the
// FIRST endpoint's port and then applied to whatever host the selector picks.
// With a list whose members listen on different ports that is simply the wrong
// port on every endpoint but one. Making it per-endpoint needs a per-endpoint
// port in the config, which the [[servers]] section does not carry today.
func warnEndpointPinnedFlags(cfg DefaultManagerConfig) {
	if len(cfg.Endpoints) < 2 {
		return
	}
	if !cfg.QUICEnabled || cfg.QUICSNIFragEnabled || cfg.QUICSalamanderPort != 0 {
		return
	}
	ports := make(map[string]bool, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		for _, addr := range []string{ep.V4, ep.V6} {
			if addr == "" {
				continue
			}
			if _, port, err := net.SplitHostPort(addr); err == nil {
				ports[port] = true
			}
		}
	}
	if len(ports) > 1 {
		log.Warn("QUIC Salamander port is derived from the first endpoint but the pool uses %d different ports; "+
			"set quic_salamander_port explicitly or Salamander will dial the wrong port on the others", len(ports))
	}
}

// registerSeqovlStrategy registers the seqovl (TCP sequence overlap, level B
// app-framing) strategy. It rides the REALITY handshake with a secret-marked
// decoy prefix, so it needs both a server and a shared secret. Cross-platform,
// including Android.
func registerSeqovlStrategy(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	seqovl := NewSeqovlStrategy(m, cfg.Secret, cfg.SeqovlPacketEnabled)
	seqovl.SetFingerprint(cfg.TLSFingerprint)
	seqovl.SetRequireDataV2(cfg.REALITYRequireDataV2)
	m.Register(seqovl)
}

// registerICMPStrategy registers the ICMP tunnel backup strategy.
// Off by default: opening a raw ICMP socket needs CAP_NET_RAW, so it is only
// wired in when the client explicitly opts in via -icmp-tunnel.
func registerICMPStrategy(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !cfg.ICMPTunnelEnabled || !hasServer || !hasSecret {
		return
	}
	m.Register(NewICMPTunnelStrategy(cfg.ServerAddr, cfg.Secret))
}

// registerSSHCamouflage registers the SSH camouflage strategy.
func registerSSHCamouflage(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	m.Register(NewSSHCamouflageStrategy(m, cfg.Secret))
}

// registerIMAPCamouflage registers the IMAP camouflage strategy.
func registerIMAPCamouflage(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	m.Register(NewIMAPCamouflageStrategy(m, cfg.Secret))
}

// registerQUICStrategies registers QUIC and QUIC-Salamander strategies.
func registerQUICStrategies(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	// Both plain QUIC and QUIC Salamander are QUIC transports, so both must be
	// gated behind QUICEnabled. Registering Salamander unconditionally leaked it
	// into the benchmark/probe list even when -quic was not passed (issue #54).
	if !cfg.QUICEnabled {
		return
	}

	port := cfg.QUICPort
	if port == 0 {
		port = 443
	}
	quicStrat := NewQUICStrategy(m, cfg.Secret, port)
	if cfg.QUICSNIFragEnabled {
		quicStrat.SetSNIFragmentation(true, nil)
	}
	m.Register(quicStrat)

	// SNI fragmentation replaces Salamander with the fragmenting plain-QUIC
	// variant above; only register Salamander when SNI frag is off.
	if !cfg.QUICSNIFragEnabled {
		salPort := cfg.QUICSalamanderPort
		if salPort == 0 {
			salPort = derivedSalamanderPort(cfg)
		}
		m.Register(NewQUICSalamanderStrategy(m, cfg.Secret, salPort))
	}
}

// registerTLSStrategies registers REALITY, WebSocket, HTTP Polling and HTTP/2 Stego.
func registerTLSStrategies(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}

	reality := NewREALITYStrategy(m, cfg.Secret)
	reality.SetFingerprint(cfg.TLSFingerprint)
	if cfg.REALITYServerPubKeyB64 != "" {
		key, err := customtls.DecodeKeyBase64(cfg.REALITYServerPubKeyB64)
		if err != nil {
			log.Warn("REALITY: B1 server key is not valid base64: %v; B1 stays off", err)
		} else {
			reality.SetB1(key)
		}
	}
	reality.SetRequireDataV2(cfg.REALITYRequireDataV2)
	if cfg.PQEnabled && cfg.PQServerKemPubB64 != "" {
		kemPub, err := base64.StdEncoding.DecodeString(cfg.PQServerKemPubB64)
		if err == nil && len(kemPub) > 0 {
			if err := reality.SetPostQuantum(kemPub); err != nil {
				log.Warn("REALITY: PQ init failed, using classical: %v", err)
			}
		}
	}
	m.Register(reality)

	m.Register(NewWebSocketPaddedStrategy(m, cfg.Secret))
	m.Register(NewHTTPPollingStrategy(m, cfg.Secret))

	stego := NewHTTP2StegoStrategy(m, cfg.Secret, cfg.CoverHost)
	if cfg.ECHEnabled && len(cfg.ECHConfigList) > 0 {
		stego.SetECH(cfg.ECHConfigList, cfg.ECHPublicName)
	}
	m.Register(stego)
}

// registerMorphStrategies registers Traffic Morphing strategies for multiple profiles.
func registerMorphStrategies(m *Manager, cfg DefaultManagerConfig, hasSecret bool) {
	if !hasSecret {
		return
	}
	for _, profile := range []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		BaiduVideoProfile,
		AparatVideoProfile,
	} {
		strat := NewTrafficMorphStrategy(m, profile, nil, cfg.Secret)
		if cfg.Shaper != nil {
			strat.SetShaperWithID(cfg.Shaper, cfg.ShaperID)
		}
		m.Register(strat)
	}
}

// registerMeshAndAntiProbe registers Mesh Relay and Anti-Probe strategies.
func registerMeshAndAntiProbe(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if hasServer && len(cfg.RelayNodes) > 0 {
		mesh := NewMeshRelayStrategy(cfg.ServerAddr)
		mesh.AddRelays(cfg.RelayNodes)
		m.Register(mesh)
	}
	if hasServer && hasSecret {
		antiprobe := NewAntiProbeStrategy(m, cfg.Secret)
		if cfg.ECHEnabled && len(cfg.ECHConfigList) > 0 {
			antiprobe.SetECH(cfg.ECHConfigList, cfg.ECHPublicName)
		}
		m.Register(antiprobe)
	}
}

// registerConfusionAndExhaustion registers Protocol Confusion and State Exhaustion.
func registerConfusionAndExhaustion(m *Manager) {
	for _, confStrat := range AllConfusionTypes(m) {
		m.Register(confStrat)
	}
	m.Register(NewStateExhaustionStrategy(m))
}

// registerGenevaStrategies registers Geneva strategies for Russia, China, and Iran.
func registerGenevaStrategies(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	m.Register(NewGenevaStrategy(m, cfg.Secret, "russia"))
	m.Register(NewGenevaStrategy(m, cfg.Secret, "china"))
	m.Register(NewGenevaStrategy(m, cfg.Secret, "iran"))
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

// StartPeriodicReprobe starts background re-probing of strategies.
//
// It takes no target: each cycle asks for the pinned candidate, so a reprobe
// started before a family fallback still measures the path the tunnel actually
// uses afterwards.
func (m *Manager) StartPeriodicReprobe(ctx context.Context) {
	m.mu.Lock()
	if m.reprobeRunning {
		m.mu.Unlock()
		log.Debug("Periodic reprobe already running")
		return
	}
	m.reprobeRunning = true
	m.stopReprobe = make(chan struct{})
	m.mu.Unlock()

	log.Info("Starting periodic reprobe (interval=%v, target=%s)", m.reprobeInterval, m.GetServerAddr(ctx))

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
	target := m.GetServerAddr(ctx)
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
		log.Info("Mux enabled (keepalive=%v)", config.KeepAliveInterval)
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

// tryMuxFastPath opens a stream on the existing mux session, if mux is enabled
// and the session is alive, without dialing a new transport. It returns the
// stream, the last successful strategy (for logging/metrics parity with the full
// path) and true on success. On a dead session it tears the session down and
// returns false so the caller falls through to a full dial. When mux is disabled
// or no session exists it returns false.
func (m *Manager) tryMuxFastPath() (net.Conn, Strategy, bool) {
	m.muxMu.Lock()
	if !m.muxEnabled || m.muxClient == nil || m.muxClient.IsClosed() {
		m.muxMu.Unlock()
		return nil, nil, false
	}

	// Trigger budget recycling if the carrier exceeded its byte limit; new
	// streams keep flowing on the current carrier until the swap completes.
	if m.muxClient.BudgetExceeded() && !m.recyclingInProgress {
		m.recyclingInProgress = true
		go m.performBudgetRecycling()
	}

	stream, err := m.muxClient.OpenStream()
	if err != nil {
		// Session is dead - tear it down and let the caller do a full dial.
		log.Debug("Mux fast-path: existing session failed, recreating: %v", err)
		m.muxClient.Close()
		m.muxClient = nil
		if m.muxConn != nil {
			m.muxConn.Close()
			m.muxConn = nil
		}
		m.muxMu.Unlock()
		return nil, nil, false
	}
	active := m.muxClient.NumStreams()
	m.muxMu.Unlock()

	m.mu.RLock()
	strat := m.lastSuccessfulStrategy
	m.mu.RUnlock()

	log.Debug("Mux fast-path: stream on existing session, no new dial (active=%d)", active)
	return stream, strat, true
}

// wrapWithMux wraps a connection with mux layer and opens a stream
// If an existing mux session is available and not closed, reuse it
func (m *Manager) wrapWithMux(conn net.Conn, config *mux.Config) (net.Conn, error) {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	// Reuse existing mux session if available and not closed
	if m.muxClient != nil && !m.muxClient.IsClosed() {
		// Trigger budget recycling if carrier exceeded its byte limit.
		// New streams continue on current carrier until the swap completes.
		if m.muxClient.BudgetExceeded() && !m.recyclingInProgress {
			m.recyclingInProgress = true
			go m.performBudgetRecycling()
		}
		stream, err := m.muxClient.OpenStream()
		if err == nil {
			// The passed-in conn is a freshly dialed transport that this reuse
			// branch does not adopt (m.muxConn stays on the live carrier). Close
			// it, otherwise it is orphaned: never written to, it hangs pre-auth on
			// the server and piles up until OOM. Belt-and-suspenders behind the
			// Connect() fast-path, which normally avoids the dial entirely.
			if conn != nil && conn != m.muxConn {
				conn.Close()
			}
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

	log.Debug("Mux client created and stream opened")
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

	// Increase socket buffers to cover the BDP on high-RTT links. 64KB was far
	// below the bandwidth-delay product at 150-300ms RTT and throttled the TCP
	// window. Applies to both client and relay sockets; relay sockets only
	// benefit from the larger buffer (the server side already uses 4MB).
	if err := tcpConn.SetReadBuffer(clientSocketBufferBytes); err != nil {
		log.Debug("Failed to set read buffer: %v", err)
	}
	if err := tcpConn.SetWriteBuffer(clientSocketBufferBytes); err != nil {
		log.Debug("Failed to set write buffer: %v", err)
	}

	log.Debug("TCP connection optimized: NoDelay=true, buffers=%dKB", clientSocketBufferBytes/1024)
}

// TriggerEmergencyReprobe starts aggressive re-probing when all strategies fail
// This helps recover from network outages by periodically retrying with short intervals
func (m *Manager) TriggerEmergencyReprobe(ctx context.Context) {
	// Read the pinned candidate BEFORE taking m.mu: GetServerAddr takes the
	// same lock to reach the selector.
	target := m.GetServerAddr(ctx)

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

				// Give strategies a fresh chance without wiping accumulated
				// failure history: only circuits already Open are nudged into
				// half-open so the next dial gets a graduated-recovery test.
				// A blind Reset() here would erase the failure window exactly
				// when it matters most (and is unnecessary - ProbeAll below
				// probes every strategy regardless of circuit state).
				m.mu.Lock()
				nudged := 0
				for _, s := range m.strategies {
					if m.circuitBreakers.Get(s.ID()).AllowRecoveryProbe() {
						nudged++
					}
				}
				m.mu.Unlock()
				log.Debug("Emergency reprobe: nudged %d open circuit(s) into half-open", nudged)

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
	// Endpoint health describes the OLD network: which family was up, which
	// server was reachable, which one is parked. None of that survives a
	// handover, and until now none of it was cleared either - the family
	// verdict outlived every network change on desktop.
	m.ResetHealth()

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

	// Storm state is tied to the old network - clear it after a network change.
	m.stormDetector.Reset()

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
	// A network change can flip which family works, so drop the cached verdict
	// and re-probe. Deliberately NO outer loop over candidates here: this path
	// already retries the last strategy five times and then walks the whole
	// list, and a second level of retries turns a WiFi/LTE handover into a
	// minute-long stall.
	if sel := m.selector(); sel != nil {
		sel.ResetHealth()
		if cand, _ := sel.ProbeCurrent(ctx); cand.Addr != "" {
			target = cand.Addr
			log.Debug("Reconnect: using effective server address: %s", target)
		}
	}
	// This path calls Connect on the strategies itself rather than going through
	// connectWithRTT, so it has to name the key for the address it just resolved.
	ctx = m.ensureDialSecret(ctx)

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
	// This is optimized for Android network handoff where the network needs time to stabilize.
	// Skip Phase 1 in auto-mode if the strategy is parked for a storm: retrying it 5x is exactly
	// the relay-mode reconnect-storm we are trying to break. Forced mode has no alternative.
	if lastStrategy != nil && (m.IsForced() || !m.stormDetector.IsParked(lastStrategy.ID())) {
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
	target := m.GetServerAddr(ctx)
	m.mu.Lock()
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

	// Try to connect using the last successful strategy. Same endpoint, only a
	// different port, so the pinned endpoint's key is the right one.
	conn, err := lastStrategy.Connect(m.ensureDialSecret(ctx), newTarget)
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

// performBudgetRecycling replaces the current mux carrier once its byte budget
// is exhausted. Runs in a goroutine; clears recyclingInProgress when done.
//
// Make-before-break: new carrier is fully established before old one is touched.
// Old carrier drains gracefully (up to 10 s) so in-flight streams finish cleanly.
func (m *Manager) performBudgetRecycling() {
	defer func() {
		m.muxMu.Lock()
		m.recyclingInProgress = false
		m.muxMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := m.GetServerAddr(ctx)
	m.mu.Lock()
	lastStrategy := m.lastSuccessfulStrategy
	m.mu.Unlock()

	if target == "" || lastStrategy == nil {
		log.Debug("Budget recycling: no target/strategy, skipping")
		return
	}

	log.Debug("Budget recycling: pre-warming new carrier to %s", target)

	// The replacement carrier goes to the same endpoint the old one did, so it
	// authenticates with that endpoint's key.
	conn, err := lastStrategy.Connect(m.ensureDialSecret(ctx), target)
	if err != nil {
		log.Warn("Budget recycling: new connection failed (%v), keeping current carrier", err)
		return
	}

	m.muxMu.Lock()
	config := m.muxConfig
	if config == nil {
		config = mux.DefaultConfig()
	}
	newClient, err := mux.NewClient(conn, config)
	if err != nil {
		m.muxMu.Unlock()
		conn.Close()
		log.Warn("Budget recycling: mux client creation failed (%v)", err)
		return
	}
	// Verify new carrier with a probe stream
	probe, err := newClient.OpenStream()
	if err != nil {
		m.muxMu.Unlock()
		newClient.Close()
		conn.Close()
		log.Warn("Budget recycling: probe stream failed (%v)", err)
		return
	}
	probe.Close()

	// Atomic swap: from this point new streams go to newClient
	oldClient := m.muxClient
	oldConn := m.muxConn
	m.muxClient = newClient
	m.muxConn = conn
	m.muxMu.Unlock()

	log.Info("Budget recycling: carrier swapped, draining old session")

	// Graceful drain: wait for in-flight streams to finish (10 s max)
	drainDeadline := time.Now().Add(10 * time.Second)
	for oldClient != nil && oldClient.NumStreams() > 0 && time.Now().Before(drainDeadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if oldClient != nil {
		oldClient.Close()
	}
	if oldConn != nil {
		oldConn.Close()
	}
	log.Debug("Budget recycling: old carrier closed")
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

// TLSSessionCache returns the shared client session cache used by stdlib-TLS
// strategies for resumption across reconnects. Safe for concurrent use; the
// returned value is fixed at construction and never replaced.
func (m *Manager) TLSSessionCache() tls.ClientSessionCache {
	return m.tlsSessionCache
}

// GetServerAddr returns the address of the currently pinned endpoint candidate.
//
// It is a pure read and never touches the network. It used to hold a mutex
// across a 3-second DialContext while roughly fifteen call sites - including
// every strategy in a scan - went through it. The probe now lives in one
// explicit step per connect cycle (see dialEndpoints); this returns whatever
// that step decided, so a whole scan sees one and the same address.
//
// The ctx parameter is retained for the fifteen existing call sites.
func (m *Manager) GetServerAddr(_ context.Context) string {
	sel := m.selector()
	if sel == nil {
		return ""
	}
	c, ok := sel.Current()
	if !ok {
		return ""
	}
	return c.Addr
}

// ProbeEndpointFamily runs the one-shot transport-family probe for the pinned
// candidate and returns the address that came out of it.
//
// This is the explicit step that replaced the dial GetServerAddr used to hide.
// Connect calls it once per cycle; it is exported so the wiring around the
// manager can drive it too.
func (m *Manager) ProbeEndpointFamily(ctx context.Context) string {
	sel := m.selector()
	if sel == nil {
		return ""
	}
	c, _ := sel.ProbeCurrent(ctx)
	return c.Addr
}

// EndpointStates returns the current endpoint candidates and their health, for
// logging and diagnostics.
func (m *Manager) EndpointStates() []endpoint.CandidateState {
	sel := m.selector()
	if sel == nil {
		return nil
	}
	return sel.Snapshot()
}

// ResetHealth discards every cached endpoint verdict and re-pins the most
// preferred candidate. Call it when the network underneath changed and old
// observations describe a network that no longer exists.
func (m *Manager) ResetHealth() {
	sel := m.selector()
	if sel == nil {
		return
	}
	sel.ResetHealth()
	log.Debug("Endpoint health reset, family will be re-probed on next connection")
}

// ResetIPv6Check forces a re-check of the transport family on the next connect.
//
// Deprecated: use ResetHealth. Kept because the Android control-socket path
// calls it by this name.
func (m *Manager) ResetIPv6Check() {
	m.ResetHealth()
}

// SetBurstReshape configures burst reshaping for strategies created afterwards.
// Call it before building strategies: the setting is copied at construction.
func (m *Manager) SetBurstReshape(cfg BurstReshapeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.burstReshape = cfg
}

// BurstReshape returns the configured reshaping settings.
func (m *Manager) BurstReshape() BurstReshapeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.burstReshape
}
