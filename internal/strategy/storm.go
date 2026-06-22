package strategy

import (
	"sync"
	"time"
)

// Storm detection defaults.
//
// The problem these constants address: a strategy whose Connect() always
// succeeds but whose session is torn down by DPI after a few seconds. The
// circuit breaker never trips (every connect succeeds), confidence stays high,
// and the client reconnects forever on a strategy that cannot carry traffic.
//
// A "short" session is one that dies before stormShortSession. When
// stormMinSessions such sessions happen in a row (and within stormWindow of
// each other), the strategy is declared "storming" and parked for
// stormCooldown so the manager can try something else.
const (
	// stormShortSession is the lifetime below which a session counts as
	// "short-lived". Real DPI teardown of REALITY was observed at ~6s; a
	// healthy tunnel lives minutes. 20s leaves comfortable margin above the
	// 10s keepalive / handshake settle time without masking the storm.
	stormShortSession = 20 * time.Second

	// stormMinSessions is how many consecutive short sessions trigger a storm.
	// 3 mirrors the circuit-breaker FailureThreshold philosophy: a couple of
	// flukes are tolerated, a sustained pattern is not.
	stormMinSessions = 3

	// stormWindow bounds how far apart the short sessions may be and still
	// count toward the same storm. If the gap between consecutive short
	// sessions exceeds this, the streak resets (the strategy was probably
	// fine and just hit one bad moment).
	stormWindow = 3 * time.Minute

	// stormCooldown is how long a storming strategy is excluded from auto
	// selection before it becomes eligible again (DPI patterns are often
	// temporary). Aligned with the manager reprobe interval (5m).
	stormCooldown = 5 * time.Minute

	// stormGrace is a settling window after the detector starts (and after every
	// network change / Reset) during which short sessions are NOT counted toward
	// a storm. Client startup and network changes legitimately churn through a
	// few short-lived sessions (handshakes, route setup, transport warm-up, the
	// occasional racey reconnect) before the tunnel stabilizes; parking a
	// strategy on that transient turbulence is exactly the false positive that
	// dumped traffic onto worse fallback strategies. A real storm persists well
	// past this window.
	stormGrace = 30 * time.Second
)

// StormConfig holds tunable storm-detection thresholds. Zero values fall back
// to the package defaults so callers can override only what they need.
type StormConfig struct {
	ShortSession time.Duration // session lifetime below which it counts as short
	MinSessions  int           // consecutive short sessions to declare a storm
	Window       time.Duration // max gap between short sessions in one streak
	Cooldown     time.Duration // how long a storming strategy stays parked
	// Grace is the post-start/post-Reset settling window in which short sessions
	// are ignored. Zero falls back to the default; a negative value disables the
	// grace window entirely (used by unit tests that exercise parking directly).
	Grace time.Duration
}

func (c StormConfig) withDefaults() StormConfig {
	if c.ShortSession <= 0 {
		c.ShortSession = stormShortSession
	}
	if c.MinSessions <= 0 {
		c.MinSessions = stormMinSessions
	}
	if c.Window <= 0 {
		c.Window = stormWindow
	}
	if c.Cooldown <= 0 {
		c.Cooldown = stormCooldown
	}
	switch {
	case c.Grace < 0:
		c.Grace = 0 // explicitly disabled
	case c.Grace == 0:
		c.Grace = stormGrace
	}
	return c
}

// strategyStorm tracks the short-session streak and cooldown for one strategy.
type strategyStorm struct {
	consecutiveShort int
	lastShortEnd     time.Time // when the most recent short session ended
	parkedUntil      time.Time // strategy excluded from selection until this time
}

// StormDetector tracks per-strategy session lifetimes and decides when a
// strategy is "storming" (repeatedly connecting but failing to hold a session).
// It is a pure data structure: it does not touch the network, the clock is
// injectable for tests, and all decisions are derived from RecordSession calls.
//
// It is safe for concurrent use.
type StormDetector struct {
	cfg StormConfig
	now func() time.Time

	mu        sync.Mutex
	byID      map[string]*strategyStorm
	openedAt  map[string]time.Time // strategyID -> when its current session began
	startedAt time.Time            // start of the current grace window (start / last Reset)
}

// NewStormDetector creates a detector with the given config (defaults applied).
func NewStormDetector(cfg StormConfig) *StormDetector {
	return &StormDetector{
		cfg:       cfg.withDefaults(),
		now:       time.Now,
		byID:      make(map[string]*strategyStorm),
		openedAt:  make(map[string]time.Time),
		startedAt: time.Now(),
	}
}

// SessionOpened records that a session for strategyID has just been established.
// Used together with SessionClosed when the caller does not measure the
// lifetime itself.
func (d *StormDetector) SessionOpened(strategyID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.openedAt[strategyID] = d.now()
}

// SessionClosed records that the session opened via SessionOpened has ended.
// It returns the same verdict as RecordSession. If no matching SessionOpened
// was seen, it is a no-op and reports storming=false.
func (d *StormDetector) SessionClosed(strategyID string) (storming bool) {
	d.mu.Lock()
	opened, ok := d.openedAt[strategyID]
	if ok {
		delete(d.openedAt, strategyID)
	}
	d.mu.Unlock()

	if !ok {
		return false
	}
	return d.RecordSession(strategyID, d.now().Sub(opened))
}

// RecordSession records a completed session of the given lifetime for
// strategyID and returns whether the strategy should now be treated as
// storming. When it returns true, the strategy is parked for the cooldown
// period (see IsParked).
//
// Streak logic:
//   - lifetime >= ShortSession: a healthy session, streak resets to 0.
//   - lifetime <  ShortSession: increments the streak, unless the gap since
//     the previous short session exceeded Window, in which case the streak
//     restarts at 1.
//   - streak >= MinSessions: storm declared, strategy parked, streak reset so
//     the next cooldown window starts fresh.
func (d *StormDetector) RecordSession(strategyID string, lifetime time.Duration) (storming bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	st := d.byID[strategyID]
	if st == nil {
		st = &strategyStorm{}
		d.byID[strategyID] = st
	}

	now := d.now()

	if lifetime >= d.cfg.ShortSession {
		// Healthy session - clear the streak.
		st.consecutiveShort = 0
		st.lastShortEnd = time.Time{}
		return false
	}

	// Within the grace window after start / network change, short sessions are
	// expected churn (handshakes, route setup, transport warm-up). Don't count
	// them and never park: a real storm persists past the window and gets caught
	// then. This is what stops startup turbulence from dumping traffic onto worse
	// fallback strategies.
	if d.cfg.Grace > 0 && now.Sub(d.startedAt) < d.cfg.Grace {
		return false
	}

	// Short session. Reset streak if the previous short session is too old.
	if !st.lastShortEnd.IsZero() && now.Sub(st.lastShortEnd) > d.cfg.Window {
		st.consecutiveShort = 0
	}
	st.consecutiveShort++
	st.lastShortEnd = now

	if st.consecutiveShort >= d.cfg.MinSessions {
		st.parkedUntil = now.Add(d.cfg.Cooldown)
		// Reset the streak so a fresh window is required after cooldown.
		st.consecutiveShort = 0
		st.lastShortEnd = time.Time{}
		return true
	}

	return false
}

// IsParked reports whether strategyID is currently excluded from selection due
// to a recent storm. Parking expires automatically after the cooldown.
func (d *StormDetector) IsParked(strategyID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.byID[strategyID]
	if st == nil {
		return false
	}
	return d.now().Before(st.parkedUntil)
}

// ParkedUntil returns the time strategyID is parked until (zero if not parked).
func (d *StormDetector) ParkedUntil(strategyID string) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.byID[strategyID]
	if st == nil {
		return time.Time{}
	}
	return st.parkedUntil
}

// AnyParked reports whether at least one strategy is currently parked. Used to
// decide whether the "all strategies parked" fallback applies.
func (d *StormDetector) AnyParked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	for _, st := range d.byID {
		if now.Before(st.parkedUntil) {
			return true
		}
	}
	return false
}

// Unpark clears any parking and streak state for strategyID. Used on network
// change, when old state is meaningless.
func (d *StormDetector) Unpark(strategyID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st := d.byID[strategyID]; st != nil {
		st.parkedUntil = time.Time{}
		st.consecutiveShort = 0
		st.lastShortEnd = time.Time{}
	}
}

// Reset clears all storm and parking state. Used on network change, which also
// restarts the grace window: a fresh network legitimately churns through a few
// short sessions before stabilizing.
func (d *StormDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.byID)
	clear(d.openedAt)
	d.startedAt = d.now()
}
