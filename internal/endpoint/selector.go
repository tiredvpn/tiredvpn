package endpoint

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// ErrNoCandidates is returned by NewSelector when the configuration yields no
// dialable address at all (no endpoints, or none with an address on an allowed
// family).
var ErrNoCandidates = errors.New("endpoint: no dialable candidates")

// Policy defaults. They are deliberately conservative: the cost of an
// unnecessary switch (a fresh handshake against a second IP, visible to an
// observer) is higher than the cost of one more failed cycle on the current
// one.
const (
	defaultFailureThreshold = 2
	defaultCooldown         = 1 * time.Minute
	defaultMaxCooldown      = 30 * time.Minute
	defaultMinDwell         = 5 * time.Minute
	defaultJitterFrac       = 0.2
	defaultProbeTimeout     = 3 * time.Second

	// latencyAlpha is the EWMA weight for a fresh latency sample.
	latencyAlpha = 0.3
)

// DialFunc is the dialer the selector uses for its family probe. Injected so
// tests drive the probe against loopback listeners instead of the network.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config configures a Selector. Every zero-valued field gets a default, so
// Config{Endpoints: eps} is valid.
type Config struct {
	Endpoints []Endpoint
	Family    FamilyPolicy

	// FailureThreshold is how many failed connect CYCLES put a candidate in
	// cooldown. Counting individual strategy failures instead would trip on the
	// first blocked transport of a scan that goes on to succeed.
	FailureThreshold int

	// Cooldown is the first cooldown; it doubles per repeat up to MaxCooldown.
	Cooldown    time.Duration
	MaxCooldown time.Duration

	// MinDwell is how long a fallback candidate is kept before the selector is
	// allowed to promote back to a more preferred one.
	MinDwell time.Duration

	// JitterFrac spreads cooldown expiry by +/- this fraction. Without it every
	// client that lost the same endpoint at the same moment comes back at the
	// same moment.
	JitterFrac float64

	ProbeTimeout time.Duration

	Dial DialFunc
	Now  func() time.Time
	Rand func() float64
}

func (c *Config) applyDefaults() {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = defaultFailureThreshold
	}
	if c.Cooldown <= 0 {
		c.Cooldown = defaultCooldown
	}
	if c.MaxCooldown <= 0 {
		c.MaxCooldown = defaultMaxCooldown
	}
	if c.MaxCooldown < c.Cooldown {
		c.MaxCooldown = c.Cooldown
	}
	if c.MinDwell <= 0 {
		c.MinDwell = defaultMinDwell
	}
	if c.JitterFrac <= 0 {
		c.JitterFrac = defaultJitterFrac
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = defaultProbeTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	if c.Dial == nil {
		timeout := c.ProbeTimeout
		c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, addr)
		}
	}
}

// health is one candidate's private state. Nothing outside this package sees
// it; callers get a read-only CandidateState from Snapshot.
type health struct {
	consecutiveFailures int
	lastSuccess         time.Time
	lastFailure         time.Time
	cooldownUntil       time.Time
	backoff             time.Duration
	latencyEWMA         time.Duration

	// probed records that the family probe has run for this candidate since the
	// last ResetHealth. It is the replacement for the old ipv6CheckedOnce flag:
	// the probe costs a dial, so it must not repeat on the hot reconnect path.
	probed bool
}

// CandidateState is the read-only view of one candidate, for logs and metrics.
type CandidateState struct {
	Candidate
	Name                string
	Pinned              bool
	ConsecutiveFailures int
	LastSuccess         time.Time
	LastFailure         time.Time
	CooldownUntil       time.Time
	LatencyEWMA         time.Duration
	Probed              bool
}

// Selector holds the candidate list, their health, and which one is currently
// pinned. All methods are safe for concurrent use.
type Selector struct {
	cfg       Config
	endpoints []Endpoint
	cands     []Candidate

	mu        sync.Mutex
	health    []health
	byAddr    map[string]int
	pinnedIdx int
	pinnedAt  time.Time
}

// NewSelector builds a selector from cfg.
func NewSelector(cfg Config) (*Selector, error) {
	cfg.applyDefaults()

	eps := make([]Endpoint, len(cfg.Endpoints))
	copy(eps, cfg.Endpoints)
	cands := buildCandidates(eps, cfg.Family)
	if len(cands) == 0 {
		return nil, fmt.Errorf("%w (policy=%s, endpoints=%d)", ErrNoCandidates, cfg.Family, len(eps))
	}

	byAddr := make(map[string]int, len(cands))
	for i, c := range cands {
		byAddr[c.Addr] = i
	}

	return &Selector{
		cfg:       cfg,
		endpoints: eps,
		cands:     cands,
		health:    make([]health, len(cands)),
		byAddr:    byAddr,
		pinnedAt:  cfg.Now(),
	}, nil
}

// Now returns the selector's clock. Callers pass it back into Next/Reconsider
// so a test that injected a fake clock controls every time-dependent decision
// from one place.
func (s *Selector) Now() time.Time { return s.cfg.Now() }

// Endpoints returns a copy of the configured endpoint list.
func (s *Selector) Endpoints() []Endpoint {
	out := make([]Endpoint, len(s.endpoints))
	copy(out, s.endpoints)
	return out
}

// Candidates returns the ordered candidate list, most preferred first.
func (s *Selector) Candidates() []Candidate {
	out := make([]Candidate, len(s.cands))
	copy(out, s.cands)
	return out
}

// Current returns the pinned candidate. The bool is false only for a selector
// with no candidates, which NewSelector refuses to build.
func (s *Selector) Current() (Candidate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cands) == 0 {
		return Candidate{}, false
	}
	return s.cands[s.pinnedIdx], true
}

// Endpoint returns the endpoint description behind a candidate.
func (s *Selector) Endpoint(c Candidate) (Endpoint, bool) {
	if c.EndpointIdx < 0 || c.EndpointIdx >= len(s.endpoints) {
		return Endpoint{}, false
	}
	return s.endpoints[c.EndpointIdx], true
}

// Pin makes c the current candidate. Re-pinning the candidate that is already
// current does NOT restart the dwell timer: otherwise a client that reconnects
// every few minutes would never reach MinDwell and never come back to its
// preferred endpoint.
func (s *Selector) Pin(c Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.byAddr[c.Addr]
	if !ok || idx == s.pinnedIdx {
		return
	}
	s.pinnedIdx = idx
	s.pinnedAt = s.cfg.Now()
}

// Siblings returns the other addresses of the SAME endpoint (i.e. its other
// address family). The connectivity gate accepts any of them: the question it
// answers is "can this client reach its server", and for a dual-addressed
// server that is true as long as one family answers.
func (s *Selector) Siblings(c Candidate) []string {
	var out []string
	for _, cand := range s.cands {
		if cand.EndpointIdx == c.EndpointIdx && cand.Addr != c.Addr {
			out = append(out, cand.Addr)
		}
	}
	return out
}

// CandidateForAddr looks a candidate up by the address that answered.
func (s *Selector) CandidateForAddr(addr string) (Candidate, bool) {
	idx, ok := s.byAddr[addr]
	if !ok {
		return Candidate{}, false
	}
	return s.cands[idx], true
}

// inCooldownLocked reports whether candidate i is parked at time now.
func (s *Selector) inCooldownLocked(i int, now time.Time) bool {
	until := s.health[i].cooldownUntil
	return !until.IsZero() && now.Before(until)
}

// Reconsider returns the candidate to use for a fresh connect cycle, applying
// the two rules that may only fire on a reconnect boundary:
//
//   - if the pinned candidate is parked, move off it;
//   - if a more preferred candidate is available and the fallback has been held
//     for at least MinDwell, go back to it.
//
// Doing this only at a boundary means the check rides a dial that was going to
// happen anyway - it never adds traffic of its own.
func (s *Selector) Reconsider(now time.Time) (Candidate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cands) == 0 {
		return Candidate{}, false
	}

	if s.inCooldownLocked(s.pinnedIdx, now) {
		if i, ok := s.firstAvailableLocked(now); ok {
			s.repinLocked(i, now)
			return s.cands[s.pinnedIdx], true
		}
	}

	if s.pinnedIdx > 0 && now.Sub(s.pinnedAt) >= s.cfg.MinDwell {
		for i := range s.pinnedIdx {
			if !s.inCooldownLocked(i, now) {
				s.repinLocked(i, now)
				break
			}
		}
	}

	return s.cands[s.pinnedIdx], true
}

// Next returns the candidate to try after the pinned one failed, without
// pinning it (the caller pins once it commits). It returns false when there is
// nowhere to go - a single-candidate selector.
//
// When every other candidate is parked it un-parks the least-bad one and
// returns that: the failover loop must converge on something, exactly like the
// storm detector un-parking every strategy rather than leaving the client with
// no tunnel at all.
func (s *Selector) Next(now time.Time) (Candidate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cands) < 2 {
		return Candidate{}, false
	}

	for k := 1; k < len(s.cands); k++ {
		i := (s.pinnedIdx + k) % len(s.cands)
		if !s.inCooldownLocked(i, now) {
			return s.cands[i], true
		}
	}

	best := -1
	for k := 1; k < len(s.cands); k++ {
		i := (s.pinnedIdx + k) % len(s.cands)
		if best < 0 || betterFallback(s.health[i], s.health[best]) {
			best = i
		}
	}
	if best < 0 {
		return Candidate{}, false
	}
	s.health[best].cooldownUntil = time.Time{}
	return s.cands[best], true
}

// betterFallback ranks two parked candidates: fewer consecutive failures wins,
// then the one whose cooldown expires soonest.
func betterFallback(a, b health) bool {
	if a.consecutiveFailures != b.consecutiveFailures {
		return a.consecutiveFailures < b.consecutiveFailures
	}
	return a.cooldownUntil.Before(b.cooldownUntil)
}

// firstAvailableLocked returns the most preferred candidate not in cooldown.
func (s *Selector) firstAvailableLocked(now time.Time) (int, bool) {
	for i := range s.cands {
		if !s.inCooldownLocked(i, now) {
			return i, true
		}
	}
	return 0, false
}

func (s *Selector) repinLocked(i int, now time.Time) {
	if i == s.pinnedIdx {
		return
	}
	s.pinnedIdx = i
	s.pinnedAt = now
}

// Report records the outcome of a real connect cycle against c.
//
// A success is the only thing that clears the failure streak: it is the only
// evidence that the transport - not merely the TCP port - works.
func (s *Selector) Report(c Candidate, ok bool, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return
	}
	now := s.cfg.Now()
	h := &s.health[idx]
	if ok {
		h.consecutiveFailures = 0
		h.backoff = 0
		h.cooldownUntil = time.Time{}
		h.lastSuccess = now
		h.probed = true
		h.latencyEWMA = blendLatency(h.latencyEWMA, latency)
		return
	}
	s.recordFailureLocked(idx, now)
}

// ReportProbe records the outcome of a reachability probe (the family probe or
// the pre-flight gate).
//
// The asymmetry with Report is deliberate. A probe failure counts against the
// candidate exactly like a connect failure - it is evidence the address is
// unreachable. A probe SUCCESS only lifts the cooldown and refreshes latency;
// it does not clear the failure streak, because a censor that lets the TCP
// handshake through and kills the session afterwards is the case this whole
// mechanism exists for. Treating "port answers" as "endpoint works" would pin
// the client to a dead endpoint forever.
func (s *Selector) ReportProbe(c Candidate, ok bool, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return
	}
	now := s.cfg.Now()
	h := &s.health[idx]
	h.probed = true
	if ok {
		h.cooldownUntil = time.Time{}
		h.latencyEWMA = blendLatency(h.latencyEWMA, latency)
		return
	}
	s.recordFailureLocked(idx, now)
}

// recordFailureLocked bumps the streak and parks the candidate once it crosses
// the threshold.
func (s *Selector) recordFailureLocked(idx int, now time.Time) {
	h := &s.health[idx]
	h.consecutiveFailures++
	h.lastFailure = now
	if h.consecutiveFailures < s.cfg.FailureThreshold {
		return
	}
	h.backoff = s.nextBackoff(h.backoff)
	h.cooldownUntil = now.Add(s.jitter(h.backoff))
}

// nextBackoff doubles the previous cooldown, clamped at MaxCooldown. The
// un-jittered value is what gets stored, so the growth stays deterministic and
// the jitter applies only to the deadline.
func (s *Selector) nextBackoff(prev time.Duration) time.Duration {
	next := s.cfg.Cooldown
	if prev > 0 {
		next = prev * 2
	}
	if next > s.cfg.MaxCooldown {
		next = s.cfg.MaxCooldown
	}
	return next
}

// jitter spreads d by +/- JitterFrac.
func (s *Selector) jitter(d time.Duration) time.Duration {
	frac := s.cfg.JitterFrac
	factor := 1 - frac + 2*frac*s.cfg.Rand()
	out := time.Duration(float64(d) * factor)
	if out <= 0 {
		out = d
	}
	return out
}

func blendLatency(cur, sample time.Duration) time.Duration {
	if sample <= 0 {
		return cur
	}
	if cur <= 0 {
		return sample
	}
	return time.Duration(float64(cur)*(1-latencyAlpha) + float64(sample)*latencyAlpha)
}

// ResetHealth forgets every verdict and re-pins the most preferred candidate.
// Called when the ground truth changed underneath us - a network change, a
// WiFi/LTE handover - where every cached observation describes a network that
// no longer exists.
func (s *Selector) ResetHealth() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.health {
		s.health[i] = health{}
	}
	s.pinnedIdx = 0
	s.pinnedAt = s.cfg.Now()
}

// Snapshot returns the current state of every candidate, for logging.
func (s *Selector) Snapshot() []CandidateState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CandidateState, len(s.cands))
	for i, c := range s.cands {
		h := s.health[i]
		out[i] = CandidateState{
			Candidate:           c,
			Name:                s.endpoints[c.EndpointIdx].Label(c.EndpointIdx),
			Pinned:              i == s.pinnedIdx,
			ConsecutiveFailures: h.consecutiveFailures,
			LastSuccess:         h.lastSuccess,
			LastFailure:         h.lastFailure,
			CooldownUntil:       h.cooldownUntil,
			LatencyEWMA:         h.latencyEWMA,
			Probed:              h.probed,
		}
	}
	return out
}

// ProbeCurrent runs the family probe for the pinned candidate and returns the
// candidate to dial. The bool reports whether the pin survived.
//
// This is the old Manager.checkIPv6Connectivity, moved here and made an
// explicit step: it costs a dial, so it must be called from one place per
// connect cycle rather than from a getter that ~15 call sites hit.
//
// It dials at most once per candidate per ResetHealth, and only when there is
// somewhere to fall back to. Probing the last candidate in the list would spend
// a dial on a verdict nobody can act on.
func (s *Selector) ProbeCurrent(ctx context.Context) (Candidate, bool) {
	s.mu.Lock()
	if len(s.cands) == 0 {
		s.mu.Unlock()
		return Candidate{}, false
	}
	cur := s.cands[s.pinnedIdx]
	now := s.cfg.Now()
	need := !s.health[s.pinnedIdx].probed && s.hasFallbackAfterLocked(s.pinnedIdx, now)
	s.mu.Unlock()

	if !need {
		return cur, true
	}

	probeCtx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()

	start := s.cfg.Now()
	conn, err := s.cfg.Dial(probeCtx, cur.Family.Network(), cur.Addr)
	if err == nil {
		conn.Close()
		s.ReportProbe(cur, true, s.cfg.Now().Sub(start))
		return cur, true
	}

	s.ReportProbe(cur, false, 0)
	next, ok := s.Next(s.cfg.Now())
	if !ok {
		return cur, false
	}
	s.Pin(next)
	return next, false
}

// hasFallbackAfterLocked reports whether some less-preferred candidate is
// available to fall back to.
func (s *Selector) hasFallbackAfterLocked(i int, now time.Time) bool {
	for j := i + 1; j < len(s.cands); j++ {
		if !s.inCooldownLocked(j, now) {
			return true
		}
	}
	return false
}
