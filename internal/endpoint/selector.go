package endpoint

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"syscall"
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

	// siblingTryHold is how long a verdict on one address of a server keeps
	// that address parked while the client tries the server's other address,
	// and how long the verdict counts toward a verdict on the whole server. It
	// covers a connect cycle on the other address and a session there dying
	// the same way: a dead session lives up to a minute under load, a stall
	// verdict comes 40-45 s in. The base cooldown (1 min, jittered) expired
	// in the middle of that, and the client went back to the first address
	// instead of on to the next server.
	siblingTryHold = 3 * time.Minute
)

// DialFunc is the dialer the selector uses for its family probe. Injected so
// tests drive the probe against loopback listeners instead of the network.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config configures a Selector. Every zero-valued field gets a default, so
// Config{Endpoints: eps} is valid.
type Config struct {
	Endpoints []Endpoint
	Family    FamilyPolicy

	// Selection ranks endpoints against each other; Family ranks the addresses
	// within one endpoint. The zero value is SelectPriority - the configured
	// order, which is what a single-endpoint client has always done.
	Selection SelectionPolicy

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

	// Shared makes NewSelector return the process-scoped selector for this
	// configuration instead of a private one, so candidate health survives a
	// client being torn down and rebuilt. See shared.go for why that matters.
	Shared bool

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

	// deadStreak counts the sessions in a row that died young on this
	// candidate (ReportDeadSession). Unlike consecutiveFailures, a successful
	// connect does not clear it - every one of those sessions began with one -
	// only a useful session does (ReportSessionUseful).
	deadStreak int

	// deadParkUntil is when this candidate's park for dead sessions ends:
	// the reason for the park, kept apart from deadStreak, which grows the
	// next one. A useful session on the server's other address clears the
	// streak, and the pool poll read the cleared streak as "not parked for
	// dead sessions" and lifted a park in force (P2-1 of the round-8 review).
	deadParkUntil time.Time

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
	Unreachable         bool
	DeadStreak          int
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

	// servers holds, per endpoint, the verdicts against its addresses that
	// may add up to a verdict on the whole server. Guarded by mu.
	servers []serverChain

	// unreachable marks candidates whose address family has no physical route
	// off the tunnel right now - e.g. an IPv6 endpoint on a host with no IPv6
	// at all. Unlike a cooldown it is not time-based and not an endpoint
	// verdict: the server is fine, this host simply cannot reach it on that
	// family, so it must be skipped by the failover walk (never dialled, never
	// un-parked) rather than parked with backoff. Set from the physical-route
	// preflight and from the TUN bypass watcher; cleared the moment the route
	// reappears. Guarded by mu.
	unreachable []bool
}

// serverChain is one server's record of verdicts against its addresses.
//
// A verdict - silence, a dead session, a stall, swallowed handshakes - lands
// on an address. Under a censor the two families of one server are often in
// different states, so the server's other address is worth one try. If that
// one gets a verdict too, the whole server is parked and the client goes on
// to the next one: before, each address was parked on its own, and the client
// walked v6, v4, v6 of one server without ever reaching its neighbour.
type serverChain struct {
	// verdicts maps a candidate index to when its address got a verdict in
	// the current chain.
	verdicts map[int]time.Time
	// backoff is the server's own park: Cooldown, doubling with each verdict
	// on the whole server up to MaxCooldown, cleared by a useful session.
	backoff time.Duration
	// until is when the server's last park ends. A server that stays quiet
	// for as long as that park lasted starts its next one from Cooldown
	// again: without it the backoff only grew, and a server that misbehaved
	// once a day was parked for half an hour within a week (P3-4 of the
	// round-5 review).
	until time.Time
	// parked is how long that park lasted, jitter included.
	parked time.Duration
}

// NewSelector builds a selector from cfg, or returns the process-scoped one
// when cfg.Shared is set.
func NewSelector(cfg Config) (*Selector, error) {
	cfg.applyDefaults()
	if cfg.Shared {
		return sharedSelectorFor(cfg)
	}
	return newSelector(cfg)
}

// newSelector always builds a fresh selector. cfg must already carry defaults.
func newSelector(cfg Config) (*Selector, error) {
	eps := make([]Endpoint, len(cfg.Endpoints))
	copy(eps, cfg.Endpoints)
	cands := buildCandidates(eps, cfg.Family, endpointOrder(eps, cfg.Selection, cfg.Rand))
	if len(cands) == 0 {
		return nil, fmt.Errorf("%w (policy=%s, endpoints=%d)", ErrNoCandidates, cfg.Family, len(eps))
	}

	byAddr := make(map[string]int, len(cands))
	for i, c := range cands {
		byAddr[c.Addr] = i
	}

	return &Selector{
		cfg:         cfg,
		endpoints:   eps,
		cands:       cands,
		health:      make([]health, len(cands)),
		byAddr:      byAddr,
		pinnedAt:    cfg.Now(),
		servers:     make([]serverChain, len(eps)),
		unreachable: make([]bool, len(cands)),
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

// GateAddrs returns every address the connectivity gate may accept on behalf of
// c: the other families of the same endpoint first, then every other endpoint in
// preference order.
//
// Siblings alone are not enough once there is a pool. The gate decides whether
// to dial or to sit in a wait loop, so feeding it one endpoint means a client
// whose first server is unreachable waits for that server to come back instead
// of moving to the next one - with three healthy servers configured and idle.
// Widening the set turns "the network is down" into what it should mean: not one
// address in the pool answers.
//
// Parked candidates are included on purpose. This is the gate, not the chooser:
// its answer only says which addresses are reachable, and Reconsider still
// applies cooldowns when picking what to dial. Leaving a parked-but-live server
// out would make the client wait when it has somewhere to go.
// Addresses whose family has no physical route are left out: the gate would
// only spend a TCP timeout on a dial that cannot leave the host.
func (s *Selector) GateAddrs(c Candidate) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	// Siblings (same endpoint, other family) first, then the rest of the pool.
	for _, cand := range s.cands {
		if cand.EndpointIdx == c.EndpointIdx && cand.Addr != c.Addr && !s.unreachable[s.byAddr[cand.Addr]] {
			out = append(out, cand.Addr)
		}
	}
	for _, cand := range s.cands {
		if cand.EndpointIdx == c.EndpointIdx || cand.Addr == c.Addr {
			continue
		}
		if s.unreachable[s.byAddr[cand.Addr]] {
			continue
		}
		out = append(out, cand.Addr)
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

// SetReachable records whether the host currently has a physical route to
// addr's family. It returns whether that flipped the stored verdict, so the
// caller logs the transition once instead of on every preflight tick. An
// address the selector does not know is ignored.
//
// Marking a candidate unreachable never touches its health: a missing IPv6
// route is the host's state, not the endpoint's, and punishing the endpoint for
// it would leave the family parked with backoff long after the route returns.
func (s *Selector) SetReachable(addr string, reachable bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[addr]
	if !found {
		return false
	}
	if s.unreachable[idx] == !reachable {
		return false
	}
	s.unreachable[idx] = !reachable
	return true
}

// Reachable reports whether addr is believed to have a physical route right
// now. Unknown addresses read as reachable: the default is to try.
func (s *Selector) Reachable(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[addr]
	if !found {
		return true
	}
	return !s.unreachable[idx]
}

// inCooldownLocked reports whether candidate i is parked at time now.
func (s *Selector) inCooldownLocked(i int, now time.Time) bool {
	until := s.health[i].cooldownUntil
	return !until.IsZero() && now.Before(until)
}

// unavailableLocked reports whether candidate i cannot be dialled right now,
// either because it is parked (cooldown) or because its family has no physical
// route. The failover walk uses this instead of inCooldownLocked so an
// unroutable family is skipped exactly like a parked one - but see Next, where
// the two diverge: a parked candidate can be un-parked as a last resort, an
// unroutable one cannot, because dialling it is futile until the route returns.
func (s *Selector) unavailableLocked(i int, now time.Time) bool {
	return s.unreachable[i] || s.inCooldownLocked(i, now)
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

	rank := s.rankLocked()

	if s.unavailableLocked(s.pinnedIdx, now) {
		if i, ok := s.firstAvailableLocked(rank, now); ok {
			s.repinLocked(i, now)
			return s.cands[s.pinnedIdx], true
		}
	}

	if pos := rankPos(rank, s.pinnedIdx); pos > 0 && now.Sub(s.pinnedAt) >= s.cfg.MinDwell {
		for _, i := range rank[:pos] {
			if !s.unavailableLocked(i, now) {
				s.repinLocked(i, now)
				break
			}
		}
	}

	return s.cands[s.pinnedIdx], true
}

// rankLocked returns the candidate indices in preference order under the active
// selection policy. For every policy but SelectLatency that is the order the
// candidate list was built in, so this is the identity permutation.
//
// Latency re-ranks ENDPOINTS, never the families inside one. Sorting the two
// addresses of one server by RTT would silently override the family policy -
// a separate decision the operator already made, and one with consequences
// (a censor that throttles IPv4 makes it the slow one on purpose) that a
// millisecond comparison has no business reversing.
func (s *Selector) rankLocked() []int {
	rank := make([]int, len(s.cands))
	for i := range rank {
		rank[i] = i
	}
	if s.cfg.Selection != SelectLatency {
		return rank
	}

	best := make(map[int]time.Duration, len(s.endpoints))
	for i, c := range s.cands {
		l := s.health[i].latencyEWMA
		if l <= 0 {
			continue
		}
		if cur, seen := best[c.EndpointIdx]; !seen || l < cur {
			best[c.EndpointIdx] = l
		}
	}
	if len(best) == 0 {
		return rank
	}

	sort.SliceStable(rank, func(a, b int) bool {
		la, oka := best[s.cands[rank[a]].EndpointIdx]
		lb, okb := best[s.cands[rank[b]].EndpointIdx]
		if oka != okb {
			// A measured endpoint outranks an unmeasured one. The alternative -
			// treating "unknown" as "fast" - would send every reconnect to a
			// server nobody has ever timed.
			return oka
		}
		if oka && la != lb {
			return la < lb
		}
		return false
	})
	return rank
}

// rankPos returns the position of candidate index i in the rank order.
func rankPos(rank []int, i int) int {
	for pos, idx := range rank {
		if idx == i {
			return pos
		}
	}
	return 0
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

	rank := s.rankLocked()
	pos := rankPos(rank, s.pinnedIdx)

	for k := 1; k < len(rank); k++ {
		i := rank[(pos+k)%len(rank)]
		if !s.unavailableLocked(i, now) {
			return s.cands[i], true
		}
	}

	// Every other candidate is parked. Un-park the least-bad one so the loop
	// converges on something - but never an unroutable one: un-parking cannot
	// give a family a route it does not have, so it would just send the dial
	// into the tunnel to time out.
	best := -1
	for k := 1; k < len(rank); k++ {
		i := rank[(pos+k)%len(rank)]
		if s.unreachable[i] {
			continue
		}
		if best < 0 || betterFallback(s.health[i], s.health[best]) {
			best = i
		}
	}
	if best < 0 {
		return Candidate{}, false
	}
	s.health[best].cooldownUntil = time.Time{}
	s.health[best].deadParkUntil = time.Time{}
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

// firstAvailableLocked returns the most preferred candidate that can be dialled
// now - neither parked nor unroutable - walking the rank order rather than the
// raw index order.
func (s *Selector) firstAvailableLocked(rank []int, now time.Time) (int, bool) {
	for _, i := range rank {
		if !s.unavailableLocked(i, now) {
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
		h.deadParkUntil = time.Time{}
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
// unreachable. A probe SUCCESS records only the latency: it clears neither the
// failure streak nor the cooldown, because a censor that lets the TCP handshake
// through and kills the session afterwards is the case this whole mechanism
// exists for. Treating "port answers" as "endpoint works" would pin the client
// to a dead endpoint forever.
//
// Clearing the cooldown used to be the one exception, and it undid the rest.
// A blackholed address answers its TCP port by definition, so the gate found it
// healthy the moment after a full scan had condemned it, and the client went
// straight back. A cooldown ends when it ends, or when Next has nowhere else to
// go - not because a port accepted a connection.
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
		h.latencyEWMA = blendLatency(h.latencyEWMA, latency)
		return
	}
	s.recordFailureLocked(idx, now)
}

// IsParked reports whether the candidate is in cooldown right now. Callers that
// hold a verdict of their own - the pre-flight gate, which sees a live TCP port
// and nothing more - use it to check whether the selector has already decided
// against this address for better reasons.
func (s *Selector) IsParked(c Candidate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return false
	}
	return s.inCooldownLocked(idx, s.cfg.Now())
}

// ReportSilent records the strongest failure verdict a connect cycle can
// produce: the address accepted the connection and then answered nothing, on
// every transport in turn.
//
// It parks the candidate immediately, without waiting for FailureThreshold.
// The threshold is there so one bad minute does not cost a good server, and it
// is right for an ordinary failure - a refusal, a reset, a handshake that got
// an answer it did not like. Silence across every transport is not a bad
// minute: it is what a blackholed address looks like, and the second cycle
// would confirm what the first one established at the price of another full
// scan. On a phone, where the service restarts the client after every failed
// cycle, that second scan may never finish.
//
// alsoSilent names other addresses of the same server that heard nothing in
// the same run of cycles (a swallow run spans both families); they join the
// server's chain without a park of their own. It reports whether the whole
// server is parked now - see addrVerdictLocked.
func (s *Selector) ReportSilent(c Candidate, alsoSilent ...string) (serverParked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return false
	}
	now := s.cfg.Now()
	for _, a := range alsoSilent {
		if j, ok := s.byAddr[a]; ok && j != idx && s.cands[j].EndpointIdx == s.cands[idx].EndpointIdx {
			s.chainLocked(j)[j] = now
		}
	}
	h := &s.health[idx]
	h.consecutiveFailures++
	h.lastFailure = now
	h.backoff = s.nextBackoff(h.backoff)
	h.cooldownUntil = now.Add(s.jitter(h.backoff))
	return s.addrVerdictLocked(idx, now)
}

// ReportDeadSession parks c for a session that connected and then died
// almost at once. Each one in a row parks longer - Cooldown, then twice that,
// up to MaxCooldown - because a successful connect starts every such session
// and clears the connect backoff, which left every park at the base cooldown:
// under a freeze the client hopped addresses every half minute.
//
// It reports whether the whole server is parked now (addrVerdictLocked).
func (s *Selector) ReportDeadSession(c Candidate) (serverParked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return false
	}
	now := s.cfg.Now()
	h := &s.health[idx]
	h.deadStreak++
	h.consecutiveFailures++
	h.lastFailure = now
	park := s.cfg.Cooldown
	for i := 1; i < h.deadStreak && park < s.cfg.MaxCooldown; i++ {
		park *= 2
	}
	park = min(park, s.cfg.MaxCooldown)
	h.backoff = park
	h.cooldownUntil = now.Add(s.jitter(park))
	serverParked = s.addrVerdictLocked(idx, now)
	h.deadParkUntil = h.cooldownUntil
	return serverParked
}

// chainLocked returns the verdict map of the server candidate idx belongs to.
func (s *Selector) chainLocked(idx int) map[int]time.Time {
	sc := &s.servers[s.cands[idx].EndpointIdx]
	if sc.verdicts == nil {
		sc.verdicts = make(map[int]time.Time)
	}
	return sc.verdicts
}

// addrVerdictLocked widens a verdict the caller has just booked and parked on
// candidate idx to its server.
//
// While the server has another routable address that has neither a verdict
// in this chain nor a park, that address gets the next try: idx stays parked
// for at least siblingTryHold, so its park cannot run out while the other
// address is tried and a session there dies. Once every routable address of
// the server is condemned, the whole server is parked for its own growing
// backoff and the chain starts over - the next connect goes to another
// server. A server with one usable address is parked by its first verdict.
func (s *Selector) addrVerdictLocked(idx int, now time.Time) (serverParked bool) {
	verdicts := s.chainLocked(idx)
	verdicts[idx] = now
	ep := s.cands[idx].EndpointIdx

	open := false
	for j, c := range s.cands {
		if c.EndpointIdx != ep || j == idx || s.unreachable[j] {
			continue
		}
		if at, ok := verdicts[j]; ok && now.Sub(at) <= siblingTryHold {
			continue
		}
		if s.inCooldownLocked(j, now) {
			continue
		}
		open = true
	}
	if open {
		if until := now.Add(siblingTryHold); s.health[idx].cooldownUntil.Before(until) {
			s.health[idx].cooldownUntil = until
		}
		return false
	}

	sc := &s.servers[ep]
	if !sc.until.IsZero() && now.Sub(sc.until) >= sc.parked {
		sc.backoff = 0
	}
	sc.backoff = s.nextBackoff(sc.backoff)
	sc.parked = s.jitter(sc.backoff)
	until := now.Add(sc.parked)
	sc.until = until
	for j, c := range s.cands {
		if c.EndpointIdx == ep && s.health[j].cooldownUntil.Before(until) {
			s.health[j].cooldownUntil = until
			if s.health[j].deadParkUntil.After(now) {
				s.health[j].deadParkUntil = until
			}
		}
	}
	clear(verdicts)
	return true
}

// ParkedForDeadSessions reports whether c is in a park for dead sessions:
// parked because sessions there connect and then die, which a completed TCP
// connect cannot speak against.
func (s *Selector) ParkedForDeadSessions(c Candidate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return false
	}
	now := s.cfg.Now()
	return s.health[idx].deadParkUntil.After(now) && s.inCooldownLocked(idx, now)
}

// Unpark clears c's cooldown, keeping its failure history. For a caller with
// newer evidence than the park (see strategy.Manager.PinAnswering).
func (s *Selector) Unpark(c Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, found := s.byAddr[c.Addr]; found {
		s.health[idx].cooldownUntil = time.Time{}
		s.health[idx].deadParkUntil = time.Time{}
	}
}

// ReportSessionUseful records that a session on c carried traffic for a
// meaningful time. The server works, so what grows its parks starts over:
// the server's backoff and verdicts, and the backoff, dead streak and
// failure count of every address of the server - the next verdict on any of
// them is a first one again. It used to clear only the server's backoff and
// c's own dead streak, while a verdict's park is the larger of the server's
// and the address's, so a useful session on v6 left v4's park growing: 1m7s,
// then 2m4s after 70 s of traffic (N14 of the fix9 stand run). A park in
// force on another address stays, and so does its reason (deadParkUntil):
// that family's failure is its own evidence, and it runs out on its own.
func (s *Selector) ReportSessionUseful(c Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, found := s.byAddr[c.Addr]
	if !found {
		return
	}
	server := s.cands[idx].EndpointIdx
	for i, cand := range s.cands {
		if cand.EndpointIdx != server {
			continue
		}
		h := &s.health[i]
		h.deadStreak, h.backoff, h.consecutiveFailures = 0, 0, 0
	}
	sc := &s.servers[server]
	sc.backoff = 0
	clear(sc.verdicts)
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
	for i := range s.servers {
		s.servers[i] = serverChain{}
	}
	// A network change can bring a family up (LTE without v6 to Wi-Fi with it),
	// so clear the route verdicts too and let the next preflight re-mark. Leaving
	// them set would keep a family excluded on a network that now carries it.
	for i := range s.unreachable {
		s.unreachable[i] = false
	}
	s.pinnedIdx = 0
	s.pinnedAt = s.cfg.Now()
}

// HealthRecord is one candidate's health, carried from one selector to
// another over the same pool (ExportHealth, ImportHealth).
type HealthRecord struct {
	Addr                string
	ConsecutiveFailures int
	LastSuccess         time.Time
	LastFailure         time.Time
	CooldownUntil       time.Time
	Backoff             time.Duration
	DeadStreak          int
	DeadParkUntil       time.Time

	// ServerBackoff is the server's own park (serverChain.backoff), the same
	// on every address of one server. The chain's verdicts need no carrying:
	// each comes with a park of at least siblingTryHold, and the park is
	// carried.
	ServerBackoff time.Duration
	// ServerParkEnd and ServerParked are when the server's last park ended
	// and how long it lasted: what the backoff's decay is measured from.
	// Without them an imported backoff doubled on the next verdict however
	// long the server had been quiet (P3-5 of the round-6 review).
	ServerParkEnd time.Time
	ServerParked  time.Duration
}

// ExportHealth returns every candidate's failure history and park.
func (s *Selector) ExportHealth() []HealthRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HealthRecord, len(s.cands))
	for i, c := range s.cands {
		h := s.health[i]
		sc := s.servers[c.EndpointIdx]
		out[i] = HealthRecord{Addr: c.Addr, ConsecutiveFailures: h.consecutiveFailures, LastSuccess: h.lastSuccess,
			LastFailure: h.lastFailure, CooldownUntil: h.cooldownUntil, Backoff: h.backoff, DeadStreak: h.deadStreak,
			DeadParkUntil: h.deadParkUntil, ServerBackoff: sc.backoff, ServerParkEnd: sc.until, ServerParked: sc.parked}
	}
	return out
}

// ImportHealth takes over the failure history and parks of the candidates in
// recs whose address this selector also has; others are ignored. It does not
// move the pin: the next connect's Reconsider moves off a parked one.
func (s *Selector) ImportHealth(recs []HealthRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range recs {
		idx, ok := s.byAddr[r.Addr]
		if !ok {
			continue
		}
		h := &s.health[idx]
		h.consecutiveFailures, h.lastSuccess, h.lastFailure = r.ConsecutiveFailures, r.LastSuccess, r.LastFailure
		h.cooldownUntil, h.backoff, h.deadStreak = r.CooldownUntil, r.Backoff, r.DeadStreak
		h.deadParkUntil = r.DeadParkUntil
		sc := &s.servers[s.cands[idx].EndpointIdx]
		if r.ServerBackoff > sc.backoff {
			sc.backoff, sc.until, sc.parked = r.ServerBackoff, r.ServerParkEnd, r.ServerParked
		}
	}
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
			Unreachable:         s.unreachable[i],
			DeadStreak:          h.deadStreak,
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
	// A family with no physical route is not probed: the dial cannot leave
	// the host, and charging the endpoint for that blamed a live server for
	// the client's own dead link (stand run #5c).
	need := !s.health[s.pinnedIdx].probed && !s.unreachable[s.pinnedIdx] && s.hasFallbackAfterLocked(s.pinnedIdx, now)
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

	if localNetworkError(err) {
		// The host could not send the probe at all - no route, no network,
		// no source address. That is the host's state, not the endpoint's:
		// leave health and pin alone and let the connect cycle find out.
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

// localNetworkError reports a dial error raised by the local stack before
// anything reached the network.
func localNetworkError(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.EADDRNOTAVAIL)
}

// hasFallbackAfterLocked reports whether some less-preferred candidate is
// available to fall back to.
func (s *Selector) hasFallbackAfterLocked(i int, now time.Time) bool {
	rank := s.rankLocked()
	for _, j := range rank[rankPos(rank, i)+1:] {
		if !s.unavailableLocked(j, now) {
			return true
		}
	}
	return false
}
