package server

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Per-node ceilings on users and traffic.
//
// This is the one defence against the only confirmed vector that has nothing to
// do with what our traffic looks like. On 2026-08-04 hosting providers were
// banned in bulk, and inside one /24 exactly one of two identical servers was
// taken out - the decision was made per address, not per subnet. A controlled
// experiment in Iran put numbers on it: 200 users on one address survived two
// hours, 5 to 7 users survived two days, and a trickle survived a week.
//
// Nothing in B1, B2 or burst reshaping moves that. They make us resemble a
// donor; this looks at how much and how many, not at shape. A factor of
// twenty-four in survival time comes from policy, not from code.
//
// Where the ceiling is enforced is the whole design.
//
// It is applied AFTER authentication, never at accept. A prober cannot
// authenticate, so it never reaches this code and cannot map it. Had it been
// applied at accept - the way the existing admission semaphore is, since that
// one guards memory rather than reputation - anyone could open connections
// until refused and learn "this server takes exactly N", which is a fingerprint
// of its own and a sharper one than what it protects against. The rule is: the
// only peers who can observe our ceiling are peers who already proved they hold
// a secret.

// nodeCapWindowBuckets is how finely the traffic window is sliced. Twelve gives
// a five-minute resolution on an hour, which is enough to see a ramp without
// keeping much state.
const nodeCapWindowBuckets = 12

// nodeCapWarnFraction is how full the node has to get before the log starts
// saying so. An operator needs time to bring another node up, so the warning
// has to arrive well before the refusal does.
const nodeCapWarnFraction = 0.8

// nodeCap holds a node's ceilings and its current standing against them.
type nodeCap struct {
	maxClients int
	maxBytes   int64
	window     time.Duration

	mu       sync.Mutex
	sessions map[string]int // client identity -> open sessions
	buckets  [nodeCapWindowBuckets]int64
	bucketAt [nodeCapWindowBuckets]time.Time
	warnedAt time.Time

	refusedClients atomic.Uint64
	refusedTraffic atomic.Uint64
}

// nodeCapacity is the process-wide instance. Nil until initNodeCap runs, and
// every method tolerates a nil receiver so call sites stay free of checks.
var nodeCapacity *nodeCap

func newNodeCap(maxClients int, maxBytes int64, window time.Duration) *nodeCap {
	if window <= 0 {
		window = time.Hour
	}
	return &nodeCap{
		maxClients: maxClients,
		maxBytes:   maxBytes,
		window:     window,
		sessions:   map[string]int{},
	}
}

// initNodeCap builds the node ceiling from configuration.
//
// Both limits default to off, which is a deliberate reading of "conservative
// defaults" rather than a dodge. A non-zero default would start refusing users
// on deployments that are running fine today, and - until a refused client can
// move to another node, which it currently cannot (see nodeCapNoFailover) - a
// refusal is a dead connection rather than a redirect. So the measurement is on
// by default and the enforcement is not: an operator can read the real numbers
// off the metrics for a week and then choose a ceiling that matches how many
// nodes they actually have.
func initNodeCap(cfg *Config) {
	nodeCapacity = newNodeCap(cfg.NodeMaxClients, cfg.NodeMaxBytesPerWindow, cfg.NodeWindow)

	switch {
	case cfg.NodeMaxClients <= 0 && cfg.NodeMaxBytesPerWindow <= 0:
		log.Info("Node ceilings off: reporting users and traffic only. " +
			"Address reputation is the one blocking vector that ignores what our traffic looks like; " +
			"watch tiredvpn_node_* and set -node-max-clients once you know your numbers")
	default:
		log.Info("Node ceilings: max %d clients, max %d bytes per %s",
			cfg.NodeMaxClients, cfg.NodeMaxBytesPerWindow, nodeCapacity.window)
	}

	if cfg.UpstreamAddr != "" && cfg.NodeMaxClients > 0 {
		// A relay's peers are downstream nodes, not people. Counting them as
		// users measures the wrong thing: one downstream node carrying a
		// hundred users counts as one. Traffic is the number that still means
		// what it says here.
		log.Warn("Node ceilings: -node-max-clients on a relay counts downstream nodes, not users; " +
			"the traffic ceiling is the one that carries meaning on this role")
	}
}

// admit reserves a slot for an authenticated session and returns the release.
//
// An empty identity means the caller could not say who this is, which on this
// funnel means the peer did not authenticate - see tunnelIdentity. Those are
// not counted and never refused: counting them would let anyone who can
// complete a plain TLS handshake measure the ceiling and then fill it.
func (c *nodeCap) admit(identity string, now time.Time) (release func(), ok bool) {
	if c == nil || identity == "" {
		return func() {}, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxBytes > 0 && c.bytesInWindowLocked(now) >= c.maxBytes {
		c.refusedTraffic.Add(1)
		return nil, false
	}

	_, alreadyHere := c.sessions[identity]
	if c.maxClients > 0 && !alreadyHere && len(c.sessions) >= c.maxClients {
		c.refusedClients.Add(1)
		return nil, false
	}

	c.sessions[identity]++
	c.warnIfNearLocked(now)

	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.sessions[identity] <= 1 {
				delete(c.sessions, identity)
				return
			}
			c.sessions[identity]--
		})
	}, true
}

// recordBytes adds traffic to the current window bucket.
func (c *nodeCap) recordBytes(n int64, now time.Time) {
	if c == nil || n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	idx, start := c.bucketFor(now)
	if !c.bucketAt[idx].Equal(start) {
		c.bucketAt[idx] = start
		c.buckets[idx] = 0
	}
	c.buckets[idx] += n
	c.warnIfNearLocked(now)
}

// bucketFor maps a time to its slot in the ring and the slot's start.
func (c *nodeCap) bucketFor(now time.Time) (int, time.Time) {
	slot := c.window / nodeCapWindowBuckets
	start := now.Truncate(slot)
	return int(start.UnixNano()/int64(slot)) % nodeCapWindowBuckets, start
}

// bytesInWindowLocked sums the buckets that are still inside the window.
func (c *nodeCap) bytesInWindowLocked(now time.Time) int64 {
	cutoff := now.Add(-c.window)
	var total int64
	for i, at := range c.bucketAt {
		if at.After(cutoff) {
			total += c.buckets[i]
		}
	}
	return total
}

// warnIfNearLocked logs once a minute while the node sits near a ceiling.
// Bringing up another node takes an operator longer than a spike lasts, so this
// has to fire before the refusals do, not alongside them.
func (c *nodeCap) warnIfNearLocked(now time.Time) {
	if now.Sub(c.warnedAt) < time.Minute {
		return
	}

	if c.maxClients > 0 {
		if frac := float64(len(c.sessions)) / float64(c.maxClients); frac >= nodeCapWarnFraction {
			c.warnedAt = now
			log.Warn("Node ceiling: %d of %d clients (%.0f%%) - bring another node up before this fills",
				len(c.sessions), c.maxClients, frac*100)
			return
		}
	}
	if c.maxBytes > 0 {
		used := c.bytesInWindowLocked(now)
		if frac := float64(used) / float64(c.maxBytes); frac >= nodeCapWarnFraction {
			c.warnedAt = now
			log.Warn("Node ceiling: %d of %d bytes in the last %s (%.0f%%)",
				used, c.maxBytes, c.window, frac*100)
		}
	}
}

// nodeCapStats is what the exporter renders.
type nodeCapStats struct {
	Clients        int
	MaxClients     int
	BytesInWindow  int64
	MaxBytes       int64
	Window         time.Duration
	RefusedClients uint64
	RefusedTraffic uint64
}

func (c *nodeCap) stats(now time.Time) nodeCapStats {
	if c == nil {
		return nodeCapStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return nodeCapStats{
		Clients:        len(c.sessions),
		MaxClients:     c.maxClients,
		BytesInWindow:  c.bytesInWindowLocked(now),
		MaxBytes:       c.maxBytes,
		Window:         c.window,
		RefusedClients: c.refusedClients.Load(),
		RefusedTraffic: c.refusedTraffic.Load(),
	}
}

// nodeCapNoFailover records the blocker the task asked to be named.
//
// A refused client is supposed to move to another node. It cannot: the client
// knows one server address and its IPv6 twin, which is the same machine, and
// Manager.GetServerAddr chooses between those two and nothing else. RelayNodes
// is the mesh strategy's own list, not a pool of entry nodes.
//
// So until a client carries a list of nodes and walks it, a refusal is a dead
// connection rather than a redirect - which is why enforcement defaults to off
// and only the reporting is on.
const nodeCapNoFailover = "client-side node failover does not exist yet: one server address plus its IPv6 twin"

// writeNodeCapMetrics renders the ceiling and the standing against it.
//
// The fractions are exported rather than left for the operator to compute,
// because the whole point is to alert before the ceiling is reached and an
// alerting rule that has to divide two gauges is one nobody writes.
func writeNodeCapMetrics(w io.Writer) {
	s := nodeCapacity.stats(time.Now())

	fmt.Fprintf(w, "# HELP tiredvpn_node_clients Distinct authenticated clients on this node\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_node_clients gauge\n")
	fmt.Fprintf(w, "tiredvpn_node_clients %d\n\n", s.Clients)

	fmt.Fprintf(w, "# HELP tiredvpn_node_bytes_window Bytes carried in the current window\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_node_bytes_window gauge\n")
	fmt.Fprintf(w, "tiredvpn_node_bytes_window %d\n\n", s.BytesInWindow)

	fmt.Fprintf(w, "# HELP tiredvpn_node_ceiling_clients Configured client ceiling, 0 = off\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_node_ceiling_clients gauge\n")
	fmt.Fprintf(w, "tiredvpn_node_ceiling_clients %d\n\n", s.MaxClients)

	fmt.Fprintf(w, "# HELP tiredvpn_node_ceiling_bytes Configured traffic ceiling per window, 0 = off\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_node_ceiling_bytes gauge\n")
	fmt.Fprintf(w, "tiredvpn_node_ceiling_bytes %d\n\n", s.MaxBytes)

	fmt.Fprintf(w, "# HELP tiredvpn_node_ceiling_used Fraction of a ceiling in use, for alerting before it fills\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_node_ceiling_used gauge\n")
	fmt.Fprintf(w, "tiredvpn_node_ceiling_used{limit=\"clients\"} %.4f\n", fraction(int64(s.Clients), int64(s.MaxClients)))
	fmt.Fprintf(w, "tiredvpn_node_ceiling_used{limit=\"bytes\"} %.4f\n\n", fraction(s.BytesInWindow, s.MaxBytes))

	fmt.Fprintf(w, "# HELP tiredvpn_node_refused_total Sessions refused because a ceiling was full\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_node_refused_total counter\n")
	fmt.Fprintf(w, "tiredvpn_node_refused_total{limit=\"clients\"} %d\n", s.RefusedClients)
	fmt.Fprintf(w, "tiredvpn_node_refused_total{limit=\"bytes\"} %d\n\n", s.RefusedTraffic)
}

// fraction reports used/limit, and 0 when there is no limit to be a fraction of.
func fraction(used, limit int64) float64 {
	if limit <= 0 {
		return 0
	}
	return float64(used) / float64(limit)
}
