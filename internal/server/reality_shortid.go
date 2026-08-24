package server

import (
	"sync"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// shortIDEntry is what a successful short-ID lookup yields: which client sent
// the ClientHello, and the secret the rest of the session is keyed with.
type shortIDEntry struct {
	clientID string
	secret   []byte
}

// shortIDIndex maps the 8-byte identifier carried in session_id to a client.
//
// It exists to kill an O(N) loop: the legacy path verifies an incoming
// ClientHello against every secret in Redis, one HMAC per client per
// connection, which is both a DoS lever and a cost that grows with the
// customer list. Here the client names itself and the server does one map
// lookup.
//
// The index is derived state - the registry is the source of truth - so it is
// rebuilt rather than mutated, and a stale entry costs at most one refresh
// interval of failed authentication for a client that was just added.
type shortIDIndex struct {
	mu      sync.RWMutex
	entries map[[customtls.AuthShortIDLen]byte]shortIDEntry
	built   time.Time

	// refreshing serialises rebuilds and, with lastRefresh, rate-limits the
	// ones triggered by a lookup miss. Without that limit an attacker who
	// sends unknown short IDs makes the server rebuild its index as fast as it
	// can accept connections.
	refreshing  sync.Mutex
	lastRefresh time.Time
}

const (
	// shortIDRefreshInterval is how stale the index may get before a lookup
	// refreshes it. The registry has no change events to hook, so this is a
	// poll; a new client waits at most this long to be able to connect.
	shortIDRefreshInterval = 30 * time.Second

	// shortIDMissRefreshInterval bounds refreshes triggered by a miss.
	shortIDMissRefreshInterval = time.Second
)

func newShortIDIndex() *shortIDIndex {
	return &shortIDIndex{entries: make(map[[customtls.AuthShortIDLen]byte]shortIDEntry)}
}

// Rebuild replaces the index contents from the registry and the global secret.
//
// The global secret gets the client ID "global", matching what the legacy path
// reports, so a deployment running one shared secret behaves the same on both
// transports.
func (i *shortIDIndex) Rebuild(clients []*ClientConfig, globalSecret []byte) {
	next := make(map[[customtls.AuthShortIDLen]byte]shortIDEntry, len(clients)+1)

	for _, c := range clients {
		if c == nil || c.Secret == "" || !c.Enabled || c.IsExpired() {
			continue
		}
		secret := []byte(c.Secret)
		next[customtls.ShortIDFor(secret)] = shortIDEntry{clientID: c.ID, secret: secret}
	}

	if len(globalSecret) > 0 {
		// Deliberately after the per-client loop: a real client that somehow
		// collides with the global secret keeps its own identity rather than
		// being silently merged into "global".
		id := customtls.ShortIDFor(globalSecret)
		if _, taken := next[id]; !taken {
			next[id] = shortIDEntry{clientID: "global", secret: globalSecret}
		}
	}

	i.mu.Lock()
	i.entries = next
	i.built = time.Now()
	i.mu.Unlock()
}

// Lookup returns the entry for a short ID.
func (i *shortIDIndex) Lookup(id [customtls.AuthShortIDLen]byte) (shortIDEntry, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	e, ok := i.entries[id]
	return e, ok
}

// stale reports whether the index is old enough to want a refresh.
func (i *shortIDIndex) stale(now time.Time) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return now.Sub(i.built) >= shortIDRefreshInterval
}

// refreshAsync rebuilds the index in the background, at most once per
// minInterval.
//
// Background is the point. A rebuild on the connection path would make an
// unknown short ID measurably slower to reject than a bad timestamp or a
// replayed session, and that difference is exactly the oracle this design is
// supposed to deny: every rejection has to look and cost the same from
// outside. The connection that missed still falls through to the donor; the
// next one gets the fresh index.
func (i *shortIDIndex) refreshAsync(srvCtx *serverContext, minInterval time.Duration) {
	if !i.refreshing.TryLock() {
		return // a rebuild is already running
	}

	now := time.Now()
	if now.Sub(i.lastRefresh) < minInterval {
		i.refreshing.Unlock()
		return
	}
	i.lastRefresh = now

	go func() {
		defer i.refreshing.Unlock()
		var clients []*ClientConfig
		if srvCtx.registry != nil {
			clients = srvCtx.registry.ListClients()
		}
		i.Rebuild(clients, srvCtx.cfg.Secret)
	}()
}

// replayCache remembers the session_id values already accepted, so the same
// sealed ClientHello cannot be re-sent for as long as its timestamp would still
// pass the clock-skew check.
//
// Local state is enough. A replay is only useful against the node that accepted
// the original, because the payload is sealed to that node's static key and no
// two nodes share one.
type replayCache struct {
	mu    sync.Mutex
	seen  map[[customtls.AuthSessionIDLen]byte]time.Time
	ttl   time.Duration
	max   int
	swept time.Time
}

const (
	// defaultReplayTTL applies when clock-skew checking is off, so there is no
	// MaxTimeDiff to derive a window from.
	defaultReplayTTL = 600 * time.Second

	// replayCacheMax bounds memory. Entries are only added for ClientHellos
	// that actually opened, so reaching this needs 100k authentic connections
	// inside one TTL window - it is a ceiling, not an attack surface.
	replayCacheMax = 100_000
)

// replayTTLFor derives the window from the configured clock tolerance: a
// session_id stops being replayable once its timestamp falls outside the skew
// check, and the doubling covers skew in both directions.
func replayTTLFor(maxTimeDiffSeconds int) time.Duration {
	if maxTimeDiffSeconds <= 0 {
		return defaultReplayTTL
	}
	return time.Duration(maxTimeDiffSeconds) * 2 * time.Second
}

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{
		seen:  make(map[[customtls.AuthSessionIDLen]byte]time.Time),
		ttl:   ttl,
		max:   replayCacheMax,
		swept: time.Now(),
	}
}

// checkAndRecord reports whether id is being seen for the first time, and
// records it either way.
//
// Callers must only reach this with a session_id that already opened, so
// garbage cannot fill the cache.
func (c *replayCache) checkAndRecord(id [customtls.AuthSessionIDLen]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sweepLocked(now)

	if seenAt, ok := c.seen[id]; ok && now.Sub(seenAt) < c.ttl {
		return false
	}
	c.seen[id] = now
	return true
}

// sweepLocked drops expired entries, and if the cache is still over its cap
// drops the oldest half. Sweeping runs on a schedule rather than every call so
// the cost does not land on one unlucky connection.
func (c *replayCache) sweepLocked(now time.Time) {
	if now.Sub(c.swept) < c.ttl/4 && len(c.seen) < c.max {
		return
	}
	c.swept = now

	for id, at := range c.seen {
		if now.Sub(at) >= c.ttl {
			delete(c.seen, id)
		}
	}
	if len(c.seen) < c.max {
		return
	}

	// Still full of live entries: give up the older half rather than grow
	// without bound. Forgetting an id can only let a replay through inside its
	// remaining window, which is strictly better than running out of memory.
	cutoff := now.Add(-c.ttl / 2)
	for id, at := range c.seen {
		if at.Before(cutoff) {
			delete(c.seen, id)
		}
	}
}
