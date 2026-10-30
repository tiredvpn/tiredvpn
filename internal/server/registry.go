package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ClientRegistry manages clients with in-memory cache and hot-reload
type ClientRegistry struct {
	store *RedisStore

	mu       sync.RWMutex
	byID     map[string]*ClientConfig // id → config
	bySecret map[string]*ClientConfig // secret → config

	// Active connections tracking
	connMu      sync.RWMutex
	activeConns map[string]int        // clientID → count
	connsByID   map[string][]net.Conn // clientID → connections (for forced disconnect)

	// Per-client traffic counters, created on first use for a known client.
	// The data path holds a pointer to them and takes no lock at all; the map
	// is only touched when a session starts, at a flush, and on removal.
	trafficMu sync.RWMutex
	trafficBy map[string]*clientTraffic

	// stats is where FlushStats adds this server's traffic: the Redis store in
	// production, nil when there is none.
	stats statsStore
	// flushSem serialises flushes. A channel rather than a mutex so that a
	// flush that cannot get it within its context gives up instead of queuing
	// behind one stuck on Redis.
	flushSem chan struct{}

	// Hot-reload
	lastVersion int64
	stopReload  chan struct{}

	// generation moves on every change to the client set (reload,
	// reloadClient, removeClient), so a cache built from ListClients can tell
	// cheaply that it is out of date (Generation).
	generation atomic.Uint64
}

// Generation returns a number that changes whenever the client set does.
func (r *ClientRegistry) Generation() uint64 { return r.generation.Load() }

// NewClientRegistry creates a new client registry
func NewClientRegistry(store *RedisStore) *ClientRegistry {
	r := &ClientRegistry{
		store:       store,
		byID:        make(map[string]*ClientConfig),
		bySecret:    make(map[string]*ClientConfig),
		activeConns: make(map[string]int),
		connsByID:   make(map[string][]net.Conn),
		trafficBy:   make(map[string]*clientTraffic),
		flushSem:    make(chan struct{}, 1),
		stopReload:  make(chan struct{}),
	}
	if store != nil {
		r.stats = store
	}
	return r
}

// statsStore is the part of RedisStore the stats flush needs.
type statsStore interface {
	AddStatsDeltas(ctx context.Context, deltas []StatsDelta) []error
}

// Start loads clients and starts hot-reload
func (r *ClientRegistry) Start(ctx context.Context) error {
	// Initial load
	if err := r.reload(ctx); err != nil {
		return fmt.Errorf("initial load: %w", err)
	}

	// Subscribe to Redis notifications
	r.store.Subscribe(ctx, func(event, clientID string) {
		switch event {
		case "set":
			r.reloadClient(ctx, clientID)
		case "del":
			r.removeClient(clientID)
		}
	})

	// Fallback polling (every 30s check version)
	go r.pollForChanges(ctx)

	log.Info("Client registry started with %d clients", len(r.byID))
	return nil
}

// Stop stops the registry
func (r *ClientRegistry) Stop() {
	close(r.stopReload)
}

// reload loads all clients from Redis
func (r *ClientRegistry) reload(ctx context.Context) error {
	clients, err := r.store.ListClients(ctx)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear maps
	r.byID = make(map[string]*ClientConfig)
	r.bySecret = make(map[string]*ClientConfig)

	for _, cfg := range clients {
		if cfg.Enabled && !cfg.IsExpired() {
			r.byID[cfg.ID] = cfg
			r.bySecret[cfg.Secret] = cfg
		}
	}

	v, _ := r.store.GetVersion(ctx)
	r.lastVersion = v
	r.generation.Add(1)

	log.Debug("Reloaded %d clients from Redis", len(r.byID))
	return nil
}

// reloadClient reloads a single client
func (r *ClientRegistry) reloadClient(ctx context.Context, clientID string) {
	cfg, err := r.store.GetClient(ctx, clientID)
	if err != nil {
		log.Warn("Failed to reload client %s: %v", clientID, err)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.generation.Add(1)

	// Remove old secret mapping if exists
	if old, exists := r.byID[clientID]; exists {
		delete(r.bySecret, old.Secret)
	}

	if cfg != nil && cfg.Enabled && !cfg.IsExpired() {
		r.byID[cfg.ID] = cfg
		r.bySecret[cfg.Secret] = cfg

		log.Info("Reloaded client: %s (%s)", cfg.Name, cfg.ID)
	} else {
		delete(r.byID, clientID)
		log.Info("Client disabled or expired: %s", clientID)
	}
}

// removeClient removes a client and disconnects all its connections
func (r *ClientRegistry) removeClient(clientID string) {
	r.mu.Lock()
	if cfg, exists := r.byID[clientID]; exists {
		delete(r.bySecret, cfg.Secret)
		delete(r.byID, clientID)
	}
	r.generation.Add(1)
	r.mu.Unlock()

	// Close all active connections for this client
	r.connMu.Lock()
	conns := r.connsByID[clientID]
	delete(r.connsByID, clientID)
	delete(r.activeConns, clientID)
	r.connMu.Unlock()

	// The store dropped this client's stats key along with the client. Under
	// r.mu, like creation in traffic, so the two cannot interleave.
	r.mu.RLock()
	r.trafficMu.Lock()
	delete(r.trafficBy, clientID)
	r.trafficMu.Unlock()
	r.mu.RUnlock()

	for _, conn := range conns {
		conn.Close()
	}

	if len(conns) > 0 {
		log.Info("Disconnected %d connections for removed client %s", len(conns), clientID)
	}
}

// pollForChanges polls Redis version for changes (fallback mechanism)
func (r *ClientRegistry) pollForChanges(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopReload:
			return
		case <-ticker.C:
			v, err := r.store.GetVersion(ctx)
			if err != nil {
				continue
			}
			if v != r.lastVersion {
				log.Debug("Version changed %d → %d, reloading", r.lastVersion, v)
				r.reload(ctx)
			}
		}
	}
}

// GetByID returns client by ID
func (r *ClientRegistry) GetByID(id string) *ClientConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// GetBySecret returns client by secret
func (r *ClientRegistry) GetBySecret(secret string) *ClientConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySecret[secret]
}

// Authenticate checks secret and returns client config if valid
func (r *ClientRegistry) Authenticate(secret string) (*ClientConfig, error) {
	cfg := r.GetBySecret(secret)
	if cfg == nil {
		return nil, fmt.Errorf("invalid secret")
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("client disabled")
	}
	if cfg.IsExpired() {
		return nil, fmt.Errorf("client expired")
	}
	return cfg, nil
}

// AddConnection registers a new connection for a client
func (r *ClientRegistry) AddConnection(clientID string, conn net.Conn) error {
	r.mu.RLock()
	cfg := r.byID[clientID]
	r.mu.RUnlock()

	if cfg == nil {
		return fmt.Errorf("client not found")
	}
	// Before connMu: traffic may wait on r.mu, which a reload holds across a
	// Redis call, and nothing should wait on that while holding connMu.
	t := r.traffic(clientID)

	r.connMu.Lock()
	defer r.connMu.Unlock()

	// Check connection limit
	if cfg.MaxConns > 0 && r.activeConns[clientID] >= cfg.MaxConns {
		return fmt.Errorf("connection limit reached (%d)", cfg.MaxConns)
	}

	r.activeConns[clientID]++
	r.connsByID[clientID] = append(r.connsByID[clientID], conn)

	if t != nil {
		t.conns.Add(1)
		t.touch(time.Now())
	}

	return nil
}

// RemoveConnection unregisters a connection
func (r *ClientRegistry) RemoveConnection(clientID string, conn net.Conn) {
	r.lookupTraffic(clientID).touch(time.Now())

	r.connMu.Lock()
	defer r.connMu.Unlock()

	if r.activeConns[clientID] > 0 {
		r.activeConns[clientID]--
	}

	// Remove from connections list
	conns := r.connsByID[clientID]
	for i, c := range conns {
		if c == conn {
			r.connsByID[clientID] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
}

// SwapConn replaces oldConn with newConn in the connection list for clientID
// without changing the active-connections counter. Used by handlers that hand
// the socket over to kTLS after AddConnection has already registered the
// original *tls.Conn — so that subsequent forced-disconnect (Close) and
// voluntary RemoveConnection target the live socket wrapper, not the stale
// *tls.Conn.
//
// If oldConn is not currently registered for clientID, SwapConn is a no-op.
func (r *ClientRegistry) SwapConn(clientID string, oldConn, newConn net.Conn) {
	r.connMu.Lock()
	defer r.connMu.Unlock()

	conns := r.connsByID[clientID]
	for i, c := range conns {
		if c == oldConn {
			conns[i] = newConn
			r.connsByID[clientID] = conns
			return
		}
	}
}

// GetActiveConns returns number of active connections for a client
func (r *ClientRegistry) GetActiveConns(clientID string) int {
	r.connMu.RLock()
	defer r.connMu.RUnlock()
	return r.activeConns[clientID]
}

// traffic returns the live counters of a known client, creating them on first
// use, or nil for an id the registry does not know. Called once per session.
//
// The check and the creation happen under r.mu, so they cannot interleave with
// removeClient: counters are never created for a client that is being deleted.
func (r *ClientRegistry) traffic(clientID string) *clientTraffic {
	if t := r.lookupTraffic(clientID); t != nil {
		return t
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.byID[clientID] == nil {
		return nil
	}
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	t := r.trafficBy[clientID]
	if t == nil {
		t = newClientTraffic()
		r.trafficBy[clientID] = t
	}
	return t
}

// lookupTraffic returns the client's counters if they exist, without creating
// them.
func (r *ClientRegistry) lookupTraffic(clientID string) *clientTraffic {
	r.trafficMu.RLock()
	defer r.trafficMu.RUnlock()
	return r.trafficBy[clientID]
}

// AddBytes accounts a finished stream's payload bytes to a client.
func (r *ClientRegistry) AddBytes(clientID string, up, down int64) {
	r.traffic(clientID).addStream(up, down)
}

// GetStats returns what this server has seen of a client since it started:
// the numbers behind /stats, /clients/{id} and the per-client /metrics series.
// They are this server's own, so a Prometheus counter resets with the process
// and a sum over servers counts every byte once. The lifetime totals over all
// servers live in the store (FlushStats).
func (r *ClientRegistry) GetStats(clientID string) ClientStats {
	r.connMu.RLock()
	active := r.activeConns[clientID]
	r.connMu.RUnlock()

	stats := ClientStats{ClientID: clientID, ActiveConns: active}
	if t := r.lookupTraffic(clientID); t != nil {
		stats.TotalConns = t.conns.Load()
		stats.BytesUp = t.bytesUp.Load()
		stats.BytesDown = t.bytesDown.Load()
		if ns := t.lastSeen.Load(); ns != 0 {
			stats.LastSeen = time.Unix(0, ns)
		}
	}
	if active > 0 {
		// Connected right now.
		stats.LastSeen = time.Now()
	}
	return stats
}

// ListClients returns all registered clients
func (r *ClientRegistry) ListClients() []*ClientConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clients := make([]*ClientConfig, 0, len(r.byID))
	for _, cfg := range r.byID {
		clients = append(clients, cfg)
	}
	return clients
}

// ClientCount returns number of registered clients
func (r *ClientRegistry) ClientCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// statsFlushTimeout bounds one periodic flush, so a Redis that stopped
// answering cannot hold the flush, and the shutdown flush behind it, for
// clients x timeouts.
const statsFlushTimeout = 20 * time.Second

// FlushStats adds what this server saw since its last flush to each client's
// lifetime record in the store. Called every flush interval and once on
// shutdown.
//
// Deltas, added atomically by the store, so servers sharing one Redis add up
// instead of overwriting each other, and a restart neither loses the stored
// total nor needs to read it first. A delta that fails to reach the store is
// kept and goes out with the next flush. A client the store no longer has
// (deleted) gets nothing written back, and its counters are dropped.
func (r *ClientRegistry) FlushStats(ctx context.Context) error {
	if r.stats == nil {
		return nil
	}
	select {
	case r.flushSem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-r.flushSem }()

	r.trafficMu.RLock()
	snapshot := maps.Clone(r.trafficBy)
	r.trafficMu.RUnlock()

	type pending struct {
		t                     *clientTraffic
		conns, up, down, seen int64
	}
	var deltas []StatsDelta
	var sent []pending
	for clientID, t := range snapshot {
		p := pending{t: t, conns: t.conns.Load(), up: t.bytesUp.Load(), down: t.bytesDown.Load(), seen: t.lastSeen.Load()}
		if p.conns == t.flushedConns && p.up == t.flushedUp && p.down == t.flushedDown && p.seen == t.flushedSeen {
			r.pruneIdle(clientID, t)
			continue
		}
		d := StatsDelta{
			ClientID:    clientID,
			Conns:       p.conns - t.flushedConns,
			BytesUp:     p.up - t.flushedUp,
			BytesDown:   p.down - t.flushedDown,
			ActiveConns: r.GetActiveConns(clientID),
		}
		if p.seen != t.flushedSeen {
			d.LastSeen = time.Unix(0, p.seen)
		}
		deltas = append(deltas, d)
		sent = append(sent, p)
	}

	if len(deltas) == 0 {
		return nil
	}
	var failed int
	for i, err := range r.stats.AddStatsDeltas(ctx, deltas) {
		p, id := sent[i], deltas[i].ClientID
		switch {
		case errors.Is(err, errClientGone):
			r.dropTraffic(id, p.t)
		case err != nil:
			failed++
			if failed == 1 {
				log.Warn("Failed to flush stats for %s (and maybe others; retried next flush): %v", id, err)
			}
		default:
			p.t.flushedConns, p.t.flushedUp, p.t.flushedDown, p.t.flushedSeen = p.conns, p.up, p.down, p.seen
		}
	}
	if failed > 0 {
		return fmt.Errorf("stats flush: %d of %d clients not written", failed, len(deltas))
	}
	return nil
}

// pruneIdle drops the counters of a client the registry no longer has
// (deleted, disabled or expired) once everything they counted has been
// flushed and no connection of it is open. Caller holds flushSem.
func (r *ClientRegistry) pruneIdle(clientID string, t *clientTraffic) {
	if r.GetActiveConns(clientID) > 0 {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.byID[clientID] != nil {
		return
	}
	r.trafficMu.Lock()
	if r.trafficBy[clientID] == t {
		delete(r.trafficBy, clientID)
	}
	r.trafficMu.Unlock()
}

// dropTraffic drops the counters of a client the store no longer has.
func (r *ClientRegistry) dropTraffic(clientID string, t *clientTraffic) {
	r.trafficMu.Lock()
	if r.trafficBy[clientID] == t {
		delete(r.trafficBy, clientID)
	}
	r.trafficMu.Unlock()
}
