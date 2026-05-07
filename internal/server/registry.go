package server

import (
	"context"
	"fmt"
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

	// Stats (atomic for performance)
	totalConns map[string]*int64 // clientID → total connections counter
	bytesUp    map[string]*int64
	bytesDown  map[string]*int64

	// Hot-reload
	lastVersion int64
	stopReload  chan struct{}
}

// NewClientRegistry creates a new client registry
func NewClientRegistry(store *RedisStore) *ClientRegistry {
	return &ClientRegistry{
		store:       store,
		byID:        make(map[string]*ClientConfig),
		bySecret:    make(map[string]*ClientConfig),
		activeConns: make(map[string]int),
		connsByID:   make(map[string][]net.Conn),
		totalConns:  make(map[string]*int64),
		bytesUp:     make(map[string]*int64),
		bytesDown:   make(map[string]*int64),
		stopReload:  make(chan struct{}),
	}
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

			// Initialize stats counters
			if r.totalConns[cfg.ID] == nil {
				var zero int64
				r.totalConns[cfg.ID] = &zero
				r.bytesUp[cfg.ID] = &zero
				r.bytesDown[cfg.ID] = &zero
			}
		}
	}

	v, _ := r.store.GetVersion(ctx)
	r.lastVersion = v

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

	// Remove old secret mapping if exists
	if old, exists := r.byID[clientID]; exists {
		delete(r.bySecret, old.Secret)
	}

	if cfg != nil && cfg.Enabled && !cfg.IsExpired() {
		r.byID[cfg.ID] = cfg
		r.bySecret[cfg.Secret] = cfg

		// Initialize stats counters
		if r.totalConns[cfg.ID] == nil {
			var zero int64
			r.totalConns[cfg.ID] = &zero
			r.bytesUp[cfg.ID] = &zero
			r.bytesDown[cfg.ID] = &zero
		}

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
	r.mu.Unlock()

	// Close all active connections for this client
	r.connMu.Lock()
	conns := r.connsByID[clientID]
	delete(r.connsByID, clientID)
	delete(r.activeConns, clientID)
	r.connMu.Unlock()

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

	r.connMu.Lock()
	defer r.connMu.Unlock()

	// Check connection limit
	if cfg.MaxConns > 0 && r.activeConns[clientID] >= cfg.MaxConns {
		return fmt.Errorf("connection limit reached (%d)", cfg.MaxConns)
	}

	r.activeConns[clientID]++
	r.connsByID[clientID] = append(r.connsByID[clientID], conn)

	// Increment total connections counter
	if counter := r.totalConns[clientID]; counter != nil {
		atomic.AddInt64(counter, 1)
	}

	return nil
}

// RemoveConnection unregisters a connection
func (r *ClientRegistry) RemoveConnection(clientID string, conn net.Conn) {
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

// AddBytes tracks bandwidth usage
func (r *ClientRegistry) AddBytes(clientID string, up, down int64) {
	if counter := r.bytesUp[clientID]; counter != nil {
		atomic.AddInt64(counter, up)
	}
	if counter := r.bytesDown[clientID]; counter != nil {
		atomic.AddInt64(counter, down)
	}
}

// GetStats returns statistics for a client
func (r *ClientRegistry) GetStats(clientID string) ClientStats {
	r.connMu.RLock()
	active := r.activeConns[clientID]
	r.connMu.RUnlock()

	var total, up, down int64
	if counter := r.totalConns[clientID]; counter != nil {
		total = atomic.LoadInt64(counter)
	}
	if counter := r.bytesUp[clientID]; counter != nil {
		up = atomic.LoadInt64(counter)
	}
	if counter := r.bytesDown[clientID]; counter != nil {
		down = atomic.LoadInt64(counter)
	}

	return ClientStats{
		ClientID:    clientID,
		ActiveConns: active,
		TotalConns:  total,
		BytesUp:     up,
		BytesDown:   down,
		LastSeen:    time.Now(),
	}
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

// FlushStats saves all stats to Redis (call periodically)
func (r *ClientRegistry) FlushStats(ctx context.Context) error {
	r.mu.RLock()
	clients := make([]string, 0, len(r.byID))
	for id := range r.byID {
		clients = append(clients, id)
	}
	r.mu.RUnlock()

	for _, clientID := range clients {
		stats := r.GetStats(clientID)
		if err := r.store.UpdateStats(ctx, clientID, &stats); err != nil {
			log.Warn("Failed to flush stats for %s: %v", clientID, err)
		}
	}

	return nil
}
