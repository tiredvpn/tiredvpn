package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// IPLease represents an IP address lease
type IPLease struct {
	IP        string    `json:"ip"`
	ClientID  string    `json:"client_id"`  // Client secret hash or identifier
	Hostname  string    `json:"hostname"`   // Optional client hostname
	LeasedAt  time.Time `json:"leased_at"`
	ExpiresAt time.Time `json:"expires_at"` // Zero = permanent (static assignment)
	Static    bool      `json:"static"`     // True if client requested specific IP
}

// IPPoolConfig configures the IP pool
type IPPoolConfig struct {
	// Network is the CIDR range for the pool (e.g., "10.8.0.0/24")
	Network string

	// ServerIP is the server's IP in the pool (excluded from allocation)
	ServerIP string

	// LeaseTime is the default lease duration (0 = permanent)
	LeaseTime time.Duration

	// ReservedIPs are IPs that should not be allocated (besides ServerIP)
	ReservedIPs []string
}

// IPPool manages IP address allocation for TUN clients
type IPPool struct {
	config     IPPoolConfig
	network    *net.IPNet
	serverIP   net.IP
	startIP    uint32 // First allocatable IP
	endIP      uint32 // Last allocatable IP
	reserved   map[uint32]bool
	mu         sync.RWMutex

	// Backend storage
	redis   *redis.Client
	leases  map[string]*IPLease // In-memory: IP -> Lease
	byClient map[string]string   // In-memory: ClientID -> IP
}

// NewIPPool creates a new IP pool manager
func NewIPPool(cfg IPPoolConfig, redisClient *redis.Client) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cfg.Network)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}

	serverIP := net.ParseIP(cfg.ServerIP)
	if serverIP == nil {
		return nil, fmt.Errorf("invalid server IP: %s", cfg.ServerIP)
	}
	serverIP = serverIP.To4()
	if serverIP == nil {
		return nil, fmt.Errorf("server IP must be IPv4: %s", cfg.ServerIP)
	}

	// Calculate IP range
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	networkIP := binary.BigEndian.Uint32(network.IP.To4())
	broadcastIP := networkIP | (0xFFFFFFFF >> ones)

	// Allocatable range: network+1 to broadcast-1
	startIP := networkIP + 1
	endIP := broadcastIP - 1

	// Build reserved set
	reserved := make(map[uint32]bool)
	reserved[networkIP] = true                              // Network address
	reserved[broadcastIP] = true                            // Broadcast
	reserved[binary.BigEndian.Uint32(serverIP)] = true      // Server IP

	for _, r := range cfg.ReservedIPs {
		ip := net.ParseIP(r)
		if ip != nil {
			reserved[binary.BigEndian.Uint32(ip.To4())] = true
		}
	}

	pool := &IPPool{
		config:    cfg,
		network:   network,
		serverIP:  serverIP,
		startIP:   startIP,
		endIP:     endIP,
		reserved:  reserved,
		redis:     redisClient,
		leases:    make(map[string]*IPLease),
		byClient:  make(map[string]string),
	}

	// Load existing leases
	if err := pool.loadLeases(); err != nil {
		log.Warn("Failed to load IP leases: %v", err)
	}

	poolSize := int(endIP - startIP + 1) - len(reserved)
	log.Info("IP Pool initialized: %s (size=%d, server=%s)", cfg.Network, poolSize, cfg.ServerIP)

	return pool, nil
}

// redisKey returns Redis key for IP lease
func (p *IPPool) redisKey(ip string) string {
	return "tiredvpn:ippool:" + ip
}

// redisClientKey returns Redis key for client->IP mapping
func (p *IPPool) redisClientKey(clientID string) string {
	return "tiredvpn:ippool:client:" + clientID
}

// loadLeases loads existing leases from Redis or initializes empty
func (p *IPPool) loadLeases() error {
	if p.redis == nil {
		return nil // In-memory only
	}

	ctx := context.Background()
	pattern := "tiredvpn:ippool:10.*"
	keys, err := p.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	for _, key := range keys {
		data, err := p.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var lease IPLease
		if err := json.Unmarshal(data, &lease); err != nil {
			continue
		}

		// Check if expired
		if !lease.ExpiresAt.IsZero() && time.Now().After(lease.ExpiresAt) {
			p.redis.Del(ctx, key)
			continue
		}

		p.leases[lease.IP] = &lease
		if lease.ClientID != "" {
			p.byClient[lease.ClientID] = lease.IP
		}
	}

	log.Info("Loaded %d IP leases from Redis", len(p.leases))
	return nil
}

// saveLease saves lease to storage
func (p *IPPool) saveLease(lease *IPLease) error {
	// Always save to memory
	p.leases[lease.IP] = lease
	if lease.ClientID != "" {
		p.byClient[lease.ClientID] = lease.IP
	}

	// Save to Redis if available
	if p.redis != nil {
		ctx := context.Background()
		data, err := json.Marshal(lease)
		if err != nil {
			return err
		}

		var ttl time.Duration
		if !lease.ExpiresAt.IsZero() {
			ttl = time.Until(lease.ExpiresAt)
			if ttl < 0 {
				ttl = 0
			}
		}

		if err := p.redis.Set(ctx, p.redisKey(lease.IP), data, ttl).Err(); err != nil {
			return err
		}

		// Also save client->IP mapping
		if lease.ClientID != "" {
			p.redis.Set(ctx, p.redisClientKey(lease.ClientID), lease.IP, ttl)
		}
	}

	return nil
}

// deleteLease removes lease from storage
func (p *IPPool) deleteLease(ip string) {
	if lease, ok := p.leases[ip]; ok {
		if lease.ClientID != "" {
			delete(p.byClient, lease.ClientID)
		}
		delete(p.leases, ip)
	}

	if p.redis != nil {
		ctx := context.Background()
		p.redis.Del(ctx, p.redisKey(ip))
	}
}

// Allocate allocates an IP address for a client
// If requestedIP is provided and available, it will be used
// If clientID already has a lease, returns existing IP
// Otherwise allocates a new IP from the pool
func (p *IPPool) Allocate(clientID string, requestedIP net.IP, hostname string) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if client already has a lease
	if existingIP, ok := p.byClient[clientID]; ok {
		lease := p.leases[existingIP]
		if lease != nil && (lease.ExpiresAt.IsZero() || time.Now().Before(lease.ExpiresAt)) {
			// Renew lease
			if p.config.LeaseTime > 0 {
				lease.ExpiresAt = time.Now().Add(p.config.LeaseTime)
				p.saveLease(lease)
			}
			log.Debug("Renewed existing lease for client %s: %s", clientID, existingIP)
			return net.ParseIP(existingIP), nil
		}
	}

	// If client requested a specific IP
	if requestedIP != nil && requestedIP.To4() != nil {
		requestedIP = requestedIP.To4()
		ipUint := binary.BigEndian.Uint32(requestedIP)

		// Check if in our network
		if p.network.Contains(requestedIP) {
			// Check if not reserved
			if !p.reserved[ipUint] {
				ipStr := requestedIP.String()
				// Check if available or already owned by this client
				if existingLease, ok := p.leases[ipStr]; !ok || existingLease.ClientID == clientID {
					// Allocate requested IP
					lease := &IPLease{
						IP:       ipStr,
						ClientID: clientID,
						Hostname: hostname,
						LeasedAt: time.Now(),
						Static:   true,
					}

					// For Redis clients, static IPs are also permanent
					if clientID != "" && p.redis != nil {
						lease.ExpiresAt = time.Time{} // permanent
						log.Info("Allocated permanent static IP %s to Redis client %s", ipStr, clientID)
					} else {
						if p.config.LeaseTime > 0 {
							lease.ExpiresAt = time.Now().Add(p.config.LeaseTime)
						}
						log.Info("Allocated static IP %s to client %s", ipStr, clientID)
					}

					if err := p.saveLease(lease); err != nil {
						return nil, err
					}
					return requestedIP, nil
				}
				log.Debug("Requested IP %s is already in use", ipStr)
			}
		}
	}

	// Find a free IP
	for ipUint := p.startIP; ipUint <= p.endIP; ipUint++ {
		if p.reserved[ipUint] {
			continue
		}

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipUint)
		ipStr := ip.String()

		// Check if already leased
		if lease, ok := p.leases[ipStr]; ok {
			// Check if lease expired
			if !lease.ExpiresAt.IsZero() && time.Now().After(lease.ExpiresAt) {
				// Expired, can reuse
				p.deleteLease(ipStr)
			} else {
				continue // Still valid
			}
		}

		// Found free IP
		lease := &IPLease{
			IP:       ipStr,
			ClientID: clientID,
			Hostname: hostname,
			LeasedAt: time.Now(),
			Static:   false,
		}

		// For clients with Redis secret (clientID != ""), assign permanent IP
		// This prevents pool exhaustion on frequent reconnects
		if clientID != "" && p.redis != nil {
			// Permanent lease - never expires
			lease.ExpiresAt = time.Time{} // zero time = permanent
			log.Info("Allocated permanent IP %s to Redis client %s", ipStr, clientID)
		} else {
			// Legacy behavior: temporary lease
			if p.config.LeaseTime > 0 {
				lease.ExpiresAt = time.Now().Add(p.config.LeaseTime)
			}
			log.Info("Allocated temporary IP %s to client %s", ipStr, clientID)
		}

		if err := p.saveLease(lease); err != nil {
			return nil, err
		}
		return ip, nil
	}

	return nil, fmt.Errorf("IP pool exhausted")
}

// Release releases an IP address back to the pool
func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()
	if lease, ok := p.leases[ipStr]; ok {
		// Don't release static assignments
		if lease.Static {
			log.Debug("Not releasing static IP %s", ipStr)
			return
		}

		// Don't release permanent leases (Redis clients with secrets)
		// These clients need the same IP on reconnect
		if lease.ClientID != "" && p.redis != nil && lease.ExpiresAt.IsZero() {
			log.Debug("Not releasing permanent IP %s for Redis client %s", ipStr, lease.ClientID)
			return
		}

		p.deleteLease(ipStr)
		log.Info("Released IP %s", ipStr)
	}
}

// ReleaseByClient releases IP for a specific client
func (p *IPPool) ReleaseByClient(clientID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ipStr, ok := p.byClient[clientID]; ok {
		if lease, ok := p.leases[ipStr]; ok {
			// Don't release static assignments
			if lease.Static {
				log.Debug("Not releasing static IP %s for client %s", ipStr, clientID)
				return
			}

			// Don't release permanent leases (Redis clients)
			if clientID != "" && p.redis != nil && lease.ExpiresAt.IsZero() {
				log.Debug("Not releasing permanent IP %s for Redis client %s", ipStr, clientID)
				return
			}

			p.deleteLease(ipStr)
			log.Info("Released IP %s for client %s", ipStr, clientID)
		}
	}
}

// GetLease returns the lease for an IP address
func (p *IPPool) GetLease(ip net.IP) *IPLease {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.leases[ip.String()]
}

// GetClientIP returns the IP address for a client
func (p *IPPool) GetClientIP(clientID string) net.IP {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if ipStr, ok := p.byClient[clientID]; ok {
		return net.ParseIP(ipStr)
	}
	return nil
}

// ListLeases returns all active leases
func (p *IPPool) ListLeases() []*IPLease {
	p.mu.RLock()
	defer p.mu.RUnlock()

	leases := make([]*IPLease, 0, len(p.leases))
	for _, lease := range p.leases {
		if lease.ExpiresAt.IsZero() || time.Now().Before(lease.ExpiresAt) {
			leases = append(leases, lease)
		}
	}
	return leases
}

// Stats returns pool statistics
func (p *IPPool) Stats() (total, used, available int) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total = int(p.endIP - p.startIP + 1) - len(p.reserved)
	used = len(p.leases)
	available = total - used
	return
}

// CleanupExpired removes expired leases
func (p *IPPool) CleanupExpired() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for ip, lease := range p.leases {
		if !lease.ExpiresAt.IsZero() && now.After(lease.ExpiresAt) {
			p.deleteLease(ip)
			cleaned++
		}
	}

	if cleaned > 0 {
		log.Info("Cleaned up %d expired IP leases", cleaned)
	}
	return cleaned
}

// StartCleanupRoutine starts a background routine to clean expired leases
func (p *IPPool) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.CleanupExpired()
			}
		}
	}()
}
