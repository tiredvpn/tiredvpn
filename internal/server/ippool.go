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

// dynamicLeaseTTL is the fallback lease duration applied to every dynamically
// allocated (non-static, sticky-renewed, or auto-assigned) lease when the pool
// is configured with LeaseTime == 0 (permanent). Without a finite TTL such
// leases would never be reclaimed by CleanupExpired: the TUN disconnect path
// deliberately does NOT Release() the IP (so a fast reconnect gets the same IP
// via stickyLookup), so the ONLY reclaim path for an abandoned dynamic lease is
// TTL expiry. The value is intentionally generous: it must comfortably outlast
// the longest expected client outage (port hopping, mobile network drops) so a
// reconnect within the window still lands on the same IP, while still bounding
// pool growth from clients that never come back.
const dynamicLeaseTTL = 24 * time.Hour

// IPLease represents an IP address lease
type IPLease struct {
	IP        string    `json:"ip"`
	ClientID  string    `json:"client_id"` // Client secret hash or identifier
	Hostname  string    `json:"hostname"`  // Optional client hostname
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

	// NetworkV6 is the optional IPv6 ULA prefix for dual-stack TUN clients
	// (e.g., "fd00:10:8::/64"). Empty = IPv4-only pool. No leases are ever
	// stored for v6: a client's v6 address is derived deterministically from
	// its v4 lease (see ClientIP6), so the Redis schema stays untouched.
	NetworkV6 string
}

// IPPool manages IP address allocation for TUN clients
type IPPool struct {
	config   IPPoolConfig
	network  *net.IPNet
	serverIP net.IP
	startIP  uint32 // First allocatable IP
	endIP    uint32 // Last allocatable IP
	reserved map[uint32]bool
	mu       sync.RWMutex

	// networkV6 is the parsed dual-stack prefix, nil when the pool is
	// IPv4-only. Immutable after construction.
	networkV6 *net.IPNet

	// Backend storage
	redis    *redis.Client
	leases   map[string]*IPLease // In-memory: IP -> Lease
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

	// Optional dual-stack prefix. Validated here (fails server startup via
	// initIPPool) rather than per-client so a bad -ip-pool-v6 is caught at
	// boot instead of silently degrading to IPv4-only handshakes.
	networkV6, err := parsePoolV6(cfg.NetworkV6)
	if err != nil {
		return nil, err
	}

	networkIP := binary.BigEndian.Uint32(network.IP.To4())
	broadcastIP := networkIP | (0xFFFFFFFF >> ones)

	// Allocatable range: network+1 to broadcast-1
	startIP := networkIP + 1
	endIP := broadcastIP - 1

	// Build reserved set
	reserved := make(map[uint32]bool)
	reserved[networkIP] = true                         // Network address
	reserved[broadcastIP] = true                       // Broadcast
	reserved[binary.BigEndian.Uint32(serverIP)] = true // Server IP

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
		networkV6: networkV6,
		redis:     redisClient,
		leases:    make(map[string]*IPLease),
		byClient:  make(map[string]string),
	}

	// Load existing leases
	if err := pool.loadLeases(); err != nil {
		log.Warn("Failed to load IP leases: %v", err)
	}

	poolSize := int(endIP-startIP+1) - len(reserved)
	if networkV6 != nil {
		log.Info("IP Pool initialized: %s (size=%d, server=%s) + dual-stack %s (server=%s)",
			cfg.Network, poolSize, cfg.ServerIP, networkV6, pool.ServerIP6())
	} else {
		log.Info("IP Pool initialized: %s (size=%d, server=%s)", cfg.Network, poolSize, cfg.ServerIP)
	}

	return pool, nil
}

// parsePoolV6 parses and validates the optional dual-stack prefix. Returns
// (nil, nil) for an empty pool. The prefix must be an IPv6 CIDR with a host
// part of at least 32 bits (prefix length <= 96) so a client's IPv4 address
// can be embedded losslessly in the low 32 bits of its derived IPv6 address.
func parsePoolV6(cidr string) (*net.IPNet, error) {
	if cidr == "" {
		return nil, nil
	}
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv6 pool %q: %w", cidr, err)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("IPv6 pool %q is not an IPv6 CIDR", cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("IPv6 pool %q is not an IPv6 CIDR", cidr)
	}
	if ones > 96 {
		return nil, fmt.Errorf("IPv6 pool %q prefix length /%d leaves <32 host bits; need /96 or shorter to embed client IPv4 addresses", cidr, ones)
	}
	return &net.IPNet{IP: network.IP.To16(), Mask: network.Mask}, nil
}

// deriveServerIP6 returns the server's address inside the dual-stack prefix:
// prefix::1. This is THE single derivation rule for the whole server — the
// pool, the handshake and the TUN setup all go through here.
func deriveServerIP6(prefix *net.IPNet) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, prefix.IP.To16())
	ip[net.IPv6len-1] = 1
	return ip
}

// deriveClientIP6 returns a client's address inside the dual-stack prefix:
// the prefix with the client's IPv4 address embedded in the low 32 bits
// (prefix | v4-uint32). The mapping is injective, so the packet dispatcher
// can recover the v4 lease key (and thus the client registry entry) from the
// low 32 bits of any pool-v6 destination. A nil/non-v4 clientIP yields
// prefix::2 as a safe fallback.
func deriveClientIP6(prefix *net.IPNet, clientIP net.IP) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, prefix.IP.To16())
	if v4 := clientIP.To4(); v4 != nil {
		copy(ip[12:], v4)
	} else {
		ip[net.IPv6len-1] = 2
	}
	return ip
}

// DualStack reports whether the pool hands out derived IPv6 tunnel addresses
// in addition to IPv4 leases.
func (p *IPPool) DualStack() bool {
	return p.networkV6 != nil
}

// V6Prefix returns the dual-stack prefix (masked network), or nil for an
// IPv4-only pool. Callers must not mutate the returned value.
func (p *IPPool) V6Prefix() *net.IPNet {
	return p.networkV6
}

// ServerIP6 returns the server's tunnel IPv6 address (prefix::1), or nil for
// an IPv4-only pool.
func (p *IPPool) ServerIP6() net.IP {
	if p.networkV6 == nil {
		return nil
	}
	return deriveServerIP6(p.networkV6)
}

// ClientIP6 derives the tunnel IPv6 address for the client holding the given
// IPv4 lease (prefix with the v4 address in the low 32 bits), or nil for an
// IPv4-only pool.
func (p *IPPool) ClientIP6(clientIPv4 net.IP) net.IP {
	if p.networkV6 == nil {
		return nil
	}
	return deriveClientIP6(p.networkV6, clientIPv4)
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

// stickyLookup returns the IP previously assigned to clientID, or "" if none.
// It checks the in-memory map first and falls back to the persisted Redis
// clientID->IP mapping so reconnects survive a server restart. Caller must hold
// p.mu. A Redis hit is folded back into the in-memory map for subsequent calls.
func (p *IPPool) stickyLookup(clientID string) string {
	if ip, ok := p.byClient[clientID]; ok {
		return ip
	}
	if p.redis == nil {
		return ""
	}
	ctx := context.Background()
	ip, err := p.redis.Get(ctx, p.redisClientKey(clientID)).Result()
	if err != nil || ip == "" {
		return ""
	}
	// Validate the mapping still resolves to a live lease owned by this client.
	if data, err := p.redis.Get(ctx, p.redisKey(ip)).Bytes(); err == nil {
		var lease IPLease
		if json.Unmarshal(data, &lease) == nil && lease.ClientID == clientID {
			p.leases[ip] = &lease
		}
	}
	p.byClient[clientID] = ip
	return ip
}

// Allocate allocates an IP address for a client
// If requestedIP is provided and available, it will be used
// If clientID already has a lease, returns existing IP
// Otherwise allocates a new IP from the pool
func (p *IPPool) Allocate(clientID string, requestedIP net.IP, hostname string) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Sticky lookup: a client that reconnects must get the SAME IP it had before,
	// otherwise the client tears down and rebuilds its TUN address on every
	// reconnect and L3 routes flap. We first consult the in-memory map and, on a
	// miss (e.g. after a server restart that cleared memory but not Redis), fall
	// back to the persisted clientID->IP mapping in Redis.
	if clientID != "" {
		if existingIP := p.stickyLookup(clientID); existingIP != "" {
			lease := p.leases[existingIP]
			if lease == nil {
				// Recover a lease record we know about from Redis but lost from memory.
				lease = &IPLease{
					IP:       existingIP,
					ClientID: clientID,
					Hostname: hostname,
					LeasedAt: time.Now(),
				}
			}
			if lease.ExpiresAt.IsZero() || time.Now().Before(lease.ExpiresAt) {
				// Renew/refresh the lease so it does not expire mid-session.
				if !lease.ExpiresAt.IsZero() {
					if p.config.LeaseTime > 0 {
						lease.ExpiresAt = time.Now().Add(p.config.LeaseTime)
					} else {
						lease.ExpiresAt = time.Now().Add(dynamicLeaseTTL)
					}
				}
				if err := p.saveLease(lease); err != nil {
					log.Warn("Failed to persist sticky lease for client %s: %v", clientID, err)
				}
				log.Debug("Sticky lease for client %s: %s", clientID, existingIP)
				return net.ParseIP(existingIP), nil
			}
		}
	}

	// If client requested a specific IP
	if requestedIP != nil && requestedIP.To4() != nil {
		requestedIP = requestedIP.To4()
		ipUint := binary.BigEndian.Uint32(requestedIP)

		// Check if in our network
		if !p.network.Contains(requestedIP) {
			// Out-of-network request: never honor it (it would be unroutable on
			// the shared TUN). Fall through to auto-allocation, but log it so the
			// misconfiguration is visible instead of silently picking a random IP.
			log.Warn("Requested IP %s is outside pool network %s; ignoring and auto-allocating for client %s",
				requestedIP.String(), p.config.Network, clientID)
		} else {
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
				// Collision: the requested IP is held by a DIFFERENT clientID. We
				// must NOT hand it out twice, so we fall through to auto-allocation
				// (the caller gets a different, free IP). Surface this at Warn with
				// both clientIDs so a real collision is visible in prod rather than
				// being swallowed at Debug level.
				owner := "<unknown>"
				if existingLease, ok := p.leases[ipStr]; ok {
					owner = existingLease.ClientID
				}
				log.Warn("Requested IP %s already leased to client %s; client %s will be auto-allocated a different IP",
					ipStr, owner, clientID)
			} else {
				log.Warn("Requested IP %s is reserved; auto-allocating for client %s",
					requestedIP.String(), clientID)
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

		// Dynamic leases ALWAYS carry a finite TTL so CleanupExpired can reclaim
		// them. When LeaseTime == 0 (permanent) we fall back to dynamicLeaseTTL
		// instead of leaving ExpiresAt zero, otherwise auto-allocated leases on
		// the Morph/Confusion/H2/Polling paths (which never call Release) would
		// be permanent and leak the pool to exhaustion under frequent reconnects.
		if p.config.LeaseTime > 0 {
			lease.ExpiresAt = time.Now().Add(p.config.LeaseTime)
		} else {
			lease.ExpiresAt = time.Now().Add(dynamicLeaseTTL)
		}
		log.Info("Allocated IP %s to client %s", ipStr, clientID)

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

	total = int(p.endIP-p.startIP+1) - len(p.reserved)
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
