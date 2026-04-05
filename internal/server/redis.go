package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ClientConfig holds client configuration stored in Redis
type ClientConfig struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Secret       string    `json:"secret"`        // 64-char hex secret
	TunIP        string    `json:"tun_ip"`        // e.g., "10.8.0.2" (optional for TUN mode)
	MaxConns     int       `json:"max_conns"`     // 0 = unlimited
	MaxBandwidth int64     `json:"max_bandwidth"` // bytes/sec, 0 = unlimited
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"` // zero = never
}

// IsExpired checks if client has expired
func (c *ClientConfig) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// ClientStats holds runtime statistics for a client
type ClientStats struct {
	ClientID    string    `json:"client_id"`
	ActiveConns int       `json:"active_conns"`
	TotalConns  int64     `json:"total_conns"`
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
	LastSeen    time.Time `json:"last_seen"`
}

// RedisStore manages client data in Redis
type RedisStore struct {
	client *redis.Client
	prefix string // default: "tiredvpn:"
}

// NewRedisStore creates a new Redis store.
// Set REDIS_PASSWORD env variable to authenticate with Redis.
func NewRedisStore(addr string) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	log.Info("Connected to Redis at %s", addr)

	return &RedisStore{
		client: client,
		prefix: "tiredvpn:",
	}, nil
}

// Close closes the Redis connection
func (r *RedisStore) Close() error {
	return r.client.Close()
}

// key helpers
func (r *RedisStore) clientKey(id string) string {
	return r.prefix + "clients:" + id
}

func (r *RedisStore) secretIndexKey(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return r.prefix + "secrets:" + hex.EncodeToString(hash[:16])
}

func (r *RedisStore) statsKey(clientID string) string {
	return r.prefix + "stats:" + clientID
}

// GenerateSecret creates a cryptographically secure 64-char hex secret
func GenerateSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate secret: %v", err))
	}
	return hex.EncodeToString(b)
}

// CreateClient creates a new client with generated secret
func (r *RedisStore) CreateClient(ctx context.Context, name, tunIP string, maxConns int, expiresIn time.Duration) (*ClientConfig, error) {
	cfg := &ClientConfig{
		ID:        uuid.New().String(),
		Name:      name,
		Secret:    GenerateSecret(),
		TunIP:     tunIP,
		MaxConns:  maxConns,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	if expiresIn > 0 {
		cfg.ExpiresAt = time.Now().Add(expiresIn)
	}

	if err := r.SaveClient(ctx, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveClient saves client config to Redis
func (r *RedisStore) SaveClient(ctx context.Context, cfg *ClientConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal client: %w", err)
	}

	pipe := r.client.Pipeline()

	// Save client data
	pipe.Set(ctx, r.clientKey(cfg.ID), data, 0)

	// Create secret index
	pipe.Set(ctx, r.secretIndexKey(cfg.Secret), cfg.ID, 0)

	// Increment version for hot-reload detection
	pipe.Incr(ctx, r.prefix+"version")

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("save client: %w", err)
	}

	log.Info("Saved client: %s (%s)", cfg.Name, cfg.ID)
	return nil
}

// GetClient retrieves client by ID
func (r *RedisStore) GetClient(ctx context.Context, id string) (*ClientConfig, error) {
	data, err := r.client.Get(ctx, r.clientKey(id)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal client: %w", err)
	}

	return &cfg, nil
}

// GetClientBySecret retrieves client by secret (O(1) lookup via index)
func (r *RedisStore) GetClientBySecret(ctx context.Context, secret string) (*ClientConfig, error) {
	clientID, err := r.client.Get(ctx, r.secretIndexKey(secret)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup secret: %w", err)
	}

	return r.GetClient(ctx, clientID)
}

// DeleteClient removes a client
func (r *RedisStore) DeleteClient(ctx context.Context, id string) error {
	// First get the client to find its secret
	cfg, err := r.GetClient(ctx, id)
	if err != nil {
		return err
	}
	if cfg == nil {
		return nil // Already deleted
	}

	pipe := r.client.Pipeline()

	// Delete client data
	pipe.Del(ctx, r.clientKey(id))

	// Delete secret index
	pipe.Del(ctx, r.secretIndexKey(cfg.Secret))

	// Delete stats
	pipe.Del(ctx, r.statsKey(id))

	// Increment version
	pipe.Incr(ctx, r.prefix+"version")

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}

	log.Info("Deleted client: %s (%s)", cfg.Name, id)
	return nil
}

// ListClients returns all clients
func (r *RedisStore) ListClients(ctx context.Context) ([]*ClientConfig, error) {
	pattern := r.prefix + "clients:*"
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}

	if len(keys) == 0 {
		return []*ClientConfig{}, nil
	}

	// Get all client data in one call
	data, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("mget clients: %w", err)
	}

	clients := make([]*ClientConfig, 0, len(data))
	for _, d := range data {
		if d == nil {
			continue
		}
		var cfg ClientConfig
		if err := json.Unmarshal([]byte(d.(string)), &cfg); err != nil {
			log.Warn("Failed to unmarshal client: %v", err)
			continue
		}
		clients = append(clients, &cfg)
	}

	return clients, nil
}

// UpdateStats updates client statistics
func (r *RedisStore) UpdateStats(ctx context.Context, clientID string, stats *ClientStats) error {
	data, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("marshal stats: %w", err)
	}

	return r.client.Set(ctx, r.statsKey(clientID), data, 0).Err()
}

// GetStats retrieves client statistics
func (r *RedisStore) GetStats(ctx context.Context, clientID string) (*ClientStats, error) {
	data, err := r.client.Get(ctx, r.statsKey(clientID)).Bytes()
	if err == redis.Nil {
		return &ClientStats{ClientID: clientID}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}

	var stats ClientStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, fmt.Errorf("unmarshal stats: %w", err)
	}

	return &stats, nil
}

// GetVersion returns current data version (for hot-reload detection)
func (r *RedisStore) GetVersion(ctx context.Context) (int64, error) {
	return r.client.Get(ctx, r.prefix+"version").Int64()
}

// Subscribe subscribes to client changes via Redis keyspace notifications
func (r *RedisStore) Subscribe(ctx context.Context, onChange func(event, clientID string)) error {
	// Enable keyspace notifications if not already enabled
	r.client.ConfigSet(ctx, "notify-keyspace-events", "KEA")

	pattern := "__keyspace@0__:" + r.prefix + "clients:*"
	pubsub := r.client.PSubscribe(ctx, pattern)

	go func() {
		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				pubsub.Close()
				return
			case msg := <-ch:
				if msg == nil {
					continue
				}
				// Extract client ID from channel name
				// Channel: __keyspace@0__:tiredvpn:clients:uuid
				parts := strings.Split(msg.Channel, ":")
				if len(parts) >= 4 {
					clientID := parts[len(parts)-1]
					event := msg.Payload // "set", "del", etc.
					log.Debug("Redis notification: %s on client %s", event, clientID)
					onChange(event, clientID)
				}
			}
		}
	}()

	log.Info("Subscribed to Redis keyspace notifications")
	return nil
}

// Client returns the underlying Redis client
func (r *RedisStore) Client() *redis.Client {
	return r.client
}
