package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

// TunnelMode defines the tunneling strategy
type TunnelMode string

const (
	ModeGRPC      TunnelMode = "grpc"      // gRPC-over-TLS (googleapis.com mimic)
	ModeWebSocket TunnelMode = "ws"        // WebSocket tunnel
	ModeFragment  TunnelMode = "fragment"  // Fragmentation exploit
	ModeReality   TunnelMode = "reality"   // VLESS REALITY-like
	ModeFake      TunnelMode = "fake"      // Fake packet injection
	ModeCombo     TunnelMode = "combo"     // Combined strategies
)

// Config holds all configuration options
type Config struct {
	// Network settings
	ListenAddr string `json:"listen_addr"` // Local SOCKS5 address
	RemoteAddr string `json:"remote_addr"` // Remote tunnel server
	RemotePort int    `json:"remote_port"` // Remote port (default 443)

	// Tunnel mode
	Mode TunnelMode `json:"mode"`

	// TLS settings
	CoverSNI       string   `json:"cover_sni"`        // SNI to show to DPI
	SNIPool        []string `json:"sni_pool"`         // Pool of whitelisted SNIs for rotation
	TLSFingerprint string   `json:"tls_fingerprint"`  // Browser to mimic: chrome, firefox, safari
	ALPN           []string `json:"alpn"`             // ALPN protocols

	// Fake packet settings (for ModeFake)
	FakePacket FakePacketConfig `json:"fake_packet"`

	// Fragmentation settings (for ModeFragment)
	Fragment FragmentConfig `json:"fragment"`

	// gRPC settings (for ModeGRPC)
	GRPC GRPCConfig `json:"grpc"`

	// WebSocket settings (for ModeWebSocket)
	WebSocket WebSocketConfig `json:"websocket"`

	// Timing settings
	ConnectTimeout time.Duration `json:"connect_timeout"`
	ReadTimeout    time.Duration `json:"read_timeout"`
	WriteTimeout   time.Duration `json:"write_timeout"`

	// Misc
	Verbose bool `json:"verbose"`
}

// FakePacketConfig configures fake packet injection
type FakePacketConfig struct {
	Enabled       bool   `json:"enabled"`
	TTL           int    `json:"ttl"`            // TTL for fake packets (1-3)
	BadChecksum   bool   `json:"bad_checksum"`   // Send with invalid checksum
	BadSeq        bool   `json:"bad_seq"`        // Send with wrong sequence number
	FakeSNI       string `json:"fake_sni"`       // SNI in fake packet
	Count         int    `json:"count"`          // Number of fake packets
	Position      string `json:"position"`       // before, after, interleaved
}

// FragmentConfig configures TCP fragmentation
type FragmentConfig struct {
	Enabled         bool          `json:"enabled"`
	Size            int           `json:"size"`             // Fragment size (bytes)
	Delay           time.Duration `json:"delay"`            // Delay between fragments
	SplitPosition   int           `json:"split_position"`   // Where to split SNI
	BufferFlood     bool          `json:"buffer_flood"`     // Flood DPI buffer
	BufferFloodSize int           `json:"buffer_flood_size"` // Number of fake fragments (max 44)
}

// GRPCConfig configures gRPC tunnel
type GRPCConfig struct {
	ServiceName string            `json:"service_name"` // e.g., "google.firestore.v1.Firestore"
	MethodName  string            `json:"method_name"`  // e.g., "Listen"
	Headers     map[string]string `json:"headers"`      // Additional HTTP/2 headers
	Padding     bool              `json:"padding"`      // Add padding frames
}

// WebSocketConfig configures WebSocket tunnel
type WebSocketConfig struct {
	Path           string            `json:"path"`            // WS path, e.g., "/ws"
	Headers        map[string]string `json:"headers"`         // Custom headers
	Compression    bool              `json:"compression"`     // Enable permessage-deflate
	BinaryFrames   bool              `json:"binary_frames"`   // Use binary vs text frames
	PingInterval   time.Duration     `json:"ping_interval"`   // WebSocket ping interval
}

// DefaultConfig returns config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:     "127.0.0.1:1080",
		RemotePort:     443,
		Mode:           ModeGRPC,
		CoverSNI:       "google.com",
		TLSFingerprint: "chrome",
		ALPN:           []string{"h2", "http/1.1"},
		SNIPool: []string{
			"google.com",
			"www.google.com",
			"googleapis.com",
			"firebaseio.com",
			"gstatic.com",
			"youtube.com",
			"microsoft.com",
			"azure.com",
			"cloudflare.com",
			// Russian whitelisted (higher priority in RU)
			"yandex.ru",
			"vk.com",
			"mail.ru",
			"sberbank.ru",
			"gosuslugi.ru",
		},
		FakePacket: FakePacketConfig{
			Enabled:     true,
			TTL:         2,
			BadChecksum: true,
			BadSeq:      false,
			FakeSNI:     "yandex.ru",
			Count:       3,
			Position:    "before",
		},
		Fragment: FragmentConfig{
			Enabled:         false,
			Size:            2,
			Delay:           0,
			SplitPosition:   1, // Split after first byte of SNI
			BufferFlood:     false,
			BufferFloodSize: 40,
		},
		GRPC: GRPCConfig{
			ServiceName: "google.firestore.v1.Firestore",
			MethodName:  "Listen",
			Headers: map[string]string{
				"user-agent":    "grpc-go/1.59.0",
				"content-type":  "application/grpc",
				"grpc-encoding": "identity",
			},
			Padding: true,
		},
		WebSocket: WebSocketConfig{
			Path:         "/ws",
			BinaryFrames: true,
			PingInterval: 30 * time.Second,
			Headers: map[string]string{
				"Origin": "https://web.telegram.org",
			},
		},
		ConnectTimeout: 10 * time.Second,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		Verbose:        false,
	}
}

// LoadFromFile loads config from JSON file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes config to file
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Validate checks config validity
func (c *Config) Validate() error {
	if c.RemoteAddr == "" {
		return errors.New("remote_addr is required")
	}

	if c.CoverSNI == "" {
		return errors.New("cover_sni is required")
	}

	switch c.Mode {
	case ModeGRPC, ModeWebSocket, ModeFragment, ModeReality, ModeFake, ModeCombo:
		// Valid modes
	default:
		return errors.New("invalid tunnel mode")
	}

	if c.FakePacket.Enabled {
		if c.FakePacket.TTL < 1 || c.FakePacket.TTL > 10 {
			return errors.New("fake packet TTL must be 1-10")
		}
	}

	if c.Fragment.Enabled {
		if c.Fragment.BufferFloodSize > 44 {
			return errors.New("buffer flood size must be <= 44 (TSPU limit is 45)")
		}
	}

	return nil
}
