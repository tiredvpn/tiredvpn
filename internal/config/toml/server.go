package toml

import "fmt"

// ServerConfig is the root TOML schema for tiredvpn server.
type ServerConfig struct {
	Listen   ServerListen  `toml:"listen"`
	Strategy Strategy      `toml:"strategy"`
	Shaper   *ShaperConfig `toml:"shaper,omitempty"`
	TLS      ServerTLS     `toml:"tls"`
	Auth     ServerAuth    `toml:"auth"`
	Logging  Logging       `toml:"logging"`
}

// ServerListen describes the public-facing listen socket.
type ServerListen struct {
	Address string `toml:"address"`
	Port    int    `toml:"port"`
}

// ServerTLS holds inbound TLS material. CertFile/KeyFile must point to PEM.
type ServerTLS struct {
	CertFile     string   `toml:"cert_file"`
	KeyFile      string   `toml:"key_file"`
	ALPN         []string `toml:"alpn,omitempty"`
	ClientCAFile string   `toml:"client_ca_file,omitempty"`
}

// ServerAuth describes authentication policy for incoming clients.
type ServerAuth struct {
	Mode      string   `toml:"mode"`
	Tokens    []string `toml:"tokens,omitempty"`
	TokensFile string  `toml:"tokens_file,omitempty"`
}

// Validate runs semantic checks not enforced by TOML decoding alone.
func (c *ServerConfig) Validate() error {
	if c.Listen.Address == "" {
		return fmt.Errorf("listen.address is required")
	}
	if c.Listen.Port <= 0 || c.Listen.Port > 65535 {
		return fmt.Errorf("listen.port must be in 1..65535, got %d", c.Listen.Port)
	}
	if c.Strategy.Mode == "" {
		return fmt.Errorf("strategy.mode is required")
	}
	if c.TLS.CertFile == "" {
		return fmt.Errorf("tls.cert_file is required")
	}
	if c.TLS.KeyFile == "" {
		return fmt.Errorf("tls.key_file is required")
	}
	if c.Auth.Mode == "" {
		return fmt.Errorf("auth.mode is required")
	}
	if err := c.Shaper.validate(); err != nil {
		return err
	}
	return nil
}
