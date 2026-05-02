package toml

import "fmt"

// ClientConfig is the root TOML schema for tiredvpn client.
type ClientConfig struct {
	Server   ClientServer  `toml:"server"`
	Strategy Strategy      `toml:"strategy"`
	Shaper   *ShaperConfig `toml:"shaper,omitempty"`
	TLS      ClientTLS     `toml:"tls"`
	Logging  Logging       `toml:"logging"`
}

// ClientServer holds the upstream tiredvpn endpoint to connect to.
type ClientServer struct {
	Address string `toml:"address"`
	Port    int    `toml:"port"`
}

// Strategy selects the TLS-mimicry transport. Concrete validation of the
// allowed values lives in the strategy package; here we only check non-empty.
type Strategy struct {
	Mode    string         `toml:"mode"`
	Options map[string]any `toml:"options,omitempty"`
}

// ClientTLS controls outbound TLS / fingerprint behavior.
type ClientTLS struct {
	ServerName     string   `toml:"server_name,omitempty"`
	Fingerprint    string   `toml:"fingerprint,omitempty"`
	ALPN           []string `toml:"alpn,omitempty"`
	InsecureSkipVerify bool `toml:"insecure_skip_verify,omitempty"`
	CACert         string   `toml:"ca_cert,omitempty"`
}

// Logging controls log verbosity and destination.
type Logging struct {
	Level  string `toml:"level,omitempty"`
	Format string `toml:"format,omitempty"`
	Output string `toml:"output,omitempty"`
}

// Validate runs semantic checks not enforced by TOML decoding alone.
func (c *ClientConfig) Validate() error {
	if c.Server.Address == "" {
		return fmt.Errorf("server.address is required")
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be in 1..65535, got %d", c.Server.Port)
	}
	if c.Strategy.Mode == "" {
		return fmt.Errorf("strategy.mode is required")
	}
	if err := c.Shaper.validate(); err != nil {
		return err
	}
	return nil
}
