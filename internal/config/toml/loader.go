// Package toml defines TOML configuration schemas and a strict loader for
// the tiredvpn client and server. Loading enforces unknown-field rejection so
// typos in config files surface immediately with a precise location.
//
// Example client.toml:
//
//	[server]
//	address = "vpn.example.org"
//	port = 443
//
//	[strategy]
//	mode = "reality"
//
//	[shaper]
//	preset = "chrome_browsing"
//	randomization_range = 0.1
//
//	[tls]
//	server_name = "www.cloudflare.com"
//	fingerprint = "chrome_120"
//	alpn = ["h2", "http/1.1"]
//
//	[logging]
//	level = "info"
//	format = "json"
package toml

import (
	"errors"
	"fmt"
	"os"

	gotoml "github.com/pelletier/go-toml/v2"
)

// LoadClient reads and validates a client TOML config from path.
func LoadClient(path string) (*ClientConfig, error) {
	var c ClientConfig
	if err := decodeStrict(path, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// LoadServer reads and validates a server TOML config from path.
func LoadServer(path string) (*ServerConfig, error) {
	var c ServerConfig
	if err := decodeStrict(path, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func decodeStrict(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := gotoml.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var serr *gotoml.StrictMissingError
		if errors.As(err, &serr) {
			return fmt.Errorf("%s: %s", path, serr.String())
		}
		var derr *gotoml.DecodeError
		if errors.As(err, &derr) {
			return fmt.Errorf("%s: %s", path, derr.String())
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
