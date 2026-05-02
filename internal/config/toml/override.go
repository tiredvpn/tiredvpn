package toml

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
)

// ApplyClientFlags overlays explicitly-set CLI flags from fs onto cfg.
// Only flags actually passed by the user (flag.Visit, not VisitAll) cause writes,
// so flag defaults never silently overwrite TOML values.
//
// Mapping (flag → TOML field):
//
//	-server      → server.address + server.port  (host:port split)
//	-strategy    → strategy.mode
//	-debug       → logging.level = "debug" (when true)
//
// Flags absent from this mapping are ignored — they belong to subsystems
// not yet represented in the TOML schema, and the caller continues to read
// them from the FlagSet directly.
func ApplyClientFlags(cfg *ClientConfig, fs *flag.FlagSet) error {
	if cfg == nil {
		return errors.New("ApplyClientFlags: nil config")
	}
	if fs == nil {
		return nil
	}
	var visitErr error
	fs.Visit(func(f *flag.Flag) {
		if visitErr != nil {
			return
		}
		switch f.Name {
		case "server":
			host, port, err := splitHostPort(f.Value.String())
			if err != nil {
				visitErr = fmt.Errorf("flag -server: %w", err)
				return
			}
			cfg.Server.Address = host
			if port != 0 {
				cfg.Server.Port = port
			}
		case "strategy":
			cfg.Strategy.Mode = f.Value.String()
		case "debug":
			if f.Value.String() == "true" {
				cfg.Logging.Level = "debug"
			}
		}
	})
	return visitErr
}

// ApplyServerFlags overlays explicitly-set CLI flags from fs onto cfg.
//
// Mapping (flag → TOML field):
//
//	-listen → listen.address + listen.port  (host:port split)
//	-cert   → tls.cert_file
//	-key    → tls.key_file
//	-debug  → logging.level = "debug" (when true)
func ApplyServerFlags(cfg *ServerConfig, fs *flag.FlagSet) error {
	if cfg == nil {
		return errors.New("ApplyServerFlags: nil config")
	}
	if fs == nil {
		return nil
	}
	var visitErr error
	fs.Visit(func(f *flag.Flag) {
		if visitErr != nil {
			return
		}
		switch f.Name {
		case "listen":
			host, port, err := splitHostPort(f.Value.String())
			if err != nil {
				visitErr = fmt.Errorf("flag -listen: %w", err)
				return
			}
			cfg.Listen.Address = host
			if port != 0 {
				cfg.Listen.Port = port
			}
		case "cert":
			cfg.TLS.CertFile = f.Value.String()
		case "key":
			cfg.TLS.KeyFile = f.Value.String()
		case "debug":
			if f.Value.String() == "true" {
				cfg.Logging.Level = "debug"
			}
		}
	})
	return visitErr
}

// ResolveClient computes the final ClientConfig with precedence
// CLI > TOML > defaults. tomlPath may be empty to skip TOML loading.
// fs may be nil to skip CLI overrides. The returned config is validated.
func ResolveClient(tomlPath string, fs *flag.FlagSet) (*ClientConfig, error) {
	cfg := DefaultClient()
	if tomlPath != "" {
		var fromFile ClientConfig
		if err := decodeStrict(tomlPath, &fromFile); err != nil {
			return nil, err
		}
		mergeClient(cfg, &fromFile)
	}
	if err := ApplyClientFlags(cfg, fs); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// ResolveServer computes the final ServerConfig with precedence
// CLI > TOML > defaults.
func ResolveServer(tomlPath string, fs *flag.FlagSet) (*ServerConfig, error) {
	cfg := DefaultServer()
	if tomlPath != "" {
		var fromFile ServerConfig
		if err := decodeStrict(tomlPath, &fromFile); err != nil {
			return nil, err
		}
		mergeServer(cfg, &fromFile)
	}
	if err := ApplyServerFlags(cfg, fs); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// mergeClient overlays non-zero fields from src onto dst.
// We intentionally enumerate fields rather than reflect: the schema is small
// and an explicit map keeps merge semantics auditable (e.g. ALPN replaces
// rather than appends — slices are treated atomically).
func mergeClient(dst, src *ClientConfig) {
	if src.Server.Address != "" {
		dst.Server.Address = src.Server.Address
	}
	if src.Server.Port != 0 {
		dst.Server.Port = src.Server.Port
	}
	if src.Strategy.Mode != "" {
		dst.Strategy.Mode = src.Strategy.Mode
	}
	if len(src.Strategy.Options) > 0 {
		dst.Strategy.Options = src.Strategy.Options
	}
	if src.Shaper != nil {
		dst.Shaper = src.Shaper
	}
	if src.TLS.ServerName != "" {
		dst.TLS.ServerName = src.TLS.ServerName
	}
	if src.TLS.Fingerprint != "" {
		dst.TLS.Fingerprint = src.TLS.Fingerprint
	}
	if len(src.TLS.ALPN) > 0 {
		dst.TLS.ALPN = src.TLS.ALPN
	}
	if src.TLS.InsecureSkipVerify {
		dst.TLS.InsecureSkipVerify = true
	}
	if src.TLS.CACert != "" {
		dst.TLS.CACert = src.TLS.CACert
	}
	mergeLogging(&dst.Logging, &src.Logging)
}

func mergeServer(dst, src *ServerConfig) {
	if src.Listen.Address != "" {
		dst.Listen.Address = src.Listen.Address
	}
	if src.Listen.Port != 0 {
		dst.Listen.Port = src.Listen.Port
	}
	if src.Strategy.Mode != "" {
		dst.Strategy.Mode = src.Strategy.Mode
	}
	if len(src.Strategy.Options) > 0 {
		dst.Strategy.Options = src.Strategy.Options
	}
	if src.Shaper != nil {
		dst.Shaper = src.Shaper
	}
	if src.TLS.CertFile != "" {
		dst.TLS.CertFile = src.TLS.CertFile
	}
	if src.TLS.KeyFile != "" {
		dst.TLS.KeyFile = src.TLS.KeyFile
	}
	if len(src.TLS.ALPN) > 0 {
		dst.TLS.ALPN = src.TLS.ALPN
	}
	if src.TLS.ClientCAFile != "" {
		dst.TLS.ClientCAFile = src.TLS.ClientCAFile
	}
	if src.Auth.Mode != "" {
		dst.Auth.Mode = src.Auth.Mode
	}
	if len(src.Auth.Tokens) > 0 {
		dst.Auth.Tokens = src.Auth.Tokens
	}
	if src.Auth.TokensFile != "" {
		dst.Auth.TokensFile = src.Auth.TokensFile
	}
	mergeLogging(&dst.Logging, &src.Logging)
}

func mergeLogging(dst, src *Logging) {
	if src.Level != "" {
		dst.Level = src.Level
	}
	if src.Format != "" {
		dst.Format = src.Format
	}
	if src.Output != "" {
		dst.Output = src.Output
	}
}

// splitHostPort accepts "host:port" or bare ":port" and returns parts.
// An empty port slot returns 0 so the caller keeps the existing value.
func splitHostPort(s string) (string, int, error) {
	if s == "" {
		return "", 0, errors.New("empty address")
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if portStr == "" {
		return host, 0, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	return host, port, nil
}

