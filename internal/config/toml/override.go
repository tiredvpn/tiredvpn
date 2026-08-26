package toml

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ApplyClientFlags overlays explicitly-set CLI flags from fs onto cfg.
// Only flags actually passed by the user (flag.Visit, not VisitAll) cause writes,
// so flag defaults never silently overwrite TOML values.
//
// Mapping (flag → TOML field):
//
//	-server        → server.address + server.port  (host:port split, collapses [[servers]])
//	-server-v6     → server.address_v6 + server.port_v6 (same collapse)
//	-server-policy → selection.policy
//	-prefer-ipv6   → selection.family (with -fallback-v4; see familyFromLegacyFlags)
//	-fallback-v4   → selection.family
//	-strategy      → strategy.mode
//	-debug         → logging.level = "debug" (when true)
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
			collapseToSingleServer(cfg, f.Name)
			cfg.Server.Address = host
			if port != 0 {
				cfg.Server.Port = port
			}
		case "server-v6":
			host, port, err := splitHostPort(f.Value.String())
			if err != nil {
				visitErr = fmt.Errorf("flag -server-v6: %w", err)
				return
			}
			collapseToSingleServer(cfg, f.Name)
			cfg.Server.AddressV6 = host
			if port != 0 {
				cfg.Server.PortV6 = port
			}
		case "server-policy":
			cfg.selection().Policy = f.Value.String()
		case "strategy":
			cfg.Strategy.Mode = f.Value.String()
		case "debug":
			if f.Value.String() == "true" {
				cfg.Logging.Level = "debug"
			}
		}
	})
	if visitErr != nil {
		return visitErr
	}
	if fam, ok := familyFromLegacyFlags(fs); ok {
		cfg.selection().Family = fam
	}
	return nil
}

// selection returns the [selection] block, creating it on first write. Callers
// that only read must go through Selection.Resolve, which tolerates nil.
func (c *ClientConfig) selection() *Selection {
	if c.Selection == nil {
		c.Selection = &Selection{}
	}
	return c.Selection
}

// familyFromLegacyFlags maps the -prefer-ipv6 / -fallback-v4 pair onto a
// selection.family spelling, but only when at least one of them was passed
// explicitly. An untouched pair must leave selection.family alone: the flags
// both default to true, and writing "prefer_v6" from a default would silently
// beat a family the config file asked for.
//
// Both values are read even when only one was passed, because the mapping is a
// function of the pair (endpoint.FamilyPolicyFromLegacy owns the table, and the
// -prefer-ipv6=false row is v4_only rather than prefer_v4 on purpose).
func familyFromLegacyFlags(fs *flag.FlagSet) (string, bool) {
	touched := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "prefer-ipv6" || f.Name == "fallback-v4" {
			touched = true
		}
	})
	if !touched {
		return "", false
	}
	return endpoint.FamilyPolicyFromLegacy(
		lookupBoolFlag(fs, "prefer-ipv6"),
		lookupBoolFlag(fs, "fallback-v4"),
	).String(), true
}

// lookupBoolFlag reads a bool flag's current value (default or set). A flag the
// FlagSet does not know reads as false, which for both of our callers is the
// conservative answer.
func lookupBoolFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	return f.Value.String() == "true"
}

// collapseToSingleServer folds a [[servers]] list down to its first entry, so
// that -server / -server-v6 have one unambiguous thing to overwrite.
//
// The first entry is kept rather than discarded wholesale: -server-v6 on its
// own must not erase the IPv4 address (the two flags have always been
// independent), and the entry's name/secret/sni stay attached to the endpoint
// they describe.
//
// One consequence worth stating: an entry that never spelled out port_v6 still
// follows port, so -server host:443 moves the IPv6 port to 443 as well. That is
// the schema's rule applied consistently rather than a special case; pin
// port_v6 in the file, or pass -server-v6, to keep the two apart.
func collapseToSingleServer(cfg *ClientConfig, flagName string) {
	if len(cfg.Servers) == 0 {
		return
	}
	kept := cfg.Servers[0]
	if len(cfg.Servers) > 1 {
		log.Warn("flag -%s collapses the %d-entry [[servers]] list to one endpoint (%s); the rest are ignored",
			flagName, len(cfg.Servers), kept.label(0))
	}
	cfg.Server = kept
	cfg.Servers = nil
}

// label names an entry for a message: its name when it has one, its position
// otherwise.
func (s ClientServer) label(i int) string {
	if s.Name != "" {
		return s.Name
	}
	return fmt.Sprintf("servers[%d]", i)
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
	if src.Server.AddressV6 != "" {
		dst.Server.AddressV6 = src.Server.AddressV6
	}
	if src.Server.PortV6 != 0 {
		dst.Server.PortV6 = src.Server.PortV6
	}
	if src.Server.Name != "" {
		dst.Server.Name = src.Server.Name
	}
	if src.Server.Weight != 0 {
		dst.Server.Weight = src.Server.Weight
	}
	if src.Server.Secret != "" {
		dst.Server.Secret = src.Server.Secret
	}
	if src.Server.SNI != "" {
		dst.Server.SNI = src.Server.SNI
	}
	// The list is atomic: a partial merge of two server lists has no meaning a
	// reader could predict (is entry 2 of the file entry 2 of the defaults?).
	if len(src.Servers) > 0 {
		dst.Servers = src.Servers
	}
	if src.Selection != nil {
		sel := *src.Selection
		dst.Selection = &sel
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
