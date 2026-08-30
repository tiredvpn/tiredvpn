package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/tiredvpn/tiredvpn/internal/client"
	tomlcfg "github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/server"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
)

// applyClientTOMLConfig optionally loads a TOML config from path and overlays
// it onto cfg. If path is empty, this is a no-op (legacy CLI-only path is
// preserved). When path is non-empty, fields present in the TOML are applied
// to cfg unless they were also explicitly set on the CLI (CLI > TOML > defaults
// — this precedence is enforced inside ResolveClient via flag.Visit).
//
// Mapped fields:
//   - [server] / [[servers]]       → cfg.Servers (and cfg.ServerAddr, the first entry)
//   - [selection]                  → cfg.Selection
//   - strategy.mode                → cfg.StrategyName
//   - tls.fingerprint              → cfg.TLSFingerprint
//   - tun.ipv6_allow               → cfg.TunIPv6Allow (joined back to the
//     comma-separated form -tun-ipv6-allow uses)
//   - shaper.{preset|custom}       → cfg.Shaper (built via presets.FromConfig)
//   - logging.level                → log.SetDebug when "debug"
//
// Unmapped TOML fields (TLS server_name/ALPN, strategy.options,
// logging.format/output) are accepted by the schema but not yet wired into the
// runtime client.Config — these are gaps tracked separately and ignored here.
func applyClientTOMLConfig(cfg *client.Config, path string, fs *flag.FlagSet) error {
	if path == "" {
		return nil
	}
	tcfg, err := tomlcfg.ResolveClient(path, fs)
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}

	if err := applyServerList(cfg, tcfg); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if tcfg.Strategy.Mode != "" {
		cfg.StrategyName = tcfg.Strategy.Mode
	}
	if tcfg.TLS.Fingerprint != "" {
		cfg.TLSFingerprint = tcfg.TLS.Fingerprint
	}
	// Back to the flag's comma-separated form, which is what the runtime
	// parses. The schema validated that no entry contains a comma, so the
	// join round-trips.
	if len(tcfg.Tun.IPv6Allow) > 0 {
		cfg.TunIPv6Allow = strings.Join(tcfg.Tun.IPv6Allow, ",")
	}
	if tcfg.Logging.Level == "debug" {
		log.SetDebug(true)
		cfg.Debug = true
	}

	if tcfg.Shaper != nil && (tcfg.Shaper.Preset != "" || tcfg.Shaper.Custom != nil) {
		sh, err := presets.FromConfig(*tcfg.Shaper)
		if err != nil {
			return fmt.Errorf("shaper: %w", err)
		}
		cfg.Shaper = sh
		// A custom (non-preset) shaper has no negotiation ID; the server
		// cannot reconstruct an arbitrary distribution, so it stays noop on
		// the wire. Named presets map to a stable ID.
		cfg.ShaperID = byte(presets.IDForName(tcfg.Shaper.Preset))
	}
	return nil
}

// applyServerList maps the resolved [server] / [[servers]] / [selection]
// blocks onto the runtime config.
//
// cfg.ServerAddr is set from the first entry here as well as by
// client.ResolveEndpoints later, because everything between the two - the
// "-server is required" check, the MTU validation, the startup log - reads it,
// and a config that only says [[servers]] would otherwise look serverless
// until the client is already running.
func applyServerList(cfg *client.Config, tcfg *tomlcfg.ClientConfig) error {
	list := tcfg.ServerList()
	specs := make([]client.ServerSpec, 0, len(list))
	for _, s := range list {
		spec := client.ServerSpec{
			Name:   s.Name,
			Weight: s.Weight,
			Secret: s.Secret,
			SNI:    s.SNI,
		}
		if s.Address != "" {
			spec.Addr = joinHostPort(s.Address, s.Port)
		}
		if s.AddressV6 != "" {
			// JoinHostPort brackets it, which is the form the transport and
			// the TUN bypass expect; the schema stores it bare so the file
			// does not have to.
			spec.AddrV6 = joinHostPort(s.AddressV6, s.PortV6)
		}
		specs = append(specs, spec)
	}
	if len(specs) > 0 {
		cfg.Servers = specs
		cfg.ServerAddr = specs[0].Addr
		cfg.ServerAddrV6 = specs[0].AddrV6
	}

	sel, err := tcfg.Selection.Resolve()
	if err != nil {
		return err
	}
	// Each field is copied only when the file (or the flag overlay that has
	// already been folded into it) says something, so a TOML that is silent
	// about selection leaves the CLI-set values - and the legacy defaults -
	// exactly where they were.
	if sel.Policy != "" {
		cfg.Selection.Policy = sel.Policy
	}
	if sel.Family != "" {
		cfg.Selection.Family = sel.Family
	}
	if sel.FailureThreshold != 0 {
		cfg.Selection.FailureThreshold = sel.FailureThreshold
	}
	if sel.Cooldown != 0 {
		cfg.Selection.Cooldown = sel.Cooldown
	}
	if sel.MaxCooldown != 0 {
		cfg.Selection.MaxCooldown = sel.MaxCooldown
	}
	if sel.MinDwell != 0 {
		cfg.Selection.MinDwell = sel.MinDwell
	}
	if sel.RecheckInterval != 0 {
		cfg.Selection.RecheckInterval = sel.RecheckInterval
	}
	if sel.HealthCheck != "" {
		cfg.Selection.HealthCheck = sel.HealthCheck
	}
	return nil
}

// scanArgValue returns the value following name in a hand-parsed argv, or "".
// Used by the JNI entry point, which has no FlagSet.
func scanArgValue(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

// collapseServers folds a configured server list down to one entry whose
// addresses come from the command line.
//
// Entry 0 is kept rather than the list dropped outright, so a name or a secret
// attached to it survives; only the addresses are replaced, and only when the
// caller actually has one.
func collapseServers(list []client.ServerSpec, addr, addrV6 string) []client.ServerSpec {
	if len(list) == 0 {
		return nil
	}
	if len(list) > 1 {
		log.Warn("-server/-server-v6 collapses the %d-entry server list to one endpoint; the rest are ignored", len(list))
	}
	kept := list[0]
	if addr != "" {
		kept.Addr = addr
	}
	if addrV6 != "" {
		kept.AddrV6 = addrV6
	}
	return []client.ServerSpec{kept}
}

// applyShaperFlag builds cfg.Shaper from the -shaper preset name and seed.
// It also resolves the negotiation ID transmitted to the server so the
// server-side morph relay reconstructs the same framing.
func applyShaperFlag(cfg *client.Config, name string, seed int64) error {
	sh, err := presets.ByName(name, seed)
	if err != nil {
		return fmt.Errorf("shaper %q: %w", name, err)
	}
	cfg.Shaper = sh
	cfg.ShaperID = byte(presets.IDForName(name))
	log.Info("shaper active: preset=%s id=%d", name, cfg.ShaperID)
	return nil
}

// applyServerTOMLConfig is the server-side counterpart of applyClientTOMLConfig.
//
// Mapped fields:
//   - listen.address + listen.port → cfg.ListenAddr
//   - tls.cert_file                → cfg.CertFile
//   - tls.key_file                 → cfg.KeyFile
//   - logging.level                → log.SetDebug when "debug"
//   - shaper.*                     → cfg.Shaper (reserved; server pipeline does
//     not yet consume it — see server.Config.Shaper)
//
// Gaps: strategy.mode, auth.{mode,tokens,tokens_file}, tls.alpn,
// tls.client_ca_file are not yet wired into server.Config.
func applyServerTOMLConfig(cfg *server.Config, path string, fs *flag.FlagSet) error {
	if path == "" {
		return nil
	}
	tcfg, err := tomlcfg.ResolveServer(path, fs)
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}

	cfg.ListenAddr = joinHostPort(tcfg.Listen.Address, tcfg.Listen.Port)
	if tcfg.TLS.CertFile != "" {
		cfg.CertFile = tcfg.TLS.CertFile
	}
	if tcfg.TLS.KeyFile != "" {
		cfg.KeyFile = tcfg.TLS.KeyFile
	}
	if tcfg.Logging.Level == "debug" {
		log.SetDebug(true)
		cfg.Debug = true
	}

	if tcfg.Shaper != nil && (tcfg.Shaper.Preset != "" || tcfg.Shaper.Custom != nil) {
		sh, err := presets.FromConfig(*tcfg.Shaper)
		if err != nil {
			return fmt.Errorf("shaper: %w", err)
		}
		cfg.Shaper = sh
	}
	return nil
}

// flagWasSet reports whether name was given explicitly on the command line,
// as opposed to sitting at its default value.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// applyRedisNamespaceEnv resolves the Redis namespace settings with the same
// precedence as the other secrets-friendly options: flag > env > default. The
// env vars let a systemd unit give each instance on a shared Redis its own
// database and key prefix via EnvironmentFile.
func applyRedisNamespaceEnv(cfg *server.Config, fs *flag.FlagSet) error {
	if !flagWasSet(fs, "redis-db") {
		if v := os.Getenv("TIREDVPN_REDIS_DB"); v != "" {
			db, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("TIREDVPN_REDIS_DB: %q is not a number", v)
			}
			cfg.RedisDB = db
		}
	}
	if !flagWasSet(fs, "redis-prefix") {
		if v := os.Getenv("TIREDVPN_REDIS_PREFIX"); v != "" {
			cfg.RedisPrefix = v
		}
	}

	if err := server.ValidateRedisDB(cfg.RedisDB); err != nil {
		return err
	}
	cfg.RedisPrefix = server.NormalizeRedisPrefix(cfg.RedisPrefix)
	return nil
}

// joinHostPort builds a "host:port" string. Empty host yields ":port" so that
// listen addresses like ":443" round-trip through the TOML schema cleanly.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
