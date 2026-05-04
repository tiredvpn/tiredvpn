package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"

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
//   - server.address + server.port → cfg.ServerAddr (joined host:port)
//   - strategy.mode                → cfg.StrategyName
//   - shaper.{preset|custom}       → cfg.Shaper (built via presets.FromConfig)
//   - logging.level                → log.SetDebug when "debug"
//
// Unmapped TOML fields (TLS server_name/fingerprint/ALPN, strategy.options,
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

	cfg.ServerAddr = joinHostPort(tcfg.Server.Address, tcfg.Server.Port)
	if tcfg.Strategy.Mode != "" {
		cfg.StrategyName = tcfg.Strategy.Mode
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

// joinHostPort builds a "host:port" string. Empty host yields ":port" so that
// listen addresses like ":443" round-trip through the TOML schema cleanly.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
