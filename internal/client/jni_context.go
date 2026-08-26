//go:build android || darwin
// +build android darwin

package client

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// RunWithContext starts the client with a cancelable context.
// This is used by the JNI bridge on Android to allow graceful shutdown.
func RunWithContext(ctx context.Context, cfg *Config) error {
	// Same order as Run: the endpoint list decides cfg.ServerAddr (the app may
	// have passed a -config with a [[servers]] list) and may carry the secret,
	// so it has to be resolved before either is read.
	if _, err := ResolveEndpoints(cfg); err != nil {
		return err
	}

	// Try environment variable for secret
	secret := resolveSecret(cfg)
	cfg.Secret = secret

	if cfg.Debug {
		log.SetDebug(true)
	}

	// Host-managed sandbox modes: disable strategies that require root (raw sockets, ICMP).
	if cfg.AndroidMode || cfg.MacOSMode {
		strategy.SetAndroidMode(true)
	}

	// Apply defaults for adaptive config
	applyAdaptiveDefaults(cfg)

	// Build the strategy manager the same way the non-JNI entrypoint does
	// (buildManager sets AndroidMode/ECH/QUIC-SNI-frag/PQ/port-hopping/shaper
	// on the manager config and wires up the connectivity checker). This
	// used to be duplicated here with a hand-rolled DefaultManagerConfig that
	// silently dropped AndroidMode and half the other flags - on Android that
	// meant the manager never applied the android-mode timeout/retry/QUIC
	// deprioritization, so QUIC strategies (dead on QUIC-less servers) were
	// tried first with full 30s/2-retry timeouts before any TCP strategy got
	// a chance, blowing past the control-socket's client-side read timeout.
	mgr, err := buildManager(cfg, secret)
	if err != nil {
		return err
	}

	log.Info("TiredVPN Client (JNI mode) starting...")
	log.Info("Server: %s", cfg.ServerAddr)
	log.Info("Strategies: %s", mgr.ListStrategyIDs())
	log.Info("Android mode: %v", cfg.AndroidMode)

	// Configure reprobe interval
	mgr.SetReprobeInterval(cfg.ReprobeInterval)

	// Create signal channel that also listens to context cancellation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Monitor context cancellation and convert to signal
	go func() {
		<-ctx.Done()
		log.Info("Context cancelled, sending interrupt signal")
		sigChan <- syscall.SIGINT
	}()

	// For Android: use control socket mode
	if cfg.ControlSocket != "" {
		return runControlSocketMode(cfg, mgr, sigChan)
	}

	// TUN mode or proxy mode (non-Android)
	if cfg.TunMode {
		return runTUNMode(cfg, mgr, sigChan)
	}
	return runProxyMode(cfg, mgr, sigChan)
}
