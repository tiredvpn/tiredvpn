// +build android

package client

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// RunWithContext starts the client with a cancelable context.
// This is used by the JNI bridge on Android to allow graceful shutdown.
func RunWithContext(ctx context.Context, cfg *Config) error {
	if cfg.ServerAddr == "" {
		return fmt.Errorf("-server is required")
	}

	// Try environment variable for secret
	secret := cfg.Secret
	if secret == "" {
		secret = os.Getenv("TIREDVPN_SECRET")
	}
	if secret == "" {
		log.Warn("No secret provided - using default (INSECURE!)")
		secret = "default-secret-change-me"
	}
	cfg.Secret = secret

	if cfg.Debug {
		log.SetDebug(true)
	}

	// Android mode: disable strategies that require root (raw sockets, ICMP)
	if cfg.AndroidMode {
		strategy.SetAndroidMode(true)
	}

	// Apply defaults for adaptive config
	if cfg.ReprobeInterval == 0 {
		cfg.ReprobeInterval = 5 * 60 * 1000000000 // 5 minutes in nanoseconds
	}
	if cfg.CircuitThreshold == 0 {
		cfg.CircuitThreshold = 3
	}
	if cfg.CircuitResetTime == 0 {
		cfg.CircuitResetTime = 5 * 60 * 1000000000 // 5 minutes
	}

	// Create strategy manager
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr: cfg.ServerAddr,
		Secret:     []byte(cfg.Secret),
		CoverHost:  cfg.CoverHost,

		// IPv6 transport
		ServerAddrV6: cfg.ServerAddrV6,
		PreferIPv6:   cfg.PreferIPv6,
		FallbackToV4: cfg.FallbackToV4,

		// QUIC
		QUICEnabled: cfg.QUICEnabled,
		QUICPort:    cfg.QUICPort,

		// RTT Masking
		RTTMaskingEnabled: cfg.RTTMaskingEnabled,
		RTTProfile:        nil, // Will be set based on network conditions
	}

	mgr := strategy.NewDefaultManager(mgrCfg)

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
