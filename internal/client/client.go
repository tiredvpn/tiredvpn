package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/benchmark"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/pool"
	"github.com/tiredvpn/tiredvpn/internal/porthopping"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

var (
	Version   = "0.2.0"
	BuildTime = "unknown"

	// Global metrics instance (nil if metrics disabled)
	clientMetrics *ClientMetrics
)

// Config holds client configuration
type Config struct {
	ListenAddr     string
	HTTPListenAddr string // Separate HTTP proxy port (optional)
	ServerAddr     string
	Secret         string
	CoverHost      string
	StrategyName   string
	Debug          bool

	// IPv6 Transport
	ServerAddrV6 string // IPv6 server address (e.g., "[2001:db8::100]:995")
	PreferIPv6   bool   // Prefer IPv6 transport if available (default: true)
	FallbackToV4 bool   // Fallback to IPv4 if IPv6 fails (default: true)

	// TUN mode
	TunMode   bool
	TunName   string
	TunIP     string
	TunPeerIP string
	TunMTU    int
	TunRoutes string

	// Android VpnService support
	TunFd         int    // Use existing TUN file descriptor (from Android VpnService)
	ProtectPath   string // Unix socket path for protect() calls
	ControlSocket string // Control socket path for Android integration
	AndroidMode   bool   // Running on Android (disables os/exec, ICMP checks, etc.)

	// Modes
	ListStrategies     bool
	BenchmarkMode      bool
	FullBenchmarkMode  bool
	BenchmarkAllCombos bool // Test all strategy + RTT profile combinations

	// Adaptive strategy config
	ReprobeInterval  time.Duration // How often to re-probe strategies (default 5m)
	CircuitThreshold int           // Failures before circuit opens (default 3)
	CircuitResetTime time.Duration // Time before circuit tries half-open (default 5m)
	EnableFallback   bool          // Enable mid-session fallback (default true)

	// QUIC transport
	QUICEnabled bool // Enable QUIC strategy
	QUICPort    int  // QUIC server port (default 443)

	// RTT Masking
	RTTMaskingEnabled bool   // Enable RTT masking
	RTTProfile        string // RTT profile name

	// ECH (Encrypted Client Hello) - hides SNI from DPI
	ECHEnabled    bool   // Enable ECH
	ECHConfigB64  string // ECHConfigList in base64 (from server)
	ECHPublicName string // Outer SNI visible to DPI (e.g., "cloudflare-ech.com")

	// QUIC SNI fragmentation for GFW bypass
	QUICSNIFragEnabled bool // Fragment SNI in QUIC CRYPTO frames

	// Post-Quantum crypto
	PQEnabled         bool   // Enable ML-KEM-768 + ML-DSA-65
	PQServerKemPubB64 string // Server's Kyber768 public key in base64

	// API/Metrics
	APIAddr string // API/Metrics HTTP endpoint (e.g., :8080)

	// Port hopping for DPI evasion
	PortHoppingEnabled bool          // Enable port hopping
	PortHopRangeStart  int           // Start of port range (default: 47000)
	PortHopRangeEnd    int           // End of port range (default: 65535)
	PortHopInterval    time.Duration // Hop interval (default: 60s)
	PortHopStrategy    string        // Strategy: random, sequential, fibonacci
	PortHopSeed        string        // Seed for deterministic hopping (optional)

	// Shaper, when non-nil, is forwarded to the strategy manager and drives
	// MorphedConn behaviour. Built from TOML [shaper] in cmd/tiredvpn.
	Shaper shaper.Shaper
}

// Run starts the client with the given configuration
func Run(cfg *Config) error {
	if cfg.ListStrategies {
		return listStrategies(cfg)
	}

	if cfg.ServerAddr == "" {
		return fmt.Errorf("-server is required")
	}

	secret := resolveSecret(cfg)

	if cfg.Debug {
		log.SetDebug(true)
	}
	if cfg.AndroidMode {
		strategy.SetAndroidMode(true)
	}

	applyAdaptiveDefaults(cfg)

	log.Info("tiredvpn client %s starting...", Version)
	log.Info("Server: %s, Cover: %s", cfg.ServerAddr, cfg.CoverHost)
	log.Info("Listening on %s (SOCKS5/HTTP)", cfg.ListenAddr)
	if cfg.HTTPListenAddr != "" {
		log.Info("HTTP proxy on %s", cfg.HTTPListenAddr)
	}
	log.Info("Adaptive config: reprobe=%v, circuitThreshold=%d, circuitReset=%v, fallback=%v",
		cfg.ReprobeInterval, cfg.CircuitThreshold, cfg.CircuitResetTime, cfg.EnableFallback)

	mgr, err := buildManager(cfg, secret)
	if err != nil {
		return err
	}

	logEnabledFeatures(cfg, mgr)

	if cfg.Debug {
		fmt.Println(mgr.PrintStrategySummary())
	}

	if cfg.BenchmarkMode {
		return runBenchmark(cfg, mgr)
	}
	if cfg.FullBenchmarkMode {
		return runFullBenchmark(cfg, mgr)
	}
	if cfg.BenchmarkAllCombos {
		return runAllCombosBenchmark(cfg, mgr)
	}

	mgr.SetReprobeInterval(cfg.ReprobeInterval)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if cfg.ControlSocket != "" {
		return runControlSocketMode(cfg, mgr, sigChan)
	}

	return runProbeAndServe(cfg, mgr, sigChan)
}

// listStrategies prints available strategy IDs and exits.
func listStrategies(cfg *Config) error {
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr: "example.com:443",
		Secret:     []byte("dummy"),
		CoverHost:  cfg.CoverHost,
	}
	mgr := strategy.NewDefaultManager(mgrCfg)
	fmt.Println(mgr.PrintStrategySummary())
	fmt.Println("\nStrategy IDs for -strategy flag:")
	fmt.Println("  http2_stego    - HTTP/2 Steganography")
	fmt.Println("  morph          - Traffic Morphing (YouTube)")
	fmt.Println("  confusion      - Protocol Confusion (DNS/TLS)")
	fmt.Println("  antiprobe      - Anti-Probe Resistance")
	return nil
}

// resolveSecret returns the effective secret: from cfg, env, or insecure default.
func resolveSecret(cfg *Config) string {
	s := cfg.Secret
	if s == "" {
		s = os.Getenv("TIREDVPN_SECRET")
	}
	if s == "" {
		log.Warn("No secret provided - using default (INSECURE!)")
		s = "default-secret-change-me"
	}
	return s
}

// applyAdaptiveDefaults fills zero-value adaptive config fields with sensible defaults.
func applyAdaptiveDefaults(cfg *Config) {
	if cfg.ReprobeInterval == 0 {
		cfg.ReprobeInterval = 5 * time.Minute
	}
	if cfg.CircuitThreshold == 0 {
		cfg.CircuitThreshold = 3
	}
	if cfg.CircuitResetTime == 0 {
		cfg.CircuitResetTime = 5 * time.Minute
	}
}

// buildManager constructs and configures the strategy manager.
func buildManager(cfg *Config, secret string) (*strategy.Manager, error) {
	rttProfile := resolveRTTProfile(cfg)
	echConfigList := decodeECHConfig(cfg)
	portHoppingCfg := buildPortHoppingConfig(cfg)

	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:         cfg.ServerAddr,
		Secret:             []byte(secret),
		CoverHost:          cfg.CoverHost,
		ServerAddrV6:       cfg.ServerAddrV6,
		PreferIPv6:         cfg.PreferIPv6,
		FallbackToV4:       cfg.FallbackToV4,
		RTTMaskingEnabled:  cfg.RTTMaskingEnabled,
		RTTProfile:         rttProfile,
		QUICEnabled:        cfg.QUICEnabled,
		QUICPort:           cfg.QUICPort,
		ECHEnabled:         cfg.ECHEnabled,
		ECHConfigList:      echConfigList,
		ECHPublicName:      cfg.ECHPublicName,
		QUICSNIFragEnabled: cfg.QUICSNIFragEnabled,
		PQEnabled:          cfg.PQEnabled,
		PQServerKemPubB64:  cfg.PQServerKemPubB64,
		AndroidMode:        cfg.AndroidMode,
		PortHopping:        portHoppingCfg,
		Shaper:             cfg.Shaper,
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	connectivityChecker := strategy.NewConnectivityChecker(cfg.ServerAddr, 3*time.Second, cfg.AndroidMode)
	mgr.SetConnectivityChecker(connectivityChecker)
	log.Debug("Connectivity checker initialized for %s", cfg.ServerAddr)

	if cfg.StrategyName != "" {
		log.Info("Forcing strategy: %s", cfg.StrategyName)
		if err := mgr.ForceStrategy(cfg.StrategyName); err != nil {
			return nil, fmt.Errorf("unknown strategy: %s (available: %s)", cfg.StrategyName, mgr.ListStrategyIDs())
		}
	}
	return mgr, nil
}

// resolveRTTProfile looks up the named RTT profile, returning nil if not found.
func resolveRTTProfile(cfg *Config) *strategy.RTTProfile {
	if !cfg.RTTMaskingEnabled || cfg.RTTProfile == "" {
		return nil
	}
	p := strategy.GetRTTProfile(cfg.RTTProfile)
	if p == nil {
		log.Warn("Unknown RTT profile '%s', using default (moscow-yandex)", cfg.RTTProfile)
		return strategy.MoscowToYandexProfile
	}
	return p
}

// decodeECHConfig base64-decodes the ECH config list, disabling ECH on failure.
func decodeECHConfig(cfg *Config) []byte {
	if !cfg.ECHEnabled || cfg.ECHConfigB64 == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(cfg.ECHConfigB64)
	if err != nil {
		log.Warn("Failed to decode ECH config: %v (ECH disabled)", err)
		cfg.ECHEnabled = false
		return nil
	}
	return b
}

// buildPortHoppingConfig creates a validated port-hopping config, or nil if disabled/invalid.
func buildPortHoppingConfig(cfg *Config) *porthopping.Config {
	if !cfg.PortHoppingEnabled {
		return nil
	}
	phCfg := &porthopping.Config{
		Enabled:        true,
		PortRangeStart: cfg.PortHopRangeStart,
		PortRangeEnd:   cfg.PortHopRangeEnd,
		HopInterval:    cfg.PortHopInterval,
		Strategy:       porthopping.Strategy(cfg.PortHopStrategy),
		Seed:           []byte(cfg.PortHopSeed),
	}
	if err := phCfg.Validate(); err != nil {
		log.Warn("Invalid port hopping config: %v (disabled)", err)
		return nil
	}
	return phCfg
}

// logEnabledFeatures logs info lines for each optional feature that is active.
func logEnabledFeatures(cfg *Config, mgr *strategy.Manager) {
	if cfg.RTTMaskingEnabled {
		log.Info("RTT masking enabled (profile=%s)", cfg.RTTProfile)
	}
	if cfg.QUICEnabled {
		log.Info("QUIC transport enabled (port=%d)", cfg.QUICPort)
	}
	if cfg.ECHEnabled {
		log.Info("ECH enabled (outer SNI: %s)", cfg.ECHPublicName)
	}
	if cfg.QUICSNIFragEnabled {
		log.Info("QUIC SNI fragmentation enabled (GFW bypass)")
	}
	if cfg.PQEnabled {
		log.Info("Post-quantum crypto enabled (ML-KEM-768 + ML-DSA-65)")
	}
	if cfg.ServerAddrV6 != "" && cfg.PreferIPv6 {
		log.Info("IPv6 transport enabled (IPv6=%s, IPv4=%s, fallback=%v)",
			cfg.ServerAddrV6, cfg.ServerAddr, cfg.FallbackToV4)
	}
	// log port hopping status if manager has a port hopper configured
	_ = mgr // used for future per-strategy logging
}

// runBenchmark runs the parallel strategy probe benchmark and prints results.
func runBenchmark(cfg *Config, mgr *strategy.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	log.Info("Running strategy benchmark...")
	result := benchmark.ParallelProbe(ctx, mgr, cfg.ServerAddr)
	fmt.Println(benchmark.FormatResults(result, false))
	return nil
}

// runFullBenchmark runs the full HTTP/latency/speed/IP-change benchmark and prints results.
func runFullBenchmark(cfg *Config, mgr *strategy.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	log.Info("Running FULL strategy benchmark (this may take several minutes)...")
	log.Info("Testing %d strategies for: HTTP, latency, speed, IP change", len(mgr.GetOrderedStrategies()))
	origIP, err := benchmark.GetOriginalIP(ctx)
	if err != nil {
		log.Warn("Could not get original IP: %v (IP change detection disabled)", err)
		origIP = "unknown"
	} else {
		log.Info("Original IP: %s", origIP)
	}
	result := benchmark.RunFullBenchmarkDirect(ctx, mgr, cfg.ServerAddr, origIP)
	fmt.Println(benchmark.FormatFullResults(result))
	return nil
}

// runAllCombosBenchmark runs the exhaustive strategies × RTT profiles benchmark.
func runAllCombosBenchmark(cfg *Config, mgr *strategy.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rttProfiles := strategy.AllRTTProfiles()
	strategies := mgr.GetOrderedStrategies()
	totalCombos := len(strategies) * (1 + len(rttProfiles))
	log.Info("Running EXHAUSTIVE benchmark of ALL combinations...")
	log.Info("Strategies: %d, RTT profiles: %d (+none), Total combinations: %d",
		len(strategies), len(rttProfiles), totalCombos)
	origIP, err := benchmark.GetOriginalIP(ctx)
	if err != nil {
		log.Warn("Could not get original IP: %v", err)
		origIP = "unknown"
	} else {
		log.Info("Original IP: %s", origIP)
	}
	result := benchmark.RunAllCombinationsBenchmark(ctx, mgr, cfg.ServerAddr, origIP, rttProfiles)
	fmt.Println(benchmark.FormatAllCombosResults(result))
	return nil
}

// runProbeAndServe probes strategies then starts proxy/TUN serving.
func runProbeAndServe(cfg *Config, mgr *strategy.Manager, sigChan chan os.Signal) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	log.Info("Probing strategies...")
	results := mgr.ProbeAll(ctx, cfg.ServerAddr)
	cancel()

	available := 0
	for _, r := range results {
		if r.Success {
			available++
			log.Debug("Strategy available: %s (latency=%v)", r.Strategy.Name(), r.Latency)
		}
	}
	log.Info("Available strategies: %d/%d", available, len(results))

	reprobeCtx, reprobeCancel := context.WithCancel(context.Background())
	mgr.StartPeriodicReprobe(reprobeCtx, cfg.ServerAddr)

	if cfg.PortHoppingEnabled {
		mgr.StartPortHopChecker(reprobeCtx)
	}

	defer func() {
		reprobeCancel()
		mgr.StopPeriodicReprobe()
		mgr.StopPortHopChecker()
	}()

	if cfg.TunMode {
		return runTUNMode(cfg, mgr, sigChan)
	}
	return runProxyMode(cfg, mgr, sigChan)
}

// runControlSocketMode runs in Android control socket mode
// Android app connects to socket, sends "connect", gets IP, creates VPN interface, sends fd
func runControlSocketMode(cfg *Config, mgr *strategy.Manager, sigChan chan os.Signal) error {
	log.Info("Starting control socket mode on %s", cfg.ControlSocket)

	// Initialize Android socket protector if protect path is provided
	// This allows strategies to protect sockets from VPN routing
	if cfg.ProtectPath != "" {
		if err := tun.InitAndroidProtector(cfg.ProtectPath); err != nil {
			log.Warn("Socket protector init failed: %v (connections may not work)", err)
		}
	}

	// Create control server with connect function
	ctrlCfg := &tun.ControlConfig{
		ServerAddr: cfg.ServerAddr,
		Secret:     cfg.Secret,
		MTU:        cfg.TunMTU,
		DNS:        "8.8.8.8", // Default DNS
		Routes:     cfg.TunRoutes,

		// ReconnectFn - called on network change (WiFi→LTE, cell handoff)
		// Resets circuit breakers and uses optimized fast reconnect
		// Must send TUN handshake with current IP so server knows this is a TUN session
		ReconnectFn: func(ctx context.Context, currentIP net.IP, mtu int) (net.Conn, net.IP, net.IP, error) {
			log.Info("Network change reconnect triggered (current IP: %s)", currentIP)

			// Reset all circuit breakers and confidences - old network state is invalid
			mgr.ResetForNetworkChange()

			// Use optimized reconnect with shorter timeouts
			conn, strat, err := mgr.ConnectForReconnect(ctx, cfg.ServerAddr)
			if err != nil {
				return nil, nil, nil, err
			}

			log.Info("Network change reconnect successful via %s, sending TUN handshake", strat.Name())

			// Enable raw mode for ConfusedConn BEFORE handshake
			if confusedConn, ok := conn.(*strategy.ConfusedConn); ok {
				confusedConn.SetRawMode(true)
				log.Debug("Enabled raw mode for ConfusedConn before reconnect handshake")
			}

			// Send TUN mode handshake with our current IP
			// Server will recognize us and restore the session
			handshake := make([]byte, 8)
			handshake[0] = 0x02 // TUN mode
			copy(handshake[1:5], currentIP.To4())
			binary.BigEndian.PutUint16(handshake[5:7], uint16(mtu))
			handshake[7] = 0x02 // Version 2: supports full port hopping config

			if _, err := conn.Write(handshake); err != nil {
				conn.Close()
				return nil, nil, nil, fmt.Errorf("handshake write failed: %w", err)
			}

			// Read response (up to 64 bytes for extended v2 with port hopping config)
			// Minimum 9 bytes: [status:1][serverIP:4][clientIP:4]
			resp := make([]byte, 64)
			n, err := io.ReadAtLeast(conn, resp, 9)
			if err != nil {
				conn.Close()
				return nil, nil, nil, fmt.Errorf("handshake read failed: %w", err)
			}
			resp = resp[:n] // Trim to actual response size

			if resp[0] != 0x00 {
				conn.Close()
				return nil, nil, nil, fmt.Errorf("server rejected reconnect: status=%d", resp[0])
			}

			serverIP := net.IP(resp[1:5])
			assignedIP := net.IP(resp[5:9])

			log.Info("Reconnect handshake complete (server: %s, assigned: %s)", serverIP, assignedIP)

			return conn, serverIP, assignedIP, nil
		},

		// Connect function - connects to server, returns assigned IP
		ConnectFn: func(ctx context.Context) (assignedIP, serverIP net.IP, conn net.Conn, err error) {
			// Connect to server via strategy
			serverConn, strat, err := mgr.Connect(ctx, cfg.ServerAddr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to connect: %w", err)
			}

			log.Info("Connected via %s, waiting for TUN fd from Android", strat.Name())

			// Enable raw mode for ConfusedConn (needed for some strategies)
			// Raw mode disables automatic length-prefix framing
			if confusedConn, ok := serverConn.(*strategy.ConfusedConn); ok {
				confusedConn.SetRawMode(true)
				log.Debug("Enabled raw mode for ConfusedConn")
			}

			// Return connection WITHOUT TUN handshake
			// TUN handshake will be done AFTER Android creates VPN interface and sends FD
			// This fixes the "handshake read failed: EOF" error
			// Use placeholder IPs (10.9.0.2/10.9.0.1) - real IPs will be set after handshake
			// NOTE: 0.0.0.0 causes Android to fail VPN interface creation
			placeholderClient := net.IPv4(10, 9, 0, 2)
			placeholderServer := net.IPv4(10, 9, 0, 1)
			return placeholderClient, placeholderServer, serverConn, nil
		},

		// GetConnectionInfoFn returns connection metadata for Android UI
		GetConnectionInfoFn: func() tun.ConnectionMetadata {
			info := mgr.GetLastConnectionInfo()
			return tun.ConnectionMetadata{
				Strategy:  info.Strategy,
				LatencyMs: info.Latency.Milliseconds(),
				Attempts:  info.Attempts,
			}
		},

		// StartVPNFn is NOT set - let control.go use the default path
		// which includes RunTUNRelayWithCallbacks with keepalive events
		// and dead connection detection
	}

	ctrlServer, err := tun.NewControlServer(cfg.ControlSocket, ctrlCfg)
	if err != nil {
		return fmt.Errorf("failed to create control server: %w", err)
	}
	defer ctrlServer.Close()

	// Run in background
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := ctrlServer.Run(ctx); err != nil {
			log.Warn("Control server error: %v", err)
		}
	}()

	// Wait for signal
	sig := <-sigChan
	log.Info("Received signal %v, shutting down...", sig)
	cancel()

	return nil
}

func runTUNMode(cfg *Config, mgr *strategy.Manager, sigChan chan os.Signal) error {
	log.Info("Starting TUN mode")

	// Parse routes
	var routes []string
	if cfg.TunRoutes != "" {
		routes = append(routes, splitRoutes(cfg.TunRoutes)...)
	}

	// Create VPN client
	// Handle "auto" TunIP for Android VpnService
	localIP := net.ParseIP(cfg.TunIP)
	if localIP == nil && cfg.TunIP == "auto" {
		localIP = net.ParseIP("10.8.0.2") // Default client IP
	}

	vpnCfg := tun.VPNConfig{
		TunName:     cfg.TunName,
		MTU:         cfg.TunMTU,
		LocalIP:     localIP,
		RemoteIP:    net.ParseIP(cfg.TunPeerIP),
		Routes:      routes,
		ServerAddr:  cfg.ServerAddr,
		Manager:     mgr,
		TunFd:       cfg.TunFd,       // Android VpnService TUN fd
		ProtectPath: cfg.ProtectPath, // Android socket protection path
	}

	vpnClient, err := tun.NewVPNClient(vpnCfg)
	if err != nil {
		return fmt.Errorf("failed to create VPN client: %w", err)
	}

	// Start VPN
	ctx, cancel := context.WithCancel(context.Background())
	if err := vpnClient.Start(ctx); err != nil {
		cancel()
		return fmt.Errorf("failed to start VPN: %w", err)
	}

	// Auto-enable port hopping from server capabilities if not already configured
	if !mgr.IsPortHoppingEnabled() {
		caps := vpnClient.GetServerCapabilities()
		if caps.PortHoppingEnabled && caps.PortRangeStart > 0 && caps.PortRangeEnd > caps.PortRangeStart {
			// Use server-provided config with defaults
			hopInterval := time.Duration(caps.HopIntervalSec) * time.Second
			if hopInterval <= 0 {
				hopInterval = 60 * time.Second
			}
			hopStrategy := porthopping.Strategy(caps.HopStrategy)
			if hopStrategy == "" {
				hopStrategy = porthopping.StrategyRandom
			}

			phCfg := &porthopping.Config{
				Enabled:        true,
				PortRangeStart: caps.PortRangeStart,
				PortRangeEnd:   caps.PortRangeEnd,
				HopInterval:    hopInterval,
				Strategy:       hopStrategy,
				Seed:           caps.HopSeed,
			}
			log.Info("Auto-enabling port hopping from server config: range %d-%d, interval %v, strategy %s",
				caps.PortRangeStart, caps.PortRangeEnd, hopInterval, hopStrategy)
			if mgr.EnablePortHopping(phCfg) {
				// Start the port hop checker
				mgr.StartPortHopChecker(ctx)
			}
		}
	}

	log.Info("VPN started on %s (IP: %s)", cfg.TunName, cfg.TunIP)
	if len(routes) > 0 {
		log.Info("Routes: %v", routes)
	}

	// Initialize metrics if API addr is configured (TUN mode, no pool yet)
	if cfg.APIAddr != "" {
		clientMetrics = NewClientMetrics(mgr, nil)
		clientMetrics.SetMode(true) // TUN mode
		go startAPIServer(cfg.APIAddr, clientMetrics)

		// Periodically sync VPN stats to metrics
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			var lastPacketsUp, lastPacketsDown, lastBytesUp, lastBytesDown int64
			for {
				select {
				case <-ticker.C:
					packetsUp, packetsDown, bytesUp, bytesDown := vpnClient.Stats()
					// Calculate deltas
					deltaPacketsUp := packetsUp - lastPacketsUp
					deltaPacketsDown := packetsDown - lastPacketsDown
					deltaBytesUp := bytesUp - lastBytesUp
					deltaBytesDown := bytesDown - lastBytesDown
					// Update metrics
					if deltaPacketsUp > 0 || deltaPacketsDown > 0 {
						clientMetrics.AddPackets(deltaPacketsUp, deltaPacketsDown)
					}
					if deltaBytesUp > 0 || deltaBytesDown > 0 {
						clientMetrics.AddBytes(deltaBytesUp, deltaBytesDown)
					}
					// Save last values
					lastPacketsUp = packetsUp
					lastPacketsDown = packetsDown
					lastBytesUp = bytesUp
					lastBytesDown = bytesDown
					// Sync current strategy from manager
					info := mgr.GetLastConnectionInfo()
					if info.Strategy != "" {
						clientMetrics.SetCurrentStrategy(info.StrategyID, info.Strategy)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Also start SOCKS/HTTP proxy if listen addresses are specified
	var tunnelPool *pool.TunnelPool
	var listener, httpListener net.Listener

	if cfg.ListenAddr != "" {
		// Create connection pool for proxy
		poolCfg := pool.DefaultConfig()
		tunnelPool = pool.NewTunnelPool(mgr, cfg.ServerAddr, poolCfg)

		var err error
		listener, err = net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Warn("Failed to start SOCKS proxy: %v", err)
		} else {
			log.Info("SOCKS5/HTTP proxy listening on %s", cfg.ListenAddr)
			go acceptConnections(listener, tunnelPool, "socks")
		}
	}

	if cfg.HTTPListenAddr != "" {
		var err error
		httpListener, err = net.Listen("tcp", cfg.HTTPListenAddr)
		if err != nil {
			log.Warn("Failed to start HTTP proxy: %v", err)
		} else {
			log.Info("HTTP proxy listening on %s", cfg.HTTPListenAddr)
			go acceptConnections(httpListener, tunnelPool, "http")
		}
	}

	// Wait for signal
	sig := <-sigChan
	log.Info("Received signal %v, shutting down...", sig)
	cancel()
	vpnClient.Stop()

	// Cleanup proxy if started
	if listener != nil {
		listener.Close()
	}
	if httpListener != nil {
		httpListener.Close()
	}
	if tunnelPool != nil {
		tunnelPool.Close()
	}

	up, down, bytesUp, bytesDown := vpnClient.Stats()
	log.Info("Final stats: packets up=%d down=%d, bytes up=%d down=%d", up, down, bytesUp, bytesDown)
	return nil
}

func runProxyMode(cfg *Config, mgr *strategy.Manager, sigChan chan os.Signal) error {
	// Create connection pool
	poolCfg := pool.DefaultConfig()
	tunnelPool := pool.NewTunnelPool(mgr, cfg.ServerAddr, poolCfg)
	log.Info("Connection pool initialized (max=%d, idle=%d)", poolCfg.MaxConnections, poolCfg.MaxIdle)

	// Initialize metrics if API addr is configured
	if cfg.APIAddr != "" {
		clientMetrics = NewClientMetrics(mgr, tunnelPool)
		clientMetrics.SetMode(false) // proxy mode
		go startAPIServer(cfg.APIAddr, clientMetrics)
	}

	// Periodic pool stats logging
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			total, idle := tunnelPool.Stats()
			log.Info("Pool stats: total=%d, idle=%d, max=%d", total, idle, poolCfg.MaxConnections)
		}
	}()

	// Main listener (auto-detect SOCKS5/HTTP)
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	var httpListener net.Listener
	if cfg.HTTPListenAddr != "" {
		httpListener, err = net.Listen("tcp", cfg.HTTPListenAddr)
		if err != nil {
			listener.Close()
			return fmt.Errorf("failed to listen HTTP: %w", err)
		}
	}

	go func() {
		sig := <-sigChan
		log.Info("Received signal %v, shutting down...", sig)
		tunnelPool.Close()
		listener.Close()
		if httpListener != nil {
			httpListener.Close()
		}
		os.Exit(0)
	}()

	var connCounter uint64

	// Start HTTP-only listener if configured
	if httpListener != nil {
		go func() {
			for {
				conn, err := httpListener.Accept()
				if err != nil {
					log.Debug("HTTP Accept error: %v", err)
					return
				}
				// Enable TCP keepalive on client connections
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(15 * time.Second)
				}
				connID := atomic.AddUint64(&connCounter, 1)
				go handleHTTPProxyPooled(conn, tunnelPool, connID)
			}
		}()
	}

	// Main listener with auto-detection
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debug("Accept error: %v", err)
			continue
		}

		// Enable TCP keepalive on client connections so browser detects dead connections faster
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(15 * time.Second) // Fast keepalive for browser
		}

		connID := atomic.AddUint64(&connCounter, 1)
		go handleConnectionPooled(conn, tunnelPool, connID)
	}
}

// acceptConnections accepts connections on a listener and handles them
func acceptConnections(listener net.Listener, tunnelPool *pool.TunnelPool, mode string) {
	var connCounter uint64
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debug("Accept error (%s): %v", mode, err)
			return
		}
		// Enable TCP keepalive
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(15 * time.Second)
		}
		connID := atomic.AddUint64(&connCounter, 1)
		if mode == "http" {
			go handleHTTPProxyPooled(conn, tunnelPool, connID)
		} else {
			go handleConnectionPooled(conn, tunnelPool, connID)
		}
	}
}

// splitRoutes splits comma-separated routes
func splitRoutes(s string) []string {
	var routes []string
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			routes = append(routes, r)
		}
	}
	return routes
}

// Health check configuration
var healthConfig = strategy.HealthConfig{
	ReadTimeout:     30 * time.Second,
	WriteTimeout:    30 * time.Second,
	IdleTimeout:     5 * time.Minute,
	HealthCheckFreq: 30 * time.Second,
}

// handleConnection auto-detects protocol (SOCKS5 or HTTP CONNECT)
func handleConnection(conn net.Conn, mgr *strategy.Manager, serverAddr string, connID uint64) {
	// Note: conn.Close() is called by handleSOCKS5 or handleHTTPProxy

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Peek first byte to detect protocol
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n < 1 {
		conn.Close()
		return
	}

	// Create buffered connection
	buffConn := &bufferedConn{
		Conn:   conn,
		buffer: buf[:n],
	}

	if buf[0] == 0x05 {
		// SOCKS5
		handleSOCKS5(buffConn, mgr, serverAddr, connID)
	} else {
		// HTTP CONNECT
		handleHTTPProxy(buffConn, mgr, serverAddr, connID)
	}
}

// bufferedConn wraps connection with pre-read buffer
type bufferedConn struct {
	net.Conn
	buffer []byte
	offset int
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.offset < len(c.buffer) {
		n := copy(p, c.buffer[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// handleHTTPProxy handles HTTP CONNECT proxy requests
func handleHTTPProxy(conn net.Conn, mgr *strategy.Manager, serverAddr string, connID uint64) {
	defer conn.Close()

	logger := log.WithPrefix(fmt.Sprintf("http:%d", connID))
	logger.Debug("New HTTP connection from %s", conn.RemoteAddr())

	// Read HTTP request line (first byte may already be buffered)
	buf := make([]byte, 4096)
	totalRead := 0

	// Read until we get \r\n\r\n (end of headers)
	for totalRead < len(buf) {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			logger.Debug("Failed to read HTTP request: %v", err)
			return
		}
		totalRead += n

		// Check for end of headers
		if strings.Contains(string(buf[:totalRead]), "\r\n\r\n") {
			break
		}
	}

	if totalRead < 10 {
		logger.Debug("HTTP request too short: %d bytes", totalRead)
		return
	}

	request := string(buf[:totalRead])

	// Parse CONNECT request: "CONNECT host:port HTTP/1.1\r\n..."
	if !strings.HasPrefix(request, "CONNECT ") {
		// Plain HTTP request (GET, POST, etc.) - forward it through tunnel
		handlePlainHTTP(conn, mgr, serverAddr, request, buf[:totalRead], logger)
		return
	}

	// Extract target address
	lines := strings.SplitN(request, "\r\n", 2)
	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		logger.Debug("Invalid CONNECT request")
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	targetAddr := parts[1]

	// Ensure port is present
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	logger.Info("CONNECT %s", targetAddr)

	// Connect to server via Strategy Manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, usedStrategy, err := mgr.Connect(ctx, serverAddr)
	if err != nil {
		logger.Warn("Failed to connect to server: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Wrap with health monitoring
	hConfig := healthConfig
	hConfig.OnUnhealthy = func(reason string) {
		logger.Warn("Connection unhealthy: %s", reason)
	}
	healthConn := strategy.NewHealthMonitoredConn(serverConn, usedStrategy, hConfig)
	healthConn.SetManager(mgr, serverAddr)
	healthConn.SetTargetAddr(targetAddr)
	// Note: Keepalive disabled - strategies have their own framing
	// TODO: Integrate control channel with strategy framing
	defer healthConn.Close()

	logger.Debug("Connected via %s", usedStrategy.Name())

	// Send target address to server
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)
	healthConn.Write(addrPacket)

	// Read server response (30s timeout - server may be slow to connect to target)
	resp := make([]byte, 1)
	serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(serverConn, resp); err != nil {
		logger.Warn("No response from server: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if resp[0] != 0x00 {
		logger.Warn("Server rejected connection: %d", resp[0])
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Send HTTP 200 Connection Established
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Clear deadlines for relay
	conn.SetDeadline(time.Time{})

	// Relay data
	reason := strategy.HealthyRelay(conn, healthConn, 5*time.Second)
	if reason != "" {
		logger.Warn("Relay stopped: %s", reason)
	}

	logger.Debug("Connection closed (strategy=%s)", usedStrategy.Name())
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// handlePlainHTTP handles plain HTTP proxy requests (GET, POST, etc.)
// These requests have absolute URLs: "GET http://host/path HTTP/1.1"
func handlePlainHTTP(conn net.Conn, mgr *strategy.Manager, serverAddr string, request string, rawRequest []byte, logger *log.Logger) {
	// Parse first line: "GET http://httpbin.org/ip HTTP/1.1"
	lines := strings.SplitN(request, "\r\n", 2)
	if len(lines) < 1 {
		logger.Debug("Invalid HTTP request")
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 {
		logger.Debug("Invalid HTTP request line: %s", lines[0])
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	method := parts[0]
	rawURL := parts[1]
	httpVersion := parts[2]

	// Parse URL to extract host
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		logger.Debug("Invalid URL in HTTP request: %s", rawURL)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Determine target address (host:port)
	targetHost := parsedURL.Host
	if !strings.Contains(targetHost, ":") {
		if parsedURL.Scheme == "https" {
			targetHost += ":443"
		} else {
			targetHost += ":80"
		}
	}

	logger.Info("%s %s (via %s)", method, parsedURL.Host, targetHost)

	// Connect to server via Strategy Manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, usedStrategy, err := mgr.Connect(ctx, serverAddr)
	if err != nil {
		logger.Warn("Failed to connect to server: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	logger.Debug("Connected via %s", usedStrategy.Name())

	// Send target address to server (same protocol as CONNECT)
	addrBytes := []byte(targetHost)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)
	serverConn.Write(addrPacket)

	// Read server response
	resp := make([]byte, 1)
	serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(serverConn, resp); err != nil {
		logger.Warn("No response from server: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if resp[0] != 0x00 {
		logger.Warn("Server rejected connection: %d", resp[0])
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Rewrite request to use relative path
	// "GET http://httpbin.org/ip HTTP/1.1" -> "GET /ip HTTP/1.1"
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	// Build rewritten request
	var rewrittenRequest strings.Builder
	rewrittenRequest.WriteString(method)
	rewrittenRequest.WriteString(" ")
	rewrittenRequest.WriteString(path)
	rewrittenRequest.WriteString(" ")
	rewrittenRequest.WriteString(httpVersion)
	rewrittenRequest.WriteString("\r\n")

	// Add remaining headers (skip first line which we already processed)
	if len(lines) > 1 {
		// Check if Host header exists, add if not
		headers := lines[1]
		hasHost := false
		for _, line := range strings.Split(headers, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				hasHost = true
				break
			}
		}
		if !hasHost {
			rewrittenRequest.WriteString("Host: ")
			rewrittenRequest.WriteString(parsedURL.Host)
			rewrittenRequest.WriteString("\r\n")
		}
		rewrittenRequest.WriteString(headers)
	}

	// Send rewritten request to target
	serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := serverConn.Write([]byte(rewrittenRequest.String())); err != nil {
		logger.Warn("Failed to send request: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Clear deadlines for relay
	serverConn.SetDeadline(time.Time{})
	conn.SetDeadline(time.Time{})

	// Relay response back to client
	// For plain HTTP we just need to relay the response, not bidirectional
	_, err = io.Copy(conn, serverConn)
	if err != nil && err != io.EOF {
		logger.Debug("Relay error: %v", err)
	}

	logger.Debug("Plain HTTP request completed")
}

// handleSOCKS5 handles a SOCKS5 connection with health monitoring
func handleSOCKS5(conn net.Conn, mgr *strategy.Manager, serverAddr string, connID uint64) {
	defer conn.Close()

	logger := log.WithPrefix(fmt.Sprintf("socks:%d", connID))
	logger.Debug("New connection from %s", conn.RemoteAddr())

	// Note: first byte (0x05) may already be read by auto-detection
	// bufferedConn will return it first

	// SOCKS5 handshake
	// Read version and number of auth methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		logger.Debug("Failed to read greeting header: %v", err)
		return
	}

	if header[0] != 0x05 {
		logger.Debug("Not SOCKS5: version=%d", header[0])
		return
	}

	// Read auth methods
	numMethods := int(header[1])
	if numMethods > 0 {
		methods := make([]byte, numMethods)
		if _, err := io.ReadFull(conn, methods); err != nil {
			logger.Debug("Failed to read auth methods: %v", err)
			return
		}
	}

	// No auth required
	conn.Write([]byte{0x05, 0x00})

	// Read request header: VER CMD RSV ATYP
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		logger.Debug("Failed to read request header: %v", err)
		return
	}

	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 {
		logger.Debug("Invalid request: ver=%d cmd=%d", reqHeader[0], reqHeader[1])
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse target address based on ATYP
	var targetAddr string
	switch reqHeader[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4+2) // IP + port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		ip := net.IP(addr[0:4])
		port := int(addr[4])<<8 | int(addr[5])
		targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)

	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		addr := make([]byte, domainLen+2) // domain + port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		domain := string(addr[:domainLen])
		port := int(addr[domainLen])<<8 | int(addr[domainLen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)

	case 0x04: // IPv6 - not supported, reject
		logger.Debug("IPv6 not supported, rejecting")
		// Read and discard the IPv6 address (16 bytes) + port (2 bytes)
		discard := make([]byte, 18)
		io.ReadFull(conn, discard)
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return

	default:
		logger.Debug("Unknown address type: %d", reqHeader[3])
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	logger.Info("CONNECT %s", targetAddr)

	// Connect to server via Strategy Manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, usedStrategy, err := mgr.Connect(ctx, serverAddr)
	if err != nil {
		logger.Warn("Failed to connect to server: %v", err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Wrap with health monitoring
	hConfig := healthConfig
	hConfig.OnUnhealthy = func(reason string) {
		logger.Warn("Connection unhealthy: %s, marking strategy for retry", reason)
	}
	healthConn := strategy.NewHealthMonitoredConn(serverConn, usedStrategy, hConfig)
	healthConn.SetManager(mgr, serverAddr)
	healthConn.SetTargetAddr(targetAddr)
	// Note: Keepalive disabled - strategies have their own framing
	// TODO: Integrate control channel with strategy framing
	defer healthConn.Close()

	logger.Debug("Connected via %s", usedStrategy.Name())

	// Send target address to server (length-prefixed) in ONE write
	// Important: must be single write so morph/stego framing treats it as one unit
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)
	healthConn.Write(addrPacket)

	// Read server response (30s timeout - server may be slow to connect to target)
	resp := make([]byte, 1)
	serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(serverConn, resp); err != nil {
		logger.Warn("No response from server: %v", err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if resp[0] != 0x00 {
		logger.Warn("Server rejected connection: %d", resp[0])
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Clear deadlines for relay
	conn.SetDeadline(time.Time{})

	// Relay data with health monitoring
	reason := strategy.HealthyRelay(conn, healthConn, 5*time.Second)
	if reason != "" {
		logger.Warn("Relay stopped: %s", reason)
	}

	// Get stats from health conn
	logger.Debug("Connection closed (strategy=%s, healthy=%v)", usedStrategy.Name(), healthConn.IsHealthy())
}

// ============================================================================
// POOLED CONNECTION HANDLERS
// ============================================================================

// handleConnectionPooled auto-detects protocol using pooled connections
func handleConnectionPooled(conn net.Conn, tunnelPool *pool.TunnelPool, connID uint64) {
	// Track connection in metrics
	if clientMetrics != nil {
		clientMetrics.IncConnections()
		defer clientMetrics.DecConnections()
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Peek first byte to detect protocol
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n < 1 {
		conn.Close()
		return
	}

	// Create buffered connection
	buffConn := &bufferedConn{
		Conn:   conn,
		buffer: buf[:n],
	}

	if buf[0] == 0x05 {
		handleSOCKS5Pooled(buffConn, tunnelPool, connID)
	} else {
		handleHTTPProxyPooled(buffConn, tunnelPool, connID)
	}
}

// handleHTTPProxyPooled handles HTTP proxy with connection pooling
func handleHTTPProxyPooled(conn net.Conn, tunnelPool *pool.TunnelPool, connID uint64) {
	defer conn.Close()

	logger := log.WithPrefix(fmt.Sprintf("http:%d", connID))
	logger.Debug("New HTTP connection from %s", conn.RemoteAddr())

	// Read HTTP request
	buf := make([]byte, 4096)
	totalRead := 0

	for totalRead < len(buf) {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			logger.Debug("Failed to read HTTP request: %v", err)
			return
		}
		totalRead += n
		if strings.Contains(string(buf[:totalRead]), "\r\n\r\n") {
			break
		}
	}

	if totalRead < 10 {
		logger.Debug("HTTP request too short: %d bytes", totalRead)
		return
	}

	request := string(buf[:totalRead])

	if !strings.HasPrefix(request, "CONNECT ") {
		// Plain HTTP - use non-pooled for now (single request)
		handlePlainHTTPPooled(conn, tunnelPool, request, buf[:totalRead], logger)
		return
	}

	// Parse CONNECT request
	lines := strings.SplitN(request, "\r\n", 2)
	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	targetAddr := parts[1]
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	logger.Info("CONNECT %s", targetAddr)

	// Get connection from pool
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, err := tunnelPool.Get(ctx)
	if err != nil {
		logger.Warn("Failed to get connection from pool: %v", err)
		if clientMetrics != nil {
			clientMetrics.IncFailed()
		}
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Record successful connection
	strat := serverConn.Strategy()
	if clientMetrics != nil {
		clientMetrics.RecordConnect(strat.ID(), strat.Name())
	}
	logger.Debug("Got pooled connection (strategy=%s)", strat.Name())

	// Send target address to server
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := serverConn.Write(addrPacket); err != nil {
		logger.Warn("Failed to send target address: %v", err)
		serverConn.Close() // Don't return broken connection to pool
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Read server response
	resp := make([]byte, 1)
	serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(serverConn.Conn, resp); err != nil {
		logger.Warn("No response from server: %v", err)
		serverConn.Close()
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if resp[0] != 0x00 {
		logger.Warn("Server rejected connection: %d", resp[0])
		serverConn.Close()
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Send 200 OK
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	conn.SetDeadline(time.Time{})

	// Relay with pooled connection (no confidence penalty for idle)
	err = pool.PooledRelay(conn, serverConn, 5*time.Minute)
	if err != nil && err != io.EOF {
		logger.Debug("Relay ended: %v", err)
	}

	// Connection is used for specific target, close it (don't reuse)
	serverConn.Close()
	logger.Debug("Connection closed (strategy=%s)", serverConn.Strategy().Name())
}

// handlePlainHTTPPooled handles plain HTTP requests with pooling
func handlePlainHTTPPooled(conn net.Conn, tunnelPool *pool.TunnelPool, request string, rawRequest []byte, logger *log.Logger) {
	lines := strings.SplitN(request, "\r\n", 2)
	if len(lines) < 1 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	method := parts[0]
	rawURL := parts[1]
	httpVersion := parts[2]

	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	targetHost := parsedURL.Host
	if !strings.Contains(targetHost, ":") {
		if parsedURL.Scheme == "https" {
			targetHost += ":443"
		} else {
			targetHost += ":80"
		}
	}

	logger.Info("%s %s", method, parsedURL.Host)

	// Get connection from pool
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, err := tunnelPool.Get(ctx)
	if err != nil {
		logger.Warn("Failed to get connection from pool: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Send target address
	addrBytes := []byte(targetHost)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	serverConn.Write(addrPacket)

	// Read server response
	resp := make([]byte, 1)
	serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(serverConn.Conn, resp); err != nil {
		logger.Warn("No response from server: %v", err)
		serverConn.Close()
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if resp[0] != 0x00 {
		serverConn.Close()
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Rewrite request to relative path
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	var rewritten strings.Builder
	rewritten.WriteString(method)
	rewritten.WriteString(" ")
	rewritten.WriteString(path)
	rewritten.WriteString(" ")
	rewritten.WriteString(httpVersion)
	rewritten.WriteString("\r\n")

	if len(lines) > 1 {
		headers := lines[1]
		hasHost := false
		for _, line := range strings.Split(headers, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				hasHost = true
				break
			}
		}
		if !hasHost {
			rewritten.WriteString("Host: ")
			rewritten.WriteString(parsedURL.Host)
			rewritten.WriteString("\r\n")
		}
		rewritten.WriteString(headers)
	}

	serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	serverConn.Write([]byte(rewritten.String()))

	// Relay response
	serverConn.SetDeadline(time.Time{})
	conn.SetDeadline(time.Time{})
	io.Copy(conn, serverConn.Conn)

	serverConn.Close()
}

// handleSOCKS5Pooled handles SOCKS5 with connection pooling
func handleSOCKS5Pooled(conn net.Conn, tunnelPool *pool.TunnelPool, connID uint64) {
	defer conn.Close()

	logger := log.WithPrefix(fmt.Sprintf("socks:%d", connID))
	logger.Debug("New connection from %s", conn.RemoteAddr())

	// SOCKS5 handshake
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	if header[0] != 0x05 {
		return
	}

	numMethods := int(header[1])
	if numMethods > 0 {
		methods := make([]byte, numMethods)
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
	}

	conn.Write([]byte{0x05, 0x00})

	// Read request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse target address
	var targetAddr string
	switch reqHeader[3] {
	case 0x01: // IPv4
		addr := make([]byte, 6)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		ip := net.IP(addr[0:4])
		port := int(addr[4])<<8 | int(addr[5])
		targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)

	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		addr := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		domain := string(addr[:len(addr)-2])
		port := int(addr[len(addr)-2])<<8 | int(addr[len(addr)-1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)

	case 0x04: // IPv6 - not supported, reject
		logger.Debug("IPv6 not supported, rejecting")
		discard := make([]byte, 18)
		io.ReadFull(conn, discard)
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	logger.Info("CONNECT %s", targetAddr)

	// Get connection from pool
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, err := tunnelPool.Get(ctx)
	if err != nil {
		logger.Warn("Failed to get connection from pool: %v", err)
		if clientMetrics != nil {
			clientMetrics.IncFailed()
		}
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Record successful connection
	strat := serverConn.Strategy()
	if clientMetrics != nil {
		clientMetrics.RecordConnect(strat.ID(), strat.Name())
	}
	logger.Debug("Got pooled connection (strategy=%s)", strat.Name())

	// Send target address
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := serverConn.Write(addrPacket); err != nil {
		logger.Warn("Failed to send target: %v", err)
		serverConn.Close()
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Read server response (ConfusedConn handles length-prefix internally)
	serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp := make([]byte, 1)
	if _, err := io.ReadFull(serverConn.Conn, resp); err != nil {
		logger.Warn("No response from server: %v", err)
		serverConn.Close()
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if resp[0] != 0x00 {
		logger.Warn("Server rejected connection: %d", resp[0])
		serverConn.Close()
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})

	// Relay data (ConfusedConn handles length-prefixed framing internally)
	err = pool.PooledRelay(conn, serverConn, 5*time.Minute)
	if err != nil && err != io.EOF {
		logger.Debug("Relay ended: %v", err)
	}

	// Connection used for specific target, close (don't reuse)
	serverConn.Close()
	logger.Debug("Connection closed (strategy=%s)", serverConn.Strategy().Name())
}

// startAPIServer starts the metrics HTTP server
func startAPIServer(addr string, metrics *ClientMetrics) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics.Handler())

	log.Info("Metrics server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Warn("Metrics server error: %v", err)
	}
}
