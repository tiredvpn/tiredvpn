package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tiredvpn/tiredvpn/internal/control"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/padding"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	Version     = "0.2.0"
	connCounter uint64
)

// checkUDPBufferSizes checks if system UDP buffer sizes are adequate for QUIC
// Returns true if buffers are properly configured
func checkUDPBufferSizes() bool {
	const minBuffer = 7500000 // 7.5MB recommended for QUIC

	rmemMax, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		log.Warn("Cannot read rmem_max: %v", err)
		return false
	}

	wmemMax, err := os.ReadFile("/proc/sys/net/core/wmem_max")
	if err != nil {
		log.Warn("Cannot read wmem_max: %v", err)
		return false
	}

	var rmem, wmem int
	fmt.Sscanf(string(bytes.TrimSpace(rmemMax)), "%d", &rmem)
	fmt.Sscanf(string(bytes.TrimSpace(wmemMax)), "%d", &wmem)

	if rmem < minBuffer || wmem < minBuffer {
		log.Warn("UDP buffer sizes too small for optimal QUIC performance!")
		log.Warn("  Current: rmem_max=%d, wmem_max=%d", rmem, wmem)
		log.Warn("  Recommended: %d (7.5MB)", minBuffer)
		log.Warn("  Fix with: sysctl -w net.core.rmem_max=%d net.core.wmem_max=%d", minBuffer, minBuffer)
		log.Warn("  Persist: add to /etc/sysctl.conf")
		return false
	}

	log.Debug("UDP buffer sizes OK: rmem_max=%d, wmem_max=%d", rmem, wmem)
	return true
}

// setTCPOptions applies performance optimizations to TCP connections
func setTCPOptions(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)   // Disable Nagle's algorithm for low latency
		tc.SetKeepAlive(true) // Enable TCP keepalive
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetReadBuffer(64 * 1024)  // 64KB read buffer
		tc.SetWriteBuffer(64 * 1024) // 64KB write buffer
	}
}

// optimizedDial dials with TCP optimizations applied
func optimizedDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	setTCPOptions(conn)
	return conn, nil
}

// optimizedRelay copies between connections using larger buffers
func optimizedRelay(dst, src net.Conn) (int64, error) {
	buf := GetRelayBuffer()
	defer PutRelayBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}

// isTimeout checks if error is a timeout error
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// relayWithControl relays data while handling control messages
// clientConn is the VPN client, targetConn is the destination server
// Control messages from client are handled and responded to, not forwarded
func relayWithControl(clientConn, targetConn net.Conn) (bytesUp, bytesDown int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	var up, down int64

	// Client -> Target (with control message filtering)
	go func() {
		defer wg.Done()
		buf := GetRelayBuffer()
		defer PutRelayBuffer(buf)

		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				// Check for control message
				if control.IsControlMessage(buf[:n]) {
					// Handle control message and respond
					control.HandleServerMessage(clientConn, buf[:n])
					continue // Don't forward to target
				}
				// Forward to target
				written, werr := targetConn.Write(buf[:n])
				atomic.AddInt64(&up, int64(written))
				if werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Target -> Client (pass through)
	go func() {
		defer wg.Done()
		buf := GetRelayBuffer()
		defer PutRelayBuffer(buf)

		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				written, werr := clientConn.Write(buf[:n])
				atomic.AddInt64(&down, int64(written))
				if werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	bytesUp = atomic.LoadInt64(&up)
	bytesDown = atomic.LoadInt64(&down)
	return
}

// Config holds server configuration
type Config struct {
	ListenAddr  string
	CertFile    string
	KeyFile     string
	Secret      []byte // Single secret mode (backward compatible)
	FakeWebRoot string
	Debug       bool
	TunIP       net.IP
	TunName     string // TUN interface name (default: tiredvpn0)

	// Multi-client mode (Redis)
	RedisAddr string // e.g., "localhost:6379"
	APIAddr   string // e.g., "127.0.0.1:8080"

	// Upstream (multi-hop) mode
	UpstreamAddr   string // e.g., "exit-server.com:443"
	UpstreamSecret string // secret for upstream auth

	// QUIC mode
	QUICEnabled           bool   // Enable QUIC listener
	QUICListenAddr        string // e.g., ":443" (UDP)
	QUICSNIFragReassembly bool   // Enable SNI fragment reassembly for GFW bypass

	// IP Pool for TUN mode (auto IP assignment)
	IPPoolNetwork   string        // CIDR range, e.g., "10.8.0.0/24"
	IPPoolLeaseTime time.Duration // Lease duration (0 = permanent)

	// Port hopping (multi-port listening)
	PortRange         string        // Single port ("995") or range ("47000-47100")
	PortRangeMaxPorts int           // Maximum number of ports to open (default: 50)
	PortHopInterval   time.Duration // Hop interval hint for clients (default: 60s)
	PortHopStrategy   string        // Strategy hint: "random", "sequential", "fibonacci" (default: "random")
	PortHopSeed       string        // Optional seed for deterministic hopping

	// IPv6 Support
	ListenAddrV6 string // "[::]:995"
	EnableIPv6   bool   // default: true
	DualStack    bool   // default: true

	// Shaper, when non-nil, is built from TOML [shaper]. The server-side
	// pipeline does not yet consume it — server morph processing lives
	// outside internal/strategy.MorphedConn — so this field is reserved for
	// future wiring. Stored to keep the TOML round-trip honest.
	Shaper any
}

// serverContext holds runtime context for multi-client mode
type serverContext struct {
	cfg            *Config
	registry       *ClientRegistry
	store          *RedisStore
	upstreamDialer *UpstreamDialer // for multi-hop mode
	metrics        *Metrics        // Prometheus metrics
	tlsConfig      *tls.Config     // TLS config for non-REALITY connections
	ipPool         *IPPool         // IP pool for TUN mode
	sharedTUN      *SharedTUN      // Shared TUN device for all clients
}

// Run starts the server with the given configuration
func Run(cfg *Config) error {
	if cfg.Debug {
		log.SetDebug(true)
	}

	if err := InitREALITYKeys(); err != nil {
		return fmt.Errorf("reality initialization failed: %w", err)
	}

	srvCtx := &serverContext{cfg: cfg}

	if err := initClientMode(cfg, srvCtx); err != nil {
		return err
	}

	if err := initUpstreamMode(cfg, srvCtx); err != nil {
		return err
	}

	if err := initIPPool(cfg, srvCtx); err != nil {
		return err
	}

	if err := initTLSConfig(cfg, srvCtx); err != nil {
		return err
	}

	listener, err := createTCPListener(cfg)
	if err != nil {
		return err
	}

	log.Info("Debug mode: %v", cfg.Debug)

	quicServer := startQUICServer(cfg, srvCtx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go handleShutdownSignal(sigChan, srvCtx, quicServer, listener)

	if cfg.EnableIPv6 && cfg.ListenAddrV6 != "" {
		log.Info("Starting dual-stack mode: IPv4 and IPv6")
		go func() {
			if err := startIPv6Listener(cfg.ListenAddrV6, srvCtx); err != nil {
				log.Error("IPv6 listener failed: %v", err)
			}
		}()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debug("Accept error: %v", err)
			continue
		}
		connID := atomic.AddUint64(&connCounter, 1)
		go handleConnection(conn, srvCtx, connID)
	}
}

// initClientMode sets up multi-client (Redis) or single-secret mode.
func initClientMode(cfg *Config, srvCtx *serverContext) error {
	if cfg.RedisAddr != "" {
		return initRedisMode(cfg, srvCtx)
	}
	if len(cfg.Secret) == 0 {
		return fmt.Errorf("secret is required: set -secret flag or TIREDVPN_SECRET env variable")
	}
	secretHash := sha256.Sum256(cfg.Secret)
	log.Debug("Single-client mode, secret hash: %x", secretHash[:8])
	return nil
}

// initRedisMode initialises Redis store, client registry, API server and stats flush.
func initRedisMode(cfg *Config, srvCtx *serverContext) error {
	store, err := NewRedisStore(cfg.RedisAddr)
	if err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}
	srvCtx.store = store

	registry := NewClientRegistry(store)
	ctx := context.Background()
	if err := registry.Start(ctx); err != nil {
		return fmt.Errorf("registry start failed: %w", err)
	}
	srvCtx.registry = registry

	log.Info("Multi-client mode enabled with Redis at %s", cfg.RedisAddr)

	if cfg.APIAddr == "" {
		cfg.APIAddr = "127.0.0.1:8080"
	}
	api := NewAPIServer(registry, store, cfg.APIAddr)
	srvCtx.metrics = api.Metrics()
	go func() {
		if err := api.Start(ctx); err != nil {
			log.Error("API server error: %v", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			registry.FlushStats(ctx)
		}
	}()
	return nil
}

// initUpstreamMode configures multi-hop upstream dialer.
func initUpstreamMode(cfg *Config, srvCtx *serverContext) error {
	if cfg.UpstreamAddr == "" {
		return nil
	}
	if cfg.UpstreamSecret == "" {
		return fmt.Errorf("upstream-secret required when using upstream mode")
	}
	srvCtx.upstreamDialer = NewUpstreamDialer(cfg.UpstreamAddr, []byte(cfg.UpstreamSecret))
	log.Info("Upstream mode enabled: %s", cfg.UpstreamAddr)
	return nil
}

// initIPPool initialises the IP pool and shared TUN device for TUN mode.
func initIPPool(cfg *Config, srvCtx *serverContext) error {
	if cfg.IPPoolNetwork == "" {
		return nil
	}

	var redisClient *redis.Client
	if srvCtx.store != nil {
		redisClient = srvCtx.store.Client()
	}

	pool, err := NewIPPool(IPPoolConfig{
		Network:   cfg.IPPoolNetwork,
		ServerIP:  cfg.TunIP.String(),
		LeaseTime: cfg.IPPoolLeaseTime,
	}, redisClient)
	if err != nil {
		return fmt.Errorf("IP pool initialization failed: %w", err)
	}
	srvCtx.ipPool = pool
	pool.StartCleanupRoutine(context.Background(), 5*time.Minute)
	log.Info("IP Pool enabled: %s (server=%s, lease=%v)", cfg.IPPoolNetwork, cfg.TunIP, cfg.IPPoolLeaseTime)

	_, network, err := net.ParseCIDR(cfg.IPPoolNetwork)
	if err != nil {
		return fmt.Errorf("failed to parse IP pool network: %w", err)
	}

	tunName := cfg.TunName
	if tunName == "" {
		tunName = "tiredvpn0"
	}
	sharedTUN, err := NewSharedTUN(tunName, cfg.TunIP, network, tun.DefaultMTU, 0)
	if err != nil {
		return fmt.Errorf("failed to create shared TUN: %w", err)
	}
	srvCtx.sharedTUN = sharedTUN
	sharedTUN.StartCleanupRoutine(2*time.Minute, 5*time.Minute)
	return nil
}

// initTLSConfig loads the TLS certificate and builds the tls.Config.
func initTLSConfig(cfg *Config, srvCtx *serverContext) error {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	srvCtx.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos: []string{
			"tired-stego",
			"tired-raw",
			"tired-morph",
			"tired-ws",
			"tired-polling",
			"h2",
			"http/1.1",
		},
		MinVersion: tls.VersionTLS12,
	}
	return nil
}

// createTCPListener creates the main TCP listener (multi-port or single-port).
func createTCPListener(cfg *Config) (net.Listener, error) {
	if cfg.PortRange != "" {
		return createMultiPortTCPListener(cfg)
	}
	addr := cfg.ListenAddr
	if strings.HasPrefix(addr, ":") {
		addr = "0.0.0.0" + addr
	}
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	log.Info("tiredvpn server %s listening on %s", Version, cfg.ListenAddr)
	return l, nil
}

// createMultiPortTCPListener creates a MultiPortListener from the port-range config.
func createMultiPortTCPListener(cfg *Config) (net.Listener, error) {
	host, mainPortStr, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		host = "0.0.0.0"
		mainPortStr = ""
	}

	maxPorts := cfg.PortRangeMaxPorts
	if maxPorts <= 0 {
		maxPorts = 50
	}

	rangePorts, err := ParsePortRange(cfg.PortRange, maxPorts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port range: %w", err)
	}

	allPorts := mergeMainPort(mainPortStr, rangePorts, true)
	mpl, err := NewMultiPortListener(host, allPorts)
	if err != nil {
		return nil, fmt.Errorf("failed to create multi-port listener: %w", err)
	}
	log.Info("tiredvpn server %s listening on %d TCP ports (main: %s, range: %s)", Version, mpl.NumPorts(), mainPortStr, cfg.PortRange)
	return mpl, nil
}

// mergeMainPort prepends mainPortStr to ports if not already present.
// logIfAdded logs when the main port is added (used for TCP listener only).
func mergeMainPort(mainPortStr string, rangePorts []int, logIfAdded bool) []int {
	if mainPortStr == "" {
		return rangePorts
	}
	mainPort, perr := strconv.Atoi(mainPortStr)
	if perr != nil || mainPort <= 0 || mainPort >= 65536 {
		return rangePorts
	}
	for _, p := range rangePorts {
		if p == mainPort {
			return rangePorts
		}
	}
	if logIfAdded {
		log.Info("Including main port %d in addition to port hopping range", mainPort)
	}
	return append([]int{mainPort}, rangePorts...)
}

// startQUICServer starts the QUIC UDP server if enabled; returns nil if disabled.
func startQUICServer(cfg *Config, srvCtx *serverContext) *strategy.QUICServer {
	if !cfg.QUICEnabled {
		return nil
	}
	checkUDPBufferSizes()

	quicAddr := cfg.QUICListenAddr
	if quicAddr == "" {
		quicAddr = cfg.ListenAddr
	}

	quicCfg := buildQUICServerConfig(cfg, srvCtx, quicAddr)
	srv := strategy.NewQUICServer(quicCfg)

	ctx := context.Background()
	err := srv.Start(ctx, func(conn net.Conn) {
		connID := atomic.AddUint64(&connCounter, 1)
		handleQUICConnection(conn, srvCtx, connID)
	})
	if err != nil {
		log.Error("Failed to start QUIC server: %v", err)
		return nil
	}
	if len(quicCfg.Ports) > 0 {
		log.Info("QUIC server listening on %d UDP ports (port hopping enabled)", len(quicCfg.Ports))
	} else {
		log.Info("QUIC server listening on %s (UDP)", quicAddr)
	}
	return srv
}

// buildQUICServerConfig constructs strategy.QUICServerConfig including multi-port UDP support.
func buildQUICServerConfig(cfg *Config, srvCtx *serverContext, quicAddr string) strategy.QUICServerConfig {
	qcfg := strategy.QUICServerConfig{
		ListenAddr:            quicAddr,
		CertFile:              cfg.CertFile,
		KeyFile:               cfg.KeyFile,
		Secret:                cfg.Secret,
		SNIFragmentReassembly: cfg.QUICSNIFragReassembly,
		GetClientSecrets: func() []strategy.SecretInfo {
			if srvCtx.registry == nil {
				return nil
			}
			clients := srvCtx.registry.ListClients()
			secrets := make([]strategy.SecretInfo, 0, len(clients))
			for _, c := range clients {
				secrets = append(secrets, strategy.SecretInfo{
					Secret:   []byte(c.Secret),
					ClientID: c.ID,
					Name:     c.Name,
				})
			}
			return secrets
		},
	}

	if cfg.PortRange == "" {
		return qcfg
	}

	maxPorts := cfg.PortRangeMaxPorts
	if maxPorts <= 0 {
		maxPorts = 50
	}
	rangePorts, err := ParsePortRange(cfg.PortRange, maxPorts)
	if err != nil {
		log.Warn("QUIC: failed to parse port range: %v, using single port", err)
		return qcfg
	}
	if len(rangePorts) == 0 {
		return qcfg
	}

	_, mainPortStr, _ := net.SplitHostPort(quicAddr)
	allPorts := mergeMainPort(mainPortStr, rangePorts, false)
	qcfg.Ports = allPorts
	log.Info("QUIC multi-port mode: %d UDP ports configured", len(allPorts))
	return qcfg
}

// handleShutdownSignal waits for OS signal and performs graceful shutdown.
func handleShutdownSignal(sigChan chan os.Signal, srvCtx *serverContext, quicServer *strategy.QUICServer, listener net.Listener) {
	sig := <-sigChan
	log.Info("Received signal %v, shutting down...", sig)
	if srvCtx.registry != nil {
		srvCtx.registry.Stop()
	}
	if srvCtx.store != nil {
		srvCtx.store.Close()
	}
	if quicServer != nil {
		quicServer.Stop()
	}
	listener.Close()
	os.Exit(0)
}

// runDualStackListeners starts both IPv4 and IPv6 listeners in parallel
// startIPv6Listener creates and runs IPv6 listener
func startIPv6Listener(addr string, srvCtx *serverContext) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp6", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on IPv6: %w", err)
	}
	defer listener.Close()

	log.Info("Server listening on IPv6: %s", addr)

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debug("IPv6 accept error: %v", err)
			continue
		}

		// Log IPv6 client
		if tcpConn, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			log.Info("IPv6 client connected: %s", tcpConn.IP)
		}

		connID := atomic.AddUint64(&connCounter, 1)
		go handleConnection(conn, srvCtx, connID)
	}
}

// handleQUICConnection handles authenticated QUIC connections
func handleQUICConnection(conn net.Conn, srvCtx *serverContext, connID uint64) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger := log.WithPrefix(fmt.Sprintf("quic:%d", connID))

	logger.Info("QUIC connection from %s (authenticated)", remoteAddr)

	// Extract clientID from QUICServerConn if available
	clientID := ""
	if qc, ok := conn.(*strategy.QUICServerConn); ok {
		clientID = qc.ClientID
	}

	// Track per-client connection for metrics
	if srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track QUIC connection for client %s: %v", clientID, err)
		} else {
			defer srvCtx.registry.RemoveConnection(clientID, conn)
		}
	}

	// Read first byte to determine mode
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	modeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, modeBuf); err != nil {
		logger.Debug("Failed to read mode byte: %v", err)
		return
	}

	// Check if this is TUN mode (0x02)
	if modeBuf[0] == 0x02 {
		logger.Debug("QUIC TUN mode detected, clientID=%s", clientID)
		// Read rest of TUN handshake: [localIP:4][mtu:2][version:1]
		// Read 7 bytes to support version detection, but legacy clients only send 6
		tunData := make([]byte, 7)
		n, err := conn.Read(tunData)
		if err != nil || n < 6 {
			logger.Debug("Failed to read TUN handshake: %v (got %d bytes)", err, n)
			return
		}
		// Call TUN handler with pre-read handshake and clientID
		handleTUNModeWithHandshake(conn, srvCtx, logger, tunData[:n], clientID)
		return
	}

	// Regular SOCKS mode - first byte is high byte of address length
	// Read second byte of address length
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		logger.Debug("Failed to read address length: %v", err)
		return
	}

	addrLen := int(modeBuf[0])<<8 | int(lenBuf[0])
	if addrLen < 3 || addrLen > 256 {
		logger.Debug("Invalid address length: %d", addrLen)
		return
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(conn, addrBuf); err != nil {
		logger.Debug("Failed to read address: %v", err)
		return
	}

	targetAddr := string(addrBuf)
	logger.Info("QUIC tunnel to: %s", targetAddr)

	// Connect to target
	var targetConn net.Conn
	var err error
	if srvCtx.upstreamDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		targetConn, err = srvCtx.upstreamDialer.Dial(ctx, targetAddr)
		cancel()
	} else {
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}

	if err != nil {
		logger.Warn("Failed to connect to %s: %v", targetAddr, err)
		// Send failure response: [0x01]
		conn.Write([]byte{0x01})
		return
	}
	defer targetConn.Close()

	// Send success response: [0x00]
	conn.Write([]byte{0x00})
	logger.Debug("Connected to target, starting QUIC relay")

	// Clear deadline for relay
	conn.SetReadDeadline(time.Time{})

	// Simple bidirectional relay (no framing needed for QUIC - it handles multiplexing)
	var wg sync.WaitGroup
	var bytesUp, bytesDown int64

	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		n, _ := optimizedRelay(targetConn, conn)
		atomic.AddInt64(&bytesUp, n)
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		n, _ := optimizedRelay(conn, targetConn)
		atomic.AddInt64(&bytesDown, n)
	}()

	wg.Wait()
	logger.Info("QUIC relay closed: up=%d down=%d", bytesUp, bytesDown)

	// Update metrics
	if srvCtx.metrics != nil {
		srvCtx.metrics.AddBytes(bytesUp, bytesDown)
	}

	// Update per-client metrics
	if srvCtx.registry != nil && clientID != "" {
		srvCtx.registry.AddBytes(clientID, bytesUp, bytesDown)
	}
}

func handleConnection(conn net.Conn, srvCtx *serverContext, connID uint64) {
	cfg := srvCtx.cfg
	defer conn.Close()

	// Track connection metrics
	if srvCtx.metrics != nil {
		srvCtx.metrics.IncConnections()
		defer srvCtx.metrics.DecConnections()
	}

	remoteAddr := conn.RemoteAddr().String()
	logger := log.WithPrefix(fmt.Sprintf("conn:%d", connID))

	logger.Info("New connection from %s", remoteAddr)

	// Set initial read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Peek first bytes to detect protocol
	// First read TLS record header (5 bytes) to get record length
	header := make([]byte, 5)
	n, err := io.ReadFull(conn, header)
	if err != nil || n < 5 {
		logger.Debug("Failed to read header: %v (read %d bytes)", err, n)
		serveFakeWebsite(conn, cfg, logger)
		return
	}

	// For TLS records, read full record to catch REALITY extension in padding
	var peekBuf []byte
	if header[0] == 0x16 { // TLS Handshake
		recordLen := int(header[3])<<8 | int(header[4])
		logger.Debug("TLS header received: %02x %02x %02x %02x %02x (record_len=%d, 0x%04x)",
			header[0], header[1], header[2], header[3], header[4], recordLen, recordLen)
		if recordLen > 16384 { // Max TLS record size
			recordLen = 16384
		}
		peekBuf = make([]byte, 5+recordLen)
		copy(peekBuf, header)

		// Read TLS record in chunks to support heavily fragmented ClientHello.
		// Morph strategy sends ~750 fragments of 2 bytes each (1ms delay between).
		// Per-chunk timeouts cause false failures under congestion (parallel probing).
		// Use a single overall deadline instead.
		totalRead := 0
		startTime := time.Now()
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		for totalRead < recordLen {
			chunkSize := recordLen - totalRead
			if chunkSize > 4096 {
				chunkSize = 4096
			}

			n, err := io.ReadAtLeast(conn, peekBuf[5+totalRead:5+totalRead+chunkSize], 1)
			if err != nil {
				logger.Debug("Failed to read TLS record: %v (read %d/%d bytes)",
					err, totalRead, recordLen)
				serveFakeWebsite(conn, cfg, logger)
				return
			}

			totalRead += n
			logger.Debug("Read chunk: %d bytes (total: %d/%d)", n, totalRead, recordLen)
		}

		logger.Debug("Completed reading TLS payload: %d bytes in %v", totalRead, time.Since(startTime))

		// Reset deadline for subsequent operations
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	} else {
		// Non-TLS: read available data (up to 2048 bytes)
		restBuf := make([]byte, 2043)
		n, _ := io.ReadAtLeast(conn, restBuf, 1)
		peekBuf = make([]byte, 5+n)
		copy(peekBuf, header)
		copy(peekBuf[5:], restBuf[:n])
	}

	logger.Debug("First %d bytes: %s", len(peekBuf), log.HexDump(peekBuf, 32))

	// Create buffered connection with peeked data
	buffConn := &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peekBuf), conn),
	}

	// Check for HTTP/2 preface
	if string(peekBuf) == http2.ClientPreface {
		logger.Debug("Detected HTTP/2 protocol")
		handleHTTP2(buffConn, srvCtx, logger)
		return
	}

	// Check for Morph protocol magic "MRPH"
	if bytes.HasPrefix(peekBuf, []byte("MRPH")) {
		logger.Debug("Detected Morph protocol")
		handleMorphConnection(buffConn, srvCtx, logger)
		return
	}

	// Check for REALITY protocol (TLS with REALITY extension)
	if DetectREALITYExtension(peekBuf) {
		logger.Info("Detected REALITY protocol")
		HandleREALITYConnection(buffConn, srvCtx, logger)
		return
	}

	// Check if this is a TLS ClientHello (without REALITY extension)
	// We need to perform TLS handshake first, then detect inner protocol
	if len(peekBuf) > 0 && peekBuf[0] == 0x16 {
		logger.Debug("TLS ClientHello detected (no REALITY extension), performing TLS handshake")

		// Wrap buffered connection with TLS
		tlsConn := tls.Server(buffConn, srvCtx.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			logger.Debug("TLS handshake failed: %v", err)
			serveFakeWebsite(conn, cfg, logger)
			return
		}

		// kTLS is enabled per-handler in the relay phase, after each protocol's
		// auth/header bytes are fully drained from the TLS stack. See
		// internal/ktls.TryEnable and the handlers below.
		alpn := tlsConn.ConnectionState().NegotiatedProtocol
		_ = alpn // alpn used for logging in handleTLSConnection

		// Clear deadline after successful handshake
		tlsConn.SetReadDeadline(time.Time{})

		// Now detect protocol over TLS
		handleTLSConnection(tlsConn, srvCtx, connID)
		return
	}

	// Non-TLS connections: check for timing knock (anti-probe) with per-client secrets
	if matched, secret, clientID := detectTimingKnockWithRegistry(peekBuf, srvCtx); matched {
		logger.Debug("Detected timing knock pattern (client: %s)", clientID)
		handleAntiProbeAuth(buffConn, srvCtx, secret, clientID, logger)
		return
	}

	// Unknown protocol - serve fake website
	logger.Debug("Unknown protocol (not TLS, not timing knock), serving fake website")
	serveFakeWebsite(buffConn, cfg, logger)
}

// handleTLSConnection handles protocols over TLS (after TLS handshake completed)
// Uses ALPN-based routing when available. Each handler is responsible for
// calling ktls.TryEnable at the relay-phase boundary.
// Falls back to legacy magic-byte detection for backwards compatibility.
func handleTLSConnection(conn *tls.Conn, srvCtx *serverContext, connID uint64) {
	_ = srvCtx.cfg // Used in legacy path
	logger := log.WithPrefix(fmt.Sprintf("conn:%d", connID))

	// Get negotiated ALPN protocol from TLS handshake
	alpn := conn.ConnectionState().NegotiatedProtocol
	logger.Debug("TLS ALPN negotiated: %q", alpn)

	// ALPN-based routing (new clients with kTLS support)
	switch alpn {
	case "tired-stego":
		// HTTP/2 Stego with explicit ALPN - skip preface detection
		logger.Debug("ALPN routing: tired-stego -> HTTP/2 Stego")
		handleHTTP2WithALPN(conn, srvCtx, logger)
		return
	case "tired-raw":
		// Raw tunnel with explicit ALPN
		logger.Debug("ALPN routing: tired-raw -> Raw Tunnel")
		handleRawTunnel(conn, srvCtx, logger, "")
		return
	case "tired-confusion":
		// Protocol Confusion with explicit ALPN
		logger.Debug("ALPN routing: tired-confusion -> Protocol Confusion")
		handleProtocolConfusion(conn, srvCtx, logger)
		return
	case "tired-morph":
		// Traffic Morph with explicit ALPN
		logger.Debug("ALPN routing: tired-morph -> Traffic Morph")
		handleMorphConnectionWithALPN(conn, srvCtx, logger)
		return
	case "tired-ws":
		// WebSocket Padded with explicit ALPN
		logger.Debug("ALPN routing: tired-ws -> WebSocket Padded")
		handleWebSocketConnection(conn, srvCtx, logger)
		return
	case "tired-polling":
		// HTTP Polling (meek-style) with explicit ALPN
		logger.Debug("ALPN routing: tired-polling -> HTTP Polling")
		handleHTTPPollingWithALPN(conn, srvCtx, logger)
		return
	}

	// Fallback: legacy protocol detection (for old clients without custom ALPN)
	logger.Debug("ALPN fallback: using legacy magic-byte detection")
	handleTLSConnectionLegacy(conn, srvCtx, connID)
}

// handleTLSConnectionLegacy handles TLS connections using magic-byte detection
// Used for backwards compatibility with clients that don't send custom ALPN
func handleTLSConnectionLegacy(conn *tls.Conn, srvCtx *serverContext, connID uint64) {
	cfg := srvCtx.cfg
	logger := log.WithPrefix(fmt.Sprintf("conn:%d", connID))

	// Set read deadline for protocol detection
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Peek first bytes to detect protocol over TLS
	peekBuf := make([]byte, 512)
	n, err := io.ReadAtLeast(conn, peekBuf, 24)
	if err != nil && n < 24 {
		logger.Debug("Failed to peek over TLS: %v (read %d bytes)", err, n)
		serveFakeWebsite(conn, cfg, logger)
		return
	}
	peekBuf = peekBuf[:n]

	logger.Debug("First %d bytes over TLS: %s", n, log.HexDump(peekBuf, 64))

	// Create buffered connection with peeked data
	buffConn := &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peekBuf), conn),
	}

	// Clear deadline
	conn.SetReadDeadline(time.Time{})

	// Check for HTTP/2 preface
	if string(peekBuf) == http2.ClientPreface {
		logger.Debug("Detected HTTP/2 protocol over TLS")
		handleHTTP2(buffConn, srvCtx, logger)
		return
	}

	// Check for Morph protocol magic "MRPH"
	if bytes.HasPrefix(peekBuf, []byte("MRPH")) {
		logger.Debug("Detected Morph protocol over TLS")
		handleMorphConnection(buffConn, srvCtx, logger)
		return
	}

	// Check for timing knock sequence (anti-probe over TLS) with per-client secrets
	if matched, secret, clientID := detectTimingKnockWithRegistry(peekBuf, srvCtx); matched {
		logger.Debug("Detected timing knock pattern over TLS (client: %s)", clientID)
		handleAntiProbeAuth(buffConn, srvCtx, secret, clientID, logger)
		return
	}

	// Check for protocol confusion magic
	if detectConfusionMagic(peekBuf) {
		logger.Debug("Detected protocol confusion magic over TLS")
		handleProtocolConfusion(buffConn, srvCtx, logger)
		return
	}

	// Check for WebSocket Padded
	if detectWebSocketPadded(peekBuf) {
		logger.Debug("Detected WebSocket Padded protocol over TLS")
		handleWebSocketPadded(buffConn, srvCtx, logger)
		return
	}

	// Check for HTTP/1.x
	if bytes.HasPrefix(peekBuf, []byte("GET ")) ||
		bytes.HasPrefix(peekBuf, []byte("POST ")) ||
		bytes.HasPrefix(peekBuf, []byte("HEAD ")) {
		logger.Debug("Detected HTTP/1.x protocol over TLS")
		handleHTTP1(buffConn, srvCtx, logger)
		return
	}

	// Unknown protocol - serve fake website
	logger.Debug("Unknown protocol over TLS, serving fake website")
	serveFakeWebsite(buffConn, cfg, logger)
}

// handleHTTP2WithALPN handles HTTP/2 Stego when ALPN was used
// Since kTLS is already enabled, we just need to read the preface and delegate to handleHTTP2
func handleHTTP2WithALPN(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("HTTP/2 via ALPN (kTLS enabled)")
	// handleHTTP2 expects to read the preface first, so we pass conn directly
	// The client still sends preface after ALPN negotiation
	handleHTTP2(conn, srvCtx, logger)
}

// handleMorphConnectionWithALPN handles Morph protocol when ALPN was used
// Since kTLS is already enabled, we just need to delegate to handleMorphConnection
func handleMorphConnectionWithALPN(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Morph via ALPN (kTLS enabled)")
	// handleMorphConnection expects to read the magic first
	handleMorphConnection(conn, srvCtx, logger)
}

// h2TunnelState holds state for HTTP/2 stego tunnel
type h2TunnelState struct {
	targetConn      net.Conn
	streamID        uint32
	clientID        string // Client ID for IP pool allocation
	mu              sync.Mutex
	sharedTUNWriter *ClientWriter // For shared TUN mode
	sharedTUN       *SharedTUN    // Reference to shared TUN
}

// handleHTTP2 handles HTTP/2 connections (including steganography)
func handleHTTP2(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing HTTP/2 connection")

	framer, err := initH2Framer(conn, logger)
	if err != nil {
		return
	}

	hpackDec := hpack.NewDecoder(4096, nil)

	authenticated := false
	var authClientID string
	var tunnel *h2TunnelState
	var connTracked bool
	defer cleanupH2Conn(conn, srvCtx, &tunnel, &connTracked, &authClientID)

	runH2FrameLoop(conn, framer, hpackDec, srvCtx, logger, &authenticated, &authClientID, &connTracked, &tunnel)
}

// initH2Framer reads the HTTP/2 preface, creates a framer and sends server SETTINGS.
func initH2Framer(conn net.Conn, logger *log.Logger) (*http2.Framer, error) {
	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		logger.Debug("Failed to read HTTP/2 preface: %v", err)
		return nil, err
	}
	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalReads = true
	framer.AllowIllegalWrites = true
	if err := framer.WriteSettings(); err != nil {
		logger.Debug("Failed to write SETTINGS: %v", err)
		return nil, err
	}
	return framer, nil
}

// cleanupH2Conn closes tunnel target and removes per-client connection tracking on defer.
func cleanupH2Conn(conn net.Conn, srvCtx *serverContext, tunnel **h2TunnelState, connTracked *bool, authClientID *string) {
	if *tunnel != nil && (*tunnel).targetConn != nil {
		(*tunnel).targetConn.Close()
	}
	if *connTracked && srvCtx.registry != nil && *authClientID != "" {
		srvCtx.registry.RemoveConnection(*authClientID, conn)
	}
}

// runH2FrameLoop reads and dispatches HTTP/2 frames until the connection closes.
func runH2FrameLoop(conn net.Conn, framer *http2.Framer, hpackDec *hpack.Decoder, srvCtx *serverContext, logger *log.Logger, authenticated *bool, authClientID *string, connTracked *bool, tunnel **h2TunnelState) {
	cfg := srvCtx.cfg
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		frame, err := framer.ReadFrame()
		if err != nil {
			if err != io.EOF {
				logger.Debug("Frame read error: %v", err)
			}
			return
		}
		logger.Debug("Received frame: %T (stream=%d)", frame, frame.Header().StreamID)

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				logger.Debug("Received SETTINGS, sending ACK")
				framer.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			processH2HeadersFrame(conn, f, framer, hpackDec, srvCtx, logger, authenticated, authClientID, connTracked)
		case *http2.DataFrame:
			if !*authenticated {
				logger.Debug("Received DATA before auth, ignoring")
				continue
			}
			handleH2DataFrame(conn, f, framer, cfg, srvCtx, *tunnel, *authClientID, logger, tunnel)
		case *http2.WindowUpdateFrame:
			// Ignore
		case *http2.PingFrame:
			framer.WritePing(true, f.Data)
		}
	}
}

// processH2HeadersFrame extracts auth headers and, if valid, marks the connection authenticated.
func processH2HeadersFrame(conn net.Conn, f *http2.HeadersFrame, framer *http2.Framer, hpackDec *hpack.Decoder, srvCtx *serverContext, logger *log.Logger, authenticated *bool, authClientID *string, connTracked *bool) {
	var apiKey, requestID string
	hpackDec.SetEmitFunc(func(hf hpack.HeaderField) {
		logger.Debug("  Header: %s = %s", hf.Name, truncate(hf.Value, 50))
		switch hf.Name {
		case "x-goog-api-key":
			apiKey = hf.Value
		case "x-goog-request-id":
			requestID = hf.Value
		}
	})
	hpackDec.Write(f.HeaderBlockFragment())

	if apiKey == "" || requestID == "" {
		return
	}

	ok, clientID, secret := verifyH2AuthMulti(srvCtx, apiKey, requestID, logger)
	if !ok {
		logger.Warn("HTTP/2 steganography auth FAILED")
		return
	}

	*authenticated = true
	*authClientID = clientID
	sendH2AuthAck(framer, f.StreamID, secret)

	if !*connTracked && srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track H2 connection for client %s: %v", clientID, err)
		} else {
			*connTracked = true
		}
	}
}

// verifyH2AuthMulti checks per-client secrets then global secret for HTTP/2 stego auth.
// Returns (ok, clientID, usedSecret).
func verifyH2AuthMulti(srvCtx *serverContext, apiKey, requestID string, logger *log.Logger) (bool, string, []byte) {
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			if verifyH2Auth(apiKey, requestID, []byte(client.Secret)) {
				logger.Info("HTTP/2 steganography authenticated (client: %s, id: %s)", client.Name, client.ID)
				return true, client.ID, []byte(client.Secret)
			}
		}
	}
	if len(srvCtx.cfg.Secret) > 0 && verifyH2Auth(apiKey, requestID, srvCtx.cfg.Secret) {
		logger.Info("HTTP/2 steganography authenticated (global secret)")
		return true, "global", srvCtx.cfg.Secret
	}
	return false, "", nil
}

// handleH2DataFrame processes an authenticated HTTP/2 DATA frame.
func handleH2DataFrame(conn net.Conn, f *http2.DataFrame, framer *http2.Framer, cfg *Config, srvCtx *serverContext, _ *h2TunnelState, authClientID string, logger *log.Logger, tunnelPtr **h2TunnelState) {
	data := f.Data()
	logger.Debug("Received DATA: %d bytes", len(data))

	if len(data) < 7 || !bytes.Equal(data[0:4], []byte("TIRD")) {
		return
	}

	flags := data[4]
	length := binary.BigEndian.Uint16(data[5:7])
	logger.Debug("Stego frame: flags=%02x, length=%d", flags, length)

	if int(length) > len(data)-7 {
		return
	}

	payload := data[7 : 7+length]
	if flags&0x01 != 0 {
		paddingKey := deriveKey(cfg.Secret, "padding-key")
		for i := range payload {
			payload[i] ^= paddingKey[i%len(paddingKey)]
		}
	}
	logger.Debug("Extracted payload: %d bytes", len(payload))

	tunnel := *tunnelPtr
	if tunnel == nil {
		t := &h2TunnelState{streamID: f.StreamID, clientID: authClientID}
		setupH2Tunnel(t, framer, payload, srvCtx, logger)
		*tunnelPtr = t
		return
	}
	if tunnel.targetConn == nil {
		return
	}

	if _, ok := tunnel.targetConn.(*h2TunConn); ok {
		forwardH2TUNPacket(tunnel, f.StreamID, payload, logger)
	} else {
		forwardH2ProxyData(conn, tunnel, payload, logger)
	}
}

// forwardH2TUNPacket writes an IP packet from the stego payload to the shared TUN device.
func forwardH2TUNPacket(tunnel *h2TunnelState, streamID uint32, payload []byte, logger *log.Logger) {
	tunnel.streamID = streamID
	if len(payload) < 4 || tunnel.sharedTUN == nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(payload[0:4])
	logger.Debug("H2 TUN: received payload len=%d, pktLen=%d", len(payload), pktLen)
	if int(pktLen) > len(payload)-4 || pktLen < 20 {
		logger.Debug("H2 TUN: invalid packet - pktLen=%d, payload=%d", pktLen, len(payload))
		return
	}
	ipPkt := payload[4 : 4+pktLen]
	logger.Debug("H2 TUN: writing %d bytes to TUN, first 20: %x", len(ipPkt), ipPkt[:minInt(20, len(ipPkt))])
	if _, err := tunnel.sharedTUN.TUNDevice().Write(ipPkt); err != nil {
		logger.Debug("H2 TUN write error: %v", err)
	} else {
		logger.Debug("H2 TUN: wrote %d bytes to TUN successfully", len(ipPkt))
	}
	if tunnel.sharedTUNWriter != nil {
		tunnel.sharedTUNWriter.UpdateActivity()
	}
}

// forwardH2ProxyData forwards stego payload to the proxy target connection.
func forwardH2ProxyData(conn net.Conn, tunnel *h2TunnelState, payload []byte, logger *log.Logger) {
	if control.IsControlMessage(payload) {
		control.HandleServerMessage(conn, payload)
		return
	}
	tunnel.mu.Lock()
	n, err := tunnel.targetConn.Write(payload)
	tunnel.mu.Unlock()
	if err != nil {
		logger.Debug("Write to target failed: %v", err)
	} else {
		logger.Debug("Wrote %d bytes to target (first 20: %x)", n, payload[:minInt(20, len(payload))])
	}
}

// handleMorphConnection handles Morph protocol connections
func handleMorphConnection(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing Morph connection")

	// Read MRPH magic (4 bytes) + nameLen (1 byte)
	mrphHeader := make([]byte, 5)
	if _, err := io.ReadFull(conn, mrphHeader); err != nil {
		logger.Debug("Failed to read MRPH header: %v", err)
		return
	}

	if string(mrphHeader[0:4]) != "MRPH" {
		logger.Debug("Invalid MRPH magic")
		return
	}

	nameLen := int(mrphHeader[4])
	var profileName []byte
	if nameLen > 0 {
		// Read profile name
		profileName = make([]byte, nameLen)
		if _, err := io.ReadFull(conn, profileName); err != nil {
			logger.Debug("Failed to read profile name: %v", err)
			return
		}
		logger.Debug("Morph profile: %s", string(profileName))
	}

	// Read auth token (32 bytes HMAC-SHA256)
	authToken := make([]byte, 32)
	if _, err := io.ReadFull(conn, authToken); err != nil {
		logger.Debug("Failed to read auth token: %v", err)
		return
	}

	// Verify auth token against per-client secrets and global secret
	authenticated := false
	var usedSecret []byte
	var clientID string // For IP pool allocation

	// 1. Try per-client secrets from Redis (if registry exists)
	if srvCtx.registry != nil {
		clients := srvCtx.registry.ListClients()
		logger.Debug("Traffic Morph: checking %d clients from registry, token: %x...", len(clients), authToken[:8])
		for _, client := range clients {
			secretBytes := []byte(client.Secret)
			logger.Debug("Traffic Morph: trying client '%s' with secret len=%d prefix=%s...", client.Name, len(client.Secret), client.Secret[:min(16, len(client.Secret))])
			if verifyMorphAuth(authToken, secretBytes) {
				logger.Info("Traffic Morph authenticated (client: %s, id: %s)", client.Name, client.ID)
				authenticated = true
				usedSecret = secretBytes
				clientID = client.ID
				break
			}
		}
	} else {
		logger.Debug("Traffic Morph: no registry available")
	}

	// 2. Fallback to global secret (if not found in registry and global secret exists)
	if !authenticated && len(srvCtx.cfg.Secret) > 0 {
		if verifyMorphAuth(authToken, srvCtx.cfg.Secret) {
			logger.Info("Traffic Morph authenticated (global secret)")
			authenticated = true
			usedSecret = srvCtx.cfg.Secret
			clientID = "global" // Use "global" as clientID for global secret users
		}
	}

	if !authenticated {
		logger.Warn("Traffic Morph authentication FAILED")
		return
	}

	_ = usedSecret // Mark as used

	// Track per-client connection for metrics
	if srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track connection for client %s: %v", clientID, err)
		} else {
			defer srvCtx.registry.RemoveConnection(clientID, conn)
		}
	}

	// Read first morph packet containing target address
	// Morph packet format: [dataLen:4][paddingLen:2][data:N][padding:M]
	morphHdr := make([]byte, 6)
	if _, err := io.ReadFull(conn, morphHdr); err != nil {
		logger.Debug("Failed to read morph packet header: %v", err)
		return
	}

	dataLen := int(morphHdr[0])<<24 | int(morphHdr[1])<<16 | int(morphHdr[2])<<8 | int(morphHdr[3])
	paddingLen := int(morphHdr[4])<<8 | int(morphHdr[5])

	if dataLen == 0 {
		// Dummy packet, skip padding and read next
		logger.Debug("Received dummy packet, reading next")
		if paddingLen > 0 {
			discard := make([]byte, paddingLen)
			io.ReadFull(conn, discard)
		}
		// Try again
		if _, err := io.ReadFull(conn, morphHdr); err != nil {
			return
		}
		dataLen = int(morphHdr[0])<<24 | int(morphHdr[1])<<16 | int(morphHdr[2])<<8 | int(morphHdr[3])
		paddingLen = int(morphHdr[4])<<8 | int(morphHdr[5])
	}

	if dataLen > 256 || dataLen < 2 {
		logger.Debug("Invalid morph data length: %d", dataLen)
		return
	}

	// Read the data (which contains our 2-byte length + address)
	morphData := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, morphData); err != nil {
		logger.Debug("Failed to read morph data: %v", err)
		return
	}

	// Discard padding
	if paddingLen > 0 {
		discard := make([]byte, paddingLen)
		io.ReadFull(conn, discard)
	}

	// Parse target address from morph data
	// Client sends: [mode:1][...] where mode=0x02 is TUN, otherwise [addrLen:2][address:N]
	logger.Debug("Morph data: len=%d, first 10 bytes=%x", len(morphData), morphData[:minInt(10, len(morphData))])
	if len(morphData) < 2 {
		logger.Debug("Morph data too short")
		return
	}

	// Check for TUN mode (first byte = 0x02)
	if morphData[0] == 0x02 {
		logger.Info("Morph TUN mode detected")
		handleMorphTUNMode(conn, morphData[1:], srvCtx, logger, clientID)
		return
	}

	addrLen := int(morphData[0])<<8 | int(morphData[1])
	if addrLen > len(morphData)-2 || addrLen < 3 {
		logger.Debug("Invalid address length in morph data: %d (morphData len=%d)", addrLen, len(morphData))
		return
	}
	targetAddr := string(morphData[2 : 2+addrLen])

	logger.Info("Morph tunnel to: %s", targetAddr)

	// Connect to target (via upstream if configured)
	var targetConn net.Conn
	var err error
	if srvCtx.upstreamDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		targetConn, err = srvCtx.upstreamDialer.Dial(ctx, targetAddr)
		cancel()
	} else {
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		logger.Warn("Failed to connect to %s: %v", targetAddr, err)
		// Send failure via morph packet: [dataLen:4][paddingLen:2][data:1]
		failPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
		conn.Write(failPacket)
		return
	}
	defer targetConn.Close()

	// Send success via morph packet: [dataLen:4][paddingLen:2][data:1]
	successPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	conn.Write(successPacket)
	logger.Debug("Connected to target, starting morph relay")

	// Relay with morph framing
	var wg sync.WaitGroup
	var bytesUp, bytesDown int64

	wg.Add(2)

	// Client -> Target (need to unwrap morph packets)
	go func() {
		defer wg.Done()
		for {
			// Read morph packet header: [dataLen:4][paddingLen:2]
			hdr := make([]byte, 6)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			pktLen := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
			padLen := int(hdr[4])<<8 | int(hdr[5])

			if pktLen == 0 {
				// Dummy packet, discard padding
				if padLen > 0 {
					discard := make([]byte, padLen)
					io.ReadFull(conn, discard)
				}
				continue
			}
			if pktLen > 65536 { // Must match client buffer (32KB + padding)
				return
			}
			data := make([]byte, pktLen)
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			// Discard padding
			if padLen > 0 {
				discard := make([]byte, padLen)
				io.ReadFull(conn, discard)
			}

			// Check for control message
			if control.IsControlMessage(data) {
				control.HandleServerMessage(conn, data)
				continue
			}

			n, err := targetConn.Write(data)
			atomic.AddInt64(&bytesUp, int64(n))
			if err != nil {
				return
			}
		}
	}()

	// Target -> Client (wrap in morph packets)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1400)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			// Wrap in morph packet: [dataLen:4][paddingLen:2][data:n][padding:M]
			padLen := 30 // Simple fixed padding
			packet := make([]byte, 6+n+padLen)
			// Data length
			packet[0] = byte(n >> 24)
			packet[1] = byte(n >> 16)
			packet[2] = byte(n >> 8)
			packet[3] = byte(n)
			// Padding length
			packet[4] = byte(padLen >> 8)
			packet[5] = byte(padLen)
			// Data
			copy(packet[6:], buf[:n])
			// Random padding
			if _, err := rand.Read(packet[6+n:]); err != nil {
				return
			}

			_, err = conn.Write(packet)
			atomic.AddInt64(&bytesDown, int64(n))
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	logger.Info("Morph tunnel closed (up=%d, down=%d)", bytesUp, bytesDown)

	// Update metrics
	if srvCtx.metrics != nil {
		srvCtx.metrics.AddBytes(bytesUp, bytesDown)
	}

	// Update per-client metrics
	if srvCtx.registry != nil && clientID != "" {
		srvCtx.registry.AddBytes(clientID, bytesUp, bytesDown)
	}
}

// morphFramePacket creates Morph-framed packet for TUN->Client
// Format: [dataLen:4][paddingLen:2][len:4][packet:N][padding]
func morphFramePacket(pkt []byte) []byte {
	innerLen := 4 + len(pkt)
	padLen := 30
	totalLen := 6 + innerLen + padLen

	framed := make([]byte, totalLen)
	binary.BigEndian.PutUint32(framed[0:4], uint32(innerLen))
	binary.BigEndian.PutUint16(framed[4:6], uint16(padLen))
	binary.BigEndian.PutUint32(framed[6:10], uint32(len(pkt)))
	copy(framed[10:], pkt)
	if _, err := rand.Read(framed[10+len(pkt):]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return framed
}

// handleMorphTUNMode handles TUN mode over Morph protocol
func handleMorphTUNMode(conn net.Conn, remainingData []byte, srvCtx *serverContext, logger *log.Logger, clientID string) {
	cfg := srvCtx.cfg
	logger.Debug("Processing Morph TUN mode, remaining data: %d bytes, hex=%x", len(remainingData), remainingData)

	// Track per-client connection for metrics
	if srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track connection for client %s: %v", clientID, err)
		} else {
			defer srvCtx.registry.RemoveConnection(clientID, conn)
		}
	}

	// Parse TUN handshake from remaining data: [localIP:4][mtu:2][version:1]
	// Version byte is optional (v1 clients send 6 bytes, v2 clients send 7 bytes)
	if len(remainingData) < 6 {
		logger.Debug("Morph TUN handshake too short: %d bytes", len(remainingData))
		failPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
		conn.Write(failPacket)
		return
	}

	// Check if shared TUN is available
	if srvCtx == nil || srvCtx.sharedTUN == nil {
		logger.Error("Shared TUN not initialized")
		failPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
		conn.Write(failPacket)
		return
	}

	requestedIP := net.IP(remainingData[0:4])

	// Check for version byte (v2 clients send 7 bytes total)
	var clientVersion uint8 = 1 // Default to v1 for backwards compatibility
	if len(remainingData) >= 7 {
		clientVersion = remainingData[6]
		logger.Debug("Morph TUN client requested: IP=%s, version=%d", requestedIP, clientVersion)
	} else {
		logger.Debug("Morph TUN client requested: IP=%s (legacy v1)", requestedIP)
	}

	// Allocate IP from pool (if available) or use requested IP as fallback
	var clientIP net.IP
	if srvCtx.ipPool != nil {
		allocatedIP, err := srvCtx.ipPool.Allocate(clientID, requestedIP, "")
		if err != nil {
			logger.Error("Failed to allocate IP from pool: %v", err)
			failPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
			conn.Write(failPacket)
			return
		}
		clientIP = allocatedIP
		logger.Info("Morph TUN client: allocated IP=%s from pool (requested=%s, clientID=%s)", clientIP, requestedIP, clientID)
	} else {
		clientIP = requestedIP
		logger.Info("Morph TUN client: IP=%s (no pool)", clientIP)
	}

	serverIP := cfg.TunIP

	// Send success response via morph packet: [dataLen:4][paddingLen:2][status:1][serverIP:4][clientIP:4]
	respData := make([]byte, 9)
	respData[0] = 0x00 // Success
	copy(respData[1:5], serverIP)
	copy(respData[5:9], clientIP.To4())

	padLen := 30
	resp := make([]byte, 6+len(respData)+padLen)
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(respData)))
	binary.BigEndian.PutUint16(resp[4:6], uint16(padLen))
	copy(resp[6:], respData)
	if _, err := rand.Read(resp[6+len(respData):]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	conn.Write(resp)

	// Register client with shared TUN using Morph framing
	writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, conn, morphFramePacket)
	defer func() {
		srvCtx.sharedTUN.UnregisterClient(clientIP, writer)
		logger.Info("Morph TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
	}()

	logger.Info("Morph TUN mode established (client=%s, server=%s, tun=%s)", clientIP, serverIP, srvCtx.sharedTUN.Name())

	// Main loop: Morph -> TUN (server-bound traffic)
	// TUN -> Client is handled by SharedTUN packet dispatcher with morphFramePacket
	var packetsUp int64
	var reassemblyBuf []byte
	var writeMu sync.Mutex

	for {
		select {
		case <-writer.Done():
			logger.Debug("Morph TUN loop stopping (client replaced)")
			return
		default:
		}

		// Read morph packet header: [dataLen:4][paddingLen:2]
		hdr := make([]byte, 6)
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.ReadFull(conn, hdr); err != nil {
			logger.Debug("Morph TUN read header error: %v", err)
			return
		}

		dataLen := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		paddingLen := int(hdr[4])<<8 | int(hdr[5])

		// Handle dummy/keepalive packets - echo back
		if dataLen == 0 {
			if paddingLen > 0 {
				discard := make([]byte, paddingLen)
				io.ReadFull(conn, discard)
			}
			logger.Debug("Morph TUN: received keepalive, echoing back")
			writeMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte{0, 0, 0, 0, 0, 0})
			writeMu.Unlock()
			writer.UpdateActivity()
			continue
		}

		if dataLen > 65535 {
			logger.Debug("Invalid morph TUN packet length: %d", dataLen)
			continue
		}

		// Read packet data fragment
		pktData := make([]byte, dataLen)
		if _, err := io.ReadFull(conn, pktData); err != nil {
			logger.Debug("Morph TUN read data error: %v", err)
			return
		}

		// Discard padding
		if paddingLen > 0 {
			discard := make([]byte, paddingLen)
			io.ReadFull(conn, discard)
		}

		// Add to reassembly buffer
		reassemblyBuf = append(reassemblyBuf, pktData...)

		// Try to extract complete packets from buffer: [len:4][IP_packet:N]
		for len(reassemblyBuf) >= 4 {
			pktLen := binary.BigEndian.Uint32(reassemblyBuf[0:4])
			if pktLen > 65535 || pktLen < 20 {
				logger.Debug("Invalid IP packet length in morph buffer: %d", pktLen)
				reassemblyBuf = reassemblyBuf[1:]
				continue
			}

			totalLen := 4 + int(pktLen)
			if len(reassemblyBuf) < totalLen {
				break
			}

			ipPkt := reassemblyBuf[4:totalLen]
			reassemblyBuf = reassemblyBuf[totalLen:]

			pktUp := atomic.AddInt64(&packetsUp, 1)
			if pktUp%100 == 0 {
				writer.UpdateActivity()
			}
			logger.Debug("Morph->TUN: writing %d bytes to TUN", len(ipPkt))

			// Write packet to shared TUN device
			if _, err := srvCtx.sharedTUN.TUNDevice().Write(ipPkt); err != nil {
				logger.Debug("TUN write error: %v", err)
			}
		}

		// Prevent buffer from growing too large
		if len(reassemblyBuf) > 128*1024 {
			logger.Warn("Morph reassembly buffer overflow, resetting")
			reassemblyBuf = nil
		}
	}
}

// morphPacketWriter wraps morph framing for NAT responses
type morphPacketWriter struct {
	conn net.Conn
	mu   sync.Mutex
}

func (m *morphPacketWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Wrap in morph packet: [dataLen:4][paddingLen:2][data:N][padding:M]
	padLen := 30
	packet := make([]byte, 6+len(p)+padLen)
	binary.BigEndian.PutUint32(packet[0:4], uint32(len(p)))
	binary.BigEndian.PutUint16(packet[4:6], uint16(padLen))
	copy(packet[6:], p)
	rand.Read(packet[6+len(p):])

	_, err := m.conn.Write(packet)
	return len(p), err
}

func (m *morphPacketWriter) Read(p []byte) (int, error) {
	return 0, io.EOF // Not used for writing
}

func (m *morphPacketWriter) Close() error {
	return m.conn.Close()
}

func (m *morphPacketWriter) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

func (m *morphPacketWriter) RemoteAddr() net.Addr {
	return m.conn.RemoteAddr()
}

func (m *morphPacketWriter) SetDeadline(t time.Time) error {
	return m.conn.SetDeadline(t)
}

func (m *morphPacketWriter) SetReadDeadline(t time.Time) error {
	return m.conn.SetReadDeadline(t)
}

func (m *morphPacketWriter) SetWriteDeadline(t time.Time) error {
	return m.conn.SetWriteDeadline(t)
}

// handleHTTP1 handles HTTP/1.x connections
func handleHTTP1(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("Processing HTTP/1.x connection")

	// Read full request
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Debug("Failed to read HTTP request: %v", err)
		return
	}

	request := string(buf[:n])
	logger.Debug("HTTP request: %s", truncate(request, 100))

	// Check for HTTP Polling (meek-style) - POST with X-Session-ID header
	if bytes.HasPrefix(buf[:n], []byte("POST ")) && bytes.Contains(buf[:n], []byte("X-Session-ID:")) {
		logger.Debug("HTTP Polling request detected")
		handleHTTPPolling(conn, srvCtx, buf[:n], logger)
		return
	}

	// Check for WebSocket upgrade
	if bytes.Contains(buf[:n], []byte("Upgrade: websocket")) {
		logger.Debug("WebSocket upgrade requested")
		handleWebSocket(conn, srvCtx, logger)
		return
	}

	// Check for protocol confusion in body
	if idx := bytes.Index(buf[:n], []byte("TIRED")); idx > 0 {
		logger.Debug("Found confusion magic at offset %d", idx)
		// Extract real data after magic
		handleConfusionData(conn, buf[idx:n], srvCtx, logger)
		return
	}

	// Serve fake response
	serveFakeHTTPResponse(conn, cfg, logger)
}

// handleWebSocket handles WebSocket connections
func handleWebSocket(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	// Send WebSocket upgrade response
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(response)); err != nil {
		logger.Debug("Failed to send WebSocket upgrade: %v", err)
		return
	}

	logger.Info("WebSocket connection established")

	// Read WebSocket frames
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read frame header
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			logger.Debug("WebSocket read error: %v", err)
			return
		}

		fin := header[0]&0x80 != 0
		opcode := header[0] & 0x0F
		masked := header[1]&0x80 != 0
		payloadLen := int(header[1] & 0x7F)

		logger.Debug("WebSocket frame: fin=%v, opcode=%d, masked=%v, len=%d",
			fin, opcode, masked, payloadLen)

		// Handle extended payload length
		switch payloadLen {
		case 126:
			extLen := make([]byte, 2)
			io.ReadFull(conn, extLen)
			payloadLen = int(binary.BigEndian.Uint16(extLen))
		case 127:
			extLen := make([]byte, 8)
			io.ReadFull(conn, extLen)
			payloadLen = int(binary.BigEndian.Uint64(extLen))
		}

		// Read mask key
		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			io.ReadFull(conn, maskKey)
		}

		// Read payload
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			logger.Debug("Failed to read WebSocket payload: %v", err)
			return
		}

		// Unmask payload
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		logger.Debug("WebSocket payload: %d bytes", len(payload))

		// Close frame
		if opcode == 8 {
			logger.Debug("WebSocket close received")
			return
		}

		// Handle tunnel data in payload - use raw tunnel
		if len(payload) > 0 {
			// Create a buffered conn with the payload as initial data
			wsConn := &bufferedConn{
				Conn:   conn,
				reader: io.MultiReader(bytes.NewReader(payload), conn),
			}
			handleRawTunnel(wsConn, srvCtx, logger, "")
			return
		}
	}
}

// handleAntiProbeAuth handles anti-probe authenticated connections
func handleAntiProbeAuth(conn net.Conn, srvCtx *serverContext, secret []byte, clientID string, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("Processing anti-probe authentication (client: %s)", clientID)

	// Verify knock sequence with the matched secret
	if !verifyFullKnockSequence(conn, secret, logger) {
		logger.Warn("Knock sequence verification failed")
		serveFakeWebsite(conn, cfg, logger)
		return
	}

	// Send ACK
	conn.Write([]byte{0x01})
	logger.Info("Anti-probe authenticated (client: %s)", clientID)

	// Now expect TLS handshake with auth token
	// For simplicity, just start raw tunnel mode
	handleRawTunnel(conn, srvCtx, logger, clientID)
}

// handleProtocolConfusion handles protocol confusion connections
func handleProtocolConfusion(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("Processing protocol confusion")

	// Read enough data to find the magic marker (TIRED is at ~offset 50 in DNS confusion)
	// Use multiple reads to gather data since bufferedConn may return peeked data first
	buf := make([]byte, 4096)
	totalRead := 0

	for totalRead < 256 { // Read at least 256 bytes to find marker
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			if totalRead > 0 {
				break // Use what we have
			}
			logger.Debug("Failed to read confusion data: %v", err)
			return
		}
		totalRead += n

		// Check if we found the marker
		if bytes.Contains(buf[:totalRead], []byte("TIRED")) {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})

	logger.Debug("Read %d bytes for confusion detection", totalRead)

	// Find magic marker
	magicPos := bytes.Index(buf[:totalRead], []byte("\x00\x00TIRED"))
	if magicPos < 0 {
		magicPos = bytes.Index(buf[:totalRead], []byte("TIRED"))
	}

	if magicPos < 0 {
		logger.Debug("Magic marker not found in %d bytes", totalRead)
		serveFakeWebsite(conn, cfg, logger)
		return
	}

	logger.Debug("Found magic at position %d", magicPos)

	// Extract real data - format after TIRED: [length:4][data:N]
	// If magic is "\x00\x00TIRED", dataStart is magicPos + 7
	// If magic is "TIRED", dataStart is magicPos + 5
	dataStart := magicPos + 5
	if buf[magicPos] == 0x00 {
		dataStart = magicPos + 7
	}

	if dataStart+4 > totalRead {
		logger.Debug("Insufficient data after magic")
		return
	}

	// Read embedded data length
	dataLen := binary.BigEndian.Uint32(buf[dataStart : dataStart+4])
	logger.Debug("Embedded data length: %d", dataLen)

	// Extract embedded address from confusion packet
	// The embedded data IS the target address in format: [mode:1][...] where mode=0x02 is TUN,
	// otherwise [addrLen:2][addr:N]
	embeddedStart := dataStart + 4
	if embeddedStart+2 > totalRead {
		logger.Debug("Insufficient embedded data")
		return
	}

	// Check for TUN mode (first byte = 0x02)
	if buf[embeddedStart] == 0x02 {
		logger.Info("Confusion TUN mode detected")
		// Confirm understanding
		conn.Write([]byte("TIRED"))
		handleConfusionTUNMode(conn, buf[embeddedStart+1:totalRead], srvCtx, logger)
		return
	}

	addrLen := int(buf[embeddedStart])<<8 | int(buf[embeddedStart+1])
	if addrLen > 256 || addrLen < 3 || embeddedStart+2+addrLen > totalRead {
		logger.Debug("Invalid embedded address length: %d", addrLen)
		return
	}
	targetAddr := string(buf[embeddedStart+2 : embeddedStart+2+addrLen])
	logger.Info("Confusion tunnel to: %s", targetAddr)

	// Confirm understanding
	conn.Write([]byte("TIRED"))

	// Connect to target (via upstream if configured)
	var targetConn net.Conn
	var err error
	if srvCtx.upstreamDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		targetConn, err = srvCtx.upstreamDialer.Dial(ctx, targetAddr)
		cancel()
	} else {
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		logger.Warn("Failed to connect to %s: %v", targetAddr, err)
		conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x01}) // Send failure
		return
	}
	defer targetConn.Close()

	// Send success (length-prefixed as client expects)
	conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00})
	logger.Debug("Connected to target, starting confusion relay")

	// Relay data
	var wg sync.WaitGroup
	var bytesUp, bytesDown int64

	wg.Add(2)

	go func() {
		defer wg.Done()
		// Read length-prefixed data from client
		for {
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				logger.Debug("Confusion relay: read length error: %v", err)
				return
			}
			pktLen := binary.BigEndian.Uint32(lenBuf)
			logger.Debug("Confusion relay: received pktLen=%d", pktLen)
			if pktLen > 65536 || pktLen == 0 {
				logger.Debug("Confusion relay: invalid pktLen, closing")
				return
			}
			data := make([]byte, pktLen)
			if _, err := io.ReadFull(conn, data); err != nil {
				logger.Debug("Confusion relay: read data error: %v", err)
				return
			}

			// Check for control message
			if control.IsControlMessage(data) {
				control.HandleServerMessage(conn, data)
				continue
			}

			n, err := targetConn.Write(data)
			atomic.AddInt64(&bytesUp, int64(n))
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				logger.Debug("Confusion relay: target read error: %v", err)
				return
			}
			logger.Debug("Confusion relay: sending %d bytes to client", n)
			// Send length-prefixed response
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				logger.Debug("Confusion relay: write len error: %v", err)
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				logger.Debug("Confusion relay: write data error: %v", err)
				return
			}
			atomic.AddInt64(&bytesDown, int64(n))
		}
	}()

	wg.Wait()
	logger.Info("Confusion tunnel closed (up=%d, down=%d)", bytesUp, bytesDown)

	// Update metrics
	if srvCtx.metrics != nil {
		srvCtx.metrics.AddBytes(bytesUp, bytesDown)
	}
}

// handleConfusionTUNMode handles TUN mode over protocol confusion
// Now uses shared TUN instead of userspace NAT
func handleConfusionTUNMode(conn net.Conn, remainingData []byte, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("Processing Confusion TUN mode, remaining data: %d bytes", len(remainingData))

	// Parse TUN handshake from remaining data: [localIP:4][mtu:2][version:1]
	// Version byte is optional (v1 clients send 6 bytes, v2 clients send 7 bytes)
	if len(remainingData) < 6 {
		logger.Debug("Confusion TUN handshake too short: %d bytes", len(remainingData))
		conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x01})
		return
	}

	// Check if shared TUN is available
	if srvCtx == nil || srvCtx.sharedTUN == nil {
		logger.Error("Shared TUN not initialized")
		conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x01})
		return
	}

	requestedIP := net.IP(remainingData[0:4])
	// Use only client IP (without port) for clientID to prevent IP pool exhaustion
	// when client reconnects on different ports (e.g., port hopping)
	clientHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	clientID := fmt.Sprintf("confusion:%s", clientHost)

	// Check for version byte (v2 clients send 7 bytes total)
	var clientVersion uint8 = 1 // Default to v1 for backwards compatibility
	if len(remainingData) >= 7 {
		clientVersion = remainingData[6]
		logger.Debug("Confusion TUN client requested: IP=%s, clientID=%s, version=%d", requestedIP, clientID, clientVersion)
	} else {
		logger.Debug("Confusion TUN client requested: IP=%s, clientID=%s (legacy v1)", requestedIP, clientID)
	}

	// Allocate IP from pool
	var clientIP net.IP
	if srvCtx.ipPool != nil {
		allocatedIP, err := srvCtx.ipPool.Allocate(clientID, requestedIP, "")
		if err != nil {
			logger.Error("Failed to allocate IP from pool: %v", err)
			conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x01})
			return
		}
		clientIP = allocatedIP
		logger.Info("Confusion TUN client: allocated IP=%s from pool", clientIP)
	} else {
		clientIP = requestedIP
		logger.Info("Confusion TUN client: IP=%s (no pool)", clientIP)
	}

	// Send success response with length prefix: [length:4][status:1][serverIP:4][clientIP:4]
	// Confusion protocol uses length-prefixed frames for all data after "TIRED" magic
	serverIP := cfg.TunIP
	resp := make([]byte, 13)                 // 4 bytes length + 9 bytes data
	binary.BigEndian.PutUint32(resp[0:4], 9) // length = 9
	resp[4] = 0x00                           // Success
	copy(resp[5:9], serverIP.To4())
	copy(resp[9:13], clientIP.To4())
	conn.Write(resp)

	// Register client with shared TUN (default framing: [length:4][packet:N])
	writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, conn, nil)
	defer func() {
		srvCtx.sharedTUN.UnregisterClient(clientIP, writer)
		logger.Info("Confusion TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
	}()

	logger.Info("Confusion TUN mode established (client=%s, server=%s, tun=%s)", clientIP, serverIP, srvCtx.sharedTUN.Name())

	// Main loop: Client -> TUN
	// TUN -> Client is handled by SharedTUN packet dispatcher
	var packetsUp int64
	lenBuf := make([]byte, 4)

	for {
		select {
		case <-writer.Done():
			logger.Debug("Confusion TUN loop stopping (client replaced)")
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			logger.Debug("Confusion TUN read length error: %v", err)
			break
		}

		pktLen := binary.BigEndian.Uint32(lenBuf)

		// Handle keepalive packet (zero length) - echo back
		if pktLen == 0 {
			logger.Debug("Confusion TUN: received keepalive, echoing back")
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write(lenBuf)
			writer.UpdateActivity()
			continue
		}

		if pktLen > 65535 || pktLen < 20 {
			logger.Debug("Invalid confusion TUN packet length: %d", pktLen)
			continue
		}

		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(conn, pkt); err != nil {
			logger.Debug("Confusion TUN read data error: %v", err)
			break
		}

		pktUp := atomic.AddInt64(&packetsUp, 1)
		if pktUp%100 == 0 {
			writer.UpdateActivity()
		}

		// Check for double framing from ConfusedConn
		// ConfusedConn.Write adds [length:4] to every write, but VPN client
		// already adds [length:4][packet] framing, resulting in:
		// [outerLen:4][innerLen:4][packet]
		// We need to strip the inner length prefix if present
		actualPkt := pkt
		if len(pkt) >= 4 {
			innerLen := binary.BigEndian.Uint32(pkt[:4])
			if innerLen+4 == uint32(len(pkt)) && innerLen >= 20 {
				// Found double framing - strip inner length prefix
				if pktUp <= 5 || pktUp%100 == 0 {
					logger.Debug("Confusion TUN: stripped double framing (outer=%d, inner=%d)", pktLen, innerLen)
				}
				actualPkt = pkt[4:]
			}
		}

		// Write packet to shared TUN device
		if _, err := srvCtx.sharedTUN.TUNDevice().Write(actualPkt); err != nil {
			logger.Debug("TUN write error: %v", err)
		}
	}
}

// handleRawTunnel handles raw tunnel connections
// clientID is used for TUN mode to track IP allocation (e.g. "reality:abcd1234")
func handleRawTunnel(conn net.Conn, srvCtx *serverContext, logger *log.Logger, clientID string) {
	logger.Debug("Starting raw tunnel mode")

	// Track per-client connection for metrics
	if srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track connection for client %s: %v", clientID, err)
		} else {
			defer srvCtx.registry.RemoveConnection(clientID, conn)
		}
	}

	// Read first byte to check for TUN mode
	modeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, modeBuf); err != nil {
		logger.Debug("Failed to read mode byte: %v", err)
		return
	}

	// Check if this is TUN mode (0x02)
	if modeBuf[0] == 0x02 {
		// Read TUN handshake: [localIP:4][mtu:2][version:1]
		// Read at least 6 bytes (legacy), up to 7 (with version)
		tunHandshake := make([]byte, 7)
		n, err := io.ReadAtLeast(conn, tunHandshake, 6)
		if err != nil && err != io.ErrUnexpectedEOF {
			logger.Debug("Failed to read TUN handshake: %v (got %d bytes)", err, n)
			return
		}
		logger.Debug("Raw tunnel TUN handshake: read %d bytes", n)
		handleTUNModeWithHandshake(conn, srvCtx, logger, tunHandshake[:n], clientID)
		return
	}

	// Regular SOCKS proxy mode - mode byte was high byte of address length
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		logger.Debug("Failed to read address length low byte: %v", err)
		return
	}

	addrLen := int(modeBuf[0])<<8 | int(lenBuf[0])
	if addrLen > 256 || addrLen < 3 {
		logger.Debug("Invalid address length: %d", addrLen)
		return
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(conn, addrBuf); err != nil {
		logger.Debug("Failed to read address: %v", err)
		return
	}

	targetAddr := string(addrBuf)
	logger.Info("Tunnel to: %s", targetAddr)

	// Connect to target (via upstream if configured)
	var targetConn net.Conn
	var err error
	if srvCtx.upstreamDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		targetConn, err = srvCtx.upstreamDialer.Dial(ctx, targetAddr)
		cancel()
	} else {
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		logger.Warn("Failed to connect to %s: %v", targetAddr, err)
		conn.Write([]byte{0x01})
		return
	}
	defer targetConn.Close()

	// Send success
	conn.Write([]byte{0x00})
	logger.Debug("Connected to target, starting relay")

	// Relay data
	var wg sync.WaitGroup
	var bytesUp, bytesDown int64

	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := optimizedRelay(targetConn, conn)
		atomic.AddInt64(&bytesUp, n)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := optimizedRelay(conn, targetConn)
		atomic.AddInt64(&bytesDown, n)
	}()

	wg.Wait()

	logger.Info("Tunnel closed (up=%d, down=%d)", bytesUp, bytesDown)

	// Update metrics
	if srvCtx.metrics != nil {
		srvCtx.metrics.AddBytes(bytesUp, bytesDown)
	}

	// Update per-client metrics
	if srvCtx.registry != nil && clientID != "" {
		srvCtx.registry.AddBytes(clientID, bytesUp, bytesDown)
	}
}

// handleTUNMode handles TUN-based VPN connections
func handleTUNMode(conn net.Conn, cfg *Config, logger *log.Logger) {
	handleTUNModeWithContext(conn, cfg, nil, logger)
}

// handleTUNModeWithHandshake handles TUN mode with pre-read handshake data (for QUIC)
func handleTUNModeWithHandshake(conn net.Conn, srvCtx *serverContext, logger *log.Logger, handshake []byte, clientID string) {
	handleTUNModeCore(conn, srvCtx.cfg, srvCtx, logger, handshake, clientID)
}

// handleTUNModeWithContext handles TUN-based VPN connections with server context (for IP pool)
func handleTUNModeWithContext(conn net.Conn, cfg *Config, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing TUN mode connection")

	// Read TUN handshake: [localIP:4][mtu:2][version:1] (7 bytes for v1 clients, 6 bytes for legacy)
	// We read 7 bytes to support version detection, but legacy clients only send 6
	handshake := make([]byte, 7)
	n, err := conn.Read(handshake)
	if err != nil || n < 6 {
		logger.Debug("Failed to read TUN handshake: %v (got %d bytes)", err, n)
		return
	}

	handleTUNModeCore(conn, cfg, srvCtx, logger, handshake[:n], "")
}

// handleTUNModeCore is the core TUN mode handler
// authClientID is the authenticated client ID from QUIC/etc (empty if not available)
func handleTUNModeCore(conn net.Conn, cfg *Config, srvCtx *serverContext, logger *log.Logger, handshake []byte, authClientID string) {
	requestedIP := net.IP(handshake[0:4])
	clientMTU := int(binary.BigEndian.Uint16(handshake[4:6]))
	// Negotiate MTU: use min(clientMTU, serverMTU) as effective MTU
	serverMTU := tun.DefaultMTU
	effectiveMTU := serverMTU
	if clientMTU > 0 && clientMTU < effectiveMTU {
		effectiveMTU = clientMTU
	}
	logger.Debug("MTU negotiation: client=%d, server=%d, effective=%d", clientMTU, serverMTU, effectiveMTU)

	// Check client version for extended capabilities
	// Old format: [localIP:4][mtu:2] = 6 bytes
	// New format: [localIP:4][mtu:2][version:1] = 7 bytes
	clientVersion := byte(0x00)
	if len(handshake) >= 7 {
		clientVersion = handshake[6]
		logger.Debug("TUN client version: 0x%02x (handshake len=%d)", clientVersion, len(handshake))
	} else {
		logger.Debug("TUN legacy client (handshake len=%d)", len(handshake))
	}

	// Check if client requests auto-assignment (0.0.0.0)
	isAutoRequest := requestedIP.Equal(net.IPv4zero) || requestedIP.Equal(net.IPv4(0, 0, 0, 0))

	// Use authenticated clientID if available, otherwise fallback to connection-based ID
	var clientID string
	if authClientID != "" {
		// Use stable clientID from authentication (e.g. from Redis/API)
		clientID = authClientID
	} else {
		clientID = fmt.Sprintf("tun:%s", conn.RemoteAddr().String())
	}

	logger.Info("TUN client request: IP=%s, clientID=%s", requestedIP, clientID)

	// Check if shared TUN is available
	if srvCtx == nil || srvCtx.sharedTUN == nil {
		logger.Error("Shared TUN not initialized")
		resp := make([]byte, 9)
		resp[0] = 0x03 // Error: TUN not available
		conn.Write(resp)
		return
	}

	// Determine client IP
	var clientIP net.IP
	var ipFromPool bool

	if srvCtx.ipPool != nil {
		// Use IP Pool - it returns same IP for same clientID (from Redis leases)
		var err error
		clientIP, err = srvCtx.ipPool.Allocate(clientID, requestedIP, "")
		if err != nil {
			logger.Warn("IP allocation failed: %v", err)
			resp := make([]byte, 9)
			resp[0] = 0x01 // Error: pool exhausted
			conn.Write(resp)
			return
		}
		ipFromPool = true
		logger.Info("IP allocated from pool: %s (requested=%s, clientID=%s)", clientIP, requestedIP, clientID)
	} else {
		// No pool - use requested IP (legacy behavior)
		if isAutoRequest {
			logger.Warn("Auto IP requested but no IP pool configured")
			resp := make([]byte, 9)
			resp[0] = 0x02 // Error: no pool
			conn.Write(resp)
			return
		}
		clientIP = requestedIP
	}

	serverIP := cfg.TunIP

	// Build response based on client version
	// Legacy (9 bytes): [status:1][serverIP:4][clientIP:4]
	// Extended v1 (14 bytes): [status:1][serverIP:4][clientIP:4][flags:1][portStart:2][portEnd:2]
	// Extended v2 (20+ bytes): [status:1][serverIP:4][clientIP:4][flags:1][portStart:2][portEnd:2][hopInterval:4][strategy:1][seedLen:1][seed:0-32]
	var resp []byte
	if clientVersion >= 0x01 && cfg.PortRange != "" {
		// Get port range bounds for extended response
		portStart, portEnd := getPortRangeBounds(cfg.PortRange)
		if portStart > 0 && portEnd > portStart {
			// Check if client supports v2 (full port hop config)
			if clientVersion >= 0x02 {
				// Prepare extended v2 response
				seedBytes := []byte(cfg.PortHopSeed)
				if len(seedBytes) > 32 {
					seedBytes = seedBytes[:32]
				}
				respLen := 20 + len(seedBytes)
				resp = make([]byte, respLen)
				resp[0] = 0x00 // Success
				copy(resp[1:5], serverIP.To4())
				copy(resp[5:9], clientIP.To4())
				resp[9] = 0x01 // flags: port hopping available
				binary.BigEndian.PutUint16(resp[10:12], uint16(portStart))
				binary.BigEndian.PutUint16(resp[12:14], uint16(portEnd))

				// Hop interval in seconds (default 60)
				hopInterval := int(cfg.PortHopInterval.Seconds())
				if hopInterval <= 0 {
					hopInterval = 60
				}
				binary.BigEndian.PutUint32(resp[14:18], uint32(hopInterval))

				// Strategy byte: 0=random, 1=sequential, 2=fibonacci
				switch cfg.PortHopStrategy {
				case "sequential":
					resp[18] = 0x01
				case "fibonacci":
					resp[18] = 0x02
				default:
					resp[18] = 0x00 // random
				}

				// Seed
				resp[19] = byte(len(seedBytes))
				if len(seedBytes) > 0 {
					copy(resp[20:], seedBytes)
				}

				logger.Info("Sending v2 extended response with port hopping: %d-%d, interval=%ds, strategy=%s, seed_len=%d",
					portStart, portEnd, hopInterval, cfg.PortHopStrategy, len(seedBytes))
			} else {
				// v1 response (backward compatible)
				resp = make([]byte, 14)
				resp[0] = 0x00 // Success
				copy(resp[1:5], serverIP.To4())
				copy(resp[5:9], clientIP.To4())
				resp[9] = 0x01 // flags: port hopping available
				binary.BigEndian.PutUint16(resp[10:12], uint16(portStart))
				binary.BigEndian.PutUint16(resp[12:14], uint16(portEnd))
				logger.Info("Sending v1 extended response with port hopping: %d-%d", portStart, portEnd)
			}
		}
	}

	// Fallback to legacy response
	if resp == nil {
		resp = make([]byte, 9)
		resp[0] = 0x00 // Success
		copy(resp[1:5], serverIP.To4())
		copy(resp[5:9], clientIP.To4())
	}

	if _, err := conn.Write(resp); err != nil {
		logger.Debug("Failed to send TUN response: %v", err)
		if ipFromPool {
			srvCtx.ipPool.Release(clientIP)
		}
		return
	}

	// Register client with shared TUN
	// Default framing: [length:4][packet:N]
	writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, conn, nil)
	defer func() {
		srvCtx.sharedTUN.UnregisterClient(clientIP, writer)
		// Don't release IP - it stays allocated for reconnects
		logger.Info("TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
	}()

	logger.Info("TUN mode established (client=%s, server=%s, tun=%s)", clientIP, serverIP, srvCtx.sharedTUN.Name())

	// Main loop: Client -> TUN (client-bound traffic)
	// TUN -> Client is handled by SharedTUN packet dispatcher
	var packetsUp int64
	lenBuf := make([]byte, 4)
	var writeMu sync.Mutex

	for {
		// Check if client disconnected (replaced by new connection)
		select {
		case <-writer.Done():
			logger.Debug("Client->TUN loop stopping (client replaced)")
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			logger.Debug("TUN read length error: %v", err)
			break
		}

		pktLen := binary.BigEndian.Uint32(lenBuf)

		// Handle keepalive packet (zero length) - echo back
		if pktLen == 0 {
			logger.Debug("Received keepalive, echoing back")
			writeMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write(lenBuf)
			writeMu.Unlock()
			writer.UpdateActivity()
			continue
		}

		if pktLen > 65535 || pktLen < 20 {
			logger.Debug("Invalid packet length: %d", pktLen)
			continue
		}

		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(conn, pkt); err != nil {
			logger.Debug("TUN read packet error: %v", err)
			break
		}

		// Clamp TCP MSS on SYN/SYN-ACK to fit negotiated tunnel MTU
		tun.ClampTCPMSS(pkt, effectiveMTU)

		pktUp := atomic.AddInt64(&packetsUp, 1)

		// Update activity timestamp (every 100 packets to reduce overhead)
		if pktUp%100 == 0 {
			writer.UpdateActivity()
		}
		if pktUp <= 5 || pktUp%100 == 0 {
			logger.Debug("Client->TUN: writing %d bytes to TUN (pkt #%d)", pktLen, pktUp)
		}

		// Write packet to shared TUN device - kernel handles routing
		if _, err := srvCtx.sharedTUN.TUNDevice().Write(pkt); err != nil {
			logger.Debug("TUN write error: %v", err)
		}
	}
}

// setupH2Tunnel establishes the tunnel connection for HTTP/2 stego
func setupH2Tunnel(tunnel *h2TunnelState, framer *http2.Framer, data []byte, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("Setting up HTTP/2 stego tunnel: %d bytes", len(data))

	// Parse target address from data
	// Format: [mode:1][...] where mode=0x02 is TUN, otherwise [addrLen:2][address:N]
	if len(data) < 2 {
		logger.Debug("Tunnel data too short")
		return
	}

	// Check for TUN mode (first byte = 0x02)
	if data[0] == 0x02 {
		logger.Info("HTTP/2 Stego TUN mode detected")
		setupH2TUNTunnel(tunnel, framer, data[1:], srvCtx, logger)
		return
	}

	addrLen := int(data[0])<<8 | int(data[1])
	if addrLen > len(data)-2 || addrLen < 3 {
		logger.Debug("Invalid address length: %d", addrLen)
		return
	}
	targetAddr := string(data[2 : 2+addrLen])
	logger.Info("HTTP/2 Stego tunnel to: %s", targetAddr)

	// Connect to target (via upstream if configured)
	var targetConn net.Conn
	var err error
	if srvCtx.upstreamDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		targetConn, err = srvCtx.upstreamDialer.Dial(ctx, targetAddr)
		cancel()
	} else {
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		logger.Warn("Failed to connect to %s: %v", targetAddr, err)
		// Send failure response
		sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
		return
	}

	// Store connection in tunnel state (don't close - will be closed by caller)
	tunnel.targetConn = targetConn

	// Send success response
	sendStegoResponse(framer, tunnel.streamID, []byte{0x00}, cfg)
	logger.Debug("Connected to target, starting HTTP/2 stego relay")

	// Start goroutine to read from target and send via HTTP/2
	go func() {
		buf := make([]byte, 1400)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				logger.Debug("Target read error: %v", err)
				return
			}
			tunnel.mu.Lock()
			sendStegoResponse(framer, tunnel.streamID, buf[:n], cfg)
			tunnel.mu.Unlock()
		}
	}()
}

// sendStegoResponse sends data via HTTP/2 steganography
func sendStegoResponse(framer *http2.Framer, streamID uint32, data []byte, cfg *Config) {
	// Frame format: [TIRD:4][flags:1][length:2][data:N][cover:M]
	coverLen := 30
	response := make([]byte, 7+len(data)+coverLen)
	copy(response[0:4], []byte("TIRD"))
	response[4] = 0x00 // Raw data flag
	binary.BigEndian.PutUint16(response[5:7], uint16(len(data)))
	copy(response[7:7+len(data)], data)
	rand.Read(response[7+len(data):]) // Cover traffic

	framer.WriteData(streamID, false, response)
}

// h2StegoFrameFunc creates framing function for H2 Stego TUN->Client packets
// Format: [len:4][packet:N]
func h2StegoFrameFunc(framer *http2.Framer, streamID *uint32, cfg *Config, mu *sync.Mutex) func([]byte) []byte {
	return func(pkt []byte) []byte {
		// Frame packet: [len:4][packet:N]
		framed := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(framed[:4], uint32(len(pkt)))
		copy(framed[4:], pkt)

		// Send via H2 stego
		mu.Lock()
		sendStegoResponse(framer, *streamID, framed, cfg)
		mu.Unlock()

		return nil // Already sent
	}
}

// setupH2TUNTunnel handles TUN mode over HTTP/2 steganography
// Now uses shared TUN instead of userspace NAT
func setupH2TUNTunnel(tunnel *h2TunnelState, framer *http2.Framer, data []byte, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("Setting up HTTP/2 Stego TUN tunnel: %d bytes", len(data))

	// Parse TUN handshake: [localIP:4][mtu:2][version:1]
	// Version byte is optional (v1 clients send 6 bytes, v2 clients send 7 bytes)
	if len(data) < 6 {
		logger.Debug("H2 TUN handshake too short: %d bytes", len(data))
		sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
		return
	}

	// Check if shared TUN is available
	if srvCtx == nil || srvCtx.sharedTUN == nil {
		logger.Error("Shared TUN not initialized")
		sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
		return
	}

	requestedIP := net.IP(data[0:4])

	// Check for version byte (v2 clients send 7 bytes total)
	var clientVersion uint8 = 1 // Default to v1 for backwards compatibility
	if len(data) >= 7 {
		clientVersion = data[6]
		logger.Debug("H2 TUN client requested: IP=%s, version=%d", requestedIP, clientVersion)
	} else {
		logger.Debug("H2 TUN client requested: IP=%s (legacy v1)", requestedIP)
	}

	// Allocate IP from pool
	var clientIP net.IP
	if srvCtx.ipPool != nil {
		allocatedIP, err := srvCtx.ipPool.Allocate(tunnel.clientID, requestedIP, "")
		if err != nil {
			logger.Error("Failed to allocate IP from pool: %v", err)
			sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
			return
		}
		clientIP = allocatedIP
		logger.Info("H2 TUN client: allocated IP=%s from pool (requested=%s, clientID=%s)", clientIP, requestedIP, tunnel.clientID)
	} else {
		clientIP = requestedIP
		logger.Info("H2 TUN client: IP=%s (no pool)", clientIP)
	}

	// Send success response: [status:1][serverIP:4][clientIP:4]
	serverIP := cfg.TunIP
	resp := make([]byte, 9)
	resp[0] = 0x00 // Success
	copy(resp[1:5], serverIP)
	copy(resp[5:9], clientIP.To4())
	sendStegoResponse(framer, tunnel.streamID, resp, cfg)

	// Create H2 conn adapter for SharedTUN
	h2Conn := &h2TunConn{
		framer:   framer,
		streamID: &tunnel.streamID, // Pointer so it can be updated
		cfg:      cfg,
		mu:       &tunnel.mu,
		clientIP: clientIP,
		done:     make(chan struct{}),
	}

	// Register client with shared TUN using custom frame function
	// Note: For H2, we send directly in frameFunc, so it returns nil
	writer := srvCtx.sharedTUN.RegisterClient(clientIP, tunnel.clientID, h2Conn, func(pkt []byte) []byte {
		// Send packet via H2 stego framing: [len:4][packet:N]
		framed := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(framed[:4], uint32(len(pkt)))
		copy(framed[4:], pkt)

		tunnel.mu.Lock()
		sendStegoResponse(framer, tunnel.streamID, framed, cfg)
		tunnel.mu.Unlock()

		return nil // Already sent directly
	})

	// Store writer reference in tunnel for DATA frame handling
	tunnel.sharedTUNWriter = writer
	tunnel.sharedTUN = srvCtx.sharedTUN
	tunnel.targetConn = h2Conn // Mark as TUN mode

	logger.Info("H2 TUN mode established (client=%s, server=%s, tun=%s)", clientIP, serverIP, srvCtx.sharedTUN.Name())
}

// h2TunConn adapts HTTP/2 framer to net.Conn interface for SharedTUN
type h2TunConn struct {
	framer   *http2.Framer
	streamID *uint32
	cfg      *Config
	mu       *sync.Mutex
	clientIP net.IP
	done     chan struct{}
}

func (c *h2TunConn) Write(p []byte) (int, error) {
	// For H2 TUN, writing is handled by framePacket function
	// This method may be called but actual sending is done elsewhere
	return len(p), nil
}

func (c *h2TunConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (c *h2TunConn) Close() error                       { return nil }
func (c *h2TunConn) LocalAddr() net.Addr                { return nil }
func (c *h2TunConn) RemoteAddr() net.Addr               { return nil }
func (c *h2TunConn) SetDeadline(t time.Time) error      { return nil }
func (c *h2TunConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h2TunConn) SetWriteDeadline(t time.Time) error { return nil }

// serveFakeWebsite serves a fake website to probes
func serveFakeWebsite(conn net.Conn, cfg *Config, logger *log.Logger) {
	logger.Debug("Serving fake website")

	response := `HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/1.24.0
Connection: close

<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed.</p>
</body>
</html>`

	conn.Write([]byte(response))
}

// serveFakeHTTPResponse serves a fake HTTP response
func serveFakeHTTPResponse(conn net.Conn, cfg *Config, logger *log.Logger) {
	serveFakeWebsite(conn, cfg, logger)
}

// handleConfusionData handles extracted confusion data
func handleConfusionData(conn net.Conn, data []byte, srvCtx *serverContext, logger *log.Logger) {
	_ = srvCtx.cfg // cfg not used but keep pattern consistent
	// Find length after TIRED magic
	if len(data) < 9 {
		return
	}

	dataLen := binary.BigEndian.Uint32(data[5:9])
	logger.Debug("Confusion data length: %d", dataLen)

	// Acknowledge
	conn.Write([]byte("TIRED"))

	// Continue as raw tunnel
	handleRawTunnel(conn, srvCtx, logger, "")
}

// Helper functions

func detectTimingKnock(data []byte, secret []byte) bool {
	// Check if first byte could be sequence number 0
	if len(data) < 10 || data[0] != 0x00 {
		return false
	}

	// Calculate expected first packet size (same as generateKnockSequence)
	seqHash := hmac.New(sha256.New, secret)
	seqHash.Write([]byte("knock-sequence"))
	seqHashSum := seqHash.Sum(nil)
	firstPacketSize := 10 + int(seqHashSum[5])%90

	// Verify first packet content matches expected
	h := hmac.New(sha256.New, secret)
	h.Write([]byte{0x00})
	expected := h.Sum(nil)

	// Debug: log expected vs received
	log.Debug("Timing knock check - expected first packet size: %d", firstPacketSize)
	log.Debug("Timing knock check - expected first 8 bytes: %x", expected[:8])
	log.Debug("Timing knock check - received bytes 1-9: %x", data[1:9])

	// Only check up to firstPacketSize bytes (not all peeked data)
	checkLen := firstPacketSize
	if checkLen > len(data) {
		checkLen = len(data)
	}

	for i := 1; i < checkLen; i++ {
		if data[i] != expected[(i-1)%len(expected)] {
			log.Debug("Timing knock mismatch at position %d: expected %02x, got %02x",
				i, expected[(i-1)%len(expected)], data[i])
			return false
		}
	}

	return true
}

// detectTimingKnockWithRegistry checks timing knock against per-client secrets and global secret
// Returns (matched, secret, clientID)
func detectTimingKnockWithRegistry(data []byte, srvCtx *serverContext) (bool, []byte, string) {
	// 1. Try per-client secrets
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			if detectTimingKnock(data, []byte(client.Secret)) {
				log.Debug("Timing knock matched client: %s (id: %s)", client.Name, client.ID)
				return true, []byte(client.Secret), client.ID
			}
		}
	}

	// 2. Fallback to global secret
	if len(srvCtx.cfg.Secret) > 0 && detectTimingKnock(data, srvCtx.cfg.Secret) {
		log.Debug("Timing knock matched global secret")
		return true, srvCtx.cfg.Secret, "global"
	}

	return false, nil, ""
}

func verifyFullKnockSequence(conn net.Conn, secret []byte, logger *log.Logger) bool {
	// Generate expected knock sequence (same as client)
	seqHash := hmac.New(sha256.New, secret)
	seqHash.Write([]byte("knock-sequence"))
	seqHashSum := seqHash.Sum(nil)

	sizes := make([]int, 5)
	for i := 0; i < 5; i++ {
		sizes[i] = 10 + int(seqHashSum[i+5])%90
	}

	logger.Debug("Verifying knock sequence, packet sizes: %v", sizes)

	// Read ALL 5 packets (peek doesn't consume, so we start from packet 0)
	for i := 0; i < 5; i++ {
		// Read exact packet size
		buf := make([]byte, sizes[i])
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			logger.Debug("Knock packet %d read error: %v", i, err)
			return false
		}

		if buf[0] != byte(i) {
			logger.Debug("Knock packet %d: wrong sequence number (got %d, expected %d)", i, buf[0], i)
			return false
		}

		// Verify packet content
		h := hmac.New(sha256.New, secret)
		h.Write([]byte{byte(i)})
		expected := h.Sum(nil)

		for j := 1; j < len(buf); j++ {
			if buf[j] != expected[(j-1)%len(expected)] {
				logger.Debug("Knock packet %d: content mismatch at byte %d", i, j)
				return false
			}
		}

		logger.Debug("Knock packet %d: OK (%d bytes)", i, sizes[i])
	}

	return true
}

func detectConfusionMagic(data []byte) bool {
	// Check for DNS response pattern (confusion_0)
	// DNS header: [txid:2][flags:2] where flags = 0x8180 for response
	if len(data) >= 12 && data[2] == 0x81 && data[3] == 0x80 {
		return true
	}

	// Check for TIRED magic anywhere in peeked data
	// This catches HTTP/SSH/SMTP/Multi-layer confusion if we peeked enough data
	if bytes.Contains(data, []byte("TIRED")) {
		return true
	}

	// Check for SSH banner pattern (confusion_2) without TIRED visible yet
	// SSH-2.0-* - will need to read more to find TIRED
	if bytes.HasPrefix(data, []byte("SSH-2.0-")) {
		return true
	}

	// Check for SMTP pattern (confusion_3) without TIRED visible yet
	// "220 " SMTP greeting - will need to read more to find TIRED
	if bytes.HasPrefix(data, []byte("220 ")) {
		return true
	}

	// Note: HTTP confusion (GET/POST) is detected by presence of TIRED in data
	// If TIRED is not visible in peeked data, it's treated as regular HTTP

	return false
}

func verifyH2Auth(apiKey, requestID string, secret []byte) bool {
	// Decode hex values
	apiKeyBytes := decodeHex(apiKey)
	requestIDBytes := decodeHex(requestID)

	if len(apiKeyBytes) < 16 || len(requestIDBytes) < 16 {
		return false
	}

	// Reconstruct token
	receivedToken := append(apiKeyBytes[:16], requestIDBytes[:16]...)

	// Generate expected token
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60))

	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	expectedToken := h.Sum(nil)[:32]

	return hmac.Equal(receivedToken, expectedToken)
}

func verifyMorphAuth(receivedToken, secret []byte) bool {
	if len(receivedToken) != 32 {
		return false
	}

	// Check timestamps in range [-1, 0, +1] minutes to handle clock skew
	currentMinute := time.Now().Unix() / 60
	for offset := int64(-1); offset <= 1; offset++ {
		timestamp := make([]byte, 8)
		binary.BigEndian.PutUint64(timestamp, uint64(currentMinute+offset))

		h := hmac.New(sha256.New, secret)
		h.Write(timestamp)
		h.Write([]byte("http2-stego-auth")) // Use same context as H2 Stego for consistency
		expectedToken := h.Sum(nil)[:32]

		if hmac.Equal(receivedToken, expectedToken) {
			return true
		}
	}
	return false
}

func sendH2AuthAck(framer *http2.Framer, streamID uint32, secret []byte) {
	var headerBuf bytes.Buffer
	enc := hpack.NewEncoder(&headerBuf)

	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})

	ackKey := deriveKey(secret, "server-ack")[:16]
	enc.WriteField(hpack.HeaderField{
		Name:  "x-goog-correlation-id",
		Value: encodeHex(ackKey),
	})

	framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

func deriveKey(secret []byte, context string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(context))
	return h.Sum(nil)
}

func decodeHex(s string) []byte {
	if len(s)%2 != 0 {
		return nil
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		fmt.Sscanf(s[i:i+2], "%02x", &b)
		result[i/2] = b
	}
	return result
}

func encodeHex(data []byte) string {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = "0123456789abcdef"[b>>4]
		result[i*2+1] = "0123456789abcdef"[b&0x0f]
	}
	return string(result)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// bufferedConn wraps a connection with buffered data
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.reader.Read(p)
}

// Ensure interface compliance
var _ net.Conn = (*bufferedConn)(nil)

// detectWebSocketPadded detects WebSocket Padded protocol by X-Salamander-Version header
func detectWebSocketPadded(data []byte) bool {
	return bytes.Contains(data, []byte("GET ")) &&
		bytes.Contains(data, []byte("Upgrade: websocket")) &&
		bytes.Contains(data, []byte("X-Salamander-Version:"))
}

// handleWebSocketConnection handles WebSocket connection with ALPN routing
// This is the kTLS-compatible entry point for tired-ws ALPN
func handleWebSocketConnection(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	handleWebSocketPadded(conn, srvCtx, logger)
}

// handleWebSocketPadded handles a WebSocket Padded connection
func handleWebSocketPadded(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	defer conn.Close()

	logger.Debug("WebSocket Padded: Processing connection from %s", conn.RemoteAddr())

	// Read upgrade request (already peeked, but read full headers)
	reader := bufio.NewReader(conn)

	// Read request line
	_, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("WebSocket Padded: Failed to read request line: %v", err)
		return
	}

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			logger.Error("WebSocket Padded: Failed to read headers: %v", err)
			return
		}

		lineTrimmed := bytes.TrimSpace([]byte(line))
		if len(lineTrimmed) == 0 {
			break // End of headers
		}

		// Parse header
		parts := bytes.SplitN(lineTrimmed, []byte(":"), 2)
		if len(parts) == 2 {
			key := string(bytes.TrimSpace(parts[0]))
			value := string(bytes.TrimSpace(parts[1]))
			headers[key] = value
		}
	}

	// Verify required headers
	wsKey, hasKey := headers["Sec-WebSocket-Key"]
	if !hasKey {
		logger.Error("WebSocket Padded: Missing Sec-WebSocket-Key")
		return
	}

	_, hasSalamander := headers["X-Salamander-Version"]
	if !hasSalamander {
		logger.Error("WebSocket Padded: Missing X-Salamander-Version")
		return
	}

	// Verify X-Auth-Token against per-client secrets and global secret
	authTokenHex, hasAuthToken := headers["X-Auth-Token"]
	var usedSecret []byte
	var clientID string

	if hasAuthToken {
		authToken, err := hex.DecodeString(authTokenHex)
		if err != nil {
			logger.Error("WebSocket Padded: Invalid X-Auth-Token format: %v", err)
			return
		}

		// 1. Try per-client secrets from registry
		if srvCtx.registry != nil {
			clients := srvCtx.registry.ListClients()
			for _, client := range clients {
				if verifyMorphAuth(authToken, []byte(client.Secret)) {
					logger.Info("WebSocket Padded authenticated (client: %s, id: %s)", client.Name, client.ID)
					usedSecret = []byte(client.Secret)
					clientID = client.ID
					break
				}
			}
		}

		// 2. Fallback to global secret
		if usedSecret == nil && len(srvCtx.cfg.Secret) > 0 {
			if verifyMorphAuth(authToken, srvCtx.cfg.Secret) {
				logger.Info("WebSocket Padded authenticated (global secret)")
				usedSecret = srvCtx.cfg.Secret
				clientID = "global"
			}
		}

		if usedSecret == nil {
			logger.Error("WebSocket Padded: Authentication failed - invalid token")
			return
		}
	} else {
		// No auth token - fallback to global secret for backward compatibility
		if len(srvCtx.cfg.Secret) > 0 {
			usedSecret = srvCtx.cfg.Secret
			clientID = "global-legacy"
			logger.Debug("WebSocket Padded: No auth token, using global secret (legacy mode)")
		} else {
			logger.Error("WebSocket Padded: No auth token and no global secret configured")
			return
		}
	}

	logger.Debug("WebSocket Padded: Valid upgrade request, key=%s, clientID=%s", wsKey, clientID)

	// Compute WebSocket accept key
	acceptKey := computeWebSocketAccept(wsKey)

	// Send 101 Switching Protocols response
	response := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n", acceptKey)

	if _, err := conn.Write([]byte(response)); err != nil {
		logger.Error("WebSocket Padded: Failed to send 101 response: %v", err)
		return
	}

	logger.Info("WebSocket Padded: Upgrade complete for %s (client: %s)", conn.RemoteAddr(), clientID)

	// Wrap with SalamanderConn using the authenticated secret
	padder := padding.NewSalamanderPadder(usedSecret, padding.Balanced)
	salamanderConn := strategy.NewSalamanderConn(conn, padder, false)

	// Handle as raw tunnel
	handleRawTunnel(salamanderConn, srvCtx, logger, clientID)
}

// computeWebSocketAccept computes the Sec-WebSocket-Accept header value
func computeWebSocketAccept(key string) string {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	h := sha256.New()
	h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ==================== HTTP Polling (meek-style) Transport ====================
// This transport uses multiple short-lived HTTP/1.1 requests to tunnel data.
// Each request is independent - no long-lived connections.
// This evades DPI that throttles persistent connections (like Russian TSPU).

// HTTPPollingSession represents a single polling session
type HTTPPollingSession struct {
	ID         string
	ClientID   string
	Secret     []byte
	Created    time.Time
	LastActive time.Time

	// Bidirectional buffers
	toClient   *bytes.Buffer // Data from target to client
	fromClient *bytes.Buffer // Data from client to target
	bufLock    sync.Mutex

	// Acknowledgement tracking for reliable delivery
	sentOffset   int64     // Total bytes sent to client (before ack)
	ackOffset    int64     // Bytes acknowledged by client
	unackedBuf   []byte    // Sliding window of sent but unacked data
	lastSendTime time.Time // Time of last send (for re-send grace period)

	// Target connection (established on first data)
	targetConn net.Conn
	targetLock sync.Mutex

	// Lifecycle
	closed    bool
	closeLock sync.Mutex
}

// HTTPPollingManager manages all polling sessions
type HTTPPollingManager struct {
	sessions map[string]*HTTPPollingSession
	mu       sync.RWMutex

	// Cleanup interval
	cleanupInterval time.Duration
	sessionTimeout  time.Duration
}

// Global polling manager
var pollingManager = &HTTPPollingManager{
	sessions:        make(map[string]*HTTPPollingSession),
	cleanupInterval: 30 * time.Second,
	sessionTimeout:  5 * time.Minute,
}

// init starts the polling manager cleanup routine
func init() {
	go pollingManager.cleanupLoop()
}

// cleanupLoop removes stale sessions
func (pm *HTTPPollingManager) cleanupLoop() {
	ticker := time.NewTicker(pm.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		pm.cleanup()
	}
}

// cleanup removes sessions that haven't been active
func (pm *HTTPPollingManager) cleanup() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	now := time.Now()
	for id, sess := range pm.sessions {
		if now.Sub(sess.LastActive) > pm.sessionTimeout {
			log.Debug("HTTP Polling: Cleaning up stale session %s", id[:8])
			sess.Close()
			delete(pm.sessions, id)
		}
	}
}

// GetOrCreate gets or creates a session
func (pm *HTTPPollingManager) GetOrCreate(sessionID string, secret []byte, clientID string) (*HTTPPollingSession, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if sess, exists := pm.sessions[sessionID]; exists {
		sess.LastActive = time.Now()
		return sess, false
	}

	// Create new session
	sess := &HTTPPollingSession{
		ID:         sessionID,
		ClientID:   clientID,
		Secret:     secret,
		Created:    time.Now(),
		LastActive: time.Now(),
		toClient:   bytes.NewBuffer(nil),
		fromClient: bytes.NewBuffer(nil),
	}
	pm.sessions[sessionID] = sess
	return sess, true
}

// Get retrieves a session
func (pm *HTTPPollingManager) Get(sessionID string) *HTTPPollingSession {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.sessions[sessionID]
}

// Remove removes a session
func (pm *HTTPPollingManager) Remove(sessionID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if sess, exists := pm.sessions[sessionID]; exists {
		sess.Close()
		delete(pm.sessions, sessionID)
	}
}

// Close closes the session and its target connection
func (s *HTTPPollingSession) Close() {
	s.closeLock.Lock()
	defer s.closeLock.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	s.targetLock.Lock()
	if s.targetConn != nil {
		s.targetConn.Close()
	}
	s.targetLock.Unlock()
}

// WriteToClient writes data to be sent to client on next poll
func (s *HTTPPollingSession) WriteToClient(data []byte) {
	s.bufLock.Lock()
	defer s.bufLock.Unlock()
	s.toClient.Write(data)
}

// ReadFromClient reads data received from client
func (s *HTTPPollingSession) ReadFromClient() []byte {
	s.bufLock.Lock()
	defer s.bufLock.Unlock()
	data := s.fromClient.Bytes()
	s.fromClient.Reset()
	return data
}

// WriteFromClient writes data received from client
func (s *HTTPPollingSession) WriteFromClient(data []byte) {
	s.bufLock.Lock()
	defer s.bufLock.Unlock()
	s.fromClient.Write(data)
}

// ReadToClient reads data to send to client with acknowledgement-based reliability
// ackSeq is the total bytes the client has successfully received
func (s *HTTPPollingSession) ReadToClient(ackSeq int64) []byte {
	s.bufLock.Lock()
	defer s.bufLock.Unlock()

	const maxChunk = 16 * 1024 // 16KB max per response

	// Process acknowledgement - remove acked data from unacked buffer
	if ackSeq > s.ackOffset {
		bytesAcked := ackSeq - s.ackOffset
		if int(bytesAcked) <= len(s.unackedBuf) {
			// Remove acknowledged data from unacked buffer
			s.unackedBuf = s.unackedBuf[bytesAcked:]
			s.ackOffset = ackSeq
		} else {
			// Client acked more than we have in unacked buffer - reset
			s.unackedBuf = nil
			s.ackOffset = ackSeq
		}
	}

	// Check if we need to re-send unacked data (with grace period to allow parallel polls to ack)
	// Only re-send if: we have unacked data, client is behind, AND enough time has passed
	const resendGracePeriod = 500 * time.Millisecond // Wait before triggering re-send
	if len(s.unackedBuf) > 0 && ackSeq < s.sentOffset && time.Since(s.lastSendTime) > resendGracePeriod {
		// Client hasn't received all data after grace period - re-send from where client is
		resendOffset := ackSeq - (s.sentOffset - int64(len(s.unackedBuf)))
		if resendOffset >= 0 && resendOffset < int64(len(s.unackedBuf)) {
			// Re-send from resendOffset
			toResend := s.unackedBuf[resendOffset:]
			if len(toResend) > maxChunk {
				toResend = toResend[:maxChunk]
			}
			s.lastSendTime = time.Now() // Update send time for re-send
			return toResend
		}
	}

	// Flow control: don't send more data if unacked buffer is full
	const maxUnackedSize = 2 * 1024 * 1024 // 2MB max unacked data
	if len(s.unackedBuf) > maxUnackedSize {
		// Wait for acks before sending more
		return nil
	}

	// Get new data from buffer
	data := s.toClient.Bytes()
	if len(data) == 0 {
		return nil
	}

	// Limit chunk size
	chunk := data
	if len(chunk) > maxChunk {
		chunk = data[:maxChunk]
	}

	// Copy chunk to return (don't modify original slice)
	result := make([]byte, len(chunk))
	copy(result, chunk)

	// Move data to unacked buffer (keep for potential re-send)
	s.unackedBuf = append(s.unackedBuf, chunk...)
	s.sentOffset += int64(len(chunk))
	s.lastSendTime = time.Now() // Track send time for re-send grace period

	// Remove sent data from toClient buffer
	remaining := data[len(chunk):]
	s.toClient.Reset()
	if len(remaining) > 0 {
		s.toClient.Write(remaining)
	}

	return result
}

// verifyPollingAuth verifies the HMAC auth token for polling requests
func verifyPollingAuth(authToken, sessionID string, secret []byte) bool {
	// Auth token is generated as: HMAC(secret, sessionID:timestamp)[:16]
	// We allow tokens from last 60 seconds
	now := time.Now().Unix()

	for delta := int64(0); delta <= 60; delta++ {
		data := fmt.Sprintf("%s:%d", sessionID, now-delta)
		h := hmac.New(sha256.New, secret)
		h.Write([]byte(data))
		expected := base64.StdEncoding.EncodeToString(h.Sum(nil))[:16]
		if hmac.Equal([]byte(authToken), []byte(expected)) {
			return true
		}
	}
	return false
}

// decodeClientSecret decodes a client secret from hex string to binary bytes
// Redis stores secrets as 64-char hex strings, but auth uses binary bytes
func decodeClientSecret(secretStr string) []byte {
	// If it looks like hex (64 chars, all hex digits), decode it
	if len(secretStr) == 64 {
		decoded, err := hex.DecodeString(secretStr)
		if err == nil {
			return decoded
		}
	}
	// Fall back to raw bytes (for backwards compatibility)
	return []byte(secretStr)
}

// handleHTTPPollingWithALPN handles HTTP polling connections via ALPN routing
// This is the kTLS-compatible entry point for tired-polling ALPN
func handleHTTPPollingWithALPN(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	// Read the first HTTP request
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		logger.Debug("HTTP Polling (ALPN): Failed to read request: %v", err)
		conn.Close()
		return
	}

	logger.Debug("HTTP Polling (ALPN): Received %d bytes", n)
	handleHTTPPolling(conn, srvCtx, buf[:n], logger)
}

// handleHTTPPolling handles HTTP polling requests (one request per connection)
func handleHTTPPolling(conn net.Conn, srvCtx *serverContext, request []byte, logger *log.Logger) {
	reader := bufio.NewReader(conn)
	processHTTPPollingRequest(conn, reader, srvCtx, request, logger)
}

// processHTTPPollingRequest processes a single HTTP polling request
func processHTTPPollingRequest(conn net.Conn, reader *bufio.Reader, srvCtx *serverContext, request []byte, logger *log.Logger) {
	// Parse headers from request
	lines := bytes.Split(request, []byte("\r\n"))
	var sessionID, authToken string
	var contentLength int
	var ackSeq int64
	keepAlive := false

	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("X-Session-ID:")) {
			sessionID = strings.TrimSpace(string(line[13:]))
		}
		if bytes.HasPrefix(line, []byte("X-Auth-Token:")) {
			authToken = strings.TrimSpace(string(line[13:]))
		}
		if bytes.HasPrefix(line, []byte("X-Ack:")) {
			fmt.Sscanf(string(line), "X-Ack: %d", &ackSeq)
		}
		if bytes.HasPrefix(line, []byte("Content-Length:")) {
			fmt.Sscanf(string(line), "Content-Length: %d", &contentLength)
		}
		if bytes.HasPrefix(bytes.ToLower(line), []byte("connection:")) && bytes.Contains(bytes.ToLower(line), []byte("keep-alive")) {
			keepAlive = true
		}
	}

	if sessionID == "" {
		logger.Debug("HTTP Polling: Missing session ID")
		sendHTTPPollingError(conn, "Missing session ID")
		return
	}

	// Read body if present
	var body []byte
	if contentLength > 0 {
		// Find body start (after \r\n\r\n)
		bodyStart := bytes.Index(request, []byte("\r\n\r\n"))
		if bodyStart != -1 {
			bodyStart += 4
			existingBody := request[bodyStart:]
			if len(existingBody) < contentLength {
				// Need to read more body data from connection
				remaining := make([]byte, contentLength-len(existingBody))
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := io.ReadFull(conn, remaining)
				conn.SetReadDeadline(time.Time{})
				if err != nil {
					logger.Debug("HTTP Polling: Failed to read body: %v", err)
					sendHTTPPollingError(conn, "Failed to read body")
					return
				}
				body = append(existingBody, remaining...)
			} else if len(existingBody) >= contentLength {
				body = existingBody[:contentLength]
			}
		}
	}

	// Check if session already exists - if so, use its secret for auth
	existingSess := pollingManager.Get(sessionID)

	var usedSecret []byte
	var clientID string

	if existingSess != nil {
		// Session exists - verify auth against session's secret
		if verifyPollingAuth(authToken, sessionID, existingSess.Secret) {
			usedSecret = existingSess.Secret
			clientID = existingSess.ClientID
		} else {
			// Debug: try all secrets to find which one would match
			logger.Debug("HTTP Polling: Auth failed for existing session %s (token mismatch), sess.Secret prefix=%x, authToken=%s",
				sessionID[:8], existingSess.Secret[:min(8, len(existingSess.Secret))], authToken)

			// Try registered clients to see if any match
			if srvCtx.registry != nil {
				clients := srvCtx.registry.ListClients()
				for _, c := range clients {
					secretBytes := []byte(c.Secret)
					if verifyPollingAuth(authToken, sessionID, secretBytes) {
						logger.Debug("HTTP Polling: Token would match client '%s' secret prefix=%x", c.Name, secretBytes[:min(8, len(secretBytes))])
					}
				}
			}
			if verifyPollingAuth(authToken, sessionID, srvCtx.cfg.Secret) {
				logger.Debug("HTTP Polling: Token would match global secret prefix=%x", srvCtx.cfg.Secret[:min(8, len(srvCtx.cfg.Secret))])
			}

			sendHTTPPollingError(conn, "Authentication failed")
			return
		}
	} else {
		// New session - authenticate by trying registered clients, then global secret
		if srvCtx.registry != nil {
			clients := srvCtx.registry.ListClients()
			for _, c := range clients {
				// Use secret as-is (client uses ASCII bytes of hex string)
				secretBytes := []byte(c.Secret)
				if verifyPollingAuth(authToken, sessionID, secretBytes) {
					usedSecret = secretBytes
					clientID = c.ID
					logger.Debug("HTTP Polling: Auth matched client '%s' (id=%s)", c.Name, c.ID)
					break
				}
			}
		}

		if usedSecret == nil && len(srvCtx.cfg.Secret) > 0 {
			if verifyPollingAuth(authToken, sessionID, srvCtx.cfg.Secret) {
				usedSecret = srvCtx.cfg.Secret
				clientID = "global"
				logger.Debug("HTTP Polling: Auth matched global secret")
			}
		}

		if usedSecret == nil {
			logger.Debug("HTTP Polling: Authentication failed for new session %s", sessionID[:8])
			sendHTTPPollingError(conn, "Authentication failed")
			return
		}
	}

	// Get or create session
	sess, isNew := pollingManager.GetOrCreate(sessionID, usedSecret, clientID)

	if isNew {
		logger.Info("HTTP Polling: New session %s (client: %s), body=%d bytes, contentLength=%d", sessionID[:8], clientID, len(body), contentLength)

		// Write init body data (contains target address) BEFORE starting relay
		if len(body) > 0 {
			sess.WriteFromClient(body)
			logger.Debug("HTTP Polling: New session received %d bytes (target addr): %x", len(body), body)
		} else {
			logger.Debug("HTTP Polling: WARNING - New session has no body data!")
		}

		// Send OK for new session
		sendHTTPPollingResponse(conn, []byte("OK"), keepAlive)

		// Start background relay goroutine for this session
		go runPollingSessionRelay(sess, srvCtx, logger)
		return
	}

	// Existing session - exchange data
	sess.LastActive = time.Now()

	// Write client data to session buffer
	if len(body) > 0 {
		sess.WriteFromClient(body)
		logger.Debug("HTTP Polling: Received %d bytes from client (session %s)", len(body), sessionID[:8])
	}

	// Get data for client (with acknowledgement tracking)
	toClient := sess.ReadToClient(ackSeq)
	if len(toClient) > 0 {
		logger.Debug("HTTP Polling: Sending %d bytes to client (session %s, ack=%d)", len(toClient), sessionID[:8], ackSeq)
	}

	sendHTTPPollingResponse(conn, toClient, keepAlive)
}

// runPollingSessionRelay handles the relay for a polling session
func runPollingSessionRelay(sess *HTTPPollingSession, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("HTTP Polling: Starting relay for session %s", sess.ID[:8])

	// Wait for first data from client to determine target
	var targetAddr string
	timeout := time.After(30 * time.Second)

	for {
		select {
		case <-timeout:
			logger.Debug("HTTP Polling: Session %s timed out waiting for target", sess.ID[:8])
			pollingManager.Remove(sess.ID)
			return
		default:
		}

		data := sess.ReadFromClient()
		if len(data) > 0 {
			// Check for TUN mode (first byte = 0x02)
			if data[0] == 0x02 {
				logger.Info("HTTP Polling: TUN mode detected for session %s", sess.ID[:8])
				runPollingTUNMode(sess, data[1:], srvCtx, logger)
				return
			}

			// SOCKS mode: First 2 bytes are address length
			if len(data) < 2 {
				logger.Debug("HTTP Polling: Invalid address length")
				pollingManager.Remove(sess.ID)
				return
			}

			addrLen := int(data[0])<<8 | int(data[1])
			if addrLen < 3 || addrLen > 256 || len(data) < 2+addrLen {
				logger.Debug("HTTP Polling: Invalid address (len=%d, have=%d)", addrLen, len(data))
				pollingManager.Remove(sess.ID)
				return
			}

			targetAddr = string(data[2 : 2+addrLen])
			// Put remaining data back
			if len(data) > 2+addrLen {
				sess.WriteFromClient(data[2+addrLen:])
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	logger.Info("HTTP Polling: Session %s connecting to %s", sess.ID[:8], targetAddr)

	// Connect to target
	var targetConn net.Conn
	var err error
	if srvCtx.upstreamDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		targetConn, err = srvCtx.upstreamDialer.Dial(ctx, targetAddr)
		cancel()
	} else {
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}

	if err != nil {
		logger.Warn("HTTP Polling: Failed to connect to %s: %v", targetAddr, err)
		sess.WriteToClient([]byte{0x01}) // Failure
		pollingManager.Remove(sess.ID)
		return
	}

	sess.targetLock.Lock()
	sess.targetConn = targetConn
	sess.targetLock.Unlock()

	// Send success
	sess.WriteToClient([]byte{0x00})
	logger.Info("HTTP Polling: Session %s connected to %s", sess.ID[:8], targetAddr)

	// Start bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		for {
			if sess.closed {
				return
			}
			data := sess.ReadFromClient()
			if len(data) > 0 {
				if _, err := targetConn.Write(data); err != nil {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			targetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := targetConn.Read(buf)
			if n > 0 {
				sess.WriteToClient(buf[:n])
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					if sess.closed {
						return
					}
					continue
				}
				return
			}
		}
	}()

	wg.Wait()
	logger.Info("HTTP Polling: Session %s relay ended", sess.ID[:8])
	pollingManager.Remove(sess.ID)
}

// sendHTTPPollingResponse sends HTTP 200 OK with body (Keep-Alive)
func sendHTTPPollingResponse(conn net.Conn, body []byte, keepAlive bool) {
	connection := "close"
	if keepAlive {
		connection = "keep-alive"
	}
	response := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: %s\r\n"+
			"\r\n", len(body), connection)

	conn.Write([]byte(response))
	if len(body) > 0 {
		conn.Write(body)
	}
}

// sendHTTPPollingError sends HTTP 400 error
func sendHTTPPollingError(conn net.Conn, message string) {
	response := fmt.Sprintf(
		"HTTP/1.1 400 Bad Request\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s", len(message), message)

	conn.Write([]byte(response))
}

// runPollingTUNMode handles TUN mode over HTTP Polling
func runPollingTUNMode(sess *HTTPPollingSession, remainingData []byte, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg
	logger.Debug("HTTP Polling TUN mode, remaining data: %d bytes", len(remainingData))

	// Parse TUN handshake from remaining data: [localIP:4][mtu:2][version:1]
	// Version byte is optional (v1 clients send 6 bytes, v2 clients send 7 bytes)
	if len(remainingData) < 6 {
		logger.Debug("HTTP Polling TUN handshake too short: %d bytes", len(remainingData))
		sess.WriteToClient([]byte{0x01}) // Failure
		pollingManager.Remove(sess.ID)
		return
	}

	// Check if shared TUN is available
	if srvCtx == nil || srvCtx.sharedTUN == nil {
		logger.Error("HTTP Polling TUN: Shared TUN not initialized")
		sess.WriteToClient([]byte{0x01}) // Failure
		pollingManager.Remove(sess.ID)
		return
	}
	logger.Debug("HTTP Polling TUN: SharedTUN is available, proceeding...")

	requestedIP := net.IP(remainingData[0:4])
	clientID := fmt.Sprintf("polling:%s", sess.ClientID)
	logger.Debug("HTTP Polling TUN: requestedIP=%s, clientID=%s", requestedIP, clientID)

	// Check for version byte (v2 clients send 7 bytes total)
	var clientVersion uint8 = 1 // Default to v1 for backwards compatibility
	if len(remainingData) >= 7 {
		clientVersion = remainingData[6]
		logger.Debug("HTTP Polling TUN client requested: IP=%s, clientID=%s, version=%d", requestedIP, clientID, clientVersion)
	} else {
		logger.Debug("HTTP Polling TUN client requested: IP=%s, clientID=%s (legacy v1)", requestedIP, clientID)
	}

	// Allocate IP from pool
	var clientIP net.IP
	logger.Debug("HTTP Polling TUN: Checking IP pool, ipPool=%v", srvCtx.ipPool != nil)
	if srvCtx.ipPool != nil {
		logger.Debug("HTTP Polling TUN: Calling ipPool.Allocate for clientID=%s, requestedIP=%s", clientID, requestedIP)
		allocatedIP, err := srvCtx.ipPool.Allocate(clientID, requestedIP, "")
		if err != nil {
			logger.Error("HTTP Polling TUN: Failed to allocate IP from pool: %v", err)
			sess.WriteToClient([]byte{0x01}) // Failure
			pollingManager.Remove(sess.ID)
			return
		}
		clientIP = allocatedIP
		logger.Info("HTTP Polling TUN client: allocated IP=%s from pool (clientID=%s)", clientIP, clientID)
	} else {
		clientIP = requestedIP
		logger.Info("HTTP Polling TUN client: IP=%s (no pool)", clientIP)
	}

	// Send success response: [status:1][serverIP:4][clientIP:4]
	serverIP := cfg.TunIP
	resp := make([]byte, 9)
	resp[0] = 0x00 // Success
	copy(resp[1:5], serverIP.To4())
	copy(resp[5:9], clientIP.To4())
	sess.WriteToClient(resp)

	// Create polling TUN connection adapter
	pollConn := &pollingTUNConn{
		sess:   sess,
		closed: make(chan struct{}),
	}

	// Register client with shared TUN using custom framer for polling
	// Polling uses [length:4][packet:N] framing
	logger.Debug("HTTP Polling TUN: about to register client IP=%s, clientID=%s", clientIP, clientID)
	writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, pollConn, nil)
	logger.Debug("HTTP Polling TUN: client registered successfully, writer=%p", writer)
	defer func() {
		srvCtx.sharedTUN.UnregisterClient(clientIP, writer)
		pollingManager.Remove(sess.ID)
		logger.Info("HTTP Polling TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
	}()

	logger.Info("HTTP Polling TUN mode established (client=%s, server=%s, tun=%s)", clientIP, serverIP, srvCtx.sharedTUN.Name())

	// Main loop: Read from polling buffers -> TUN
	// TUN -> Client is handled by SharedTUN packet dispatcher via pollConn.Write()
	lenBuf := make([]byte, 4)
	var packetsUp int64

	for {
		select {
		case <-writer.Done():
			logger.Debug("HTTP Polling TUN loop stopping (client replaced)")
			return
		case <-pollConn.closed:
			logger.Debug("HTTP Polling TUN loop stopping (connection closed)")
			return
		default:
		}

		// Check if session is still active
		if sess.closed {
			logger.Debug("HTTP Polling TUN: session closed")
			return
		}

		// Read packet from client via polling buffer
		data := sess.ReadFromClient()
		if len(data) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Process packets from buffer
		logger.Debug("HTTP Polling TUN: processing data, len=%d", len(data))
		for len(data) >= 4 {
			// Read length prefix
			copy(lenBuf, data[:4])
			pktLen := binary.BigEndian.Uint32(lenBuf)
			logger.Debug("HTTP Polling TUN: read pktLen=%d", pktLen)

			// Handle keepalive (zero length)
			if pktLen == 0 {
				data = data[4:]
				logger.Debug("HTTP Polling TUN: echoing keepalive")
				sess.WriteToClient([]byte{0, 0, 0, 0}) // Echo keepalive
				continue
			}

			// Validate packet length
			if pktLen > 65535 || int(pktLen)+4 > len(data) {
				// Not enough data yet, put back for next iteration
				logger.Debug("HTTP Polling TUN: incomplete packet, pktLen=%d, data=%d", pktLen, len(data))
				sess.WriteFromClient(data)
				break
			}

			// Extract IP packet
			ipPkt := data[4 : 4+pktLen]
			data = data[4+pktLen:]

			// Validate IP packet
			if len(ipPkt) < 20 {
				logger.Debug("HTTP Polling TUN: packet too small: %d", len(ipPkt))
				continue
			}

			logger.Debug("HTTP Polling TUN: about to write %d bytes to TUN", len(ipPkt))
			// Write to TUN device
			if _, err := srvCtx.sharedTUN.TUNDevice().Write(ipPkt); err != nil {
				logger.Debug("HTTP Polling TUN: write to TUN failed: %v", err)
				continue
			}
			logger.Debug("HTTP Polling TUN: wrote %d bytes to TUN successfully", len(ipPkt))
			packetsUp++
			packetsUp++
		}

		// Put remaining partial data back
		if len(data) > 0 {
			sess.WriteFromClient(data)
		}
	}
}

// pollingTUNConn adapts HTTP Polling session to net.Conn for SharedTUN
type pollingTUNConn struct {
	sess   *HTTPPollingSession
	closed chan struct{}
}

func (c *pollingTUNConn) Read(b []byte) (int, error) {
	// Not used - data comes via sess.ReadFromClient() in the main loop
	return 0, io.EOF
}

func (c *pollingTUNConn) Write(b []byte) (int, error) {
	// Write packet to client with length prefix
	if c.sess.closed {
		return 0, io.EOF
	}
	// Frame: [length:4][packet:N]
	frame := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(b)))
	copy(frame[4:], b)
	c.sess.WriteToClient(frame)
	return len(b), nil
}

func (c *pollingTUNConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *pollingTUNConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *pollingTUNConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *pollingTUNConn) SetDeadline(t time.Time) error      { return nil }
func (c *pollingTUNConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pollingTUNConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*pollingTUNConn)(nil)

// getPortRangeBounds parses a port range string and returns start/end bounds
// Supports formats: "995" (single port), "47000-47100" (range)
// Returns (0, 0) on error
func getPortRangeBounds(portRange string) (start, end int) {
	if portRange == "" {
		return 0, 0
	}

	portRange = strings.TrimSpace(portRange)

	// Check for range format: "47000-47100"
	if idx := strings.Index(portRange, "-"); idx > 0 {
		startStr := strings.TrimSpace(portRange[:idx])
		endStr := strings.TrimSpace(portRange[idx+1:])

		fmt.Sscanf(startStr, "%d", &start)
		fmt.Sscanf(endStr, "%d", &end)

		// Validate
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			return 0, 0
		}
		if start > end {
			start, end = end, start
		}
		return start, end
	}

	// Single port - return same start and end
	fmt.Sscanf(portRange, "%d", &start)
	if start < 1 || start > 65535 {
		return 0, 0
	}
	return start, start
}

var _ http.Handler = nil // Import check
