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
	mrand "math/rand/v2"
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
	"github.com/tiredvpn/tiredvpn/internal/capabilities"
	"github.com/tiredvpn/tiredvpn/internal/control"
	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/padding"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	Version     = "1.3.24"
	connCounter uint64
)

const (
	// defaultMaxConcurrentConns is the admission-control limit applied when
	// Config.MaxConcurrentConns is unset. Chosen to comfortably serve a real
	// client population while capping memory under a probe storm: each in-flight
	// connection can hold a peek-buffer (up to 16KB) plus relay buffers.
	defaultMaxConcurrentConns = 4096

	// defaultRelayMaxConcurrentConns is the admission-control limit applied to a
	// relay node (-upstream set) when Config.MaxConcurrentConns is unset. A relay
	// holds a full upstream stego/TLS bridge per client (socket buffers + framer
	// + goroutines), so it is far heavier per connection than an exit node and a
	// 3GB box cannot survive the 4096 exit default. 256 keeps the worst-case
	// memory ceiling bounded while still serving a real client population.
	defaultRelayMaxConcurrentConns = 256

	// defaultRelayIdleTimeout is the idle deadline for a relay->upstream TUN
	// bridge when Config.RelayIdleTimeout is unset. If no bytes flow in either
	// direction for this long the bridge is force-closed to reap half-open
	// downstreams (lost RU->AMS link) that would otherwise pin an admission slot,
	// an 8MB-buffered upstream conn and goroutines forever. A healthy TUN client
	// sends a keepalive frame every 10s (internal/tun keepaliveInterval), so 90s
	// never trips a live session.
	defaultRelayIdleTimeout = 90 * time.Second

	// probeReadDeadline is the initial read deadline for un-classified inbound
	// connections. Kept short so probe-storm goroutines (and their peek-buffers)
	// are released quickly instead of lingering for the legitimate-handshake
	// timeout. 5s is ample for a real ClientHello, including fragmented REALITY.
	probeReadDeadline = 5 * time.Second
)

// admissionSem is a buffered-channel semaphore bounding concurrent in-flight
// incoming TCP connections across all accept-loops. Initialised once by
// initAdmissionControl before listeners start accepting.
var admissionSem chan struct{}

// initAdmissionControl sizes the global admission semaphore from cfg. Safe to
// call once at startup before any accept-loop runs.
func initAdmissionControl(cfg *Config) {
	limit := cfg.MaxConcurrentConns
	if limit <= 0 {
		// A relay (-upstream) holds a heavy per-client upstream bridge, so it gets
		// a much smaller default than an exit node. An explicit -max-conns always
		// wins for both roles.
		if cfg.UpstreamAddr != "" {
			limit = defaultRelayMaxConcurrentConns
		} else {
			limit = defaultMaxConcurrentConns
		}
	}
	admissionSem = make(chan struct{}, limit)
	log.Info("Admission control: max %d concurrent incoming connections", limit)
}

// onHandlerDone, when non-nil, is invoked after a spawned handler goroutine
// fully exits and releases its admission slot. Production leaves it nil; tests
// set it to observe goroutine completion deterministically (no shared-var
// polling), which keeps `go test -race` clean.
var onHandlerDone func()

// acceptConnection applies admission control: it tries to reserve a slot and,
// on success, spawns handleConnection in a goroutine that releases the slot on
// exit. When the limit is reached the new connection is dropped (closed)
// immediately rather than queued, so a reconnect storm cannot accumulate
// goroutines or buffers. Returns true if the connection was admitted.
func acceptConnection(conn net.Conn, srvCtx *serverContext, connID uint64) bool {
	// Capture the semaphore into a local so the spawned goroutine releases the
	// exact channel it acquired and never reads the package-level admissionSem
	// variable concurrently with any reassignment.
	sem := admissionSem

	// Defensive: if admission control was not initialised, fall back to the old
	// unbounded behaviour rather than dropping every connection.
	if sem == nil {
		go handleConnection(conn, srvCtx, connID)
		return true
	}
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() {
				<-sem
				if onHandlerDone != nil {
					onHandlerDone()
				}
			}()
			handleConnection(conn, srvCtx, connID)
		}()
		return true
	default:
		log.Warn("Admission control: dropping connection %d from %s (limit %d reached)",
			connID, conn.RemoteAddr(), cap(sem))
		conn.Close()
		return false
	}
}

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
		tc.SetReadBuffer(4 * 1024 * 1024)  // 4MB read buffer (BDP at high RTT)
		tc.SetWriteBuffer(4 * 1024 * 1024) // 4MB write buffer (BDP at high RTT)
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
	TunMTU      int    // TUN interface MTU (0 = tun.DefaultMTU = 1280)

	// Multi-client mode (Redis)
	RedisAddr string // e.g., "localhost:6379"
	APIAddr   string // e.g., "127.0.0.1:8080"
	APIToken  string // optional bearer token for the management API ("" = no auth)

	// Upstream (multi-hop) mode
	UpstreamAddr   string // e.g., "exit-server.com:443"
	UpstreamSecret string // secret for upstream auth

	// RelayIdleTimeout is the idle deadline for a relay->upstream TUN bridge.
	// 0 = use defaultRelayIdleTimeout. A bridge with no traffic in either
	// direction for this long is force-closed to reap half-open downstreams.
	RelayIdleTimeout time.Duration

	// RelayUpstreamBufBytes overrides the SO_RCVBUF/SO_SNDBUF size set on the TCP
	// connection to the upstream exit. 0 = use defaultUpstreamSockBuf (512KB).
	// Each relay bridge commits these buffers, so this is a direct memory
	// multiplier on a relay node under load.
	RelayUpstreamBufBytes int

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

	// MaxConcurrentConns caps the number of simultaneously in-flight incoming
	// TCP connections (admission control). Under a DPI reconnect storm the
	// accept-loop would otherwise spawn unbounded goroutines, each holding a
	// peek-buffer, leading to OOM. 0 = use defaultMaxConcurrentConns.
	MaxConcurrentConns int

	// IPv6 Support
	ListenAddrV6 string // "[::]:995"
	EnableIPv6   bool   // default: true
	DualStack    bool   // default: true

	// EnableICMP enables the ICMP tunnel server (requires CAP_NET_RAW).
	// If the process lacks the capability, the listener is silently skipped.
	EnableICMP bool

	// SeqovlPacketDrop requests the server-side input NFQUEUE drop for the
	// packet-level (level A) seqovl overlap. Currently a stub: the client's
	// default safe geometry needs no server drop, so enabling this only logs
	// that the aggressive overlap-into-ClientHello variant is not yet supported.
	// See internal/geneva/overlap_server.go (OverlapServerDropper).
	SeqovlPacketDrop bool

	// REALITYCoverDomain is the domain to proxy unauthorized REALITY connections
	// to, making the server look like a legitimate HTTPS endpoint when probed.
	// Must be a hostname without port (port 443 is used).
	// If empty, unauthorized REALITY connections are silently dropped.
	REALITYCoverDomain string

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

	initAdmissionControl(cfg)

	if err := InitREALITYKeys(); err != nil {
		return fmt.Errorf("reality initialization failed: %w", err)
	}

	caps := capabilities.Probe()
	log.Info("capabilities: %s", caps)
	if cfg.EnableICMP && !caps.HasNetRaw {
		log.Warn("ICMP tunnel disabled: CAP_NET_RAW required")
		cfg.EnableICMP = false
	}
	if !caps.HasTUNDevice {
		log.Warn("TUN device /dev/net/tun not available")
	}
	if cfg.SeqovlPacketDrop {
		// The client's default safe overlap geometry keeps the fake segment
		// below rcv_nxt, so the kernel discards it on its own. The input NFQUEUE
		// drop is only needed for the aggressive overlap-into-ClientHello variant,
		// which is not implemented yet (see geneva.OverlapServerDropper).
		log.Warn("seqovl -seqovl-packet-drop set but server-side overlap drop is not implemented; safe client geometry needs no drop")
		cfg.SeqovlPacketDrop = false
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

	if cfg.EnableICMP {
		go startICMPServer(srvCtx)
	}

	// Surface a TUN-incapable exit at boot instead of failing every native
	// full-tunnel client silently per-connection (issue #51). A proxy-only
	// deployment without TUN is legitimate, so warn rather than abort.
	if ok, reason := tunModeReady(srvCtx); !ok {
		log.Warn("TUN mode unavailable: %s", reason)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debug("Accept error: %v", err)
			continue
		}
		connID := atomic.AddUint64(&connCounter, 1)
		acceptConnection(conn, srvCtx, connID)
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
	api := NewAPIServer(registry, store, cfg.APIAddr, cfg.APIToken)
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
	dialer := NewUpstreamDialer(cfg.UpstreamAddr, []byte(cfg.UpstreamSecret))
	if cfg.RelayUpstreamBufBytes > 0 {
		dialer.sockBufBytes = cfg.RelayUpstreamBufBytes
	}
	srvCtx.upstreamDialer = dialer
	log.Info("Upstream mode enabled: %s", cfg.UpstreamAddr)
	return nil
}

// tunModeReady reports whether this instance can serve native full-tunnel (TUN
// mode) clients such as the Android app. Relays forward TUN packets to an
// upstream exit and never need a local TUN; exits need the shared TUN device,
// which only exists when -ip-pool is configured (see initIPPool). Returns false
// with an actionable reason when a native TUN client would be rejected at
// connect time with "Shared TUN not initialized" (issue #51).
func tunModeReady(srvCtx *serverContext) (bool, string) {
	if srvCtx == nil {
		return false, "server context not initialized"
	}
	if srvCtx.upstreamDialer != nil {
		// Relay: TUN packets are forwarded upstream, no local TUN required.
		return true, ""
	}
	if srvCtx.sharedTUN == nil {
		return false, "shared TUN not initialized (server started without -ip-pool); native full-tunnel clients (e.g. Android) will be rejected — set -ip-pool (e.g. 10.8.0.0/24) to enable"
	}
	return true, ""
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
	sharedTUN, err := NewSharedTUN(tunName, cfg.TunIP, network, resolveTunMTU(cfg), 0)
	if err != nil {
		return fmt.Errorf("failed to create shared TUN: %w", err)
	}
	srvCtx.sharedTUN = sharedTUN
	sharedTUN.StartCleanupRoutine(2*time.Minute, 5*time.Minute)

	// Bring up ip_forward + NAT for the pool so client traffic egresses
	// through the host WAN. Non-fatal: a server started without NET_ADMIN
	// (or one behind an external NAT setup already) should still come up in
	// a degraded-but-running state, matching the old `ExecStartPre=-` /
	// Docker entrypoint warn-and-continue behavior this replaces.
	if err := tun.SetupServerNAT(cfg.IPPoolNetwork, os.Getenv("TIREDVPN_WAN_IFACE")); err != nil {
		log.Warn("NAT auto-config failed: %v", err)
	}

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

	// QUIC server lifecycle is driven by srv.Stop() (closes its internal stopChan),
	// invoked from handleShutdownSignal. acceptLoop selects on stopChan for both
	// shutdown and interruptible accept-error backoff, so a non-cancelable
	// background context here does not block shutdown or cause CPU spin.
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
		acceptConnection(conn, srvCtx, connID)
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

// readFirstPeek reads the first framing unit from conn for protocol
// classification: a full TLS record when the 5-byte header is a handshake
// record, otherwise up to ~2KB of non-TLS data. It preserves the original
// deadline handling (probeReadDeadline for the header, 30s for the record body)
// and the partial-REALITY tolerance (DPI may drop trailing padding). ok is false
// on a fatal read error; the caller then serves the fake website.
//
// It is called once per connection, and again for each leading seqovl decoy
// record that must be skipped before the real first flight.
func readFirstPeek(conn net.Conn, logger *log.Logger) (header, peekBuf []byte, ok bool) {
	// Set a short initial read deadline for the (still unclassified) connection.
	// A probe that connects but never sends a valid handshake must not pin a
	// goroutine and its peek-buffer for 30s under a reconnect storm. A real
	// ClientHello arrives well within probeReadDeadline; once the TLS record is
	// being read the deadline is extended below for fragmented handshakes.
	conn.SetReadDeadline(time.Now().Add(probeReadDeadline))

	// Peek first bytes to detect protocol
	// First read TLS record header (5 bytes) to get record length
	header = make([]byte, 5)
	n, err := io.ReadFull(conn, header)
	if err != nil || n < 5 {
		logger.Debug("Failed to read header: %v (read %d bytes)", err, n)
		return nil, nil, false
	}

	// For TLS records, read full record to catch REALITY extension in padding
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
				// DPI may drop trailing bytes of a REALITY ClientHello (random padding).
				// peekBuf is zero-initialized so missing bytes are already zeroed.
				// If REALITY is detectable in what we received, proceed with zero-padded record.
				if totalRead > 0 && DetectREALITYExtension(peekBuf[:5+totalRead]) {
					logger.Debug("Partial REALITY ClientHello: %d/%d bytes, zero-padding remainder", totalRead, recordLen)
					break
				}
				logger.Debug("Failed to read TLS record: %v (read %d/%d bytes)",
					err, totalRead, recordLen)
				return nil, nil, false
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

	return header, peekBuf, true
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

	// Read the first framing unit (full TLS record or non-TLS peek) for protocol
	// classification.
	header, peekBuf, ok := readFirstPeek(conn, logger)
	if !ok {
		serveFakeWebsite(conn, cfg, logger)
		return
	}

	// seqovl (level B): the client may prepend one or more secret-marked decoy
	// TLS records before the real ClientHello to desync stateful DPI reassembly.
	// Drop any leading decoy(s) so the real first flight classifies normally. The
	// isSeqovlDecoy gate is additive — a genuine ClientHello (payload[0]==0x01) is
	// rejected before any HMAC, so REALITY / Geneva / Morph are unaffected.
	decoyCount := 0
	for header[0] == 0x16 && isSeqovlDecoy(peekBuf, srvCtx) {
		decoyCount++
		if decoyCount > seqovlMaxDecoys {
			logger.Debug("seqovl: decoy limit (%d) exceeded, serving fake website", seqovlMaxDecoys)
			serveFakeWebsite(conn, cfg, logger)
			return
		}
		logger.Debug("seqovl: dropped decoy record (%d bytes), reading real first flight", len(peekBuf))
		header, peekBuf, ok = readFirstPeek(conn, logger)
		if !ok {
			serveFakeWebsite(conn, cfg, logger)
			return
		}
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
		// internal/ktls.TryEnable; per-protocol handlers (tired-raw, tired-confusion)
		// call it after their auth phase completes.

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

	// SSH camouflage: plaintext SSH-2.0 banner with no TIRED marker. Must be
	// checked before protocol confusion (which also matches "SSH-2.0-") and
	// before TLS, since the SSH handshake is plaintext.
	if DetectSSHCamouflage(peekBuf) {
		logger.Debug("Detected SSH camouflage")
		handleSSHCamouflage(buffConn, srvCtx, logger)
		return
	}

	// IMAP camouflage: plaintext Dovecot greeting ("* OK ... Dovecot ... ready")
	// emitted by the client so this peek-based dispatch can class it. Checked
	// alongside SSH camouflage, before protocol confusion and the fake website
	// fallback. The "* OK" prefix never collides with TLS (0x16) or SSH.
	if DetectIMAPCamouflage(peekBuf) {
		logger.Debug("Detected IMAP camouflage")
		handleIMAPCamouflage(buffConn, srvCtx, logger)
		return
	}

	// Raw TCP protocol confusion: DNS-over-TCP / HTTP / SSH / SMTP preamble + TIRED marker
	if detectConfusionMagic(peekBuf) {
		logger.Debug("Detected raw TCP protocol confusion")
		handleProtocolConfusion(buffConn, srvCtx, logger)
		return
	}

	// Unknown protocol - serve fake website
	logger.Debug("Unknown protocol (not TLS, not timing knock), serving fake website")
	serveFakeWebsite(buffConn, cfg, logger)
}

// handleTLSConnection handles protocols over TLS (after TLS handshake completed).
// conn must be a fully-handshaked *tls.Conn — kTLS upgrade is deferred to each
// per-protocol handler at the relay-phase boundary via ktls.TryEnable.
// Routes by the first encrypted byte (protocol discriminator) sent by the client.
func handleTLSConnection(conn *tls.Conn, srvCtx *serverContext, connID uint64) {
	logger := log.WithPrefix(fmt.Sprintf("conn:%d", connID))

	// Read 1-byte protocol discriminator (encrypted; invisible in ClientHello)
	protoType, err := protocol.ReadDispatch(conn)
	if err != nil {
		logger.Debug("dispatch read failed: %v; falling back to legacy detection", err)
		handleTLSConnectionLegacy(conn, srvCtx, connID)
		return
	}

	logger.Debug("dispatch routing: type=0x%02x", protoType)

	switch protoType {
	case protocol.TypeStego:
		handleHTTP2WithALPN(conn, srvCtx, logger)
	case protocol.TypeRaw:
		handleRawTunnel(conn, srvCtx, logger, "")
	case protocol.TypeConfusion:
		handleProtocolConfusion(conn, srvCtx, logger)
	case protocol.TypeAntiProbe:
		handleAntiProbeDispatch(conn, srvCtx, logger)
	case protocol.TypeMorph:
		handleMorphConnectionWithALPN(conn, srvCtx, logger)
	case protocol.TypeWS:
		handleWebSocketConnection(conn, srvCtx, logger)
	case protocol.TypePolling:
		handleHTTPPollingWithALPN(conn, srvCtx, logger)
	default:
		logger.Debug("unknown dispatch type 0x%02x; falling back to legacy detection", protoType)
		// Prepend the consumed dispatch byte so legacy detectors see the full stream.
		prefixed := &bufferedConn{
			Conn:   conn,
			reader: io.MultiReader(bytes.NewReader([]byte{protoType}), conn),
		}
		handleTLSConnectionLegacy(prefixed, srvCtx, connID)
	}
}

// handleTLSConnectionLegacy handles TLS connections using magic-byte detection.
// conn is net.Conn (not *tls.Conn) so callers can prepend unread bytes via bufferedConn.
func handleTLSConnectionLegacy(conn net.Conn, srvCtx *serverContext, connID uint64) {
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

// handleHTTP2WithALPN handles HTTP/2 Stego when ALPN was used.
//
// kTLS handover boundary: unlike tired-raw / tired-confusion, the HTTP/2
// stego client streams its whole opening burst — preface + SETTINGS + auth
// HEADERS — back-to-back without waiting for a server signal. If we enable
// kTLS right after reading the 24-byte preface, the TLS stack has already
// decrypted the SETTINGS/HEADERS that trailed the preface in the same TCP
// segment into tls.Conn's internal buffer; the kernel then takes over the
// raw socket and those decrypted bytes are lost forever. The server waits
// for HEADERS that never arrive, the client waits for an auth ack that never
// comes, and the handshake hangs until timeout.
//
// Fix: run the entire auth handshake (SETTINGS exchange + auth HEADERS +
// auth ack) through the TLS stack, and only hand the socket to kTLS once the
// client is authenticated. At that point the client is blocked in
// waitForServerAck and has not sent any DATA, so tls.Conn's buffer is empty
// and the handover is lossless. The framer is rebuilt on the kTLS wrapper
// for the relay phase; the HPACK decoder state is carried over unchanged.
func handleHTTP2WithALPN(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("HTTP/2 via ALPN")

	// Read the preface through the TLS stack.
	if err := readH2Preface(conn, logger); err != nil {
		return
	}

	framer, err := newH2Framer(conn, logger)
	if err != nil {
		return
	}

	hpackDec := hpack.NewDecoder(4096, nil)
	authenticated := false
	var authClientID string
	var tunnel *h2TunnelState
	var connTracked bool

	// kTLS handover is intentionally disabled for the stego path.
	//
	// On loopback (and on fast links in general) the client pipelines relay
	// frames immediately after the auth HEADERS before the server's handover
	// has completed. The http2.Framer / tls.Conn pair buffers those TLS
	// records in userspace; when the kernel takes over the raw socket its RX
	// sequence counter is already behind → EBADMSG → RST. Staying on the
	// userspace TLS stack for the full session avoids the sequence-number
	// desync with no correctness impact (kTLS is only a CPU optimisation).

	defer func() { cleanupH2Conn(conn, srvCtx, &tunnel, &connTracked, &authClientID) }()

	runH2FrameLoop(&conn, &framer, hpackDec, srvCtx, logger, &authenticated, &authClientID, &connTracked, &tunnel, nil)
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
	remoteAddr      string // Peer host, used to qualify the IP-pool lease key
	mu              sync.Mutex
	sharedTUNWriter *ClientWriter // For shared TUN mode
	sharedTUN       *SharedTUN    // Reference to shared TUN
	// sink is where packets from this client go: the shared TUN on an exit, the
	// upstream tunnel on a relay. Set once the TUN handshake completes.
	sink tunPacketSink
	// reasmBuf accumulates inbound TUN bytes across stego DATA frames so a single
	// [len:4][pkt:N] frame split over several payloads (relay leg uses a non-tunMode
	// stego conn that chunks at 1000/1400 bytes) is reassembled instead of dropped.
	// Read/written only from the single runH2FrameLoop goroutine -> no lock needed.
	reasmBuf []byte
}

// h2ReasmBufLimit caps the inbound reassembly buffer. AMS prod runs with swap 0, so
// a desynced stream must not grow the buffer without bound.
const h2ReasmBufLimit = 128 * 1024

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

	runH2FrameLoop(&conn, &framer, hpackDec, srvCtx, logger, &authenticated, &authClientID, &connTracked, &tunnel, nil)
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
	if *tunnel != nil && (*tunnel).sink != nil {
		(*tunnel).sink.Close()
	}
	if *connTracked && srvCtx.registry != nil && *authClientID != "" {
		srvCtx.registry.RemoveConnection(*authClientID, conn)
	}
}

// runH2FrameLoop reads and dispatches HTTP/2 frames until the connection closes.
//
// connPtr / framerPtr are pointers so the loop can swap the connection and
// framer in place after a kTLS handover (see handover). handover may be nil
// (legacy non-ALPN path), in which case no kTLS upgrade happens. When set, it
// is invoked exactly once — immediately after auth succeeds — and returns the
// connection and framer to use for the subsequent relay phase.
func runH2FrameLoop(connPtr *net.Conn, framerPtr **http2.Framer, hpackDec *hpack.Decoder, srvCtx *serverContext, logger *log.Logger, authenticated *bool, authClientID *string, connTracked *bool, tunnel **h2TunnelState, handover func(net.Conn) (net.Conn, *http2.Framer)) {
	cfg := srvCtx.cfg
	for {
		conn := *connPtr
		framer := *framerPtr
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
			wasAuthed := *authenticated
			processH2HeadersFrame(conn, f, framer, hpackDec, srvCtx, logger, authenticated, authClientID, connTracked)
			// Auth just succeeded on this frame: perform the kTLS handover
			// now, before reading any further frames. The auth ack has been
			// written through the TLS stack and flushed; the client is parked
			// in waitForServerAck, so no client bytes are in flight.
			if !wasAuthed && *authenticated && handover != nil {
				newConn, newFramer := handover(conn)
				*connPtr = newConn
				*framerPtr = newFramer
			}
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
		t := &h2TunnelState{streamID: f.StreamID, clientID: authClientID, remoteAddr: originOf(conn.RemoteAddr())}
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

// forwardH2TUNPacket reassembles inbound TUN frames from stego payloads and writes
// the contained IP packets to the shared TUN device.
//
// The stego stream is a byte stream carrying [len:4][pkt:N] frames. A single frame
// can arrive split across several stego DATA-frame payloads: a relay forwards a
// downstream client's packets over a non-tunMode upstream stego conn that caps
// chunks at 1000/1400 bytes (writeViaPaddedData / writeViaData), so a 1404-byte
// frame (1400-byte inner packet) is emitted as 2+ payloads. The previous version
// treated each payload as one self-contained frame and dropped anything that did
// not fit (int(pktLen) > len(payload)-4), black-holing every inner packet above
// ~996 bytes on relay chains. We now buffer across payloads like the morph path.
func forwardH2TUNPacket(tunnel *h2TunnelState, streamID uint32, payload []byte, logger *log.Logger) {
	tunnel.streamID = streamID
	if tunnel.sink == nil {
		return
	}

	tunnel.reasmBuf = append(tunnel.reasmBuf, payload...)
	tunnel.reasmBuf = reassembleH2TUNFrames(tunnel.reasmBuf,
		func(ipPkt []byte) {
			// Auto-MTU: reflect probe REQUESTs back over the stego channel instead
			// of writing them to the TUN device. Reassembly above has already
			// rebuilt the whole frame, so the marker check sees a complete probe.
			if tun.IsProbeFrame(ipPkt) {
				if reply := tun.MakeProbeReply(ipPkt); reply != nil {
					if h2c, ok := tunnel.targetConn.(*h2TunConn); ok {
						frame := make([]byte, 4+len(reply))
						binary.BigEndian.PutUint32(frame[:4], uint32(len(reply)))
						copy(frame[4:], reply)
						tunnel.mu.Lock()
						sendStegoResponse(h2c.framer, tunnel.streamID, frame, h2c.cfg)
						tunnel.mu.Unlock()
						logger.Debug("Auto-MTU: H2 echoed PROBE_REPLY size=%d", len(reply))
					}
					tunnel.sink.UpdateActivity()
				}
				return
			}
			logger.Debug("H2 TUN: forwarding %d bytes, first 20: %x", len(ipPkt), ipPkt[:minInt(20, len(ipPkt))])
			if err := tunnel.sink.WritePacket(ipPkt); err != nil {
				logger.Debug("H2 TUN sink write error: %v", err)
			}
			tunnel.sink.UpdateActivity()
		},
		func() {
			// Keepalive (zero length) - echo back. The morph, confusion and native
			// TUN handlers all echo zero-length keepalives; without it idle H2
			// clients get no inbound traffic and self-disconnect when their
			// readTimeout expires.
			if h2c, ok := tunnel.targetConn.(*h2TunConn); ok {
				logger.Debug("H2 TUN: received keepalive, echoing back")
				tunnel.mu.Lock()
				sendStegoResponse(h2c.framer, tunnel.streamID, []byte{0, 0, 0, 0}, h2c.cfg)
				tunnel.mu.Unlock()
			}
			tunnel.sink.UpdateActivity()
		})
}

// reassembleH2TUNFrames extracts complete [len:4][pkt:N] frames from buf, calling
// deliver(ipPkt) for each data packet and onKeepalive() for each zero-length frame.
// It returns the unconsumed remainder (a partial frame awaiting more bytes). A bogus
// length desyncs the stream, recovered by sliding one byte forward like the morph
// reassembler. If the remainder exceeds h2ReasmBufLimit (a persistently desynced
// stream) it is dropped and nil is returned, so the buffer cannot grow without bound
// on the swap-0 AMS box.
func reassembleH2TUNFrames(buf []byte, deliver func(ipPkt []byte), onKeepalive func()) []byte {
	for len(buf) >= 4 {
		pktLen := binary.BigEndian.Uint32(buf[0:4])

		if pktLen == 0 {
			buf = buf[4:]
			onKeepalive()
			continue
		}

		if pktLen < 20 || pktLen > 65535 {
			buf = buf[1:]
			continue
		}

		totalLen := 4 + int(pktLen)
		if len(buf) < totalLen {
			break
		}

		deliver(buf[4:totalLen])
		buf = buf[totalLen:]
	}

	if len(buf) > h2ReasmBufLimit {
		log.Warn("H2 TUN reassembly buffer overflow (%d bytes), resetting", len(buf))
		return nil
	}
	return buf
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
// morphShaperReadTimeout bounds how long the server waits for the optional
// wire-protocol v2 shaper-ID byte. v2 clients send it in the same TCP segment
// as the auth token, so it is present immediately; pre-v2 clients never send
// it and the read times out, yielding a noop shaper.
const morphShaperReadTimeout = 2 * time.Second

// readMorphShaperID reads the optional 1-byte shaper ID that trails the MRPH
// auth token in wire-protocol v2. On timeout, EOF or an unknown ID it returns
// a NoopShaper so the connection falls back to the legacy byte-relay framing.
// The seed is drawn locally: it only affects this side's outbound packet
// sizing, never Unwrap correctness (the frame layout is seed-independent).
func readMorphShaperID(conn net.Conn, logger *log.Logger) shaper.Shaper {
	idBuf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(morphShaperReadTimeout))
	_, err := io.ReadFull(conn, idBuf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		// Old client (no ID byte) or slow link: stay on the legacy wire format.
		logger.Debug("Morph shaper ID absent (%v); using noop", err)
		return shaper.NoopShaper{}
	}
	id := presets.ShaperID(idBuf[0])
	if id == presets.ShaperIDNoop {
		return shaper.NoopShaper{}
	}
	sh, err := presets.ShaperByID(id, 0)
	if err != nil {
		logger.Warn("Morph: unknown shaper ID %d (%v); using noop", idBuf[0], err)
		return shaper.NoopShaper{}
	}
	logger.Debug("Morph: negotiated shaper ID %d", idBuf[0])
	return sh
}

// isMorphNoopShaper reports whether sh is the passthrough shaper. The legacy
// byte-relay path stays bit-identical when this is true.
func isMorphNoopShaper(sh shaper.Shaper) bool {
	if sh == nil {
		return true
	}
	switch sh.(type) {
	case shaper.NoopShaper, *shaper.NoopShaper:
		return true
	}
	return false
}

// writeMorphShapedFrames writes each shaper frame as one morph packet
// [dataLen:4][paddingLen:2][frame:N], mirroring the client's writeShaped. The
// shaper already padded each frame to its target size, so no extra morph
// padding is added here (paddingLen=0); the client's readShaped reads the
// whole frame and hands it to Unwrap, which strips the shaper's own padding.
func writeMorphShapedFrames(conn net.Conn, sh shaper.Shaper, frames [][]byte) error {
	for _, frame := range frames {
		hdr := make([]byte, 6+len(frame))
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(frame)))
		// paddingLen stays 0: the shaper frame carries its own padding.
		copy(hdr[6:], frame)
		if _, err := conn.Write(hdr); err != nil {
			return err
		}
	}
	return nil
}

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
		logger.Debug("Traffic Morph: checking %d clients from registry", len(clients))
		for _, client := range clients {
			secretBytes := []byte(client.Secret)
			logger.Debug("Traffic Morph: trying client '%s' (secret len=%d)", client.Name, len(client.Secret))
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
		conn.Write([]byte{0x01}) // best-effort fail ack; client treats as fail and closes
		return
	}

	_ = usedSecret // Mark as used

	// Wire-protocol v2: a 1-byte shaper ID trails the auth token in the same
	// handshake write. v2 clients always send it; pre-v2 clients send nothing
	// more until they read the ack, so a short read deadline distinguishes the
	// two without a version negotiation. Timeout / EOF => ID 0 (noop), keeping
	// the legacy wire format for old clients.
	morphShaper := readMorphShaperID(conn, logger)

	// Track per-client connection for metrics. Use a closure on the conn
	// variable so the defer picks up the kTLS-wrapped value if we hand
	// the socket over later via ktls.TryEnable + registry.SwapConn.
	if srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track connection for client %s: %v", clientID, err)
		} else {
			defer func() {
				srvCtx.registry.RemoveConnection(clientID, conn)
			}()
		}
	}

	// Auth complete — write 1-byte ack to client (Phase 2 wire protocol).
	// 0x00 = auth ok, dialing target next. The client must read this byte
	// before sending the first morph frame, so it can ktls.TryEnable on
	// the matching boundary.
	if _, err := conn.Write([]byte{0x00}); err != nil {
		logger.Warn("Failed to write morph auth ack: %v", err)
		return
	}

	// Auth phase complete: hand the socket over to kTLS for the relay
	// phase. We have read MRPH+name+auth to completion and the ack write
	// flushed synchronously to the kernel send buffer. Subsequent morph
	// frame reads (target addr) and writes (relay data) go through kTLS.
	preSwap := conn
	conn = ktls.TryEnable(conn, "tired-morph")
	if conn != preSwap && srvCtx.registry != nil && clientID != "" {
		// Replace the stored *tls.Conn with the live *ktls.Conn so
		// forced-disconnect Close() targets the right socket wrapper.
		srvCtx.registry.SwapConn(clientID, preSwap, conn)
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

	// With a shaper active the address payload is wrapped (len-prefixed +
	// zero-padded up to the preset's packet size), so the wire dataLen can be
	// up to MTU rather than the tight [2,256] the legacy address frame uses.
	// Validate the unwrapped length below instead.
	noopShaper := isMorphNoopShaper(morphShaper)
	maxFirstFrame := 256
	if !noopShaper {
		maxFirstFrame = 1500
	}
	if dataLen > maxFirstFrame || dataLen < 2 {
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

	// Unwrap the shaper framing to recover the original address payload. For
	// NoopShaper this is identity, so the legacy path is byte-unchanged.
	if !noopShaper {
		morphData = morphShaper.Unwrap([][]byte{morphData})
		if len(morphData) < 2 {
			logger.Debug("Morph data too short after unwrap: %d", len(morphData))
			return
		}
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
		// The TUN relay path (SharedTUN dispatcher + morphPacketWriter) does
		// not yet apply shaper Wrap/Unwrap, so a negotiated shaper would
		// corrupt the stream. Refuse loudly rather than relay garbage; the
		// addr-relay path below fully supports shapers.
		if !noopShaper {
			logger.Warn("Morph TUN mode with non-noop shaper is unsupported; closing")
			failPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
			conn.Write(failPacket)
			return
		}
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

			// Strip shaper framing to recover the original payload. NoopShaper
			// is identity here, preserving the legacy wire format exactly.
			if !noopShaper {
				data = morphShaper.Unwrap([][]byte{data})
				if len(data) == 0 {
					continue
				}
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

			if !noopShaper {
				// Shaper path: fragment+pad the payload into shaper frames,
				// then wrap each frame in the morph header. This mirrors the
				// client's writeShaped so its readShaped/Unwrap reconstructs
				// the bytes. Downstream sizing uses this side's own RNG; only
				// the frame layout has to match, which it does by construction.
				frames := morphShaper.Wrap(buf[:n])
				werr := writeMorphShapedFrames(conn, morphShaper, frames)
				morphShaper.Release(frames)
				atomic.AddInt64(&bytesDown, int64(n))
				if werr != nil {
					return
				}
				continue
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

// fillRandPadding fills b with non-cryptographic random bytes. These bytes are
// frame padding that only varies packet sizes for DPI evasion; the peer
// discards them by length and never inspects their content. A fast PRNG is
// therefore sufficient and, unlike crypto/rand, cannot fail - so it must never
// panic and tear down the data plane. This mirrors the client side, which
// already fills morph padding with a fast RNG.
func fillRandPadding(b []byte) {
	for i := 0; i < len(b); i += 8 {
		v := mrand.Uint64()
		for j := 0; j < 8 && i+j < len(b); j++ {
			b[i+j] = byte(v >> (8 * j))
		}
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
	fillRandPadding(framed[10+len(pkt):])
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

	// A relay forwards this client upstream and never touches its own TUN, so
	// only an exit needs the shared device here.
	if srvCtx == nil || (srvCtx.sharedTUN == nil && srvCtx.upstreamDialer == nil) {
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

	var writeMu sync.Mutex
	writeMorphFrame := func(framed []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := conn.Write(framed)
		return err
	}

	var clientIP, serverIP net.IP
	var sink tunPacketSink

	if srvCtx.upstreamDialer != nil {
		// Relay: hand this client to the upstream exit instead of terminating it
		// here, so a client that fell back to morph still exits where it asked.
		relaySink, upServerIP, upClientIP, err := dialRelayTUN(srvCtx, logger, remainingData,
			originOf(conn.RemoteAddr()), func(pkt []byte) error {
				return writeMorphFrame(morphFramePacket(pkt))
			})
		if err != nil {
			logger.Warn("Morph TUN relay: upstream dial failed: %v", err)
			failPacket := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
			conn.Write(failPacket)
			return
		}
		sink, serverIP, clientIP = relaySink, upServerIP, upClientIP
		defer func() {
			relaySink.Close()
			logger.Info("Morph TUN relay client disconnected: %s (clientID=%s)", clientIP, clientID)
		}()
	} else {
		// Allocate IP from pool (if available) or use requested IP as fallback
		if srvCtx.ipPool != nil {
			allocatedIP, err := srvCtx.ipPool.Allocate(allocationKey(clientID, originOf(conn.RemoteAddr())), requestedIP, "")
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
		serverIP = cfg.TunIP

		// Register client with shared TUN using Morph framing
		writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, conn, morphFramePacket)
		localSink := newLocalTUNSink(srvCtx.sharedTUN, writer, clientIP)
		sink = localSink
		defer func() {
			localSink.Close()
			logger.Info("Morph TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
		}()
	}

	// Send success response via morph packet: [dataLen:4][paddingLen:2][status:1][serverIP:4][clientIP:4]
	respData := make([]byte, 9)
	respData[0] = 0x00 // Success
	copy(respData[1:5], serverIP.To4())
	copy(respData[5:9], clientIP.To4())

	padLen := 30
	resp := make([]byte, 6+len(respData)+padLen)
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(respData)))
	binary.BigEndian.PutUint16(resp[4:6], uint16(padLen))
	copy(resp[6:], respData)
	fillRandPadding(resp[6+len(respData):])
	if err := writeMorphFrame(resp); err != nil {
		logger.Debug("Morph TUN handshake response write failed: %v", err)
		return
	}

	logger.Info("Morph TUN mode established (client=%s, server=%s)", clientIP, serverIP)

	// Main loop: Morph -> sink (server-bound traffic)
	// sink -> Client is handled by SharedTUN's dispatcher (exit) or the relay pump.
	var packetsUp int64
	var reassemblyBuf []byte

	for {
		select {
		case <-sink.Done():
			logger.Debug("Morph TUN loop stopping (client replaced or upstream gone)")
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
			writeMorphFrame([]byte{0, 0, 0, 0, 0, 0})
			sink.UpdateActivity()
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
				sink.UpdateActivity()
			}
			logger.Debug("Morph->sink: forwarding %d bytes", len(ipPkt))

			if err := sink.WritePacket(ipPkt); err != nil {
				logger.Debug("Morph TUN sink write error: %v", err)
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

	// Serve fake response. We already drained the client's request into buf[:n]
	// above; serveFakeWebsite starts a fresh http.ReadRequest, so without
	// replaying those bytes it blocks on an empty socket until the 75s
	// keep-alive timeout — the client gets 0 bytes and the silent hang
	// fingerprints the box as non-nginx to DPI (issue #50). Replay the consumed
	// request so the fake nginx answers immediately, exactly like a real server.
	replay := &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(buf[:n]), conn),
	}
	serveFakeHTTPResponse(replay, cfg, logger)
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

// handleAntiProbeDispatch handles anti-probe connections that arrive over the
// 1-byte protocol dispatch (TypeAntiProbe), after the TLS handshake. The
// dispatch byte has already been consumed by handleTLSConnection, so the next
// bytes are the timing-knock packets. Peek the first packet to resolve which
// per-client (or global) secret the knock was built from, then hand off to the
// shared knock verifier.
func handleAntiProbeDispatch(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	cfg := srvCtx.cfg

	// Peek the first knock packet so detectTimingKnockWithRegistry can match a
	// secret. The first packet is at most 99 bytes (10 + hash%90); reading 99
	// bytes covers it without blocking on the inter-packet client sleeps.
	peekBuf := make([]byte, 99)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := io.ReadAtLeast(conn, peekBuf, 10)
	if err != nil {
		logger.Debug("Anti-probe dispatch: failed to peek knock: %v (read %d)", err, n)
		serveFakeWebsite(conn, cfg, logger)
		return
	}
	conn.SetReadDeadline(time.Time{})
	peekBuf = peekBuf[:n]

	matched, secret, clientID := detectTimingKnockWithRegistry(peekBuf, srvCtx)
	if !matched {
		logger.Debug("Anti-probe dispatch: knock did not match any secret")
		serveFakeWebsite(conn, cfg, logger)
		return
	}

	// Replay the peeked bytes so verifyFullKnockSequence sees the full knock.
	buffConn := &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peekBuf), conn),
	}
	handleAntiProbeAuth(buffConn, srvCtx, secret, clientID, logger)
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
		if _, err := conn.Write([]byte("TIRED")); err != nil {
			logger.Warn("Failed to write confusion TUN ack: %v", err)
			return
		}
		// Auth phase complete: hand the socket over to kTLS for the byte-relay phase.
		// At this point the TLS stack's read buffer is empty (we read the magic
		// + embedded data block to completion) and tls.Conn.Write has written
		// the ack synchronously to the kernel send buffer.
		conn = ktls.TryEnable(conn, "tired-confusion")
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
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00}); err != nil {
		logger.Warn("Failed to write confusion tunnel ack: %v", err)
		return
	}
	logger.Debug("Connected to target, starting confusion relay")

	// Auth phase complete: hand the socket over to kTLS for the byte-relay phase.
	// At this point the TLS stack's read buffer is empty (we read the magic
	// + embedded data block to completion) and tls.Conn.Write has written
	// the ack synchronously to the kernel send buffer.
	conn = ktls.TryEnable(conn, "tired-confusion")

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

	// A relay forwards this client upstream and never touches its own TUN, so
	// only an exit needs the shared device here.
	if srvCtx == nil || (srvCtx.sharedTUN == nil && srvCtx.upstreamDialer == nil) {
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

	var confWriteMu sync.Mutex
	writeConfusionFrame := func(frame []byte) error {
		confWriteMu.Lock()
		defer confWriteMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := conn.Write(frame)
		return err
	}

	var clientIP, serverIP net.IP
	var sink tunPacketSink

	if srvCtx.upstreamDialer != nil {
		// Relay: forward to the upstream exit rather than terminating here.
		relaySink, upServerIP, upClientIP, err := dialRelayTUN(srvCtx, logger, remainingData,
			originOf(conn.RemoteAddr()), func(pkt []byte) error {
				frame := make([]byte, 4+len(pkt))
				binary.BigEndian.PutUint32(frame[:4], uint32(len(pkt)))
				copy(frame[4:], pkt)
				return writeConfusionFrame(frame)
			})
		if err != nil {
			logger.Warn("Confusion TUN relay: upstream dial failed: %v", err)
			conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x01})
			return
		}
		sink, serverIP, clientIP = relaySink, upServerIP, upClientIP
		defer func() {
			relaySink.Close()
			logger.Info("Confusion TUN relay client disconnected: %s (clientID=%s)", clientIP, clientID)
		}()
	} else {
		// Allocate IP from pool
		if srvCtx.ipPool != nil {
			allocatedIP, err := srvCtx.ipPool.Allocate(allocationKey(clientID, originOf(conn.RemoteAddr())), requestedIP, "")
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
		serverIP = cfg.TunIP

		// Register client with shared TUN (default framing: [length:4][packet:N])
		writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, conn, nil)
		localSink := newLocalTUNSink(srvCtx.sharedTUN, writer, clientIP)
		sink = localSink
		defer func() {
			localSink.Close()
			logger.Info("Confusion TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
		}()
	}

	// Send success response with length prefix: [length:4][status:1][serverIP:4][clientIP:4]
	// Confusion protocol uses length-prefixed frames for all data after "TIRED" magic
	resp := make([]byte, 13)                 // 4 bytes length + 9 bytes data
	binary.BigEndian.PutUint32(resp[0:4], 9) // length = 9
	resp[4] = 0x00                           // Success
	copy(resp[5:9], serverIP.To4())
	copy(resp[9:13], clientIP.To4())
	if err := writeConfusionFrame(resp); err != nil {
		logger.Debug("Confusion TUN handshake response write failed: %v", err)
		return
	}

	logger.Info("Confusion TUN mode established (client=%s, server=%s)", clientIP, serverIP)

	// Main loop: Client -> sink
	var packetsUp int64
	lenBuf := make([]byte, 4)

	for {
		select {
		case <-sink.Done():
			logger.Debug("Confusion TUN loop stopping (client replaced or upstream gone)")
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
			writeConfusionFrame(lenBuf)
			sink.UpdateActivity()
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
			sink.UpdateActivity()
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

		if err := sink.WritePacket(actualPkt); err != nil {
			logger.Debug("Confusion TUN sink write error: %v", err)
		}
	}
}

// handleRawTunnel handles raw tunnel connections
// clientID is used for TUN mode to track IP allocation (e.g. "reality:abcd1234")
func handleRawTunnel(conn net.Conn, srvCtx *serverContext, logger *log.Logger, clientID string) {
	logger.Debug("Starting raw tunnel mode")

	// Track per-client connection for metrics. Use a closure on the conn
	// variable so the defer picks up the kTLS-wrapped value if we hand
	// the socket over later via ktls.TryEnable + registry.SwapConn.
	if srvCtx.registry != nil && clientID != "" {
		if err := srvCtx.registry.AddConnection(clientID, conn); err != nil {
			logger.Warn("Failed to track connection for client %s: %v", clientID, err)
		} else {
			defer func() {
				srvCtx.registry.RemoveConnection(clientID, conn)
			}()
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

	// Send success ack
	if _, err := conn.Write([]byte{0x00}); err != nil {
		logger.Warn("Failed to write success ack: %v", err)
		return
	}
	logger.Debug("Connected to target, starting relay")

	// Auth phase complete: hand the socket over to kTLS for the byte-relay phase.
	// At this point the TLS stack's read buffer is empty (we read mode + addr
	// to completion) and tls.Conn.Write has written the ack synchronously to
	// the kernel send buffer.
	preSwap := conn
	conn = ktls.TryEnable(conn, "tired-raw")
	if conn != preSwap && srvCtx.registry != nil && clientID != "" {
		// Replace the stored *tls.Conn pointer so forced-disconnect Close()
		// targets the live ktls.Conn wrapper rather than the stale *tls.Conn.
		srvCtx.registry.SwapConn(clientID, preSwap, conn)
	}

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

// resolveTunMTU returns the configured TUN MTU, falling back to the package
// default when unset. Both the shared interface setup and the per-connection
// MTU negotiation go through here so the interface MTU and the MSS clamp can
// never drift apart.
func resolveTunMTU(cfg *Config) int {
	if cfg.TunMTU > 0 {
		return cfg.TunMTU
	}
	return tun.DefaultMTU
}

// negotiateMTU picks the effective tunnel MTU as min(clientMTU, serverMTU),
// keeping the legacy guard for clients that advertise no MTU (clientMTU == 0).
func negotiateMTU(clientMTU, serverMTU int) int {
	if clientMTU > 0 && clientMTU < serverMTU {
		return clientMTU
	}
	return serverMTU
}

// handleTUNModeCore is the core TUN mode handler
// authClientID is the authenticated client ID from QUIC/etc (empty if not available)
func handleTUNModeCore(conn net.Conn, cfg *Config, srvCtx *serverContext, logger *log.Logger, handshake []byte, authClientID string) {
	requestedIP := net.IP(handshake[0:4])
	clientMTU := int(binary.BigEndian.Uint16(handshake[4:6]))
	// Negotiate MTU: use min(clientMTU, serverMTU) as effective MTU.
	// serverMTU must match the shared TUN interface MTU (both via resolveTunMTU)
	// so the MSS clamp below stays in lock-step with the interface.
	serverMTU := resolveTunMTU(cfg)
	effectiveMTU := negotiateMTU(clientMTU, serverMTU)
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

	// Multi-hop relay: when -upstream is set this node is a relay, not an exit.
	// Forward the downstream client's raw IP packets to the upstream exit over a
	// stego TUN tunnel instead of terminating them on our local TUN. Without this
	// branch the loop below writes client packets into our own TUN device, the
	// kernel never routes them to the upstream, and the client gets no exit.
	if srvCtx != nil && srvCtx.upstreamDialer != nil {
		relayTUNToUpstream(conn, srvCtx, logger, handshake)
		return
	}

	// Check if shared TUN is available. If this fires, the instance was started
	// without -ip-pool (the only thing that creates the shared TUN, see
	// initIPPool) and is not a relay, so it cannot terminate native full-tunnel
	// clients such as the Android app (issue #51). Not IPv6/auto-IP specific:
	// this guard runs before any IP-family branch.
	if srvCtx == nil || srvCtx.sharedTUN == nil {
		logger.Error("Shared TUN not initialized: server started without -ip-pool; native full-tunnel clients cannot connect. Set -ip-pool (e.g. 10.8.0.0/24) to enable")
		resp := make([]byte, 9)
		resp[0] = 0x03 // Error: TUN not available
		conn.Write(resp)
		return
	}

	// Determine client IP
	var clientIP net.IP
	var ipFromPool bool

	if srvCtx.ipPool != nil {
		// Use IP Pool - it returns same IP for same lease key (from Redis leases)
		var err error
		clientIP, err = srvCtx.ipPool.Allocate(allocationKey(clientID, originOf(conn.RemoteAddr())), requestedIP, "")
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
	//
	// Auto-MTU: a v3 client understands the active probe. As the terminating exit
	// (no upstream relay - that branch returned earlier) we always echo probe
	// frames, so advertise the capability via the flags byte (bit 0x02).
	var probeFlags byte
	if clientVersion >= 0x03 {
		probeFlags = tun.ProbeCapFlag
	}
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
				resp[9] = 0x01 | probeFlags // flags: port hopping available (+ auto-MTU)
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
				resp[9] = 0x01 | probeFlags // flags: port hopping available (+ auto-MTU)
				binary.BigEndian.PutUint16(resp[10:12], uint16(portStart))
				binary.BigEndian.PutUint16(resp[12:14], uint16(portEnd))
				logger.Info("Sending v1 extended response with port hopping: %d-%d", portStart, portEnd)
			}
		}
	}

	// v3 client without a port-hop extended response still needs the flags byte to
	// carry the auto-MTU probe capability: emit a 10-byte response.
	if resp == nil && probeFlags != 0 {
		resp = make([]byte, 10)
		resp[0] = 0x00 // Success
		copy(resp[1:5], serverIP.To4())
		copy(resp[5:9], clientIP.To4())
		resp[9] = probeFlags
		logger.Debug("Sending v3 response advertising auto-MTU probe capability")
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

		// Auto-MTU: if this is a probe REQUEST, reflect a same-size REPLY and do
		// NOT write it to the TUN device. The reply tests the return path at the
		// same size. Detection by marker precedes any IP handling.
		if tun.IsProbeFrame(pkt) {
			if reply := tun.MakeProbeReply(pkt); reply != nil {
				if cfg.Debug {
					logger.Debug("Auto-MTU: echoing PROBE_REPLY size=%d", len(reply))
				}
				replyFrame := make([]byte, 4+len(reply))
				binary.BigEndian.PutUint32(replyFrame[:4], uint32(len(reply)))
				copy(replyFrame[4:], reply)
				writeMu.Lock()
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				conn.Write(replyFrame)
				writeMu.Unlock()
				writer.UpdateActivity()
			}
			// A non-request or malformed probe frame is dropped silently.
			continue
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

// relayTUNToUpstream bridges a downstream TUN client to the upstream exit when
// this node runs in multi-hop relay mode (-upstream set). It opens a stego TUN
// tunnel to the upstream, relays the upstream's handshake response (including the
// IP the upstream assigned) back to the downstream client, then byte-copies the
// raw [len:4][pkt:N] frames (and zero-length keepalives) in both directions. The
// relay never touches its own sharedTUN/ippool for these clients.
func relayTUNToUpstream(conn net.Conn, srvCtx *serverContext, logger *log.Logger, handshake []byte) {
	// Carry the downstream client's identity upstream. Without it every client
	// behind this relay reaches the exit as the same anonymous "global" client,
	// so the exit's sticky IP pool hands them all one tunnel IP and they evict
	// each other. A relay further down may have attached the origin already;
	// keep that one so the chain reports the real client, not the middle hop.
	handshake, origin := splitTUNOrigin(handshake)
	if origin == "" {
		origin = originOf(conn.RemoteAddr())
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	upstreamConn, resp, err := srvCtx.upstreamDialer.DialTUN(dialCtx, handshake, origin)
	cancel()
	if err != nil {
		logger.Warn("Relay: upstream TUN dial failed: %v", err)
		// Mirror the local error response so the client fails fast instead of hanging.
		failResp := make([]byte, 9)
		failResp[0] = 0x01
		conn.Write(failResp)
		return
	}
	defer upstreamConn.Close()

	// Forward the upstream's handshake response (assigned IP etc.) to the client.
	if _, err := conn.Write(resp); err != nil {
		logger.Debug("Relay: failed to send handshake response to client: %v", err)
		return
	}

	logger.Info("Relay TUN bridge established (client=%s, upstream-assigned=%s)",
		conn.RemoteAddr(), net.IP(resp[5:9]))

	// Bidirectional transparent copy with an idle watchdog. Both ends speak the
	// identical TUN wire format, so no reframing is needed.
	idleTimeout := srvCtx.cfg.RelayIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultRelayIdleTimeout
	}
	runIdleWatchedBridge(conn, upstreamConn, idleTimeout, logger)

	logger.Info("Relay TUN bridge closed (client=%s)", conn.RemoteAddr())
}

// runIdleWatchedBridge byte-copies traffic in both directions between a and b
// and force-closes BOTH once no bytes flow in either direction for idleTimeout.
// It returns when both copy directions have finished (peer close, error, or the
// idle force-close).
//
// The idle watchdog exists because SetReadDeadline cannot reap a stuck relay
// bridge: the downstream may be an h2TunConn whose SetReadDeadline is a no-op,
// so a silently-vanished client leaves the client->upstream copy blocked on Read
// forever, pinning the admission slot and the upstream's socket buffers. Both
// copy goroutines stamp lastActivity on every read; the watchdog closes both
// sides once the stamp ages past idleTimeout. Real traffic - including 10s TUN
// keepalive frames - keeps the stamp fresh, so a live session is never reaped.
func runIdleWatchedBridge(a, b net.Conn, idleTimeout time.Duration, logger *log.Logger) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			a.Close()
			b.Close()
		})
	}

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	watchdogDone := make(chan struct{})
	go func() {
		// Poll at a quarter of the timeout so the bridge is reaped within
		// ~idleTimeout of going silent, without a tight spin.
		interval := idleTimeout / 4
		if interval < time.Second {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-watchdogDone:
				return
			case <-ticker.C:
				idle := time.Since(time.Unix(0, lastActivity.Load()))
				if idle >= idleTimeout {
					if logger != nil {
						logger.Info("Relay TUN bridge idle for %s, force-closing", idle.Round(time.Second))
					}
					closeBoth()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeBoth()
		copyWithActivity(b, a, &lastActivity) // a -> b
	}()
	go func() {
		defer wg.Done()
		defer closeBoth()
		copyWithActivity(a, b, &lastActivity) // b -> a
	}()
	wg.Wait()
	close(watchdogDone)
}

// copyWithActivity is io.Copy with an activity stamp: it records time.Now (as
// UnixNano) into lastActivity on every successful read from src. The relay
// idle-watchdog reads this stamp to detect a silent bridge and force-close it.
// Buffer size matches io.Copy's internal 32KB.
func copyWithActivity(dst io.Writer, src io.Reader, lastActivity *atomic.Int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			nw, werr := dst.Write(buf[:nr])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return written, nil
			}
			return written, rerr
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

	// A relay forwarding a downstream client appends that client's origin after
	// the handshake; strip it before parsing the fixed fields.
	data, origin := splitTUNOrigin(data)
	if origin == "" {
		origin = tunnel.remoteAddr
	}

	// Parse TUN handshake: [localIP:4][mtu:2][version:1]
	// Version byte is optional (v1 clients send 6 bytes, v2 clients send 7 bytes)
	if len(data) < 6 {
		logger.Debug("H2 TUN handshake too short: %d bytes", len(data))
		sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
		return
	}

	// A relay forwards this client upstream and never touches its own TUN, so
	// only an exit needs the shared device here.
	if srvCtx == nil || (srvCtx.sharedTUN == nil && srvCtx.upstreamDialer == nil) {
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

	// Create H2 conn adapter (also marks this tunnel as TUN mode)
	h2Conn := &h2TunConn{
		framer:   framer,
		streamID: &tunnel.streamID, // Pointer so it can be updated
		cfg:      cfg,
		mu:       &tunnel.mu,
		done:     make(chan struct{}),
	}

	// sendPacketDown wraps one IP packet in the stego TUN framing the client
	// expects: [len:4][packet:N].
	sendPacketDown := func(pkt []byte) error {
		framed := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(framed[:4], uint32(len(pkt)))
		copy(framed[4:], pkt)

		tunnel.mu.Lock()
		sendStegoResponse(framer, tunnel.streamID, framed, cfg)
		tunnel.mu.Unlock()
		return nil
	}

	var clientIP, serverIP net.IP

	if srvCtx.upstreamDialer != nil {
		// Relay: forward to the upstream exit rather than terminating here.
		relaySink, upServerIP, upClientIP, err := dialRelayTUN(srvCtx, logger, data, origin, sendPacketDown)
		if err != nil {
			logger.Warn("H2 TUN relay: upstream dial failed: %v", err)
			sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
			return
		}
		clientIP, serverIP = upClientIP, upServerIP
		tunnel.sink = relaySink
	} else {
		// Allocate IP from pool
		if srvCtx.ipPool != nil {
			leaseKey := allocationKey(tunnel.clientID, origin)
			allocatedIP, err := srvCtx.ipPool.Allocate(leaseKey, requestedIP, "")
			if err != nil {
				logger.Error("Failed to allocate IP from pool: %v", err)
				sendStegoResponse(framer, tunnel.streamID, []byte{0x01}, cfg)
				return
			}
			clientIP = allocatedIP
			logger.Info("H2 TUN client: allocated IP=%s from pool (requested=%s, clientID=%s, origin=%s)", clientIP, requestedIP, tunnel.clientID, origin)
		} else {
			clientIP = requestedIP
			logger.Info("H2 TUN client: IP=%s (no pool)", clientIP)
		}
		serverIP = cfg.TunIP
		h2Conn.clientIP = clientIP

		// Register client with shared TUN using custom frame function
		// Note: For H2, we send directly in frameFunc, so it returns nil
		writer := srvCtx.sharedTUN.RegisterClient(clientIP, tunnel.clientID, h2Conn, func(pkt []byte) []byte {
			sendPacketDown(pkt)
			return nil // Already sent directly
		})
		tunnel.sharedTUNWriter = writer
		tunnel.sharedTUN = srvCtx.sharedTUN
		tunnel.sink = newLocalTUNSink(srvCtx.sharedTUN, writer, clientIP)
	}

	h2Conn.clientIP = clientIP
	tunnel.targetConn = h2Conn // Mark as TUN mode

	// Send success response: [status:1][serverIP:4][clientIP:4]
	resp := make([]byte, 9)
	resp[0] = 0x00 // Success
	copy(resp[1:5], serverIP.To4())
	copy(resp[5:9], clientIP.To4())
	sendStegoResponse(framer, tunnel.streamID, resp, cfg)

	logger.Info("H2 TUN mode established (client=%s, server=%s)", clientIP, serverIP)
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
	// TIRED magic anywhere in peeked data — catches all confusion types once enough
	// bytes are buffered
	if bytes.Contains(data, []byte("TIRED")) {
		return true
	}

	// DNS-over-TCP confusion: [len:2][txid:2][flags:0x0100...] — query with RD bit
	// len(data) >= 6 covers the 2-byte TCP length prefix + 4 bytes of DNS header
	if len(data) >= 6 && data[4] == 0x01 && data[5] == 0x00 {
		return true
	}

	// SSH banner — will need to read more to find TIRED marker
	if bytes.HasPrefix(data, []byte("SSH-2.0-")) {
		return true
	}

	// SMTP client EHLO — will need to read more to find TIRED marker
	if bytes.HasPrefix(data, []byte("EHLO ")) {
		return true
	}

	return false
}

// authClockSkewGraceMinutes bounds how many 1-minute buckets on either side of
// "now" verifyH2Auth/verifyMorphAuth accept, tolerating client/server clock
// drift. REALITY tolerates roughly +-5 minutes via its own 5-minute bucket
// scheme (internal/tls/reality_extension.go); matching that order of magnitude
// here fixes clients whose clock drifts by more than the original 1 minute.
const authClockSkewGraceMinutes int64 = 10

func verifyH2Auth(apiKey, requestID string, secret []byte) bool {
	// Decode hex values
	apiKeyBytes := decodeHex(apiKey)
	requestIDBytes := decodeHex(requestID)

	if len(apiKeyBytes) < 16 || len(requestIDBytes) < 16 {
		return false
	}

	// Reconstruct token
	receivedToken := append(apiKeyBytes[:16], requestIDBytes[:16]...)

	// Check timestamps in range [-authClockSkewGraceMinutes, +authClockSkewGraceMinutes]
	// to handle clock skew (widened from the original +-1 minute, which rejected
	// clients with more than ~60s of drift - see REALITY's +-5min bucket for the
	// same tolerance class).
	currentMinute := time.Now().Unix() / 60
	for offset := -authClockSkewGraceMinutes; offset <= authClockSkewGraceMinutes; offset++ {
		timestamp := make([]byte, 8)
		binary.BigEndian.PutUint64(timestamp, uint64(currentMinute+offset))

		h := hmac.New(sha256.New, secret)
		h.Write(timestamp)
		h.Write([]byte("http2-stego-auth"))
		expectedToken := h.Sum(nil)[:32]

		if hmac.Equal(receivedToken, expectedToken) {
			return true
		}
	}
	return false
}

func verifyMorphAuth(receivedToken, secret []byte) bool {
	if len(receivedToken) != 32 {
		return false
	}

	// Check timestamps in range [-authClockSkewGraceMinutes, +authClockSkewGraceMinutes]
	// to handle clock skew (widened from the original +-1 minute - prod measured
	// 509 FAILED/7 OK over 7 days, traced to clients with clock drift beyond the
	// old +-1min window; REALITY tolerates ~+-5min via its own bucket scheme).
	currentMinute := time.Now().Unix() / 60
	for offset := -authClockSkewGraceMinutes; offset <= authClockSkewGraceMinutes; offset++ {
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

	// Read upgrade request byte-exactly so no bytes past \r\n\r\n are
	// consumed into an internal buffer. bufio.NewReader would pre-fetch
	// past the empty line and lose those bytes when kTLS takes over.
	_, headers, err := readHTTPRequestExact(conn, 8192)
	if err != nil {
		logger.Error("WebSocket Padded: Failed to read upgrade request: %v", err)
		return
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

	// Auth + upgrade complete: hand the socket over to kTLS for the
	// frame-relay phase. readHTTPRequestExact stopped at \r\n\r\n with no
	// over-read, and the upgrade response was written synchronously to
	// the kernel send buffer.
	preSwap := conn
	conn = ktls.TryEnable(conn, "tired-ws")
	if conn != preSwap && srvCtx.registry != nil && clientID != "" {
		srvCtx.registry.SwapConn(clientID, preSwap, conn)
	}

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
	Origin     string // Peer host of the request that opened the session
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
func (pm *HTTPPollingManager) GetOrCreate(sessionID string, secret []byte, clientID, origin string) (*HTTPPollingSession, bool) {
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
		Origin:     origin,
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

// maxFromClientBuffered bounds fromClient so a stuck consumer (bad framing,
// dead target) can't grow it without limit under a chatty poller. Legitimate
// traffic never approaches this - it's individual TUN/SOCKS frames capped at
// 65535 bytes each, drained every ~10ms.
const maxFromClientBuffered = 4 * 1024 * 1024

// WriteFromClient writes data received from client
func (s *HTTPPollingSession) WriteFromClient(data []byte) {
	s.bufLock.Lock()
	defer s.bufLock.Unlock()
	if s.fromClient.Len()+len(data) > maxFromClientBuffered {
		// Consumer is stuck or the client is misbehaving; drop rather than
		// grow unbounded. The stuck-consumer case above already tears the
		// session down, so this is a backstop against similar bugs elsewhere.
		return
	}
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
			logger.Debug("HTTP Polling: Auth failed for existing session %s (token mismatch)", sessionID[:8])

			// Try registered clients to see if any match
			if srvCtx.registry != nil {
				clients := srvCtx.registry.ListClients()
				for _, c := range clients {
					secretBytes := []byte(c.Secret)
					if verifyPollingAuth(authToken, sessionID, secretBytes) {
						logger.Debug("HTTP Polling: Token would match client '%s'", c.Name)
					}
				}
			}
			if verifyPollingAuth(authToken, sessionID, srvCtx.cfg.Secret) {
				logger.Debug("HTTP Polling: Token would match global secret")
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
	sess, isNew := pollingManager.GetOrCreate(sessionID, usedSecret, clientID, originOf(conn.RemoteAddr()))

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

	// A relay forwards this client upstream and never touches its own TUN, so
	// only an exit needs the shared device here.
	if srvCtx == nil || (srvCtx.sharedTUN == nil && srvCtx.upstreamDialer == nil) {
		logger.Error("HTTP Polling TUN: Shared TUN not initialized")
		sess.WriteToClient([]byte{0x01}) // Failure
		pollingManager.Remove(sess.ID)
		return
	}

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

	// Create polling TUN connection adapter
	pollConn := &pollingTUNConn{
		sess:   sess,
		closed: make(chan struct{}),
	}

	var clientIP, serverIP net.IP
	var sink tunPacketSink

	if srvCtx.upstreamDialer != nil {
		// Relay: forward to the upstream exit rather than terminating here. This
		// is the path a client lands on after falling back to meek-style polling,
		// which used to strand it on the relay's own exit and address pool.
		relaySink, upServerIP, upClientIP, err := dialRelayTUN(srvCtx, logger, remainingData, sess.Origin,
			func(pkt []byte) error {
				_, err := pollConn.Write(pkt)
				return err
			})
		if err != nil {
			logger.Warn("HTTP Polling TUN relay: upstream dial failed: %v", err)
			sess.WriteToClient([]byte{0x01}) // Failure
			pollingManager.Remove(sess.ID)
			return
		}
		sink, serverIP, clientIP = relaySink, upServerIP, upClientIP
		defer func() {
			relaySink.Close()
			pollingManager.Remove(sess.ID)
			logger.Info("HTTP Polling TUN relay client disconnected: %s (clientID=%s)", clientIP, clientID)
		}()
	} else {
		// Allocate IP from pool
		if srvCtx.ipPool != nil {
			allocatedIP, err := srvCtx.ipPool.Allocate(allocationKey(clientID, sess.Origin), requestedIP, "")
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
		serverIP = cfg.TunIP

		// Register client with shared TUN using custom framer for polling
		// Polling uses [length:4][packet:N] framing
		writer := srvCtx.sharedTUN.RegisterClient(clientIP, clientID, pollConn, nil)
		localSink := newLocalTUNSink(srvCtx.sharedTUN, writer, clientIP)
		sink = localSink
		defer func() {
			localSink.Close()
			pollingManager.Remove(sess.ID)
			logger.Info("HTTP Polling TUN client disconnected: %s (clientID=%s)", clientIP, clientID)
		}()
	}

	// Send success response: [status:1][serverIP:4][clientIP:4]
	resp := make([]byte, 9)
	resp[0] = 0x00 // Success
	copy(resp[1:5], serverIP.To4())
	copy(resp[5:9], clientIP.To4())
	sess.WriteToClient(resp)

	logger.Info("HTTP Polling TUN mode established (client=%s, server=%s)", clientIP, serverIP)

	// Main loop: Read from polling buffers -> TUN
	// TUN -> Client is handled by SharedTUN packet dispatcher via pollConn.Write()
	lenBuf := make([]byte, 4)
	var packetsUp int64

	for {
		select {
		case <-sink.Done():
			logger.Debug("HTTP Polling TUN loop stopping (client replaced or upstream gone)")
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

			// A length prefix over the max possible IP packet size is corrupt
			// framing, not a partial read - the stream can never resync past it.
			// Putting it back (like the incomplete-data case below) would just
			// re-parse the same leading 4 bytes forever while every subsequent
			// poll's body piles up behind it, unbounded. Tear the session down.
			if pktLen > 65535 {
				logger.Debug("HTTP Polling TUN: invalid packet length %d, closing session", pktLen)
				sess.Close()
				pollingManager.Remove(sess.ID)
				return
			}

			if int(pktLen)+4 > len(data) {
				// Genuinely incomplete - wait for the rest on the next poll.
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

			if err := sink.WritePacket(ipPkt); err != nil {
				logger.Debug("HTTP Polling TUN: sink write failed: %v", err)
				continue
			}
			packetsUp++
			sink.UpdateActivity()
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
