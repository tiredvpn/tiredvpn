package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" // pprof for profiling
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/server"
)

// version is overridden at link time via -ldflags="-X main.version=$VERSION".
// "dev" indicates an untagged local build.
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Ignore SIGPIPE to prevent crashes when writing to closed sockets
	// (e.g., Android VpnService closing control socket)
	signal.Ignore(syscall.SIGPIPE)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "admin":
		runAdmin(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Printf("tiredvpn %s (built %s)\n", version, buildTime)
	case "help", "-help", "--help", "-h":
		printUsage()
	default:
		// For backwards compatibility, treat as client mode if first arg looks like a flag
		if len(os.Args[1]) > 0 && os.Args[1][0] == '-' {
			runClient(os.Args[1:])
		} else {
			fmt.Printf("Unknown command: %s\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Println(`tiredvpn - DPI-resistant VPN

Usage:
  tiredvpn <command> [options]

Commands:
  server    Run VPN server (exit node)
  client    Run VPN client (SOCKS5 proxy or TUN mode)
  admin     Manage clients (add, list, delete, qr)
  version   Show version
  help      Show this help

Examples:

  Server (single-client):
    tiredvpn server -listen :443 -cert server.crt -key server.key -secret <secret>

  Server (multi-client with Redis):
    tiredvpn server -listen :443 -cert server.crt -key server.key -redis localhost:6379 -api-addr :8080

  Server (dual-stack IPv4 + IPv6):
    tiredvpn server -listen :443 -listen-v6 [::]:995 -dual-stack -cert server.crt -key server.key

  Client (SOCKS5 proxy):
    tiredvpn client -server host:443 -secret <secret> -listen 127.0.0.1:1080

  Client (TUN mode - full VPN):
    sudo tiredvpn client -server host:443 -secret <secret> -tun -tun-routes 0.0.0.0/0

  Client (IPv6 preferred):
    tiredvpn client -server host:443 -server-v6 [2001:db8::1]:995 -prefer-ipv6 -secret <secret>

  Admin (add client):
    tiredvpn admin add -api http://127.0.0.1:8080 -server vpn.example.com:443

  Admin (generate QR code):
    tiredvpn admin qr -server vpn.example.com:443 -secret <secret>

For detailed options, run:
  tiredvpn server -help
  tiredvpn client -help
  tiredvpn admin -help`)
}

func printServerHelp() {
	fmt.Println(`tiredvpn server - VPN exit node

Usage:
  tiredvpn server [options]

CORE OPTIONS:
  -listen string
        Listen address for IPv4 (default ":443")
  -listen-v6 string
        IPv6 listen address (default "[::]:995")
  -cert string
        TLS certificate file (default "server.crt")
  -key string
        TLS key file (default "server.key")
  -secret string
        Shared secret for authentication (single-client mode)
  -debug
        Enable debug logging

IPv6 OPTIONS:
  -enable-v6
        Enable IPv6 listener (default true)
  -dual-stack
        Listen on both IPv4 and IPv6 (default true)

MULTI-CLIENT OPTIONS:
  -redis string
        Redis address for multi-client mode (e.g., localhost:6379)
  -api-addr string
        HTTP API address for client management (default "127.0.0.1:8080")
  -ip-pool string
        IP pool CIDR for TUN clients (e.g., '10.8.0.0/24')
  -ip-pool-lease duration
        IP lease duration (default 24h)

PORT HOPPING OPTIONS:
  -port-range string
        Port or range for multi-port listening (e.g., '995' or '47000-47100')
  -port-range-max int
        Maximum number of ports to listen on when using range (default 50)
  -port-hop-interval duration
        Recommended hop interval for clients (default 1m0s)
  -port-hop-strategy string
        Recommended hop strategy for clients: random, sequential, fibonacci (default "random")
  -port-hop-seed string
        Optional seed for deterministic hopping

QUIC OPTIONS:
  -no-quic
        Disable QUIC listener (UDP)
  -quic-listen string
        QUIC listen address (default: same as -listen but UDP)
  -quic-sni-reassembly
        Enable QUIC SNI fragment reassembly (for clients using -quic-sni-frag)

MULTI-HOP OPTIONS:
  -upstream string
        Upstream TiredVPN server for multi-hop (e.g., exit-server.com:443)
  -upstream-secret string
        Secret for upstream authentication

ADVANCED OPTIONS:
  -fake-root string
        Fake website root directory (default "./www")
  -tun-ip string
        TUN interface IP address for VPN server (default "10.8.0.1")
  -tun-name string
        TUN interface name (default "tiredvpn0")
  -pprof string
        Enable pprof profiling on address (e.g., :6060)
  -version
        Show version`)
}

func printClientHelp() {
	fmt.Println(`tiredvpn client - VPN client

Usage:
  tiredvpn client [options]

CORE OPTIONS:
  -server string
        Remote server address (host:port) [REQUIRED]
  -secret string
        Shared secret for authentication [REQUIRED]
  -listen string
        Local proxy address (SOCKS5/HTTP auto-detect) (default "127.0.0.1:1080")
  -http-listen string
        Separate HTTP proxy address (optional)
  -strategy string
        Force specific strategy (use -list to see available)
  -list
        List available strategies and exit
  -debug
        Enable debug logging

IPv6 TRANSPORT:
  -server-v6 string
        Server IPv6 address (e.g., [2001:db8::100]:995)
  -prefer-ipv6
        Prefer IPv6 transport if available (default true)
  -fallback-v4
        Fallback to IPv4 if IPv6 fails (default true)

TUN MODE (Full VPN):
  -tun
        Enable TUN mode (full VPN with system routes)
  -tun-name string
        TUN device name (default "tiredvpn0")
  -tun-ip string
        Local TUN IP address (default "10.8.0.2")
  -tun-peer-ip string
        Remote TUN IP address (default "10.8.0.1")
  -tun-mtu int
        TUN device MTU (default 1280)
  -tun-routes string
        Routes to add (comma-separated, e.g. '0.0.0.0/0' for full tunnel)
  -tun-fd int
        Use existing TUN file descriptor - for Android VpnService (default -1)

ANDROID INTEGRATION:
  -android
        Running on Android (disables os/exec, ICMP checks)
  -protect-path string
        Unix socket path for Android VpnService protect() calls
  -control-socket string
        Control socket path for Android integration (2-phase connect)

PORT HOPPING:
  -port-hop
        Enable port hopping (DPI evasion)
  -port-hop-start int
        Port range start (default 47000)
  -port-hop-end int
        Port range end (default 65535)
  -port-hop-interval duration
        Hop interval with jitter (default 1m0s)
  -port-hop-strategy string
        Hop strategy: random, sequential, fibonacci (default "random")
  -port-hop-seed string
        Seed for deterministic hopping (optional)

ADVANCED EVASION:
  -quic
        Enable QUIC transport (highest priority, hardest to block)
  -quic-port int
        QUIC server port (default 443)
  -quic-sni-frag
        Enable QUIC SNI fragmentation for GFW bypass
  -ech
        Enable ECH (Encrypted Client Hello) to hide SNI from DPI
  -ech-config string
        ECHConfigList in base64 (from server)
  -ech-public-name string
        Outer SNI visible to network when using ECH (default "cloudflare-ech.com")
  -pq
        Enable post-quantum crypto (ML-KEM-768 + ML-DSA-65)
  -pq-server-key string
        Server's Kyber768 public key in base64
  -rtt-masking
        Enable RTT masking (hides proxy timing signature)
  -rtt-profile string
        RTT profile: moscow-yandex, moscow-vk, regional-russia, siberia, cdn, beijing-baidu, tehran-aparat (default "moscow-yandex")
  -cover string
        Cover host for traffic mimicry (default "api.googleapis.com")

ADAPTIVE STRATEGY:
  -reprobe-interval duration
        How often to re-probe strategies (default 5m0s)
  -circuit-threshold int
        Failures before circuit opens (default 3)
  -circuit-reset duration
        Time before circuit tries half-open (default 5m0s)
  -fallback
        Enable mid-session fallback to other strategies (default true)

BENCHMARKING:
  -benchmark
        Run strategy benchmark (latency test)
  -benchmark-full
        Run FULL strategy benchmark (HTTP, latency, speed, IP change)
  -benchmark-all
        Run EXHAUSTIVE benchmark: all strategies × all RTT profiles (78 combinations)

MONITORING:
  -api-addr string
        API/Metrics HTTP endpoint (e.g., :8080)
  -pprof string
        Enable pprof profiling on address (e.g., :6060)
  -version
        Show version`)
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.Usage = printServerHelp

	cfg := &server.Config{}

	configPath := fs.String("config", "", "Path to TOML config (overrides defaults; CLI flags override TOML)")

	fs.StringVar(&cfg.ListenAddr, "listen", ":443", "Listen address")
	fs.StringVar(&cfg.CertFile, "cert", "server.crt", "TLS certificate file")
	fs.StringVar(&cfg.KeyFile, "key", "server.key", "TLS key file")
	secret := fs.String("secret", "", "Shared secret for authentication (single-client mode)")
	fs.StringVar(&cfg.FakeWebRoot, "fake-root", "./www", "Fake website root directory")
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	tunIP := fs.String("tun-ip", "10.8.0.1", "TUN interface IP address for VPN server")
	fs.StringVar(&cfg.TunName, "tun-name", "tiredvpn0", "TUN interface name")
	fs.StringVar(&cfg.RedisAddr, "redis", "", "Redis address for multi-client mode (e.g., localhost:6379)")
	fs.StringVar(&cfg.APIAddr, "api-addr", "127.0.0.1:8080", "HTTP API address for client management")
	fs.StringVar(&cfg.UpstreamAddr, "upstream", "", "Upstream TiredVPN server for multi-hop (e.g., exit-server.com:443)")
	fs.StringVar(&cfg.UpstreamSecret, "upstream-secret", "", "Secret for upstream authentication")

	// Port hopping flags
	fs.StringVar(&cfg.PortRange, "port-range", "", "Port or range for multi-port listening (e.g., '995' or '47000-47100')")
	fs.IntVar(&cfg.PortRangeMaxPorts, "port-range-max", 50, "Maximum number of ports to listen on when using range")
	portHopInterval := fs.Duration("port-hop-interval", 60*time.Second, "Recommended hop interval for clients (transmitted during handshake)")
	fs.StringVar(&cfg.PortHopStrategy, "port-hop-strategy", "random", "Recommended hop strategy for clients: random, sequential, fibonacci")
	fs.StringVar(&cfg.PortHopSeed, "port-hop-seed", "", "Optional seed for deterministic hopping (transmitted to clients)")

	// Profiling
	pprofAddr := fs.String("pprof", "", "Enable pprof profiling on address (e.g., :6060)")

	// QUIC flags (enabled by default)
	noQUIC := fs.Bool("no-quic", false, "Disable QUIC listener (UDP)")
	fs.StringVar(&cfg.QUICListenAddr, "quic-listen", "", "QUIC listen address (default: same as -listen but UDP)")
	fs.BoolVar(&cfg.QUICSNIFragReassembly, "quic-sni-reassembly", false, "Enable QUIC SNI fragment reassembly (for clients using -quic-sni-frag)")

	// IP Pool flags for TUN mode
	fs.StringVar(&cfg.IPPoolNetwork, "ip-pool", "", "IP pool CIDR for TUN clients (e.g., '10.8.0.0/24'). Enables auto IP assignment.")
	ipPoolLease := fs.Duration("ip-pool-lease", 24*time.Hour, "IP lease duration (0 = permanent)")

	// IPv6 Transport flags
	fs.StringVar(&cfg.ListenAddrV6, "listen-v6", "[::]:995", "IPv6 listen address")
	fs.BoolVar(&cfg.EnableIPv6, "enable-v6", true, "Enable IPv6 listener")
	fs.BoolVar(&cfg.DualStack, "dual-stack", true, "Listen on both IPv4 and IPv6")

	showVersion := fs.Bool("version", false, "Show version")

	fs.Parse(args)

	if *showVersion {
		fmt.Printf("tiredvpn server %s\n", version)
		os.Exit(0)
	}

	cfg.TunIP = net.ParseIP(*tunIP).To4()
	if cfg.TunIP == nil {
		fmt.Printf("Error: Invalid TUN IP address: %s\n", *tunIP)
		os.Exit(1)
	}

	cfg.Secret = []byte(*secret)
	cfg.QUICEnabled = !*noQUIC // QUIC enabled by default
	cfg.IPPoolLeaseTime = *ipPoolLease
	cfg.PortHopInterval = *portHopInterval

	if err := applyServerTOMLConfig(cfg, *configPath, fs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Start pprof server if enabled
	if *pprofAddr != "" {
		go func() {
			fmt.Printf("pprof listening on %s\n", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				fmt.Printf("pprof error: %v\n", err)
			}
		}()
	}

	if err := server.Run(cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	fs.Usage = printClientHelp

	cfg := &client.Config{}

	configPath := fs.String("config", "", "Path to TOML config (overrides defaults; CLI flags override TOML)")

	fs.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:1080", "Local proxy address (SOCKS5/HTTP auto-detect)")
	fs.StringVar(&cfg.HTTPListenAddr, "http-listen", "", "Separate HTTP proxy address (optional)")
	fs.StringVar(&cfg.ServerAddr, "server", "", "Remote server address (host:port)")
	fs.StringVar(&cfg.Secret, "secret", "", "Shared secret for authentication")
	fs.StringVar(&cfg.CoverHost, "cover", "api.googleapis.com", "Cover host for traffic mimicry")
	fs.StringVar(&cfg.StrategyName, "strategy", "", "Force specific strategy (http2_stego, morph, confusion, antiprobe, quic, http_polling)")
	fs.BoolVar(&cfg.ListStrategies, "list", false, "List available strategies and exit")
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")

	// IPv6 Transport
	fs.StringVar(&cfg.ServerAddrV6, "server-v6", "", "Server IPv6 address (e.g., [2001:db8::100]:995)")
	fs.BoolVar(&cfg.PreferIPv6, "prefer-ipv6", true, "Prefer IPv6 transport if available")
	fs.BoolVar(&cfg.FallbackToV4, "fallback-v4", true, "Fallback to IPv4 if IPv6 fails")

	// TUN mode flags
	fs.BoolVar(&cfg.TunMode, "tun", false, "Enable TUN mode (full VPN with system routes)")
	fs.StringVar(&cfg.TunName, "tun-name", "tiredvpn0", "TUN device name")
	fs.StringVar(&cfg.TunIP, "tun-ip", "10.8.0.2", "Local TUN IP address")
	fs.StringVar(&cfg.TunPeerIP, "tun-peer-ip", "10.8.0.1", "Remote TUN IP address (server's TUN IP)")
	fs.IntVar(&cfg.TunMTU, "tun-mtu", 1280, "TUN device MTU")
	fs.StringVar(&cfg.TunRoutes, "tun-routes", "", "Routes to add (comma-separated, e.g. '0.0.0.0/0' for full tunnel)")

	// Android VpnService flags
	fs.IntVar(&cfg.TunFd, "tun-fd", -1, "Use existing TUN file descriptor (for Android VpnService)")
	fs.StringVar(&cfg.ProtectPath, "protect-path", "", "Unix socket path for Android VpnService protect() calls")
	fs.StringVar(&cfg.ControlSocket, "control-socket", "", "Control socket path for Android integration (2-phase connect)")
	fs.BoolVar(&cfg.AndroidMode, "android", false, "Running on Android (disables os/exec, ICMP checks)")

	// Benchmark flags
	fs.BoolVar(&cfg.BenchmarkMode, "benchmark", false, "Run strategy benchmark (latency test)")
	fs.BoolVar(&cfg.FullBenchmarkMode, "benchmark-full", false, "Run FULL strategy benchmark (HTTP, latency, speed, IP change)")
	fs.BoolVar(&cfg.BenchmarkAllCombos, "benchmark-all", false, "Run EXHAUSTIVE benchmark: all strategies × all RTT profiles (78 combinations)")

	// Adaptive strategy flags
	reprobeInterval := fs.Duration("reprobe-interval", 5*time.Minute, "How often to re-probe strategies")
	fs.IntVar(&cfg.CircuitThreshold, "circuit-threshold", 3, "Failures before circuit opens")
	circuitResetTime := fs.Duration("circuit-reset", 5*time.Minute, "Time before circuit tries half-open")
	fs.BoolVar(&cfg.EnableFallback, "fallback", true, "Enable mid-session fallback to other strategies")

	// QUIC transport flags
	fs.BoolVar(&cfg.QUICEnabled, "quic", false, "Enable QUIC transport (highest priority, hardest to block)")
	fs.IntVar(&cfg.QUICPort, "quic-port", 443, "QUIC server port")

	// RTT Masking flags
	fs.BoolVar(&cfg.RTTMaskingEnabled, "rtt-masking", false, "Enable RTT masking (hides proxy timing signature)")
	fs.StringVar(&cfg.RTTProfile, "rtt-profile", "moscow-yandex", "RTT profile (moscow-yandex, moscow-vk, regional-russia, siberia, cdn, beijing-baidu, tehran-aparat)")

	// ECH (Encrypted Client Hello) flags - hide SNI from DPI
	fs.BoolVar(&cfg.ECHEnabled, "ech", false, "Enable ECH (Encrypted Client Hello) to hide SNI from DPI")
	fs.StringVar(&cfg.ECHConfigB64, "ech-config", "", "ECHConfigList in base64 (from server)")
	fs.StringVar(&cfg.ECHPublicName, "ech-public-name", "cloudflare-ech.com", "Outer SNI visible to network when using ECH")

	// QUIC SNI fragmentation for GFW bypass
	fs.BoolVar(&cfg.QUICSNIFragEnabled, "quic-sni-frag", false, "Enable QUIC SNI fragmentation for GFW bypass")

	// Post-Quantum crypto flags
	fs.BoolVar(&cfg.PQEnabled, "pq", false, "Enable post-quantum crypto (ML-KEM-768 + ML-DSA-65)")
	fs.StringVar(&cfg.PQServerKemPubB64, "pq-server-key", "", "Server's Kyber768 public key in base64")

	pprofAddr := fs.String("pprof", "", "Enable pprof profiling on address (e.g., :6060)")

	// API/Metrics
	apiAddr := fs.String("api-addr", "", "API/Metrics HTTP endpoint (e.g., :8080)")

	// Port hopping for DPI evasion
	fs.BoolVar(&cfg.PortHoppingEnabled, "port-hop", false, "Enable port hopping (DPI evasion)")
	fs.IntVar(&cfg.PortHopRangeStart, "port-hop-start", 47000, "Port range start")
	fs.IntVar(&cfg.PortHopRangeEnd, "port-hop-end", 65535, "Port range end")
	portHopInterval := fs.Duration("port-hop-interval", 60*time.Second, "Hop interval with jitter")
	fs.StringVar(&cfg.PortHopStrategy, "port-hop-strategy", "random", "Hop strategy: random, sequential, fibonacci")
	fs.StringVar(&cfg.PortHopSeed, "port-hop-seed", "", "Seed for deterministic hopping (optional)")

	showVersion := fs.Bool("version", false, "Show version")

	fs.Parse(args)

	// Apply duration values after parse
	cfg.ReprobeInterval = *reprobeInterval
	cfg.CircuitResetTime = *circuitResetTime
	cfg.APIAddr = *apiAddr
	cfg.PortHopInterval = *portHopInterval

	if err := applyClientTOMLConfig(cfg, *configPath, fs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("tiredvpn client %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Start pprof server if enabled
	if *pprofAddr != "" {
		go func() {
			fmt.Printf("pprof client listening on %s\n", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				fmt.Printf("pprof client error: %v\n", err)
			}
		}()
	}

	if err := client.Run(cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// runAdmin handles admin commands for client management
func runAdmin(args []string) {
	if len(args) < 1 {
		printAdminUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		adminAdd(args[1:])
	case "list":
		adminList(args[1:])
	case "delete":
		adminDelete(args[1:])
	case "qr":
		adminQR(args[1:])
	case "help", "-help", "--help", "-h":
		printAdminUsage()
	default:
		fmt.Printf("Unknown admin command: %s\n", args[0])
		printAdminUsage()
		os.Exit(1)
	}
}

func printAdminUsage() {
	fmt.Println(`tiredvpn admin - Client management

Usage:
  tiredvpn admin <command> [options]

Commands:
  add       Add a new client
  list      List all clients
  delete    Delete a client
  qr        Generate QR code for connection string

Add client:
  tiredvpn admin add -api http://127.0.0.1:8080 -server vpn.example.com:443 [options]
    -api        API endpoint (required)
    -server     Server address for connection string (required)
    -id         Client ID (default: auto-generated)
    -secret     Client secret (default: auto-generated)
    -quic       Enable QUIC in connection string (default: true)
    -quic-port  QUIC port (default: 443)

List clients:
  tiredvpn admin list -api http://127.0.0.1:8080

Delete client:
  tiredvpn admin delete -api http://127.0.0.1:8080 -id <client_id>

Generate QR:
  tiredvpn admin qr -server vpn.example.com:443 -secret <secret> [options]
    -server     Server address (required)
    -secret     Client secret (required)
    -quic       Enable QUIC (default: true)
    -quic-port  QUIC port (default: 443)
    -strategy   Strategy (default: auto)
    -cover      Cover host (default: api.googleapis.com)`)
}

// generateSecret generates a random hex secret
func generateSecret(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate secret: %v", err))
	}
	return hex.EncodeToString(b)
}

// generateClientID generates a random client ID
func generateClientID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate client ID: %v", err))
	}
	return "client-" + hex.EncodeToString(b)
}

// buildConnectionString builds a tired:// connection string
func buildConnectionString(serverAddr, secret string, quic bool, quicPort int, strategy, cover string) string {
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("strategy", strategy)
	params.Set("quic", fmt.Sprintf("%t", quic))
	params.Set("quicPort", fmt.Sprintf("%d", quicPort))
	params.Set("cover", cover)
	params.Set("rtt", "false")
	params.Set("rttProfile", "moscow-yandex")
	params.Set("fallback", "true")

	return fmt.Sprintf("tired://%s?%s", serverAddr, params.Encode())
}

// printQRCode prints a QR code to terminal using Unicode block characters
func printQRCode(data string) {
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		fmt.Printf("\nError generating QR: %v\n", err)
		return
	}

	// Convert to terminal-friendly format
	bitmap := qr.Bitmap()
	fmt.Println("\n  QR Code (scan with TiredVPN app):")
	fmt.Println()

	// Print QR using Unicode block characters (2 rows per line)
	for y := 0; y < len(bitmap); y += 2 {
		fmt.Print("  ")
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x]
			}

			// Use Unicode block characters for compact display
			// top=black, bottom=black: full block
			// top=black, bottom=white: upper half
			// top=white, bottom=black: lower half
			// top=white, bottom=white: space
			if top && bottom {
				fmt.Print("█")
			} else if top && !bottom {
				fmt.Print("▀")
			} else if !top && bottom {
				fmt.Print("▄")
			} else {
				fmt.Print(" ")
			}
		}
		fmt.Println()
	}
	fmt.Println()
}

func adminAdd(args []string) {
	fs := flag.NewFlagSet("admin add", flag.ExitOnError)

	apiAddr := fs.String("api", "", "API endpoint (e.g., http://127.0.0.1:8080)")
	serverAddr := fs.String("server", "", "Server address for connection string")
	clientID := fs.String("id", "", "Client ID (auto-generated if empty)")
	clientSecret := fs.String("secret", "", "Client secret (auto-generated if empty)")
	quic := fs.Bool("quic", true, "Enable QUIC")
	quicPort := fs.Int("quic-port", 443, "QUIC port")
	strategy := fs.String("strategy", "auto", "Strategy")
	cover := fs.String("cover", "api.googleapis.com", "Cover host")

	fs.Parse(args)

	if *apiAddr == "" || *serverAddr == "" {
		fmt.Println("Error: -api and -server are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Auto-generate if not provided
	if *clientID == "" {
		*clientID = generateClientID()
	}
	if *clientSecret == "" {
		*clientSecret = generateSecret(32)
	}

	// Call API to add client
	apiURL := strings.TrimSuffix(*apiAddr, "/") + "/api/clients"

	payload := map[string]string{
		"id":     *clientID,
		"secret": *clientSecret,
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		fmt.Printf("Error calling API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		fmt.Printf("API error: %s\n", resp.Status)
		os.Exit(1)
	}

	// Build connection string
	connStr := buildConnectionString(*serverAddr, *clientSecret, *quic, *quicPort, *strategy, *cover)

	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    CLIENT ADDED SUCCESSFULLY                   ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Client ID:  %-50s║\n", *clientID)
	fmt.Printf("║  Secret:     %-50s║\n", *clientSecret)
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Connection String:                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n%s\n", connStr)

	printQRCode(connStr)
}

func adminList(args []string) {
	fs := flag.NewFlagSet("admin list", flag.ExitOnError)

	apiAddr := fs.String("api", "", "API endpoint")

	fs.Parse(args)

	if *apiAddr == "" {
		fmt.Println("Error: -api is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	apiURL := strings.TrimSuffix(*apiAddr, "/") + "/api/clients"

	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Printf("Error calling API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var clients []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         CLIENT LIST                            ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")

	if len(clients) == 0 {
		fmt.Println("║  No clients found                                              ║")
	} else {
		for _, c := range clients {
			id := fmt.Sprintf("%v", c["id"])
			fmt.Printf("║  %-62s║\n", id)
		}
	}

	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
}

func adminDelete(args []string) {
	fs := flag.NewFlagSet("admin delete", flag.ExitOnError)

	apiAddr := fs.String("api", "", "API endpoint")
	clientID := fs.String("id", "", "Client ID to delete")

	fs.Parse(args)

	if *apiAddr == "" || *clientID == "" {
		fmt.Println("Error: -api and -id are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	apiURL := strings.TrimSuffix(*apiAddr, "/") + "/api/clients/" + *clientID

	req, _ := http.NewRequest(http.MethodDelete, apiURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error calling API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		fmt.Printf("Client '%s' deleted successfully\n", *clientID)
	} else {
		fmt.Printf("API error: %s\n", resp.Status)
		os.Exit(1)
	}
}

func adminQR(args []string) {
	fs := flag.NewFlagSet("admin qr", flag.ExitOnError)

	serverAddr := fs.String("server", "", "Server address")
	secret := fs.String("secret", "", "Client secret")
	quic := fs.Bool("quic", true, "Enable QUIC")
	quicPort := fs.Int("quic-port", 443, "QUIC port")
	strategy := fs.String("strategy", "auto", "Strategy")
	cover := fs.String("cover", "api.googleapis.com", "Cover host")

	fs.Parse(args)

	if *serverAddr == "" || *secret == "" {
		fmt.Println("Error: -server and -secret are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	connStr := buildConnectionString(*serverAddr, *secret, *quic, *quicPort, *strategy, *cover)

	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      CONNECTION STRING                         ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n%s\n", connStr)

	printQRCode(connStr)
}
