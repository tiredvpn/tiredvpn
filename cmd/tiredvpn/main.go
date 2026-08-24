package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// version is overridden at link time via -ldflags="-X main.version=$VERSION".
// "dev" indicates an untagged local build.
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Handle -version/--version/version FIRST, before any other work. This must
	// not depend on flag parsing, network, TUN or kTLS state: a plain
	// `tiredvpn -version` (or `tiredvpn client -version`) has to print the build
	// version and exit cleanly even on hosts where later initialization would
	// fail. Printing here and os.Exit(0) keeps it from ever reaching code that
	// could crash.
	for _, arg := range os.Args[1:] {
		if arg == "version" || arg == "-version" || arg == "--version" {
			fmt.Printf("tiredvpn %s (built %s)\n", version, buildTime)
			os.Exit(0)
		}
	}

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
	case "reality-keygen":
		runREALITYKeygen()
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

  reality-keygen  Generate the server's static REALITY key pair
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

ICMP TUNNEL:
  -enable-icmp
        Enable ICMP tunnel listener (requires CAP_NET_RAW)

REALITY OPTIONS:
  -reality-cover-domain string
        Operator-set hostname to transparently proxy unauthorized REALITY probes to (empty = drop)
  -reality-b1
        Accept the B1 transport: real TLS 1.3 with auth in session_id. Needs -reality-private-key.
  -reality-private-key string
        Server's static X25519 key, base64 (or TIREDVPN_REALITY_PRIVATE_KEY). Generate with: tiredvpn reality-keygen
  -reality-legacy
        Accept the legacy transport, credentials in padding extension 0x0015 (default true)
  -reality-max-time-diff int
        Client clock skew tolerated by B1 auth, seconds; 0 = do not check (default 300)
  -reality-min-client-ver string
        Lowest client version B1 accepts, X.Y.Z (empty = do not check)
  -reality-mirror string
        Mirror the handshake to the real donor: off, adaptive, always. Only off is implemented until B1.5. (default "off")
  -reality-require-data-v2
        Reject REALITY clients still on the v1 data layer (turn on after every client is upgraded)

ADVANCED OPTIONS:
  -fake-root string
        Fake website root directory (default "./www")
  -tun-ip string
        TUN interface IP address for VPN server (default "10.8.0.1")
  -tun-name string
        TUN interface name (default "tiredvpn0")
  -tun-mtu int
        TUN interface MTU, 1280-9000 (default 1280)
  -pprof string
        Enable pprof profiling on address (e.g., :6060)
  -config string
        Path to TOML config (overrides defaults; CLI flags override TOML)
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
        QUIC server port (default 8443)
  -quic-sni-frag
        Enable QUIC SNI fragmentation for GFW bypass
  -tls-fingerprint string
        uTLS browser profile for ClientHello (default "firefox")
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
  -reality-require-data-v2
        Refuse REALITY servers still on the v1 data layer instead of falling back
  -reality-server-pubkey string
        Server's static REALITY public key, base64. Set it to speak the B1 transport; empty uses the legacy one.

ICMP TUNNEL (backup transport):
  -icmp-tunnel
        Enable ICMP tunnel backup strategy (requires CAP_NET_RAW; server must run with -enable-icmp)

ADAPTIVE STRATEGY:
  -reprobe-interval duration
        How often to re-probe strategies (default 5m0s)
  -circuit-threshold int
        Failures before circuit opens (default 3)
  -circuit-reset duration
        Time before circuit tries half-open (default 5m0s)
  -fallback
        Enable mid-session fallback to other strategies (default true)

TRAFFIC SHAPING (morph strategies):
  -shaper string
        Traffic shaper preset: youtube_streaming, chrome_browsing, imap_sync, random_per_session
  -shaper-seed int
        Seed for deterministic shaper (0 = random)
  -config string
        Path to TOML config (overrides defaults; CLI flags override TOML)

BENCHMARKING:
  -benchmark
        Run strategy benchmark (latency test)
  -benchmark-json
        Run strategy benchmark, output results as JSON (for automation); logs go to stderr
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

// serverFlagOpts holds the server flags that need post-parse processing because
// they don't live directly on server.Config (env fallbacks, unit conversion,
// derived fields).
type serverFlagOpts struct {
	configPath      *string
	secret          *string
	tunIP           *string
	pprofAddr       *string
	portHopInterval *time.Duration
	ipPoolLease     *time.Duration
	noQUIC          *bool
	showVersion     *bool
}

// registerClientREALITYFlags binds the client-side REALITY flags.
//
// Split out for the same reason registerServerFlags exists: a config field
// bound to no flag is dead and nothing notices. That matters more than usual
// here, because the B1 fields land before the code that reads them - until the
// transport itself is written, "does nothing" is indistinguishable from "never
// wired up". It also gives streams A and B somewhere to add client flags
// without editing runClient, which everyone shares.
func registerClientREALITYFlags(fs *flag.FlagSet, cfg *client.Config) {
	fs.StringVar(&cfg.REALITYServerPubKey, "reality-server-pubkey", "", "Server's static REALITY public key, base64. Set it to speak the B1 transport; empty uses the legacy one. No probing, no downgrade on error.")
}

// registerServerFlags binds every server flag onto fs and cfg. It is split out
// of runServer so the flag surface is unit-testable (guards against config keys
// silently going dead, e.g. -reality-cover-domain).
func registerServerFlags(fs *flag.FlagSet, cfg *server.Config) *serverFlagOpts {
	opts := &serverFlagOpts{}

	opts.configPath = fs.String("config", "", "Path to TOML config (overrides defaults; CLI flags override TOML)")

	fs.StringVar(&cfg.ListenAddr, "listen", ":443", "Listen address")
	fs.StringVar(&cfg.CertFile, "cert", "server.crt", "TLS certificate file")
	fs.StringVar(&cfg.KeyFile, "key", "server.key", "TLS key file")
	opts.secret = fs.String("secret", "", "Shared secret for authentication (single-client mode)")
	fs.StringVar(&cfg.FakeWebRoot, "fake-root", "./www", "Fake website root directory")
	// Operator-set hostname that unauthorized REALITY probes are transparently
	// proxied to (see reality.go handleREALITYUnauthorized). Empty = silently
	// drop. Never sourced from the client's SNI, so there is no SSRF via a
	// client-controlled hostname.
	fs.StringVar(&cfg.REALITYCoverDomain, "reality-cover-domain", "", "Hostname to transparently proxy unauthorized REALITY probes to (operator-set, e.g. 'www.microsoft.com'); empty = silently drop. Never derived from client SNI.")
	// Transition switch for the data-layer rewrite: leave off while old clients
	// are still around, turn on afterwards to remove the v1 downgrade path.
	fs.BoolVar(&cfg.REALITYRequireDataV2, "reality-require-data-v2", false, "Reject REALITY clients that do not negotiate the v2 data layer (per-connection keys + AEAD). Turn on only after every client is upgraded.")
	// B1 transport. -reality-b1 defaults to off while the B1 handler is still
	// a stub: with it on, a server without a static key refuses to start, and
	// that is not a thing to hand every existing deployment in exchange for a
	// code path that does nothing yet. Flip the default in the release that
	// ships the handler (task 005).
	fs.StringVar(&cfg.REALITYPrivateKey, "reality-private-key", "", "Server's static X25519 key for REALITY B1, base64 (falls back to TIREDVPN_REALITY_PRIVATE_KEY). Generate with `tiredvpn reality-keygen`. Required with -reality-b1.")
	fs.BoolVar(&cfg.REALITYB1Enabled, "reality-b1", false, "Accept the REALITY B1 transport (real TLS 1.3, auth in session_id). Requires -reality-private-key.")
	fs.BoolVar(&cfg.REALITYLegacyEnabled, "reality-legacy", true, "Accept the legacy REALITY transport (credentials in padding extension 0x0015). Turn off once no client uses it.")
	fs.IntVar(&cfg.REALITYMaxTimeDiff, "reality-max-time-diff", 300, "Client clock skew tolerated by B1 auth, seconds (0 = do not check)")
	fs.StringVar(&cfg.REALITYMinClientVer, "reality-min-client-ver", "", "Lowest client version B1 accepts, X.Y.Z (empty = do not check)")
	fs.StringVar(&cfg.REALITYMirrorMode, "reality-mirror", "off", "How much of the handshake to mirror to the real donor: off, adaptive, always. Only off is implemented until B1.5.")
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	opts.tunIP = fs.String("tun-ip", "10.8.0.1", "TUN interface IP address for VPN server")
	fs.StringVar(&cfg.TunName, "tun-name", "tiredvpn0", "TUN interface name")
	fs.IntVar(&cfg.TunMTU, "tun-mtu", 1280, "TUN interface MTU (1280-9000)")
	fs.StringVar(&cfg.RedisAddr, "redis", "", "Redis address for multi-client mode (e.g., localhost:6379)")
	fs.StringVar(&cfg.APIAddr, "api-addr", "127.0.0.1:8080", "HTTP API address for client management")
	fs.StringVar(&cfg.APIToken, "api-token", "", "Bearer token required for the management API (falls back to TIREDVPN_API_TOKEN; empty = no auth)")
	fs.StringVar(&cfg.UpstreamAddr, "upstream", "", "Upstream TiredVPN server for multi-hop (e.g., exit-server.com:443)")
	fs.StringVar(&cfg.UpstreamSecret, "upstream-secret", "", "Secret for upstream authentication")
	fs.DurationVar(&cfg.RelayIdleTimeout, "relay-idle-timeout", 0, "Idle deadline for a relay->upstream TUN bridge; silent bridges are force-closed to free admission slots and buffers (0 = default 90s)")
	fs.IntVar(&cfg.RelayUpstreamBufBytes, "relay-upstream-buf", 0, "SO_RCVBUF/SO_SNDBUF size in bytes for the TCP dial to the upstream exit (0 = default 512KB); lower to bound relay memory")

	// Port hopping flags
	fs.StringVar(&cfg.PortRange, "port-range", "", "Port or range for multi-port listening (e.g., '995' or '47000-47100')")
	fs.IntVar(&cfg.PortRangeMaxPorts, "port-range-max", 50, "Maximum number of ports to listen on when using range")
	opts.portHopInterval = fs.Duration("port-hop-interval", 60*time.Second, "Recommended hop interval for clients (transmitted during handshake)")
	fs.StringVar(&cfg.PortHopStrategy, "port-hop-strategy", "random", "Recommended hop strategy for clients: random, sequential, fibonacci")
	fs.StringVar(&cfg.PortHopSeed, "port-hop-seed", "", "Optional seed for deterministic hopping (transmitted to clients)")

	// Admission control
	fs.IntVar(&cfg.MaxConcurrentConns, "max-conns", 0, "Max concurrent in-flight incoming connections (0 = default 4096); excess connections are dropped to bound memory under DPI reconnect storms")

	// Profiling
	opts.pprofAddr = fs.String("pprof", "", "Enable pprof profiling on address (e.g., :6060)")

	// QUIC flags (enabled by default)
	opts.noQUIC = fs.Bool("no-quic", false, "Disable QUIC listener (UDP)")
	fs.StringVar(&cfg.QUICListenAddr, "quic-listen", "", "QUIC listen address (default: same as -listen but UDP)")
	fs.BoolVar(&cfg.QUICSNIFragReassembly, "quic-sni-reassembly", false, "Enable QUIC SNI fragment reassembly (for clients using -quic-sni-frag)")

	// IP Pool flags for TUN mode
	fs.StringVar(&cfg.IPPoolNetwork, "ip-pool", "", "IP pool CIDR for TUN clients (e.g., '10.8.0.0/24'). Enables auto IP assignment.")
	opts.ipPoolLease = fs.Duration("ip-pool-lease", 24*time.Hour, "IP lease duration (0 = permanent)")

	// IPv6 Transport flags
	fs.StringVar(&cfg.ListenAddrV6, "listen-v6", "[::]:995", "IPv6 listen address")
	fs.BoolVar(&cfg.EnableIPv6, "enable-v6", true, "Enable IPv6 listener")
	fs.BoolVar(&cfg.DualStack, "dual-stack", true, "Listen on both IPv4 and IPv6")

	// ICMP tunnel
	fs.BoolVar(&cfg.EnableICMP, "enable-icmp", false, "Enable ICMP tunnel listener (requires CAP_NET_RAW)")

	// Seqovl level-A packet overlap: server-side input NFQUEUE drop (stub, off by default)
	fs.BoolVar(&cfg.SeqovlPacketDrop, "seqovl-packet-drop", false, "Enable server-side NFQUEUE drop for packet-level seqovl (stub; not yet implemented)")

	opts.showVersion = fs.Bool("version", false, "Show version")

	return opts
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.Usage = printServerHelp

	cfg := &server.Config{}
	opts := registerServerFlags(fs, cfg)

	fs.Parse(args)

	if *opts.showVersion {
		fmt.Printf("tiredvpn server %s\n", version)
		os.Exit(0)
	}

	cfg.TunIP = net.ParseIP(*opts.tunIP).To4()
	if cfg.TunIP == nil {
		fmt.Printf("Error: Invalid TUN IP address: %s\n", *opts.tunIP)
		os.Exit(1)
	}

	if cfg.TunMTU < 1280 || cfg.TunMTU > 9000 {
		fmt.Printf("Error: -tun-mtu must be between 1280 and 9000, got %d\n", cfg.TunMTU)
		os.Exit(1)
	}

	cfg.Secret = []byte(*opts.secret)
	// Fall back to the TIREDVPN_SECRET env var when -secret is not given, so a
	// systemd unit can pass the secret via EnvironmentFile instead of putting it
	// on the command line (where it would show up in ps/cmdline). The error in
	// server.go already documents this env var.
	if len(cfg.Secret) == 0 {
		cfg.Secret = []byte(os.Getenv("TIREDVPN_SECRET"))
	}
	// Same pattern for the management-API token: prefer the flag, fall back to
	// the env var so it need not appear in the process command line.
	if cfg.APIToken == "" {
		cfg.APIToken = os.Getenv("TIREDVPN_API_TOKEN")
	}
	// Same for the REALITY static key: a private key passed as an argument is
	// readable by any local user through /proc.
	if cfg.REALITYPrivateKey == "" {
		cfg.REALITYPrivateKey = os.Getenv("TIREDVPN_REALITY_PRIVATE_KEY")
	}
	cfg.QUICEnabled = !*opts.noQUIC // QUIC enabled by default
	cfg.IPPoolLeaseTime = *opts.ipPoolLease
	cfg.PortHopInterval = *opts.portHopInterval

	if err := applyServerTOMLConfig(cfg, *opts.configPath, fs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Start pprof server if enabled
	if *opts.pprofAddr != "" {
		go func() {
			fmt.Printf("pprof listening on %s\n", *opts.pprofAddr)
			if err := http.ListenAndServe(*opts.pprofAddr, nil); err != nil {
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
	fs.IntVar(&cfg.TunMTU, "tun-mtu", 1280, "TUN device MTU (with -auto-mtu this is the upper bound/cap)")
	fs.BoolVar(&cfg.AutoMTU, "auto-mtu", true, "Actively probe the real end-to-end MTU and apply min(probed, -tun-mtu); floor 1280")
	fs.StringVar(&cfg.TunRoutes, "tun-routes", "", "Routes to add (comma-separated, e.g. '0.0.0.0/0' for full tunnel)")

	// Android VpnService flags
	fs.IntVar(&cfg.TunFd, "tun-fd", -1, "Use existing TUN file descriptor (for Android VpnService)")
	fs.StringVar(&cfg.ProtectPath, "protect-path", "", "Unix socket path for Android VpnService protect() calls")
	fs.StringVar(&cfg.ControlSocket, "control-socket", "", "Control socket path for Android integration (2-phase connect)")
	fs.BoolVar(&cfg.AndroidMode, "android", false, "Running on Android (disables os/exec, ICMP checks)")

	// Benchmark flags
	fs.BoolVar(&cfg.BenchmarkMode, "benchmark", false, "Run strategy benchmark (latency test)")
	fs.BoolVar(&cfg.BenchmarkJSONMode, "benchmark-json", false, "Run strategy benchmark, output results as JSON (for automation)")
	fs.BoolVar(&cfg.FullBenchmarkMode, "benchmark-full", false, "Run FULL strategy benchmark (HTTP, latency, speed, IP change)")
	fs.BoolVar(&cfg.BenchmarkAllCombos, "benchmark-all", false, "Run EXHAUSTIVE benchmark: all strategies × all RTT profiles (78 combinations)")

	// Adaptive strategy flags
	reprobeInterval := fs.Duration("reprobe-interval", 5*time.Minute, "How often to re-probe strategies")
	fs.IntVar(&cfg.CircuitThreshold, "circuit-threshold", 3, "Failures before circuit opens")
	circuitResetTime := fs.Duration("circuit-reset", 5*time.Minute, "Time before circuit tries half-open")
	fs.BoolVar(&cfg.EnableFallback, "fallback", true, "Enable mid-session fallback to other strategies")

	// QUIC transport flags
	fs.BoolVar(&cfg.QUICEnabled, "quic", false, "Enable QUIC transport (highest priority, hardest to block)")
	fs.IntVar(&cfg.QUICPort, "quic-port", 8443, "QUIC server port")

	// ICMP tunnel (backup transport, requires CAP_NET_RAW)
	fs.BoolVar(&cfg.ICMPTunnelEnabled, "icmp-tunnel", false, "Enable ICMP tunnel backup strategy (requires CAP_NET_RAW; server must run with -enable-icmp)")

	// Seqovl level-A packet overlap (Linux only, requires CAP_NET_ADMIN + OUTPUT NFQUEUE rule)
	fs.BoolVar(&cfg.SeqovlPacketEnabled, "seqovl-packet", false, "Enable packet-level TCP sequence overlap for seqovl (Linux + CAP_NET_ADMIN; additive to the app-framing decoy)")
	fs.BoolVar(&cfg.REALITYRequireDataV2, "reality-require-data-v2", false, "Refuse REALITY servers still on the v1 data layer instead of falling back (turn on once every server is upgraded)")
	registerClientREALITYFlags(fs, cfg)

	// RTT Masking flags
	fs.BoolVar(&cfg.RTTMaskingEnabled, "rtt-masking", false, "Enable RTT masking (hides proxy timing signature)")
	fs.StringVar(&cfg.RTTProfile, "rtt-profile", "moscow-yandex", "RTT profile (moscow-yandex, moscow-vk, regional-russia, siberia, cdn, beijing-baidu, tehran-aparat)")

	fs.StringVar(&cfg.TLSFingerprint, "tls-fingerprint", "",
		"uTLS browser profile for ClientHello ("+strings.Join(customtls.FingerprintNames(), ", ")+"); empty uses "+customtls.DefaultFingerprintName)

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

	// Traffic shaper for Morph strategies
	shaperName := fs.String("shaper", "", "Traffic shaper preset for morph strategies (youtube_streaming, chrome_browsing, imap_sync, random_per_session)")
	shaperSeed := fs.Int64("shaper-seed", 0, "Seed for deterministic shaper (0 = random)")

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

	// Validate MTU after TOML resolution so a TOML-supplied value is checked too.
	if cfg.TunMTU < 1280 || cfg.TunMTU > 9000 {
		fmt.Printf("Error: -tun-mtu must be between 1280 and 9000, got %d\n", cfg.TunMTU)
		os.Exit(1)
	}

	// Build shaper from -shaper flag last so an explicit CLI flag wins over
	// any [shaper] section in the TOML (CLI > TOML precedence).
	if *shaperName != "" {
		if err := applyShaperFlag(cfg, *shaperName, *shaperSeed); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
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

	client.Version = version
	client.BuildTime = buildTime
	if err := client.Run(cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// runREALITYKeygen prints a fresh static REALITY key pair.
//
// The two halves go to opposite ends of the deployment, so they are labelled by
// where they belong rather than by what they are: the private key is server
// configuration, the public key is client configuration. Getting that backwards
// is the one mistake this command exists to prevent.
func runREALITYKeygen() {
	priv, pub, err := server.GenerateREALITYKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "reality-keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Private key: %s\n", priv)
	fmt.Printf("Public  key: %s\n", pub)
	fmt.Println()
	fmt.Println("Server: -reality-private-key <private> (or TIREDVPN_REALITY_PRIVATE_KEY)")
	fmt.Println("Client: -reality-server-pubkey <public>")
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
  tiredvpn admin add -api http://127.0.0.1:8080 -server vpn.example.com:443 -name alice [options]
    -api         API endpoint (required)
    -api-token   Bearer token if the server runs with -api-token (or TIREDVPN_API_TOKEN)
    -server      Server address for connection string (required)
    -name        Client name (required)
    -tun-ip      Fixed TUN IP (default: server-assigned)
    -max-conns   Max concurrent connections (default: server default)
    -expires-in  Expiry as Go duration, e.g. 720h (default: never)
    -quic        Enable QUIC in connection string (default: true)
    -quic-port   QUIC port (default: 8443)
  Note: id and secret are generated by the server and printed on success.

List clients:
  tiredvpn admin list -api http://127.0.0.1:8080

Delete client:
  tiredvpn admin delete -api http://127.0.0.1:8080 -id <client_id>

Generate QR:
  tiredvpn admin qr -server vpn.example.com:443 -secret <secret> [options]
    -server     Server address (required)
    -secret     Client secret (required)
    -quic       Enable QUIC (default: true)
    -quic-port  QUIC port (default: 8443)
    -strategy   Strategy (default: auto)
    -cover      Cover host (default: api.googleapis.com)`)
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

// adminAPIToken resolves the management-API token from the flag, falling back
// to TIREDVPN_API_TOKEN so the CLI matches the server's resolution order. When
// both are empty the CLI sends no Authorization header (pre-auth behaviour).
func adminAPIToken(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("TIREDVPN_API_TOKEN")
}

// adminDoRequest sends req, attaching the bearer token when one is configured.
func adminDoRequest(req *http.Request, token string) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func adminAdd(args []string) {
	fs := flag.NewFlagSet("admin add", flag.ExitOnError)

	apiAddr := fs.String("api", "", "API endpoint (e.g., http://127.0.0.1:8080)")
	apiToken := fs.String("api-token", "", "Bearer token if the API requires auth (falls back to TIREDVPN_API_TOKEN)")
	serverAddr := fs.String("server", "", "Server address for connection string")
	name := fs.String("name", "", "Client name (required)")
	tunIP := fs.String("tun-ip", "", "Fixed TUN IP (optional, server assigns if empty)")
	maxConns := fs.Int("max-conns", 0, "Max concurrent connections (0 = server default)")
	expiresIn := fs.String("expires-in", "", "Expiry as Go duration, e.g. 720h (optional)")
	quic := fs.Bool("quic", true, "Enable QUIC")
	quicPort := fs.Int("quic-port", 8443, "QUIC port")
	strategy := fs.String("strategy", "auto", "Strategy")
	cover := fs.String("cover", "api.googleapis.com", "Cover host")

	fs.Parse(args)

	if *apiAddr == "" || *serverAddr == "" || *name == "" {
		fmt.Println("Error: -api, -server and -name are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Call API to create the client. The server generates the id (UUID)
	// and secret itself and returns them in the response.
	apiURL := strings.TrimSuffix(*apiAddr, "/") + "/clients"

	payload := map[string]interface{}{
		"name": *name,
	}
	if *tunIP != "" {
		payload["tun_ip"] = *tunIP
	}
	if *maxConns > 0 {
		payload["max_conns"] = *maxConns
	}
	if *expiresIn != "" {
		payload["expires_in"] = *expiresIn
	}
	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(string(jsonData)))
	if err != nil {
		fmt.Printf("Error building request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminDoRequest(req, adminAPIToken(*apiToken))
	if err != nil {
		fmt.Printf("Error calling API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("API error: %s\n%s\n", resp.Status, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	var created struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// Build connection string from the server-issued secret
	connStr := buildConnectionString(*serverAddr, created.Secret, *quic, *quicPort, *strategy, *cover)

	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    CLIENT ADDED SUCCESSFULLY                   ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Client ID:  %-50s║\n", created.ID)
	fmt.Printf("║  Secret:     %-50s║\n", created.Secret)
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Connection String:                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n%s\n", connStr)

	printQRCode(connStr)
}

func adminList(args []string) {
	fs := flag.NewFlagSet("admin list", flag.ExitOnError)

	apiAddr := fs.String("api", "", "API endpoint")
	apiToken := fs.String("api-token", "", "Bearer token if the API requires auth (falls back to TIREDVPN_API_TOKEN)")

	fs.Parse(args)

	if *apiAddr == "" {
		fmt.Println("Error: -api is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	apiURL := strings.TrimSuffix(*apiAddr, "/") + "/clients"

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		fmt.Printf("Error building request: %v\n", err)
		os.Exit(1)
	}
	resp, err := adminDoRequest(req, adminAPIToken(*apiToken))
	if err != nil {
		fmt.Printf("Error calling API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var listResp struct {
		Clients []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"clients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}
	clients := listResp.Clients

	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         CLIENT LIST                            ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")

	if len(clients) == 0 {
		fmt.Println("║  No clients found                                              ║")
	} else {
		for _, c := range clients {
			line := c.ID
			if c.Name != "" {
				line = c.ID + "  " + c.Name
			}
			fmt.Printf("║  %-62s║\n", line)
		}
	}

	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
}

func adminDelete(args []string) {
	fs := flag.NewFlagSet("admin delete", flag.ExitOnError)

	apiAddr := fs.String("api", "", "API endpoint")
	clientID := fs.String("id", "", "Client ID to delete")
	apiToken := fs.String("api-token", "", "Bearer token if the API requires auth (falls back to TIREDVPN_API_TOKEN)")

	fs.Parse(args)

	if *apiAddr == "" || *clientID == "" {
		fmt.Println("Error: -api and -id are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	apiURL := strings.TrimSuffix(*apiAddr, "/") + "/clients/" + *clientID

	req, _ := http.NewRequest(http.MethodDelete, apiURL, nil)
	resp, err := adminDoRequest(req, adminAPIToken(*apiToken))
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
	quicPort := fs.Int("quic-port", 8443, "QUIC port")
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
