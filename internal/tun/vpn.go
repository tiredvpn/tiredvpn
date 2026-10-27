package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// isTemporaryError checks if error is EAGAIN/EWOULDBLOCK (non-blocking fd)
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	// Check for syscall.EAGAIN
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	// Also check error message for "resource temporarily unavailable"
	errStr := err.Error()
	return strings.Contains(errStr, "resource temporarily unavailable") ||
		strings.Contains(errStr, "would block")
}

// keepaliveIntervalNs is the keepalive ticker's period (a zero-length frame
// signals keepalive): 10 s. Atomic so a test can shorten it while another
// test's relay is still winding down.
var keepaliveIntervalNs = func() *atomic.Int64 {
	var v atomic.Int64
	v.Store(int64(10 * time.Second))
	return &v
}()

func keepaliveInterval() time.Duration { return time.Duration(keepaliveIntervalNs.Load()) }

// SetKeepaliveInterval replaces the keepalive period for a test in another
// package and returns the old value.
func SetKeepaliveInterval(d time.Duration) time.Duration {
	return time.Duration(keepaliveIntervalNs.Swap(int64(d)))
}

var readTimeout = 30 * time.Second    // Must be > keepaliveInterval, detect dead connection faster. A var so tests can shorten it.
const writeTimeout = 30 * time.Second // Write timeout (was 5s, caused i/o timeouts with bufferbloat)

// keepaliveWriteTimeout bounds one keepalive write. A var so tests can
// shorten it.
var keepaliveWriteTimeout = 5 * time.Second

const deadConnectionTimeout = 45 * time.Second // Proactive dead connection detection timeout

// maxFrameLen is the largest [len:4][data:N] payload the tunnel protocol accepts;
// anything above it is treated as a desynced stream and drops the connection.
const maxFrameLen = 65535

// pollingResetMarker is the frame length an exit sends an HTTP Polling client
// whose session it does not have (server.go pollingSessionResetFrame): the
// smallest length over the ceiling, chosen so every deployed client drops the
// session at once.
const pollingResetMarker = maxFrameLen + 1

// Reconnect configuration
const (
	reconnectInitialDelay = 1 * time.Second // Start with 1 second
	reconnectMaxDelay     = 2 * time.Minute // Cap at 2 minutes
	reconnectMultiplier   = 2.0             // Double each time
	reconnectJitterFactor = 0.3             // +/- 30% jitter
)

// silentCycleMaxDelay caps the reconnect backoff after a cycle that ended in
// silence (strategy.ErrAddrSilent) or heard nothing back without a verdict
// (strategy.ErrCycleUnanswered).
const silentCycleMaxDelay = 30 * time.Second

// nextReconnectDelay is the backoff after a failed reconnect with err:
// doubled, capped. A cycle that ended in silence - the pool answered TCP, then
// every transport heard nothing - caps lower: it is the same "servers
// unreachable from a working network" story as a silent pool, one layer up,
// and the 2-minute cap slept through up to two minutes of recovered network.
func nextReconnectDelay(cur time.Duration, err error) time.Duration {
	return capReconnectDelay(time.Duration(float64(cur)*reconnectMultiplier), err)
}

// capReconnectDelay caps a backoff for the failure err: silentCycleMaxDelay
// after a silent or unanswered cycle, reconnectMaxDelay otherwise. Applied to
// the pause about to be slept as well, not only to the next one: a silent
// cycle after answered failures slept the old backoff first, up to 2 minutes
// plus jitter.
func capReconnectDelay(d time.Duration, err error) time.Duration {
	maxDelay := reconnectMaxDelay
	if errors.Is(err, strategy.ErrAddrSilent) || errors.Is(err, strategy.ErrCycleUnanswered) {
		maxDelay = silentCycleMaxDelay
	}
	return min(d, maxDelay)
}

// Port hop reconnect configuration (faster than regular reconnect)
const (
	portHopReconnectTimeout = 5 * time.Second // Quick timeout for port hop
	portHopMaxAttempts      = 3               // Max attempts before falling back to regular reconnect
)

// VPNClient manages the TUN-based VPN connection
// tunHandshakeVersion is the default TUN handshake version byte sent by this
// client. v3 is additive over v2 (full port-hop config) and additionally
// advertises that the client understands the auto-MTU active probe. Older
// servers treat >=0x02 identically, so the bump is backward-compatible.
const tunHandshakeVersion = 0x03

// tunHandshakeVersionDualStack advertises IPv6 dual-stack support inside the
// tunnel. Sent only when the client is built with dual-stack enabled
// (VPNConfig.DualStack); the request format is unchanged, so old servers
// ReadFull the same 8 bytes and simply ignore the unknown version.
const tunHandshakeVersionDualStack = 0x04

// DualStackCapFlag is the handshake-response flag bit (resp[9]) by which an
// exit advertises IPv6 dual-stack inside the tunnel. When set, the response
// carries a trailing 32-byte block [serverIP6:16][clientIP6:16] after the
// version-dependent layout.
const DualStackCapFlag = 0x04

// Handshake-response flag bits (resp[9]).
const (
	tunFlagPortHopping = 0x01             // server advertises port hopping
	tunFlagMTUProbe    = ProbeCapFlag     // server supports the auto-MTU echo (exit only)
	tunFlagDualStack   = DualStackCapFlag // server assigned IPv6 tunnel addresses
)

// ServerCapabilities contains optional features advertised by server
type ServerCapabilities struct {
	PortHoppingEnabled bool
	PortRangeStart     int
	PortRangeEnd       int
	HopIntervalSec     int    // Hop interval in seconds (0 = use default 60s)
	HopStrategy        string // "random", "sequential", "fibonacci" (empty = "random")
	HopSeed            []byte // Optional seed for deterministic hopping
	MTUProbeSupported  bool   // exit echoes auto-MTU probe frames

	// DualStackEnabled reports that the exit assigned IPv6 tunnel addresses
	// (server answered a v0x04 handshake with the dual-stack flag and the
	// trailing 32-byte address block).
	DualStackEnabled bool
	ServerIP6        net.IP // exit's IPv6 tunnel address (16 bytes)
	ClientIP6        net.IP // assigned client IPv6 tunnel address (16 bytes)
}

type VPNClient struct {
	tun        *TUNDevice
	manager    *strategy.Manager
	serverAddr string
	localIP    net.IP
	conn       net.Conn
	strategy   strategy.Strategy

	// sessionCand is the endpoint candidate the current session rides, as
	// ConnectSession named it; hasSessionCand is false when there is none.
	// The session's end is booked against it. Guarded by mu.
	sessionCand    endpoint.Candidate
	hasSessionCand bool

	// Stats
	packetsUp   int64
	packetsDown int64
	bytesUp     int64
	bytesDown   int64

	// Lifecycle counters for observability (accessed atomically). Polled by the
	// client's metrics syncer and surfaced as reconnects_total / connections_total
	// — previously these Prometheus counters were always zero in TUN mode because
	// nothing fed them.
	tunnelConnects int64 // successful tunnel establishments (initial + reconnects)
	reconnectsOK   int64 // reconnect attempts that re-established the tunnel
	reconnectsFail int64 // reconnect attempts that failed and backed off

	// Control
	running      int32
	reconnecting int32 // Prevents concurrent reconnect attempts
	stopCh       chan struct{}
	mu           sync.Mutex
	// lastRx is when the server last sent anything, data or keepalive echo.
	// It gates the keepalive and goes into the disconnect log next to
	// connectedAt. Only downlink counts: the server echoes keepalives and sends
	// none of its own, so uplink that draws no reply must not hold them back,
	// or readTimeout fires on a live tunnel.
	connectedAt time.Time
	lastRx      time.Time
	// lastData is when the session last carried a data packet down -
	// keepalive echoes move lastRx, not this. Zero until the first one.
	lastData time.Time

	// lastTx is a monoNow stamp of the last frame written up the tunnel,
	// keepalives included (keepUplinkAlive).
	lastTx atomic.Int64
	// lastDataTx is a monoNow stamp of the last packet from the TUN written
	// up the tunnel: lastTx without keepalives and probes.
	lastDataTx atomic.Int64
	// returnNotBefore is a monoNow stamp before which no return to a
	// preferred server is tried again (tryReturnToPreferred).
	returnNotBefore atomic.Int64
	// keepaliveMu serialises the two keepalives, the server-silence one
	// and the uplink's own, from their last look at the stamps to the
	// write; lastKeepalive is a monoNow stamp of the last one sent.
	keepaliveMu   sync.Mutex
	lastKeepalive atomic.Int64

	// stall follows the session's TCP flows for the stall detector
	// (watchStalls): one table per tunnel connection, replaced together with
	// conn under mu, so whatever works on a table works on its own session.
	stall *flowTable
	// keepaliveEchoes counts the zero-length frames read off the tunnel.
	keepaliveEchoes atomic.Uint64

	// connCancel cancels the context of an in-flight connect() so Stop() can
	// abort a dial/handshake that is blocked on the network without waiting
	// for v.mu (connect no longer holds v.mu while dialing). Accessed atomically.
	connCancel atomic.Pointer[context.CancelFunc]

	// Server capabilities (received during handshake)
	serverCaps ServerCapabilities

	// ipv6Policy is what the client does with IPv6 for the life of this
	// tunnel: negotiate it into the tunnel (handshake version 0x04), block it
	// when the tunnel cannot carry it, or leave the host alone. Resolved from
	// VPNConfig by VPNConfig.ipv6PolicyOrLegacy.
	ipv6Policy IPv6Policy
	// Auto-MTU active probe state.
	autoMTU       bool                   // -auto-mtu enabled
	ownsInterface bool                   // we created the TUN (can change MTU live)
	prober        atomic.Pointer[Prober] // current prober (replies routed here)
	lastProbeMu   sync.Mutex
	lastProbe     ProbeResult
	lastProbeOK   bool

	// noStrategyUpgrade mirrors VPNConfig.NoStrategyUpgrade; upgrading is set
	// while a strategy upgrade is dialling, so two reprobes never run two.
	noStrategyUpgrade bool
	upgrading         atomic.Bool

	// upgradePending is the strategy an upgrade moved the tunnel to, until
	// its session has carried traffic for deadSessionMax (then the upgrade
	// is confirmed) or ends first (then it failed). Guarded by mu.
	upgradePending strategy.Strategy

	// upgradeOff lists endpoints whose exit answered an upgrade with another
	// tunnel address - an exit older than the credential lease, which will do
	// so every time - for as long as the tunnel's session there lasts. An
	// exit is updated by restarting it, which ends that session, so the entry
	// goes with it (disconnect): one wasted upgrade per session at most,
	// instead of none ever again until the client restarts. Guarded by mu.
	upgradeOff map[string]bool

	// sessionMu is held by every operation that registers a new session on
	// the exit and installs it - connect, port hop, strategy upgrade - from
	// the TUN handshake to the commit. The exit replaces whatever session held
	// the client's address when a new one handshakes, so two of these
	// interleaving left the client keeping a session the exit had already
	// evicted.
	sessionMu sync.Mutex

	// poolRound rotates waitForPool's one dial per round through the pool.
	// Only the reconnect loop touches it.
	poolRound int

	// Port hop state for seamless reconnect
	portHopInProgress int32    // 1 if port hop reconnect in progress
	pendingConn       net.Conn // New connection being established during port hop
	pendingStrategy   strategy.Strategy
}

// VPNConfig configures the VPN client
type VPNConfig struct {
	TunName    string   // TUN device name (e.g., "tiredvpn0")
	MTU        int      // MTU size (default 1280)
	LocalIP    net.IP   // Local TUN IP (e.g., 10.8.0.2)
	RemoteIP   net.IP   // Server TUN IP (e.g., 10.8.0.1)
	Routes     []string // Routes to add (e.g., "0.0.0.0/0")
	ServerAddr string   // Server address (host:port)
	Manager    *strategy.Manager

	// ServerAddrV6 is the server's IPv6 transport address ("[2001:db8::1]:995",
	// from -server-v6). The strategy manager may dial it instead of ServerAddr
	// when -prefer-ipv6 is on, and the v6 half-default routes installed by a
	// negotiated dual-stack tunnel would then swallow the client's own
	// transport socket. Recorded so the TUN can pin a /128 bypass for it.
	ServerAddrV6 string

	// ServerAddrs is every transport address of every configured endpoint, in
	// "host:port" form; ServerAddr and ServerAddrV6 are the first endpoint's
	// and appear here too.
	//
	// A full tunnel needs a host route for each of them: with a single bypass
	// pinned, dialling a second server sends the transport socket into the
	// tunnel it is supposed to carry, and it dies there. Every entry is pinned
	// at start-up rather than at the moment of a switch, so there is no window
	// where the client has moved and the route has not.
	//
	// Empty means "just ServerAddr / ServerAddrV6", which is what every
	// single-server caller (macOS, JNI, benchmarks) keeps passing.
	ServerAddrs []string

	// AutoMTU enables the active MTU probe. When set, MTU becomes the upper bound
	// (cap) and the client measures the real end-to-end ceiling, applying
	// min(probed, cap). Only effective on interfaces we own (non-fd Linux/macOS).
	AutoMTU bool

	// IPv6Policy selects what happens to IPv6 while the tunnel is up:
	// IPv6PolicyDual (the -tun-ipv6 default) asks the exit for IPv6 tunnel
	// addresses with handshake version 0x04 instead of 0x03 and blocks
	// outbound IPv6 if it declines; IPv6PolicyBlock blocks without asking;
	// IPv6PolicyOff is the historical v4-only tunnel with host IPv6 untouched.
	// The handshake request format is identical either way, so asking is safe
	// against old exits — they ignore the unknown version.
	IPv6Policy IPv6Policy

	// IPv6Allow is the parsed -tun-ipv6-allow list: interfaces and destination
	// prefixes the leak block must not touch. It exists because the block is a
	// host-wide reject and the host may carry IPv6 the client knows nothing
	// about — a 6in4 tunnel, another VPN, a routed prefix. Empty by default,
	// which is the block as it shipped.
	IPv6Allow IPv6AllowList

	// IPv6Routes is the parsed -tun-routes6 spec: which IPv6 destinations the
	// tunnel claims once dual-stack is negotiated. The zero value is the
	// ::/1 + 8000::/1 half-defaults, i.e. the full tunnel issue #55 asks for.
	// Setting it hands IPv6 routing policy back to the operator, which also
	// takes the blanket leak block out of play — see IPv6RouteSpec.
	IPv6Routes IPv6RouteSpec

	// DualStack is the pre-policy spelling of IPv6Policy == IPv6PolicyDual,
	// kept for callers that have not moved over (macOS, benchmarks). Ignored
	// when IPv6Policy is set to anything but its zero value.
	//
	// Deprecated: set IPv6Policy instead.
	DualStack bool

	// Android VpnService support
	TunFd       int    // Use existing TUN file descriptor (from VpnService.establish())
	ProtectPath string // Unix socket path for VpnService.protect() calls

	// NoStrategyUpgrade keeps a live tunnel on the strategy it connected with
	// even when a periodic reprobe finds a better one working (-fallback=false).
	// By default the client moves to it make-before-break; see
	// tryStrategyUpgrade.
	NoStrategyUpgrade bool
}

// serverAddrList returns every configured transport address, most preferred
// first and deduplicated: -server-v6, -server, then the rest of the endpoint
// list. The first two lead so a single-server client keeps the exact ordering
// it had before the list existed.
func serverAddrList(cfg VPNConfig) []string {
	out := make([]string, 0, 2+len(cfg.ServerAddrs))
	seen := make(map[string]bool, 2+len(cfg.ServerAddrs))
	for _, addr := range append([]string{cfg.ServerAddrV6, cfg.ServerAddr}, cfg.ServerAddrs...) {
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// serverIP6s lists every IPv6 transport address this client might dial, in
// preference order. serverBypassIP6 pins a route for the first one; the IPv6
// leak block has to punch a hole for all of them, since the client can switch
// between them across reconnects and a hole for an address that is never
// dialled costs nothing.
func serverIP6s(cfg VPNConfig) []net.IP {
	var out []net.IP
	for _, addr := range serverAddrList(cfg) {
		for _, ip := range resolveBypassIPs(addr) {
			// A v4-mapped literal (::ffff:1.2.3.4) is an IPv4 address wearing
			// v6 syntax: the kernel has no v6 route for that form, and the v4
			// bypass already covers the host.
			if ip.To4() != nil || containsIP(out, ip) {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

// serverBypassIPs lists every address a host route has to be pinned for: one
// per configured endpoint, both families.
//
// A hostname contributes ALL of its records, not just the first. The dialer is
// free to pick any of them, and a /32 to an address that is never dialled costs
// one routing-table entry - whereas missing the one that IS dialled costs the
// tunnel.
func serverBypassIPs(cfg VPNConfig) []net.IP {
	var out []net.IP
	for _, addr := range serverAddrList(cfg) {
		for _, ip := range resolveBypassIPs(addr) {
			if containsIP(out, ip) {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

// resolveBypassIPs turns one "host:port" address into every IP behind it. An
// address literal resolves to itself; a hostname to all of its A and AAAA
// records. An unresolvable host yields nothing and is simply skipped, which is
// the pre-existing behaviour for a bypass that cannot be computed.
func resolveBypassIPs(serverAddr string) []net.IP {
	if serverAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, existing := range list {
		if existing.Equal(ip) {
			return true
		}
	}
	return false
}

// ipv6PolicyOrLegacy resolves the effective policy: IPv6Policy when set,
// otherwise the deprecated DualStack bool.
func (cfg VPNConfig) ipv6PolicyOrLegacy() IPv6Policy {
	if cfg.IPv6Policy != IPv6PolicyOff {
		return cfg.IPv6Policy
	}
	if cfg.DualStack {
		return IPv6PolicyDual
	}
	return IPv6PolicyOff
}

// applyIPv6BlockConfig records everything the leak block is built from onto a
// device we own: the policy that decides whether it goes in at all, the holes
// for the client's own exits, and the operator's exceptions.
//
// Extracted from NewVPNClient because that function needs a real TUN and root,
// while this is three field writes — and the interesting failure is a config
// field that never reaches the device, which is exactly what a test of
// NewVPNClient cannot check and a test of this can.
func applyIPv6BlockConfig(dev *TUNDevice, cfg VPNConfig) {
	dev.SetIPv6Policy(cfg.ipv6PolicyOrLegacy())
	// The client's own transport addresses, one layer below the /128 bypass
	// routes: the block rejects outbound v6, and the dial to an exit reached
	// over IPv6 must not be caught by it.
	dev.SetIPv6BlockAllow(serverIP6s(cfg))
	dev.SetIPv6BlockAllowList(cfg.IPv6Allow)
	// The route spec belongs here rather than next to Configure: it decides
	// what EnableDualStack installs *and* whether the block applies at all, so
	// it has to be on the device before either is consulted.
	dev.SetIPv6Routes(cfg.IPv6Routes)
}

// NewVPNClient creates a new VPN client
func NewVPNClient(cfg VPNConfig) (*VPNClient, error) {
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.TunName == "" {
		cfg.TunName = "tiredvpn0"
	}
	if cfg.LocalIP == nil {
		cfg.LocalIP = net.ParseIP("10.8.0.2")
	}
	if cfg.RemoteIP == nil {
		cfg.RemoteIP = net.ParseIP("10.8.0.1")
	}

	// Initialize Android socket protector if path is provided
	if cfg.ProtectPath != "" {
		if err := InitAndroidProtector(cfg.ProtectPath); err != nil {
			return nil, err
		}
	}

	var tunDev *TUNDevice
	var err error

	// Use existing TUN fd if provided (Android VpnService mode)
	if cfg.TunFd > 0 {
		log.Info("Using existing TUN fd=%d (Android VpnService mode)", cfg.TunFd)
		tunDev, err = CreateTUNFromFd(cfg.TunFd, cfg.TunName, cfg.MTU)
		if err != nil {
			return nil, err
		}
		// Configure from fd (skip system config, VpnService handles it)
		if err := tunDev.ConfigureFromFd(cfg.LocalIP, cfg.RemoteIP); err != nil {
			tunDev.Close()
			return nil, err
		}
	} else {
		// Create new TUN device (normal Linux mode)
		tunDev, err = CreateTUN(cfg.TunName, cfg.MTU)
		if err != nil {
			return nil, err
		}
		// Record the IPv6 policy before Configure: it keeps IPv6 enabled on
		// the interface for the post-handshake EnableDualStack, and decides
		// whether outbound IPv6 gets blocked once the tunnel's IPv6 fate is
		// known. Only on interfaces we own — the fd branch above leaves the
		// device at IPv6PolicyOff, because on Android VpnService owns both
		// routing and filtering.
		applyIPv6BlockConfig(tunDev, cfg)
		// Pin a bypass route for EVERY configured endpoint before configuring
		// routes, so a full-tunnel default route does not loop the client's own
		// server traffic - not for the current endpoint alone, because by the
		// time the client decides to try the second one the tunnel is already
		// up and the unpinned dial goes into it.
		//
		// This covers both families for the same reason it always did on the v6
		// side: once dual-stack is negotiated the ::/1 + 8000::/1 half-defaults
		// cover every IPv6 destination, the client's own servers among them.
		if bypassIPs := serverBypassIPs(cfg); len(bypassIPs) > 0 {
			tunDev.SetServerBypassIPs(bypassIPs)
			log.Debug("Server bypass: %d endpoint address(es) will be pinned", len(bypassIPs))
		}
		// Defer route installation (notably the 0.0.0.0/0 default route) until a
		// real connection + handshake to the server succeeds. Configure brings
		// the interface up and assigns its address, but leaves the host's normal
		// routing intact so an unreachable server cannot strand the machine
		// offline. Routes go in via InstallRoutes from Start() after connect.
		tunDev.SetDeferRoutes(true)
		// Configure TUN device
		if err := tunDev.Configure(cfg.LocalIP, cfg.RemoteIP, cfg.Routes); err != nil {
			tunDev.Close()
			return nil, err
		}
	}

	return &VPNClient{
		tun:           tunDev,
		manager:       cfg.Manager,
		serverAddr:    cfg.ServerAddr,
		localIP:       cfg.LocalIP,
		stopCh:        make(chan struct{}),
		autoMTU:       cfg.AutoMTU,
		ownsInterface: cfg.TunFd <= 0,
		ipv6Policy:    cfg.ipv6PolicyOrLegacy(),

		noStrategyUpgrade: cfg.NoStrategyUpgrade,
	}, nil
}

// handshakeVersion returns the TUN handshake version byte this client sends:
// 0x04 when the policy negotiates dual-stack, else the default 0x03. The
// request layout is identical either way, so this is the only on-wire
// difference the IPv6 policy makes. -tun-ipv6=block keeps 0x03: it wants the
// host's IPv6 stopped, not carried, so there is nothing to ask the exit for.
func (v *VPNClient) handshakeVersion() byte {
	if v.ipv6Policy.NegotiatesDualStack() {
		return tunHandshakeVersionDualStack
	}
	return tunHandshakeVersion
}

// Start starts the VPN tunnel
func (v *VPNClient) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&v.running, 0, 1) {
		return nil // Already running
	}

	// Wire the physical-route signals between the TUN and the strategy manager
	// BEFORE the first connect. Two directions, one truth:
	//   - the family preflight asks HasPhysicalRoute so the very first scan skips
	//     a family this host cannot reach (IPv6 endpoints with no IPv6 on the
	//     line) instead of timing out on it;
	//   - the bypass watcher reports when an address loses or regains its
	//     physical route, so a family that dies mid-session is excluded from the
	//     next reconnect and re-admitted once the route is back.
	// Only for interfaces we own — on Android VpnService owns routing and the
	// TUN methods are no-ops there.
	if v.ownsInterface && v.manager != nil {
		tunDev, mgr := v.tun, v.manager
		mgr.SetRouteReachable(func(addr string) (routable, known bool) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return false, false
			}
			return tunDev.HasPhysicalRoute(ip)
		})
		tunDev.SetBypassUnroutableFunc(func(ip net.IP, unroutable bool) {
			mgr.SetEndpointReachableIP(ip, !unroutable)
		})
	}

	// Connect to server
	if err := v.connect(ctx); err != nil {
		atomic.StoreInt32(&v.running, 0)
		return err
	}

	// Connection + handshake succeeded. Only now point routes (incl. the
	// default route) at the tunnel. If connect had failed, routes were never
	// installed and the host kept its normal routing, staying online while the
	// background reconnect loop retries.
	v.tun.InstallRoutes()

	v.mu.Lock()
	v.lastRx = time.Now()
	v.mu.Unlock()

	if v.manager != nil && !v.noStrategyUpgrade {
		v.manager.SetStrategyUpgradeCallback(v.tryStrategyUpgrade)
	}

	// Subscribe to port hop events from strategy manager
	// This ensures VPN reconnects when port hopping changes the server port
	// Uses seamless "make before break" approach to minimize downtime
	if v.manager != nil {
		v.manager.SetPortHopCallback(func(oldPort, newPort int) {
			log.Info("VPN: port hop detected (%d -> %d), initiating seamless reconnect", oldPort, newPort)
			go v.seamlessPortHop(newPort)
		})
	}

	// Keep the server reachable off-tunnel for as long as the tunnel lives. The
	// bypass route sits on the physical link, so anything that takes that link
	// down (Wi-Fi reassociation, dock, suspend) makes the kernel drop it and the
	// client starts dialling its own server through its own tunnel. Only for
	// interfaces we own — on Android the socket is protected by VpnService.
	if v.ownsInterface {
		go v.tun.WatchServerBypass(v.stopCh)
	}

	// Start packet forwarding
	go v.readFromTun()
	go v.readFromServer()
	go v.sendKeepalive()
	go v.keepUplinkAlive()
	go v.watchStalls()
	go v.watchReturnToPreferred()

	// Auto-MTU: measure the real end-to-end ceiling and apply min(probed, cap).
	// readFromServer is already running so PROBE_REPLY frames can be routed to the
	// prober. Runs in the background so connectivity is never blocked beyond the
	// fast-probe deadline.
	v.maybeStartMTUProbe(ctx, "connect")

	log.Info("VPN tunnel started")
	return nil
}

// maybeStartMTUProbe launches the active MTU probe when enabled, supported by the
// exit, and the interface MTU can be changed live (interfaces we created). It is a
// no-op otherwise, leaving the statically negotiated MTU in place.
func (v *VPNClient) maybeStartMTUProbe(ctx context.Context, trigger string) {
	if !v.autoMTU {
		return
	}
	if !v.serverCaps.MTUProbeSupported {
		log.Info("Auto-MTU: exit did not advertise probe support, keeping static MTU %d (reason=no-capability)", v.tun.mtu)
		v.storeProbeResult(ProbeResult{AppliedMTU: v.tun.mtu, Source: "cap", FallbackReason: "no-capability"})
		return
	}
	if !v.ownsInterface {
		// Host-owned fd (Android VpnService / macOS NE): the MTU can only be set at
		// establish() time by the host, so a live probe-and-raise is not possible
		// here. The host should probe before establish (out of scope for Go core).
		// TODO: expose a probe-before-establish entry point for host integrations.
		log.Debug("Auto-MTU: interface is host-owned (fd mode), skipping live probe")
		return
	}
	go v.runMTUProbe(ctx, trigger)
}

// runMTUProbe performs the connect-time fast probe and, on failure, lowers the
// interface to the floor and refines in the background. See
// research/auto-mtu-design-2026-06-28.md section 4.4.
func (v *VPNClient) runMTUProbe(ctx context.Context, trigger string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("runMTUProbe panic: %v", r)
		}
	}()

	capMTU := v.tun.mtu
	if capMTU < MTUFloor {
		// Configured below the floor: nothing to measure, the floor is the ceiling.
		log.Debug("Auto-MTU: configured MTU %d <= floor, skipping probe", capMTU)
		return
	}

	// Per-probe timeout from the measured RTT (>= 500ms floor).
	timeout := minProbeTimeout
	if v.manager != nil {
		if rtt := v.manager.GetLastConnectionInfo().Latency; rtt > 0 {
			if t := 3 * rtt; t > timeout {
				timeout = t
			}
		}
	}

	prober := NewProber(ProbeConfig{
		Floor:   MTUFloor,
		Cap:     capMTU,
		Step:    defaultProbeStep,
		Timeout: timeout,
		Retries: defaultProbeRetries,
	}, v.sendProbeFrame)
	v.prober.Store(prober)
	defer v.prober.Store(nil)

	start := time.Now()

	// Fast synchronous probe of cap: the common 1500-path case answers in ~1 RTT
	// and we keep the tunnel at full MTU.
	if prober.FastProbe(ctx, fastProbeDeadline) {
		v.applyProbedMTU(capMTU)
		res := ProbeResult{AppliedMTU: capMTU, Source: "cap", Probes: prober.Probes(), DurationMs: time.Since(start).Milliseconds()}
		v.storeProbeResult(res)
		log.Info("Auto-MTU[%s]: cap %d confirmed via fast probe in %dms (%d probes)", trigger, capMTU, res.DurationMs, res.Probes)
		return
	}

	// Fast probe failed: drop to the conservative floor immediately (safe, see 5.2)
	// so oversized frames cannot black-hole, then refine the real ceiling and raise.
	log.Info("Auto-MTU[%s]: fast probe of cap %d failed, lowering to floor %d and refining in background", trigger, capMTU, MTUFloor)
	v.applyProbedMTU(MTUFloor)

	res := prober.Run(ctx)
	v.applyProbedMTU(res.AppliedMTU)
	v.storeProbeResult(res)
	log.Info("Auto-MTU[%s]: probed=%d source=%s probes=%d duration=%dms fallback=%q",
		trigger, res.AppliedMTU, res.Source, res.Probes, res.DurationMs, res.FallbackReason)
}

// sendProbeFrame frames a probe control payload as [len:4][payload] and writes it
// to the current server connection.
func (v *VPNClient) sendProbeFrame(payload []byte) error {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)

	v.mu.Lock()
	conn := v.conn
	v.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("no server connection")
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(frame)
	if err == nil {
		v.lastTx.Store(monoNow())
	}
	return err
}

// applyProbedMTU sets the live interface MTU to min(max(mtu, floor), cap). It is a
// no-op when the value is unchanged.
func (v *VPNClient) applyProbedMTU(mtu int) {
	if mtu < MTUFloor {
		mtu = MTUFloor
	}
	if mtu > v.tun.mtu {
		mtu = v.tun.mtu
	}
	if mtu == v.tun.MTU() {
		return
	}
	if err := v.tun.SetMTU(mtu); err != nil {
		log.Warn("Auto-MTU: failed to apply MTU %d: %v", mtu, err)
	}
}

func (v *VPNClient) storeProbeResult(res ProbeResult) {
	v.lastProbeMu.Lock()
	v.lastProbe = res
	v.lastProbeOK = true
	v.lastProbeMu.Unlock()
}

// LastMTUProbe returns the most recent probe result and whether one has completed.
func (v *VPNClient) LastMTUProbe() (ProbeResult, bool) {
	v.lastProbeMu.Lock()
	defer v.lastProbeMu.Unlock()
	return v.lastProbe, v.lastProbeOK
}

// ForceReconnect forces an immediate VPN reconnect
// Used when port hopping changes the server port
func (v *VPNClient) ForceReconnect() {
	if atomic.LoadInt32(&v.running) == 0 {
		return
	}

	// Close current connection to trigger reconnect in readFromServer/readFromTun
	v.mu.Lock()
	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
	}
	v.mu.Unlock()

	// Reset reconnecting flag to allow handleDisconnect to proceed
	atomic.StoreInt32(&v.reconnecting, 0)

	log.Debug("VPN: ForceReconnect - connection closed, reconnect will be triggered")
}

// seamlessPortHop performs "make before break" port hop
// Establishes new connection first, then atomically swaps, minimizing downtime
func (v *VPNClient) seamlessPortHop(newPort int) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("seamlessPortHop panic: %v", r)
			atomic.StoreInt32(&v.portHopInProgress, 0)
			v.handleDisconnect("port hop panic", fmt.Errorf("%v", r))
		}
	}()

	// Prevent concurrent port hops
	if !atomic.CompareAndSwapInt32(&v.portHopInProgress, 0, 1) {
		log.Debug("VPN: port hop already in progress, skipping")
		return
	}
	defer atomic.StoreInt32(&v.portHopInProgress, 0)

	start := time.Now()
	log.Debug("VPN: starting seamless port hop to port %d", newPort)

	// Get server host from current address
	host, _, err := net.SplitHostPort(v.serverAddr)
	if err != nil {
		host = v.serverAddr
	}
	newTarget := net.JoinHostPort(host, strconv.Itoa(newPort))

	// Try to establish new connection (make)
	var newConn net.Conn
	var newStrategy strategy.Strategy
	var newCand endpoint.Candidate
	var hasNewCand bool
	var connectErr error

	for attempt := 1; attempt <= portHopMaxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), portHopReconnectTimeout)

		// Connect to new port using strategy manager
		newConn, newStrategy, newCand, hasNewCand, connectErr = v.manager.ConnectSession(ctx, newTarget)
		cancel()

		if connectErr == nil {
			break
		}

		log.Debug("VPN: port hop connect attempt %d/%d failed: %v", attempt, portHopMaxAttempts, connectErr)

		if attempt < portHopMaxAttempts {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if connectErr != nil {
		log.Warn("VPN: seamless port hop failed after %d attempts, falling back to force reconnect", portHopMaxAttempts)
		v.ForceReconnect()
		return
	}

	// Perform TUN mode handshake on new connection; see sessionMu. A hop that
	// waited here behind an upgrade may find the client stopped meanwhile.
	v.sessionMu.Lock()
	defer v.sessionMu.Unlock()
	if atomic.LoadInt32(&v.running) == 0 {
		newConn.Close()
		return
	}
	tunnelConn, handshakeErr := v.performHandshake(newConn)
	if handshakeErr != nil {
		newConn.Close()
		log.Warn("VPN: port hop handshake failed: %v, falling back to force reconnect", handshakeErr)
		v.ForceReconnect()
		return
	}

	// Atomic swap: new connection ready, swap with old (break). The hop's
	// session is a session like any other: it rides the endpoint it was
	// dialled at, and a pending upgrade can no longer be judged by it.
	v.mu.Lock()
	if atomic.LoadInt32(&v.running) == 0 {
		v.mu.Unlock()
		tunnelConn.Close()
		return
	}
	oldConn := v.conn
	oldStrategy, oldConnectedAt, oldLastRx := v.strategy, v.connectedAt, v.lastRx
	oldCand, oldHasCand := v.sessionCand, v.hasSessionCand
	abandoned := v.upgradePending
	v.conn = tunnelConn
	v.strategy = newStrategy
	v.serverAddr = newTarget
	v.sessionCand, v.hasSessionCand = newCand, hasNewCand
	v.upgradePending = nil
	v.connectedAt = time.Now()
	v.lastRx = v.connectedAt
	v.lastData = time.Time{}
	v.stall = newFlowTable()
	v.mu.Unlock()

	// The hop replaced the session; book it like the upgrade swap does, and
	// start the storm detector's clock with connectedAt, so the two measure
	// the hop's session from the same moment. A pending upgrade is abandoned,
	// not failed: the hop dialled through the scan, which goes the way the
	// tunnel came, and its session is no evidence about the upgrade.
	if v.manager != nil {
		if oldStrategy != nil {
			v.manager.SessionEnded(strategy.SessionEnd{Strategy: oldStrategy.ID(), Replaced: true,
				Useful: sessionWasUseful(oldConnectedAt, oldLastRx), Endpoint: oldCand, HasEndpoint: oldHasCand})
		}
		v.manager.RecordSessionStart(newStrategy.ID())
	}
	if abandoned != nil {
		log.Info("VPN: port hop abandoned the pending upgrade to %s; the next reprobe may offer it again", abandoned.Name())
	}

	// Close old connection after swap
	if oldConn != nil {
		oldConn.Close()
	}

	elapsed := time.Since(start)
	log.Info("VPN: seamless port hop complete in %v (port %d, strategy %s)", elapsed, newPort, newStrategy.Name())
}

// performHandshake performs TUN mode handshake on a connection
// Used by seamlessPortHop to setup new connection before swapping
//
// It returns the conn to install: the handshake reader may hand back the start
// of the first tunnel frame through a wrapper (see readHandshakeResponse).
func (v *VPNClient) performHandshake(conn net.Conn) (net.Conn, error) {
	// Send TUN mode handshake
	// Format: [mode:1][localIP:4][mtu:2][version:1]
	handshake := make([]byte, 8)
	handshake[0] = 0x02 // TUN mode
	copy(handshake[1:5], v.localIP.To4())
	binary.BigEndian.PutUint16(handshake[5:7], uint16(v.tun.mtu))
	handshake[7] = v.handshakeVersion() // v3: auto-MTU probe; v4: + dual-stack

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(handshake); err != nil {
		return nil, fmt.Errorf("handshake write failed: %w", err)
	}

	// Read server response (drains the dual-stack block when advertised, so
	// the stream stays frame-aligned for the packet loop that follows).
	resp, n, conn, err := readHandshakeResponse(conn, v.handshakeVersion(), time.Now().Add(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("handshake read failed: %w", err)
	}
	if n < 9 {
		return nil, fmt.Errorf("invalid server response: got %d bytes", n)
	}
	if resp[0] != 0x00 {
		return nil, fmt.Errorf("server error: status=%d", resp[0])
	}

	// Verify server assigned same IP (port hop should preserve IP)
	assignedIP := net.IP(resp[5:9])
	if !assignedIP.Equal(v.localIP) && !assignedIP.Equal(net.IPv4zero) {
		log.Debug("VPN: port hop got different IP: %s (was %s)", assignedIP, v.localIP)
		// Update if different
		v.localIP = assignedIP
		if err := v.tun.UpdateLocalIP(assignedIP); err != nil {
			log.Warn("VPN: failed to update TUN local IP: %v", err)
		}
	}

	log.Debug("VPN: port hop handshake successful")
	return conn, nil
}

// connect establishes connection to server.
//
// The dial and handshake run WITHOUT holding v.mu so that Stop() can abort an
// in-flight connect immediately (via connCancel + the conn deadline) instead of
// blocking on the mutex until a 10-30s network timeout elapses. v.mu is taken
// only briefly: at the start to snapshot localIP and close the old conn, and at
// the end to publish the new conn/strategy/caps.
func (v *VPNClient) connect(parent context.Context) error {
	// Register a cancellable context so Stop() can abort the dial without v.mu.
	ctx, cancel := context.WithCancel(parent)
	cancelPtr := &cancel
	v.connCancel.Store(cancelPtr)
	defer func() {
		// Only clear our own cancel pointer (Stop may have swapped/cancelled).
		v.connCancel.CompareAndSwap(cancelPtr, nil)
		cancel()
	}()

	// If Stop already fired, bail before opening anything.
	if atomic.LoadInt32(&v.running) == 0 {
		return context.Canceled
	}

	// Close any existing connection before dialing a new one.
	v.mu.Lock()
	oldConn := v.conn
	v.conn = nil
	localIP := v.localIP
	v.mu.Unlock()
	if oldConn != nil {
		oldConn.Close()
	}

	// Connect via strategy manager (no lock held — may block on the network).
	conn, strat, cand, hasCand, err := v.manager.ConnectSession(ctx, v.serverAddr)
	if err != nil {
		return err
	}

	// Perform the TUN-mode handshake on local variables (still no v.mu), with
	// sessionMu held until the session is published: see sessionMu.
	v.sessionMu.Lock()
	defer v.sessionMu.Unlock()
	resp, n, tunnelConn, err := v.doHandshake(conn, localIP)
	if err != nil {
		conn.Close()
		if IsHandshakeUnanswered(err) {
			// The transport connected and the server swallowed the session
			// handshake: not a success of the transport, and a cycle that
			// heard nothing (R1 of the fix9 stand run).
			return fmt.Errorf("%w: %w", v.manager.HandshakeUnanswered(strat, cand, hasCand), err)
		}
		switch {
		case IsHandshakeAnswered(err):
			v.manager.HandshakeAnswered(strat, cand, hasCand)
		case IsHandshakeFailed(ctx, err):
			// Neither answered nor silent: a reset or an end of stream
			// after the request. A failure of cand, which its connect's
			// success must not hide (finding 1 of the round-13 review).
			v.manager.HandshakeFailed(cand, hasCand)
		}
		return err
	}
	v.manager.HandshakeAnswered(strat, cand, hasCand)
	// From here on the tunnel is read through tunnelConn: the handshake reader
	// may have had to look at the first byte of the first frame.
	conn = tunnelConn

	return v.publishSession(conn, strat, cand, hasCand, resp, n, nil)
}

// errSessionChanged is publishSession refusing a session because the tunnel
// is no longer riding the conn the caller replaces.
var errSessionChanged = errors.New("the tunnel changed meanwhile")

// publishSession installs conn, whose TUN handshake answered resp[:n], as the
// tunnel's session on cand: the conn, the strategy, the addresses the exit
// assigned (onto the TUN device too), the IPv6 side and the session's
// bookkeeping. With replaces set it installs only while the tunnel still
// rides replaces, and leaves closing it to the caller. Called with sessionMu
// held.
func (v *VPNClient) publishSession(conn net.Conn, strat strategy.Strategy, cand endpoint.Candidate, hasCand bool, resp []byte, n int, replaces net.Conn) error {
	// Server sends its TUN IP and assigned client IP.
	serverIP := net.IP(resp[1:5])
	assignedIP := net.IP(resp[5:9])
	log.Info("VPN connected via %s (server IP: %s, assigned IP: %s)", strat.Name(), serverIP, assignedIP)

	// No raw-mode switch for the confusion transport any more. It existed
	// because ConfusedConn's Read stripped a length prefix that the VPN layer
	// then needed back, so the tunnel had to ask for a passthrough mode in
	// which user packets reached the socket unencrypted. The sealed record
	// layer replaced both halves: one framing, and no plaintext path to turn on.
	caps, hasCaps := parseServerCapabilities(resp, n)

	// Publish the new connection under the lock. If Stop() ran while we were
	// dialing, abandon the freshly built conn instead of resurrecting the tunnel.
	v.mu.Lock()
	if atomic.LoadInt32(&v.running) == 0 {
		v.mu.Unlock()
		conn.Close()
		return context.Canceled
	}
	if replaces != nil && (v.conn != replaces || atomic.LoadInt32(&v.reconnecting) == 1 ||
		atomic.LoadInt32(&v.portHopInProgress) == 1) {
		v.mu.Unlock()
		conn.Close()
		return errSessionChanged
	}
	v.conn = conn
	v.strategy = strat
	v.sessionCand, v.hasSessionCand = cand, hasCand
	v.upgradePending = nil
	v.connectedAt = time.Now()
	v.lastRx = v.connectedAt
	v.lastData = time.Time{}
	v.stall = newFlowTable()
	if hasCaps {
		v.serverCaps = caps
	}

	// Update local IP if the server assigned a different one (mutates v.localIP
	// and the TUN device, so it stays under the lock).
	if !assignedIP.Equal(v.localIP) && !assignedIP.Equal(net.IPv4zero) {
		log.Info("Server assigned IP: %s (requested: %s)", assignedIP, v.localIP)
		v.localIP = assignedIP
		if err := v.tun.UpdateLocalIP(assignedIP); err != nil {
			log.Warn("Failed to update TUN local IP: %v", err)
		}
	}

	// Update TUN peer IP if it changed.
	if !serverIP.Equal(v.tun.remoteIP) {
		log.Info("Updating TUN peer IP from %s to %s", v.tun.remoteIP, serverIP)
		if err := v.tun.UpdatePeerIP(serverIP); err != nil {
			log.Warn("Failed to update TUN peer IP: %v", err)
		}
	}
	v.mu.Unlock()

	// IPv6: bring up the v6 side of the tunnel only when the exit actually
	// negotiated it. A declined negotiation (old server, no -ip-pool-v6)
	// restores the exact v4-only interface state — no v6 address, no v6
	// routes, disable_ipv6=1 — and then blocks outbound IPv6, so it neither
	// blackholes nor escapes the tunnel. Host-owned interfaces (Android
	// VpnService / macOS NE fd) are configured by the host, which consumes the
	// negotiated addresses and owns its own filtering.
	//
	// Done here rather than at Configure time on purpose: routes are deferred
	// until a connect succeeds, so until this point the host still relies on
	// its own routing and cutting its IPv6 would take away connectivity the
	// tunnel is not yet replacing.
	switch ipv6ActionFor(v.ipv6Policy, v.ownsInterface, hasCaps && caps.DualStackEnabled) {
	case ipv6ActionNone:
		// Historical behavior: the tunnel is v4-only, host IPv6 untouched.
	case ipv6ActionEnableDual:
		if err := v.tun.EnableDualStack(caps.ClientIP6, caps.ServerIP6); err != nil {
			log.Warn("Dual-stack: failed to configure IPv6 on the tunnel: %v (continuing IPv4-only)", err)
			// DisableIPv6 restores the v4-only interface and, since the
			// tunnel ends up not carrying IPv6, applies the leak block.
			v.tun.DisableIPv6()
		}
	case ipv6ActionBlock:
		if v.ipv6Policy == IPv6PolicyDual {
			log.Warn("Dual-stack requested but the exit did not negotiate IPv6; " +
				"continuing IPv4-only and blocking outbound IPv6 so it cannot leave outside the tunnel")
			v.tun.DisableIPv6()
			break
		}
		v.tun.ApplyIPv6LeakBlock()
	}

	// Mark the start of this session for storm detection. If the DPI tears the
	// session down within seconds, handleDisconnect's RecordSessionEnd will see
	// a short lifetime and (in auto mode) park this strategy. Called without
	// v.mu held, after the conn is published.
	if v.manager != nil {
		v.manager.RecordSessionStart(strat.ID())
	}

	// Count every successful tunnel establishment (initial connect and every
	// reconnect) so connections_total reflects reality in TUN mode.
	atomic.AddInt64(&v.tunnelConnects, 1)

	return nil
}

// doHandshake writes the TUN-mode handshake and reads the server response.
// It runs without holding v.mu and returns the raw response buffer and its
// length for the caller to parse, plus the conn the tunnel must be read from
// afterwards (see readHandshakeResponse).
func (v *VPNClient) doHandshake(conn net.Conn, localIP net.IP) ([]byte, int, net.Conn, error) {
	// Send TUN mode handshake.
	// Format: [mode:1][localIP:4][mtu:2][version:1]
	// If localIP is 0.0.0.0, server will auto-assign an IP.
	// version=0x02 means client supports full port hopping config (interval, strategy, seed)
	handshake := make([]byte, 8)
	handshake[0] = 0x02 // TUN mode
	copy(handshake[1:5], localIP.To4())
	binary.BigEndian.PutUint16(handshake[5:7], uint16(v.tun.mtu))
	handshake[7] = v.handshakeVersion() // v3: auto-MTU probe; v4: + dual-stack

	writeDeadline := time.Now().Add(10 * time.Second)
	conn.SetWriteDeadline(writeDeadline)
	if _, err := conn.Write(handshake); err != nil {
		return nil, 0, nil, fmt.Errorf("%w: %w", errHandshakeNotSent, markWriteTimeout(err, writeDeadline))
	}

	// Read server response.
	// Legacy (9 bytes): [status:1][serverIP:4][clientIP:4]
	// Extended v1 (14 bytes): [status:1][serverIP:4][clientIP:4][flags:1][portStart:2][portEnd:2]
	// Extended v2 (20+ bytes): [status:1][serverIP:4][clientIP:4][flags:1][portStart:2][portEnd:2][hopInterval:4][strategy:1][seedLen:1][seed:0-32]
	// Dual-stack (v4): the version-dependent layout followed by [serverIP6:16][clientIP6:16]
	resp, n, conn, err := readHandshakeResponse(conn, v.handshakeVersion(), time.Time{})
	if err != nil {
		return nil, 0, nil, err
	}
	if n < 9 {
		return nil, 0, nil, fmt.Errorf("invalid server response: got %d bytes, expected at least 9", n)
	}
	if resp[0] != 0x00 {
		switch resp[0] {
		case 0x01:
			return nil, 0, nil, fmt.Errorf("%w: IP pool exhausted", errHandshakeRefused)
		case 0x02:
			return nil, 0, nil, fmt.Errorf("%w: no IP pool configured (auto IP not supported)", errHandshakeRefused)
		default:
			return nil, 0, nil, fmt.Errorf("%w: status=%d", errHandshakeRefused, resp[0])
		}
	}
	return resp, n, conn, nil
}

// IsHandshakeUnanswered reports whether a session handshake failed because
// the request went out and no byte of an answer came in the full
// handshakeReadTimeout. A wait the caller's budget cut short says nothing
// about the server - on a reconnect a late connect leaves the handshake what
// is left of the cycle, and booking that as the server's silence parked
// healthy servers (P2-2 of the round-8 review) - and neither does a request
// that never left or an answer that came in part.
func IsHandshakeUnanswered(err error) bool {
	switch {
	case errors.Is(err, errHandshakeSilent):
		return true
	case errors.Is(err, errHandshakeNotSent), errors.Is(err, errHandshakeRefused),
		errors.Is(err, errHandshakeCutShort), errors.Is(err, errHandshakePartlyAnswered),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// IsHandshakeFailed reports a session handshake on ctx that the server's
// side ended with neither an answer nor silence: a reset or an end of stream
// after the request, or a request write the peer reset. Such a failure is
// the candidate's (Manager.HandshakeFailed).
//
// A request that never left counts only when the peer reset it - EPIPE or
// ECONNRESET - and nothing else does: booking all but a list of exclusions
// charged a healthy server with smux's write timeout, a mux closed locally
// and every errno the list missed (P3-1 of the round-16 review). Left out
// whole, a session that dies on the write - smux, polling - brought back
// the loop round 13 closed (finding 3 of the round-15 review).
//
// After the request, everything counts except what says nothing of the
// server: a wait the caller's budget cut short; a cancellation - ctx done,
// or a conn closed under the handshake (net.ErrClosed, or smux's
// io.ErrClosedPipe, which it returns only for a local close); a timeout;
// and a local abort - netd destroying the sockets of an address Android
// lost, or a network or route gone (finding 2 of the round-15 review).
//
// Not caught: on smux a local abort can come back to the request's write as
// a bare EPIPE, the abort itself consumed by the session's reader (P3-2 of
// the round-16 review, a window of microseconds after the session starts).
// Known until 1.11.10.
func IsHandshakeFailed(ctx context.Context, err error) bool {
	if err == nil || IsHandshakeUnanswered(err) || IsHandshakeAnswered(err) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if errors.Is(err, errHandshakeNotSent) {
		return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
	}
	switch {
	case errors.Is(err, errHandshakeCutShort), errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		localNetAbort(err):
		return false
	}
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout()
}

// localNetAbort reports an error the client's own host or network raised:
// the socket aborted under it, or the network, route or address gone.
func localNetAbort(err error) bool {
	for _, local := range []error{syscall.ECONNABORTED, syscall.ENETDOWN, syscall.ENETUNREACH,
		syscall.EHOSTUNREACH, syscall.EADDRNOTAVAIL} {
		if errors.Is(err, local) {
			return true
		}
	}
	return false
}

// markWriteTimeout makes a write error that came back at or after deadline
// report itself as a timeout. smux calls its deadline errors.New("timeout"),
// no net.Error; the client's clock says what it was (as markSilence does for
// reads).
func markWriteTimeout(err error, deadline time.Time) error {
	if err == nil || time.Now().Before(deadline) {
		return err
	}
	return &writeTimeoutError{err: err}
}

// writeTimeoutError is a write error that came back at its deadline.
type writeTimeoutError struct{ err error }

func (e *writeTimeoutError) Error() string   { return e.err.Error() }
func (e *writeTimeoutError) Unwrap() error   { return e.err }
func (e *writeTimeoutError) Timeout() bool   { return true }
func (e *writeTimeoutError) Temporary() bool { return true }

// IsHandshakeAnswered reports whether a failed session handshake was
// answered all the same: refused with an error status, or answered in part.
// Either ends the server's run of unanswered handshakes (P3-4 of the
// round-8 review).
func IsHandshakeAnswered(err error) bool {
	return errors.Is(err, errHandshakeRefused) || errors.Is(err, errHandshakePartlyAnswered)
}

// KeepHandshakeMark returns outer with what the handshake learned from
// inner kept on it: a refusal or an answer that came in part, either of
// which ends the server's run of unanswered handshakes (IsHandshakeAnswered),
// and a request that never left. A cancellation that replaced the handshake's
// error dropped the mark, so a run of unanswered handshakes with a partial
// answer cut short in the middle still read as the server's silence (P3-7 of
// the round-9 review). Without a mark, outer is returned as it is.
func KeepHandshakeMark(outer, inner error) error {
	for _, mark := range []error{errHandshakePartlyAnswered, errHandshakeRefused, errHandshakeNotSent} {
		if errors.Is(inner, mark) {
			return fmt.Errorf("%w: %w", mark, outer)
		}
	}
	return outer
}

// HandshakeRefused is the error for a handshake the server refused with
// status, for a caller in another package (the client's reconnect).
func HandshakeRefused(status byte) error {
	return fmt.Errorf("%w: status=%d", errHandshakeRefused, status)
}

// HandshakeNotSent marks err, a failed write of the session handshake
// request, as a request that never left: for a caller in another package
// (the client's reconnect).
func HandshakeNotSent(err error) error {
	return fmt.Errorf("%w: %w", errHandshakeNotSent, err)
}

// errHandshakeNotSent and errHandshakeRefused are the two handshake failures
// after which the exit has registered nothing: the request never left, or the
// exit answered with an error status. Any other failure - a response that
// never came, a read that broke - may follow a registration, which displaces
// whatever session held the client's address.
var (
	errHandshakeNotSent = errors.New("TUN handshake request not sent")
	errHandshakeRefused = errors.New("server error")
)

// errHandshakeCutShort and errHandshakePartlyAnswered are the handshake
// failures that say nothing of whether the server answers (see
// IsHandshakeUnanswered): the read ran out of the caller's budget before
// its full wait, or part of the answer came.
var (
	errHandshakeCutShort       = errors.New("TUN handshake read cut short by the caller's budget")
	errHandshakePartlyAnswered = errors.New("TUN handshake answered in part")
)

// errHandshakeSilent marks a handshake read that got nothing and came back
// at or after its full wait, by the client's clock: the server's silence,
// whatever the transport calls its deadline. smux, which carries REALITY,
// calls it errors.New("timeout"), no net.Error, and the silence of a
// REALITY front went unrecognised (finding 1 of the round-13 review; see
// markSilence).
var errHandshakeSilent = errors.New("TUN handshake unanswered for the full wait")

// handshakeRespBufSize fits the largest handshake response: the v2 layout
// with a max-length seed (20+32) plus the 32-byte dual-stack block.
const handshakeRespBufSize = 96

// ReadTUNHandshakeResponse reads a TUN handshake response from conn and
// returns the raw response bytes: the version-dependent base layout plus the
// trailing 32-byte dual-stack block when the flags byte advertises it.
// Exported for the multi-hop relay (internal/server), which must forward the
// exit's response to the downstream client verbatim, and for the client's
// reconnect path.
//
// clientVersion is the handshake version byte that was sent to the exit (the
// relay forwards its client's byte verbatim, so it knows it too): it decides
// whether a flags byte follows the 9-byte prefix. deadline bounds the read of
// the response (zero: handshakeReadTimeout from now); it is cleared again
// before returning, so the returned conn carries no read deadline. The
// returned conn is the one to keep reading from; see readHandshakeResponse
// for why it can differ.
func ReadTUNHandshakeResponse(conn net.Conn, clientVersion byte, deadline time.Time) ([]byte, net.Conn, error) {
	resp, n, next, err := readHandshakeResponse(conn, clientVersion, deadline)
	if err != nil {
		return nil, conn, err
	}
	return resp[:n], next, nil
}

// ParseTUNHandshakeCapabilities decodes the capabilities of a raw TUN
// handshake response (as returned by ReadTUNHandshakeResponse), including the
// dual-stack address block. Exported for the multi-hop relay, which sources
// the downstream client's IPv6 tunnel addresses from the exit's response.
func ParseTUNHandshakeCapabilities(resp []byte) (ServerCapabilities, bool) {
	return parseServerCapabilities(resp, len(resp))
}

// handshakeReadTimeout is the default budget for reading a handshake
// response, used when the caller has no deadline of its own. A var so tests
// can shorten it.
var handshakeReadTimeout = 10 * time.Second

// HandshakeReadTimeout is the full wait for a handshake response, the one
// after which no answer is the server's (IsHandshakeUnanswered).
func HandshakeReadTimeout() time.Duration { return handshakeReadTimeout }

// SetHandshakeReadTimeout replaces handshakeReadTimeout for a test in
// another package and returns the old value. Not for concurrent tests.
func SetHandshakeReadTimeout(d time.Duration) time.Duration {
	old := handshakeReadTimeout
	handshakeReadTimeout = d
	return old
}

// handshakeFlagsGrace bounds the wait for the byte after the 9-byte prefix of
// a success response to a client below v0x04, the only case where the reader
// cannot tell from the version whether a flags byte follows (see
// readHandshakeFlags). An answer that ends at 9 bytes is followed by nothing
// until the first tunnel frame, so the reader must never wait on it for long.
const handshakeFlagsGrace = 300 * time.Millisecond

// readHandshakeResponse reads the server's TUN handshake response and returns
// it together with the conn the caller must keep reading tunnel frames from.
//
// Nothing past the response is ever consumed: the response is read with exact
// reads (the 9-byte prefix [status:1][serverIP:4][clientIP:4], the flags byte
// when there is one, then the layout the flags announce), never with a
// buffer-sized Read. An exit or relay may start sending tunnel frames right
// after the response, and a transport is free to hand them over in the same
// Read; a byte of a frame taken as part of the response shifts every frame
// after it and the session dies at the next read timeout (issue #93).
//
// Whether a flags byte follows the prefix is decided from what the client
// knows, never from whether a byte happens to arrive in time:
//
//   - status != 0: the TUN core refused, and its refusals are the bare 9-byte
//     prefix. (Some transports refuse with a single 0x01 byte instead; the
//     prefix read fails on those, bounded by the response deadline.)
//   - clientVersion >= 0x04: every exit and relay since dual-stack emits the
//     flags byte to such a client, even when it is zero (buildTUNHandshakeResponse),
//     so it is read unconditionally.
//   - below 0x04 the version alone does not settle it: over one transport a
//     terminating exit answers with a flags byte and a relay forwarding an
//     exit's h2 answer does not, and the response carries no version echo.
//     The byte's value does settle it: those versions only get a flags byte
//     when it is non-zero, while the first byte of any tunnel frame
//     [len:4][pkt] is zero (len <= maxFrameLen). See readHandshakeFlags.
//
// When the byte after the prefix turns out to belong to the first frame, or
// has not arrived yet, it is handed over through the returned conn; otherwise
// the returned conn is conn itself. Callers must use the returned conn from
// then on.
//
// deadline bounds every read of the response (zero means handshakeReadTimeout
// from now), so a peer that sends a prefix and goes quiet fails the handshake
// instead of hanging it. The reader clears the read deadline before it
// returns, on every path: the conn goes on to consumers that read without
// deadlines of their own (the relay's bridge and pump), and a deadline left
// behind would cut them off once it passed, however busy the tunnel was.
func readHandshakeResponse(conn net.Conn, clientVersion byte, deadline time.Time) ([]byte, int, net.Conn, error) {
	full := time.Now().Add(handshakeReadTimeout)
	if deadline.IsZero() {
		deadline = full
	}
	_ = conn.SetReadDeadline(deadline)
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	resp := make([]byte, handshakeRespBufSize)
	if got, err := io.ReadFull(conn, resp[:9]); err != nil {
		switch {
		case got > 0:
			err = fmt.Errorf("%w: %w", errHandshakePartlyAnswered, err)
		case time.Now().Before(deadline):
			// Ended before the wait did - a reset or an end of stream:
			// neither silence nor a wait cut short, whatever the budget.
			// Marked cut short whenever the budget was the shorter, a reset
			// on a reconnect was booked as nothing (P2 of the round-14
			// review).
		case deadline.Before(full):
			// The caller's budget ran out before the full wait: the
			// server may simply not have had the time (P2-2 of the
			// round-8 review).
			err = fmt.Errorf("%w: %w", errHandshakeCutShort, err)
		default:
			err = fmt.Errorf("%w: %w", errHandshakeSilent, err)
		}
		return nil, 0, conn, err
	}
	if resp[0] != 0x00 {
		// Refusals built by the TUN core are the bare 9-byte prefix and
		// nothing follows them. (Transports that refuse with a single byte
		// never get here: the 9-byte read above fails on them.)
		return resp, 9, conn, nil
	}
	n, next, err := readHandshakeFlags(conn, resp, clientVersion, deadline)
	if err != nil {
		return nil, 0, conn, fmt.Errorf("%w: %w", errHandshakePartlyAnswered, err)
	}
	n, err = readResponseTail(next, resp, n, clientVersion)
	if err != nil {
		return nil, 0, conn, fmt.Errorf("%w: %w", errHandshakePartlyAnswered, err)
	}
	return resp, n, next, nil
}

// readHandshakeFlags reads the flags byte resp[9] of a success response whose
// 9-byte prefix is already in resp, and returns the number of valid bytes in
// resp (9 or 10) and the conn to continue on.
//
// A v0x04 client always gets the byte, so it is read unconditionally under the
// response deadline. Below v0x04 the byte is present only when non-zero, and
// what follows a bare 9-byte answer is a tunnel frame starting with 0x00, so
// the byte is looked at rather than assumed: non-zero is the flags byte, zero
// is the first byte of a frame and is handed back through a replayConn. When
// nothing has arrived within handshakeFlagsGrace the answer is taken to have
// no flags (the only answer that can end at 9 bytes with nothing behind it),
// and the read still in flight is handed over too. deadline is the read
// deadline in force on conn, the one the peek runs under.
func readHandshakeFlags(conn net.Conn, resp []byte, clientVersion byte, deadline time.Time) (int, net.Conn, error) {
	if clientVersion >= tunHandshakeVersionDualStack {
		if _, err := io.ReadFull(conn, resp[9:10]); err != nil {
			return 9, conn, fmt.Errorf("handshake flags read failed: %w", err)
		}
		return 10, conn, nil
	}
	peek := peekHandshakeByte(conn)
	select {
	case r := <-peek:
		switch {
		case r.err != nil:
			// Nothing followed: the response deadline ran out first, or the
			// peer closed. Either way there is no flags byte, and the conn
			// reports its own state to the next read.
			return 9, conn, nil
		case r.b != 0:
			resp[9] = r.b
			return 10, conn, nil
		default:
			return 9, &replayConn{Conn: conn, pending: []byte{r.b}}, nil
		}
	case <-time.After(handshakeFlagsGrace):
		return 9, &replayConn{Conn: conn, inflight: peek, peekDeadline: deadline}, nil
	}
}

// peekResult is the outcome of the one-byte read peekHandshakeByte starts.
type peekResult struct {
	b   byte
	err error
	at  time.Time // when the read came back
}

// peekHandshakeByte reads the byte after the 9-byte prefix on its own
// goroutine and delivers it on the returned channel.
//
// The wait is bounded by a timer in readHandshakeFlags, not by a read
// deadline on the transport. A deadline that fires inside a transport's
// record read is only harmless when the record layer can resume after it
// (confusion could not before #98), and a transport that ignores read
// deadlines (the ICMP tunnel before #98) would stretch the peek to the first
// packet. The timer keeps the reader independent of both. A read left running
// past the grace is not lost either: the replayConn that carries it delivers
// its byte first, or fails the session if it is a late flags byte.
func peekHandshakeByte(conn net.Conn) <-chan peekResult {
	ch := make(chan peekResult, 1) // buffered: the goroutine never blocks on a reader that went away
	go func() {
		var one [1]byte
		_, err := io.ReadFull(conn, one[:])
		ch <- peekResult{b: one[0], err: err, at: time.Now()}
	}()
	return ch
}

// errLateHandshakeFlags fails a session whose handshake flags byte arrived
// after handshakeFlagsGrace, when the reader had already settled on a bare
// 9-byte answer. Dropping the byte instead would keep the framing only when
// nothing follows it: with port hopping advertised the byte is followed by
// the rest of the port-hop layout, which would land in the stream. And a
// session kept alive without its flags would run without the auto-MTU probe
// and port hopping the server offered, with nothing in the log to say so; a
// reconnect gets them back. The server writes the whole answer in one Write,
// so only a transport stall inside that answer gets here.
var errLateHandshakeFlags = errors.New("handshake flags byte arrived after the grace window")

// replayConn returns bytes the handshake reader had to look at before the
// packet loop reads from the underlying conn, and finishes a peek read the
// reader stopped waiting for. It deliberately exposes no Unwrap/NetConn
// accessor: anything reading the inner conn directly would skip the pending
// bytes or race the read in flight.
type replayConn struct {
	net.Conn
	pending  []byte
	inflight <-chan peekResult // a peek read still running, nil once collected
	err      error             // set once the stream can no longer be framed

	// peekDeadline is the read deadline the peek in flight was started
	// under.
	peekDeadline time.Time
}

// peekOutlived reports a peek that came back with an error on the deadline
// it was started under. A transport where a deadline reaches a Read already
// blocked never does that once the handshake reader has cleared it: clearing
// wakes the read. smux v2, which carries every REALITY tunnel, reads the
// deadline only when a Read starts, so the peek kept the handshake's deadline
// after the reader cleared it, and a tunnel that sent nothing down for the
// rest of the response budget (10 s) was dropped with "server read: timeout"
// (stand twocli/f14-registry, session=9.396s).
func (c *replayConn) peekOutlived(r peekResult) bool {
	return r.err != nil && !c.peekDeadline.IsZero() && !r.at.Before(c.peekDeadline)
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.inflight != nil {
		r := <-c.inflight
		c.inflight = nil
		if c.peekOutlived(r) {
			// The peek read nothing: read its byte again, under the
			// deadline in force now. A close or a broken stream comes back
			// again, and so does a deadline set since that has run out.
			var one [1]byte
			_, err := io.ReadFull(c.Conn, one[:])
			r = peekResult{b: one[0], err: err}
		}
		if r.err != nil {
			// The read ended without a byte; whatever ended it (a deadline
			// the caller set since, a close) is this read's answer.
			return 0, r.err
		}
		if r.b != 0 {
			// Every tunnel frame starts with 0x00, so this is a flags byte
			// that came after the grace (issue #99). Delivering it would
			// shift every frame after it. The error sticks: a later Read
			// would hand out what follows the byte as frames.
			c.err = errLateHandshakeFlags
			return 0, c.err
		}
		c.pending = append(c.pending, r.b)
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// readResponseTail completes the handshake response beyond the mandatory
// 9-byte prefix: the version-dependent extended layout and, when the flags
// byte advertises it, the trailing 32-byte dual-stack block. n is the number
// of valid bytes already in resp.
//
// This runs for every client version, not just the dual-stack one. A v0x03
// client can be sent the 20+seed port-hop layout, and reading only what the
// first Read happened to return left the rest of it in the stream for the
// packet loop to parse as [len:4][pkt:N] - the same silent desync the
// dual-stack path was fixed for.
//
// clientVersion disambiguates the two port-hop layouts, which are otherwise
// indistinguishable by content: a v0x01 client gets the 14-byte v1 form, and
// anything above it gets the 20+seed v2 form. Version 0 (a client that sent
// no version byte) is never offered port hopping, so its branch is moot.
func readResponseTail(conn net.Conn, resp []byte, n int, clientVersion byte) (int, error) {
	if n < 10 {
		return n, nil // legacy 9-byte form, nothing follows
	}
	flags := resp[9]

	base := 10
	switch {
	case flags&tunFlagPortHopping == 0:
		// flags-only form
	case clientVersion == 0x01:
		base = 14 // v1: port range only
	default:
		// v2: the seed length lives at resp[19], so the base has to be
		// completed that far before its own length is knowable.
		if n < 20 {
			m, err := io.ReadFull(conn, resp[n:20])
			if err != nil {
				return n, fmt.Errorf("handshake base read failed: %w", err)
			}
			n += m
		}
		seedLen := int(resp[19])
		if seedLen > 32 {
			return n, fmt.Errorf("handshake response declares a %d-byte hop seed, max 32", seedLen)
		}
		base = 20 + seedLen
	}

	need := base
	if flags&tunFlagDualStack != 0 {
		need += 32
	}
	if need > len(resp) {
		return n, fmt.Errorf("handshake response too large: need %d bytes", need)
	}
	if n < need {
		m, err := io.ReadFull(conn, resp[n:need])
		if err != nil {
			return n, fmt.Errorf("handshake tail read failed: %w", err)
		}
		n += m
	}
	return n, nil
}

// handshakeResponseBaseLen returns the length of the version-dependent base
// layout of a handshake response, excluding the optional 32-byte dual-stack
// block. A dual-capable client (version 0x04) only ever receives the v2
// (20+seed) or 10-byte flags-only extended forms — never the 14-byte v1
// form — so for responses carrying the dual-stack flag the base length is
// unambiguous.
func handshakeResponseBaseLen(resp []byte, n int) int {
	if n < 10 {
		return n // legacy 9-byte form (or an error response)
	}
	if resp[9]&tunFlagPortHopping == 0 {
		return 10 // flags-only form (v3 probe / v4 dual-stack)
	}
	if n >= 20 {
		if seedLen := int(resp[19]); seedLen <= 32 {
			return 20 + seedLen // v2 form
		}
	}
	if n >= 14 {
		return 14 // v1 form
	}
	return n
}

// parseServerCapabilities decodes the optional port-hopping capabilities from a
// handshake response. The second return value reports whether any capabilities
// were present.
func parseServerCapabilities(resp []byte, n int) (ServerCapabilities, bool) {
	// The flags byte at resp[9] is present in any extended response (>=10 bytes).
	// A v3 exit may emit a 10-byte response carrying only the MTU-probe flag (no
	// port hopping), so we no longer require the full 14-byte port-hop response.
	if n < 10 {
		return ServerCapabilities{}, false
	}

	flags := resp[9]
	caps := ServerCapabilities{
		MTUProbeSupported: flags&tunFlagMTUProbe != 0,
	}

	// Dual-stack: the v6 address block trails the version-dependent layout.
	caps.DualStackEnabled = flags&tunFlagDualStack != 0
	if caps.DualStackEnabled {
		base := handshakeResponseBaseLen(resp, n)
		if n >= base+32 {
			caps.ServerIP6 = append(net.IP(nil), resp[base:base+16]...)
			caps.ClientIP6 = append(net.IP(nil), resp[base+16:base+32]...)
		} else {
			// Flag set but block missing/truncated: treat as v4-only.
			caps.DualStackEnabled = false
		}
	}

	// Port-hopping fields need the full 14-byte form.
	if n < 14 || flags&tunFlagPortHopping == 0 {
		return caps, caps.MTUProbeSupported || caps.DualStackEnabled
	}

	portStart := int(binary.BigEndian.Uint16(resp[10:12]))
	portEnd := int(binary.BigEndian.Uint16(resp[12:14]))
	if portStart <= 0 || portEnd <= portStart {
		return caps, caps.MTUProbeSupported || caps.DualStackEnabled
	}

	caps.PortHoppingEnabled = true
	caps.PortRangeStart = portStart
	caps.PortRangeEnd = portEnd
	caps.HopIntervalSec = 60    // Default
	caps.HopStrategy = "random" // Default

	// Parse extended v2 fields if available (20+ bytes).
	if n < 20 {
		log.Info("Server advertises port hopping: range %d-%d (v1 response)", portStart, portEnd)
		return caps, true
	}

	hopInterval := int(binary.BigEndian.Uint32(resp[14:18]))
	strategyByte := resp[18]
	seedLen := int(resp[19])

	if hopInterval > 0 {
		caps.HopIntervalSec = hopInterval
	}

	switch strategyByte {
	case 0x00:
		caps.HopStrategy = "random"
	case 0x01:
		caps.HopStrategy = "sequential"
	case 0x02:
		caps.HopStrategy = "fibonacci"
	}

	if seedLen > 0 && n >= 20+seedLen && seedLen <= 32 {
		caps.HopSeed = make([]byte, seedLen)
		copy(caps.HopSeed, resp[20:20+seedLen])
		log.Info("Server advertises port hopping: range %d-%d, interval %ds, strategy %s, seed_len %d",
			portStart, portEnd, caps.HopIntervalSec, caps.HopStrategy, seedLen)
	} else {
		log.Info("Server advertises port hopping: range %d-%d, interval %ds, strategy %s",
			portStart, portEnd, caps.HopIntervalSec, caps.HopStrategy)
	}

	return caps, true
}

// GetServerCapabilities returns capabilities received from server during handshake
func (v *VPNClient) GetServerCapabilities() ServerCapabilities {
	return v.serverCaps
}

// LocalIP returns the tunnel address the interface actually carries: the one
// the exit assigned during the handshake, or the requested one when the exit
// echoed it back unchanged. Callers that log the address must use this rather
// than the configured VPNConfig.LocalIP — after Start returns, connect has
// already replaced the requested address with the assigned one and updated the
// TUN device, so the configured value is stale.
//
// Taken under v.mu, the same lock connect holds while it mutates localIP.
// The result is a copy: net.IP is a slice, and handing out the live one would
// let a caller mutate the client's own state.
func (v *VPNClient) LocalIP() net.IP {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.localIP == nil {
		return nil
	}
	out := make(net.IP, len(v.localIP))
	copy(out, v.localIP)
	return out
}

// sendKeepalive periodically sends keepalive packets to prevent timeout
func (v *VPNClient) sendKeepalive() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("sendKeepalive panic: %v", r)
			v.handleDisconnect("sendKeepalive panic", fmt.Errorf("%v", r))
		}
	}()

	ticker := time.NewTicker(keepaliveInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&v.running) == 0 {
				return
			}

			v.mu.Lock()
			conn := v.conn
			lastRx := v.lastRx
			v.mu.Unlock()

			if conn == nil {
				continue
			}

			// Send unless the server spoke within the last interval. Outgoing
			// packets do not count: they may draw no reply at all, and then the
			// echo is the only thing keeping readFromServer under readTimeout.
			if time.Since(lastRx) >= keepaliveInterval()*9/10 {
				v.writeSilenceKeepalive(conn)
			}

		case <-v.stopCh:
			return
		}
	}
}

// writeSilenceKeepalive sends the keepalive that answers the server's
// silence, a zero-length frame [length:4=0], under keepaliveMu with the
// uplink's own keepalive. One of those that went just before - its echo
// answers the same silence - makes it skip: while one keepalive's write was
// blocked, the other saw the old stamps and went too, and two keepalives
// back to back are a pair no client sends (P3-5 of the round-9 review).
func (v *VPNClient) writeSilenceKeepalive(conn net.Conn) {
	v.keepaliveMu.Lock()
	defer v.keepaliveMu.Unlock()
	if at := v.lastKeepalive.Load(); at != 0 && time.Duration(monoNow()-at) < keepaliveInterval()/2 {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(keepaliveWriteTimeout))
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		v.connLost(conn, "keepalive write", uplinkFailed(err))
		return
	}
	now := monoNow()
	v.lastTx.Store(now)
	v.lastKeepalive.Store(now)
	log.Debug("Sent keepalive packet")
}

// uplinkKeepaliveDraw draws how long the uplink may stay silent before
// keepUplinkAlive sends a keepalive. Atomic so tests in other packages can
// scale it (SetUplinkKeepaliveDraw).
var uplinkKeepaliveDraw atomic.Pointer[func() time.Duration]

func init() {
	draw := func() time.Duration { return strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) }
	uplinkKeepaliveDraw.Store(&draw)
}

// uplinkTimerReset, when a test sets it, is told of every reset of the
// uplink keepalive's timer: the wait chosen, the period, and how long the
// uplink had been silent. Nil in production.
var uplinkTimerReset atomic.Pointer[func(next, quiet, silent time.Duration)]

// uplinkKeepaliveSent, when a test sets it, is called for each uplink
// keepalive written. Nil in production.
var uplinkKeepaliveSent atomic.Pointer[func()]

// SetUplinkKeepaliveSent sets the hook for a test in another package, nil
// to clear it.
func SetUplinkKeepaliveSent(f func()) {
	if f == nil {
		uplinkKeepaliveSent.Store(nil)
		return
	}
	uplinkKeepaliveSent.Store(&f)
}

// uplinkConnTaken, when a test sets it, runs once the uplink keepalive has
// taken the conn and before it looks at the uplink's stamp again. Nil in
// production.
var uplinkConnTaken atomic.Pointer[func()]

// SetUplinkKeepaliveDraw replaces the draw for a test and returns the one it
// replaced.
func SetUplinkKeepaliveDraw(draw func() time.Duration) func() time.Duration {
	return *uplinkKeepaliveDraw.Swap(&draw)
}

// monoBase anchors monoNow to the monotonic clock.
var monoBase = time.Now()

// monoNow is a monotonic stamp, in nanoseconds since monoBase.
func monoNow() int64 { return int64(time.Since(monoBase)) }

// keepUplinkAlive sends a keepalive when nothing has gone up for a drawn
// quiet period, on a timer of its own. sendKeepalive answers only the
// server's silence: on a download with nothing going up - a one-way UDP
// stream - the server is never silent, the client wrote nothing, and the
// exit closed the session on its read deadline (60 s for HTTP/2 Stego, 120 s
// for Morph and Confusion), about 68 s in (P3-13 of the round-7 review). The
// quiet period is drawn like the relay's, 20-45 s (HumpDelay, mean 30 s), well
// inside every exit's deadline and off any grid; there is no measured
// reference distribution for it. A busy uplink, or the server-silence
// keepalive every 10 s, keeps it from ever firing. A tick that comes before
// the period is up waits out the rest of it, never a whole period.
//
// A transport that makes its own keepalives (strategy.KeepaliveMaker, HTTP
// Polling) gets none: its polls already reach the exit, and a keepalive
// written into it woke the idle poll loop out of its backoff - a 4-byte poll
// and a run of fast ones every 20-45 s on a session that had sent only
// backed-off empty polls (P2-4 of the round-8 review).
func (v *VPNClient) keepUplinkAlive() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("keepUplinkAlive panic: %v", r)
		}
	}()
	v.lastTx.CompareAndSwap(0, monoNow())
	quiet := (*uplinkKeepaliveDraw.Load())()
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	for {
		select {
		case <-v.stopCh:
			return
		case <-timer.C:
		}
		if atomic.LoadInt32(&v.running) == 0 {
			return
		}
		silent := time.Duration(monoNow() - v.lastTx.Load())
		if silent >= quiet {
			v.mu.Lock()
			conn, strat := v.conn, v.strategy
			v.mu.Unlock()
			if f := uplinkConnTaken.Load(); f != nil {
				(*f)()
			}
			km, own := strat.(strategy.KeepaliveMaker)
			own = own && km.MakesUpKeepalives()
			// Looked at again with the conn in hand, under keepaliveMu: a
			// write may have gone up while the lock was waited for, the
			// server-silence keepalive among them, and two keepalives back
			// to back are a pair no client sends (P3-9 of the round-8
			// review, P3-5 of the round-9 one).
			v.keepaliveMu.Lock()
			silent = time.Duration(monoNow() - v.lastTx.Load())
			if silent >= quiet {
				if conn != nil && !own {
					_ = conn.SetWriteDeadline(time.Now().Add(keepaliveWriteTimeout))
					if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
						v.connLost(conn, "keepalive write", uplinkFailed(err))
					} else {
						now := monoNow()
						v.lastTx.Store(now)
						v.lastKeepalive.Store(now)
						log.Debug("Sent keepalive packet (uplink silent %v)", silent.Round(time.Millisecond))
						if f := uplinkKeepaliveSent.Load(); f != nil {
							(*f)()
						}
					}
				}
				quiet = (*uplinkKeepaliveDraw.Load())()
				silent = 0
			}
			v.keepaliveMu.Unlock()
		}
		next := max(quiet-silent, 10*time.Millisecond)
		if f := uplinkTimerReset.Load(); f != nil {
			(*f)(next, quiet, silent)
		}
		timer.Reset(next)
	}
}

// readFromTun reads packets from TUN and sends to server
func (v *VPNClient) readFromTun() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("readFromTun panic: %v", r)
			v.handleDisconnect("readFromTun panic", fmt.Errorf("%v", r))
		}
	}()

	buf := make([]byte, v.tun.mtu+4)
	log.Debug("readFromTun goroutine started, waiting for packets from TUN device")
	// buf is sized at the construction-time cap; auto-MTU only lowers (or raises
	// back up to the cap) the live MTU, so this buffer always fits a read.

	for atomic.LoadInt32(&v.running) == 1 {
		n, err := v.tun.Read(buf[4:])
		if err != nil {
			if atomic.LoadInt32(&v.running) == 0 {
				return
			}
			log.Debug("TUN read error: %v", err)
			continue
		}
		if log.DebugEnabled() {
			dumpEnd := n + 4
			if dumpEnd > 24 {
				dumpEnd = 24
			}
			log.Debug("Read %d bytes from TUN, first 20 bytes: % x", n, buf[4:dumpEnd])
		}

		// Clamp TCP MSS on SYN/SYN-ACK packets to prevent oversized segments
		ClampTCPMSS(buf[4:4+n], v.tun.MTU())

		// Frame packet: [length:4][data:n]
		binary.BigEndian.PutUint32(buf[:4], uint32(n))

		v.mu.Lock()
		conn, flows := v.conn, v.stall
		v.mu.Unlock()

		if conn == nil {
			log.Debug("TUN->Server: conn is nil, dropping %d bytes", n)
			continue
		}
		flows.up(buf[4:4+n], time.Now())

		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		written, err := conn.Write(buf[:n+4])
		if err != nil {
			v.connLost(conn, "server write", uplinkFailed(err))
			continue
		}
		now := monoNow()
		v.lastTx.Store(now)
		v.lastDataTx.Store(now)

		if log.DebugEnabled() {
			log.Debug("TUN->Server: sent %d bytes (payload=%d) to server", written, n)
		}
		atomic.AddInt64(&v.packetsUp, 1)
		atomic.AddInt64(&v.bytesUp, int64(n))
	}
}

// readFromServer reads packets from server and writes to TUN
func (v *VPNClient) readFromServer() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("readFromServer panic: %v", r)
			v.handleDisconnect("readFromServer panic", fmt.Errorf("%v", r))
		}
	}()

	lenBuf := make([]byte, 4)

	// One rx buffer for the whole goroutine instead of a per-packet make(): this
	// is the single reader of the connection and nothing downstream retains the
	// slice past the loop iteration (the probe decoder copies out its nonce,
	// BuildICMPFragNeeded builds a fresh packet, tun.Write is synchronous).
	// Sized at the protocol frame ceiling because an oversized frame still has to
	// be read off the wire before it can be dropped.
	rxBuf := make([]byte, maxFrameLen)

	for atomic.LoadInt32(&v.running) == 1 {
		v.mu.Lock()
		conn, flows := v.conn, v.stall
		v.mu.Unlock()

		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Read packet length with extended timeout (keepalive keeps connection alive)
		deadline := time.Now().Add(readTimeout)
		conn.SetReadDeadline(deadline)
		nLen, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if atomic.LoadInt32(&v.running) == 0 {
				return
			}
			v.connLost(conn, "server read", markSilence(err, deadline))
			continue
		}

		pktLen := binary.BigEndian.Uint32(lenBuf)

		// Handle keepalive packet (zero length)
		if pktLen == 0 {
			log.Debug("Received keepalive from server")
			v.keepaliveEchoes.Add(1)
			v.noteDownlink(false)
			continue
		}

		if log.DebugEnabled() {
			log.Debug("Read length header: %d bytes, value=%d (0x%02x %02x %02x %02x)",
				nLen, pktLen, lenBuf[0], lenBuf[1], lenBuf[2], lenBuf[3])
		}

		if pktLen == pollingResetMarker {
			// Not a desync: the exit's "no such session" for HTTP Polling,
			// sent on purpose after it lost the session (a restart). Named so
			// the log reads as what it is.
			v.connLost(conn, "session reset by server", fmt.Errorf("frame length %d is the exit's session-reset marker", pktLen))
			continue
		}
		if pktLen > maxFrameLen {
			v.connLost(conn, "bad frame", fmt.Errorf("length %d exceeds protocol max", pktLen))
			continue
		}

		// Read packet data
		buf := rxBuf[:pktLen]
		nRead, err := io.ReadFull(conn, buf)
		if err != nil {
			v.connLost(conn, "server read data", markSilence(err, deadline))
			continue
		}

		// Auto-MTU: intercept PROBE_REPLY control frames before any IP handling.
		// They must never be written to the TUN device, and a reply may be larger
		// than the current (lowered) interface MTU, so this check precedes the
		// oversized-packet guard below.
		if isProbeFramePayload(buf) {
			if pr := v.prober.Load(); pr != nil {
				pr.HandleReply(buf)
			}
			continue
		}

		// Oversized real packet: drop and inject ICMP Fragmentation Needed so the
		// inner peer shrinks instead of black-holing.
		if pktLen > uint32(v.tun.MTU()) {
			log.Debug("Packet too large (%d > MTU %d), dropping and sending ICMP", pktLen, v.tun.MTU())
			icmpPkt := BuildICMPFragNeeded(v.tun.remoteIP, buf, uint16(v.tun.MTU()))
			if icmpPkt != nil {
				if _, err := v.tun.Write(icmpPkt); err != nil {
					log.Debug("Failed to inject ICMP frag needed: %v", err)
				}
			}
			continue
		}
		if log.DebugEnabled() {
			if len(buf) >= 8 {
				log.Debug("Read packet data: %d bytes, first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
					nRead, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7])
			} else if len(buf) > 0 {
				log.Debug("Read packet data: %d bytes: % x", nRead, buf)
			}
		}

		// Check if packet data starts with another length prefix (HTTP/2 framing artifact)
		// Server sends: [outer_len=88][inner_len=84][IP_packet=84 bytes]
		// We read outer_len (88), then 88 bytes containing both inner_len and IP packet
		actualBuf := buf
		if len(buf) >= 4 {
			innerLen := binary.BigEndian.Uint32(buf[:4])
			if innerLen+4 == uint32(len(buf)) {
				log.Debug("DETECTED: Packet has inner length prefix (%d+4=%d), skipping 4 bytes", innerLen, len(buf))
				actualBuf = buf[4:]
			}
		}

		// Clamp TCP MSS on incoming SYN/SYN-ACK before writing to TUN
		ClampTCPMSS(actualBuf, v.tun.MTU())

		// Write to TUN
		if log.DebugEnabled() && len(actualBuf) > 0 {
			// Log first 20 bytes to verify IP packet format
			dumpLen := 20
			if len(actualBuf) < dumpLen {
				dumpLen = len(actualBuf)
			}
			log.Debug("About to write %d bytes to TUN, first %d bytes: % x", len(actualBuf), dumpLen, actualBuf[:dumpLen])
		}

		n, err := v.tun.Write(actualBuf)
		if err != nil {
			log.Debug("TUN write error: %v | len=%d | wrote=%d", err, len(actualBuf), n)
			continue
		}
		if log.DebugEnabled() {
			log.Debug("Successfully wrote %d bytes to TUN", n)
		}

		flows.down(actualBuf, time.Now())
		v.noteDownlink(true)

		atomic.AddInt64(&v.packetsDown, 1)
		atomic.AddInt64(&v.bytesDown, int64(pktLen))
	}
}

// noteDownlink records that the server just sent something, and confirms a
// pending strategy upgrade once its session has carried traffic for
// deadSessionMax - the same line past which a session no longer counts as
// having died young: a dial and a handshake prove less than that, and a session
// frozen a second after the swap must count as a failed upgrade, not a
// successful one (see Manager.UpgradeOutcome).
//
// data is whether it was a packet for the TUN rather than a keepalive echo:
// lastData, which Stop books a session as useful by, is stamped under the
// same lock (P3-8 of the round-7 review).
func (v *VPNClient) noteDownlink(data bool) {
	now := time.Now()
	v.mu.Lock()
	v.lastRx = now
	if data {
		v.lastData = now
	}
	var confirmed strategy.Strategy
	if v.upgradePending != nil && now.Sub(v.connectedAt) >= deadSessionMax {
		confirmed, v.upgradePending = v.upgradePending, nil
	}
	v.mu.Unlock()
	if confirmed != nil && v.manager != nil {
		v.manager.UpgradeOutcome(confirmed, true)
		log.Info("Strategy upgrade to %s confirmed: the session has carried traffic for %v", confirmed.Name(), deadSessionMax)
	}
}

// connLost hands a failed conn to handleDisconnect - unless it is no longer
// the tunnel's conn. A make-before-break swap (strategy upgrade, port hop)
// closes the conn it replaced, and every read or write still blocked on it
// fails on its way out; reconnecting on that failure tore down the healthy
// conn that had just been installed.
func (v *VPNClient) connLost(conn net.Conn, reason string, err error) {
	v.disconnect(conn, reason, err)
}

// upgradeConnectTimeout bounds one strategy upgrade dial. The TUN handshake
// that follows is bounded by its own deadlines (10 s write, handshakeReadTimeout
// read) and is not cut short by Stop; the swap after it checks running.
const upgradeConnectTimeout = 15 * time.Second

// errUpgradeRejected is the reason a session is handed to handleDisconnect
// when an upgrade was dropped after its handshake: the exit had already moved
// the client's address to the new session, so the old one is gone too.
var errUpgradeRejected = errors.New("strategy upgrade rejected after the handshake")

// tryStrategyUpgrade is the strategy manager's upgrade callback: cands are the
// strategies the last periodic reprobe found reachable, best first. If one
// ranks above the strategy carrying the tunnel (Manager.UpgradeRank - the
// scan's own penalties, not just the base priority), the client dials it at
// the tunnel's endpoint, runs the TUN handshake on it, and only then swaps it
// in and closes the old conn - make before break, so the data plane sees a
// swap rather than an outage.
//
// It exists because nothing else ever moved a live tunnel off a fallback: a
// client that came back from a fault on HTTP Polling, Geneva or Traffic Morph
// stayed there for as long as the session held, and sessions hold for hours.
//
// The upgrade is not booked as a success until the new session has carried
// traffic (noteDownlink); a failed handshake, a dropped session, or a session
// that dies first are booked as failures and feed the upgrade backoff.
func (v *VPNClient) tryStrategyUpgrade(cands []strategy.Strategy) {
	if atomic.LoadInt32(&v.running) == 0 || atomic.LoadInt32(&v.reconnecting) == 1 ||
		atomic.LoadInt32(&v.portHopInProgress) == 1 {
		return
	}
	if !v.upgrading.CompareAndSwap(false, true) {
		return
	}
	defer v.upgrading.Store(false)

	v.mu.Lock()
	cur, oldConn, localIP := v.strategy, v.conn, v.localIP
	cand, hasCand := v.sessionCand, v.hasSessionCand
	pending := v.upgradePending
	v.mu.Unlock()
	if cur == nil || oldConn == nil || pending != nil {
		return
	}
	if !hasCand {
		var ok bool
		if cand, ok = v.manager.CurrentCandidate(); !ok {
			return
		}
	}
	v.mu.Lock()
	off := v.upgradeOff[cand.Addr]
	v.mu.Unlock()
	if off {
		return
	}

	// Shut down with the client: Stop cannot otherwise reach an upgrade
	// dialling on its own context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-v.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	for _, next := range cands {
		if next.ID() == cur.ID() || v.manager.UpgradeRank(next) >= v.manager.UpgradeRank(cur) {
			continue
		}
		// What the scan itself would rank lower - a QUIC that keeps failing
		// against a REALITY that works - is no upgrade, whatever its base
		// priority. And the offer is minutes old: what a scan would not admit
		// now (UDP excluded, storm-parked, breaker open) is not dialled.
		if v.manager.ScanScore(next) >= v.manager.ScanScore(cur) || !v.manager.UpgradeEligible(next, cand.Addr) {
			continue
		}
		log.Info("Strategy upgrade: %s is reachable again, moving the tunnel off %s", next.Name(), cur.Name())
		dialCtx, dialCancel := context.WithTimeout(ctx, upgradeConnectTimeout)
		conn, err := v.manager.ConnectStrategy(dialCtx, next, cand)
		dialCancel()
		if err != nil {
			// One offer, one dial. Walking on to the next candidate put a
			// handshake of every transport the reprobe found on the wire
			// within milliseconds (five on the stand, all reset), a sweep no
			// client of one protocol makes; against a censor that drops
			// instead of resetting it would hold the tunnel's upgrade slot for
			// a connect timeout per candidate. The next reprobe makes the next
			// offer.
			log.Info("Strategy upgrade: %s failed (%v), staying on %s", next.Name(), err, cur.Name())
			return
		}
		v.handshakeUpgrade(oldConn, conn, cur, next, localIP, cand)
		return
	}
}

// handshakeUpgrade runs the TUN handshake on an upgrade's fresh conn and
// commits it, all under sessionMu so no reconnect or port hop registers a
// session on the exit in between.
func (v *VPNClient) handshakeUpgrade(oldConn, conn net.Conn, cur, next strategy.Strategy, localIP net.IP, cand endpoint.Candidate) {
	if !v.sessionMu.TryLock() {
		// A reconnect or a port hop is mid-handshake. Registering ours now
		// would evict theirs on the exit.
		conn.Close()
		log.Info("Strategy upgrade: another session change is in progress, not upgrading to %s now", next.Name())
		return
	}
	v.mu.Lock()
	stale := v.conn != oldConn || atomic.LoadInt32(&v.running) == 0 || atomic.LoadInt32(&v.reconnecting) == 1 ||
		atomic.LoadInt32(&v.portHopInProgress) == 1
	v.mu.Unlock()
	if stale {
		v.sessionMu.Unlock()
		conn.Close()
		log.Info("Strategy upgrade: the tunnel changed before the %s handshake, dropping it", next.Name())
		return
	}

	resp, n, tunnelConn, err := v.doHandshake(conn, localIP)
	if err != nil {
		v.sessionMu.Unlock()
		conn.Close()
		v.manager.UpgradeOutcome(next, false)
		if errors.Is(err, errHandshakeNotSent) || errors.Is(err, errHandshakeRefused) {
			log.Info("Strategy upgrade: %s handshake failed (%v), staying on %s", next.Name(), err, cur.Name())
			return
		}
		// The request went out and the answer did not come back: the exit may
		// already have moved the client's address to the new session, and the
		// old one with it.
		log.Info("Strategy upgrade: %s handshake lost after the request (%v), reconnecting", next.Name(), err)
		// %v, not %w: whatever the new transport ran into - a read deadline,
		// a QUIC idle timeout - says nothing about the server going quiet on
		// the tunnel the old conn was carrying.
		v.connLost(oldConn, "strategy upgrade", fmt.Errorf("%w: %v", errUpgradeRejected, err))
		return
	}
	caps, hasCaps := parseServerCapabilities(resp, n)
	v.mu.Lock()
	oldConnectedAt, oldLastRx := v.connectedAt, v.lastRx
	sessCand, hasSessCand := v.sessionCand, v.hasSessionCand
	v.mu.Unlock()
	verdict := v.swapUpgradedConn(oldConn, tunnelConn, next, net.IP(resp[1:5]), net.IP(resp[5:9]), caps, hasCaps)
	v.sessionMu.Unlock()

	switch verdict {
	case upgradeSwapped:
		oldConn.Close()
		// The fallback session the swap ends did not die, it was replaced.
		// If it was useful the endpoint has to hear it: that clears its
		// dead-session streak like any useful end. A young one - an upgrade
		// offered seconds after a reconnect - says nothing either way.
		v.manager.SessionEnded(strategy.SessionEnd{Strategy: cur.ID(), Replaced: true,
			Useful: sessionWasUseful(oldConnectedAt, oldLastRx), Endpoint: sessCand, HasEndpoint: hasSessCand})
		v.manager.RecordSessionStart(next.ID())
		log.Info("Strategy upgrade: tunnel moved from %s to %s, pending confirmation", cur.Name(), next.Name())
	case upgradeOtherAddress:
		// A different address means the exit leased the new session apart
		// from the old one (an exit older than the credential lease), so the
		// old session still stands.
		tunnelConn.Close()
		v.manager.UpgradeOutcome(next, false)
		// It will answer the same way every time; stop spending a dial and a
		// handshake per reprobe cycle on it.
		v.mu.Lock()
		if v.upgradeOff == nil {
			v.upgradeOff = make(map[string]bool)
		}
		v.upgradeOff[cand.Addr] = true
		v.mu.Unlock()
		log.Info("Strategy upgrade: the exit at %s leases per transport (older server), no more upgrades on it", cand.Addr)
	default:
		// Same address, so the exit has moved it to the new session and the
		// old one is gone with it: whatever made us drop the new one, the
		// tunnel is lost, and keeping the old conn would only wait out the
		// read deadline on a dead session.
		tunnelConn.Close()
		v.manager.UpgradeOutcome(next, false)
		v.connLost(oldConn, "strategy upgrade", errUpgradeRejected)
	}
}

// upgradeVerdict is what swapUpgradedConn decided.
type upgradeVerdict int

const (
	upgradeSwapped      upgradeVerdict = iota // installed
	upgradeOtherAddress                       // dropped: the exit gave the new session another address
	upgradeRejected                           // dropped after the exit moved the address to it
)

// swapUpgradedConn installs an upgraded conn in place of oldConn if the tunnel
// is still riding oldConn and the new session kept the tunnel's addresses.
func (v *VPNClient) swapUpgradedConn(oldConn, newConn net.Conn, strat strategy.Strategy, serverIP, assignedIP net.IP,
	caps ServerCapabilities, hasCaps bool) upgradeVerdict {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !assignedIP.Equal(v.localIP) || (v.tun != nil && !serverIP.Equal(v.tun.remoteIP)) {
		log.Warn("Strategy upgrade: %s came back with different tunnel addresses (server %s, assigned %s), staying put",
			strat.Name(), serverIP, assignedIP)
		return upgradeOtherAddress
	}
	if v.conn != oldConn || atomic.LoadInt32(&v.running) == 0 || atomic.LoadInt32(&v.reconnecting) == 1 {
		log.Info("Strategy upgrade: the tunnel changed meanwhile, dropping the %s session", strat.Name())
		return upgradeRejected
	}
	// An exit that sends no capabilities (an older one) cannot be confirmed to
	// keep the IPv6 side the tunnel runs; a lost capability block is a
	// mismatch, not a match.
	if (hasCaps && (caps.DualStackEnabled != v.serverCaps.DualStackEnabled ||
		caps.DualStackEnabled && !caps.ClientIP6.Equal(v.serverCaps.ClientIP6))) ||
		(!hasCaps && v.serverCaps.DualStackEnabled) {
		log.Warn("Strategy upgrade: %s came back with a different IPv6 assignment", strat.Name())
		return upgradeRejected
	}
	v.conn = newConn
	v.strategy = strat
	v.upgradePending = strat
	v.connectedAt = time.Now()
	v.lastRx = v.connectedAt
	v.lastData = time.Time{}
	v.stall = newFlowTable()
	if hasCaps {
		v.serverCaps = caps
	}
	return upgradeSwapped
}

// handleDisconnect handles connection loss and reconnects with exponential backoff
// and network connectivity detection. reason names the path that saw the loss
// and err is what it saw; both go to the log, where a disconnect used to show
// up without a cause.
func (v *VPNClient) handleDisconnect(reason string, err error) {
	v.disconnect(nil, reason, err)
}

// disconnect is handleDisconnect for a loss seen on conn; nil means "the
// tunnel, whatever conn it is on". A conn the tunnel has already replaced is
// ignored. The check is made after taking the reconnect slot and under the
// same lock that closes the conn, so a swap landing in between cannot get its
// fresh conn closed by a loss reported on the old one.
func (v *VPNClient) disconnect(conn net.Conn, reason string, err error) {
	// Skip if seamless port hop is in progress (it handles its own reconnect)
	if atomic.LoadInt32(&v.portHopInProgress) == 1 {
		log.Debug("Port hop in progress, skipping handleDisconnect")
		return
	}

	// Prevent concurrent reconnect attempts from multiple goroutines
	// (readFromTun, readFromServer, sendKeepalive can all call this)
	if !atomic.CompareAndSwapInt32(&v.reconnecting, 0, 1) {
		log.Debug("Reconnect already in progress, skipping")
		return
	}
	defer atomic.StoreInt32(&v.reconnecting, 0)
	if v.manager != nil {
		v.manager.HoldReprobe(true)
		defer v.manager.HoldReprobe(false)
	}

	v.mu.Lock()
	if conn != nil && v.conn != nil && v.conn != conn {
		v.mu.Unlock()
		log.Debug("%s failed on a replaced connection (%v), the tunnel has moved on", reason, err)
		return
	}
	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
	}
	endedStrategy := v.strategy
	connectedAt, lastRx := v.connectedAt, v.lastRx
	sessionCand, hasSessionCand := v.sessionCand, v.hasSessionCand
	pendingUpgrade := v.upgradePending
	v.upgradePending = nil
	if hasSessionCand {
		delete(v.upgradeOff, sessionCand.Addr)
	}
	v.mu.Unlock()

	if pendingUpgrade != nil && v.manager != nil {
		// The upgraded session ended before it had carried traffic for
		// sessionUsefulMin: the upgrade failed, whatever the dial said.
		v.manager.UpgradeOutcome(pendingUpgrade, false)
	}

	// Update strategy confidence and feed the storm detector. A session that
	// connected fine but died within seconds is the signature of DPI tearing
	// down a strategy's pattern: connect() keeps succeeding so the circuit
	// breaker never trips, but the tunnel carries no traffic. The detector
	// catches this by session lifetime and (in auto mode) parks the strategy so
	// the next reconnect picks a different one.
	silent := serverWentSilent(err)
	if endedStrategy != nil && v.manager != nil {
		// Connected, carried a moment, then nothing until the deadline: the
		// endpoint's verdict, not the transport's (SessionEnd.Dead). A reset
		// or an EOF proves the server was there and stays the storm
		// detector's business. And the client's own link is asked first: a
		// link that dropped right after a reconnect kills the session just
		// the same, and parking the server for it is D7 over again.
		//
		// Not while an upgrade is pending: that session is the upgrade's, and
		// its death says the new strategy failed (UpgradeOutcome above), not
		// that the server - which just carried the fallback - is dead.
		//
		// A degraded session (the stall detector's verdict) is booked the
		// same way whatever its age, once: not also as dead.
		_, degraded := errors.AsType[*sessionDegradedError](err)
		dead := pendingUpgrade == nil && silent && !degraded && sessionDiedYoung(connectedAt, lastRx)
		v.manager.SessionEnded(strategy.SessionEnd{
			Strategy:       endedStrategy.ID(),
			Endpoint:       sessionCand,
			HasEndpoint:    hasSessionCand,
			Useful:         sessionWasUseful(connectedAt, lastRx) && !degraded,
			Dead:           dead,
			Degraded:       degraded && pendingUpgrade == nil,
			UpgradeFailed:  pendingUpgrade != nil,
			LocalNetworkUp: probeLocalLink,
		})
	}

	// Initialize exponential backoff
	currentDelay := reconnectInitialDelay
	consecutiveFailures := 0
	lastNetworkCheck := time.Time{}
	networkAvailable := true
	var poolSilentSince time.Time // when the gate first found nobody in the pool answering

	strategyName := "unknown"
	if endedStrategy != nil {
		strategyName = endedStrategy.Name()
	}
	log.Warn("VPN disconnected: %s: %v (strategy=%s, session=%s, last downlink %s ago), starting reconnect with exponential backoff",
		reason, err, strategyName, sinceOrUnknown(connectedAt), sinceOrUnknown(lastRx))

	// A server that went quiet may be gone. Have the first reconnect walk the
	// pool through the pre-flight gate instead of spending its budget on one
	// silent address, and skip the network check below on that attempt: it
	// stops at the first silent address after 3 seconds and tells the gate
	// nothing, while the gate answers the same question for the whole pool.
	gateArmed := false
	if silent && v.manager != nil {
		v.manager.NoteServerSilent()
		gateArmed = v.manager.ConnectivityChecker() != nil
	}

	// Try to reconnect with exponential backoff
	for atomic.LoadInt32(&v.running) == 1 {
		consecutiveFailures++

		// Check network connectivity periodically (every 10 failures or 30 seconds)
		// This prevents wasting resources when network is down
		if !gateArmed && (consecutiveFailures%10 == 0 || time.Since(lastNetworkCheck) > 30*time.Second) {
			networkAvailable = v.checkNetworkConnectivity()
			lastNetworkCheck = time.Now()

			if !networkAvailable {
				// Reset circuit breakers since failures are due to no network
				if v.manager != nil {
					v.manager.ResetForNetworkChange()
				}
				log.Warn("No network connectivity, waiting for network to restore...")
				if !v.waitForNetworkRestore() {
					return
				}
				// After the wait, reset backoff and fall through to a real
				// connect attempt. Falling through instead of continue is the
				// point: the probe that said "no network" can itself be wrong,
				// so every wait must end in an actual dial rather than in
				// another probe round that parks again.
				currentDelay = reconnectInitialDelay
				consecutiveFailures = 1
			}
		}

		log.Info("Reconnecting VPN (attempt %d, backoff %v)...", consecutiveFailures, currentDelay)

		// Use shorter timeout for reconnect attempts
		connectTimeout := reconnectConnectTimeout
		if currentDelay > 30*time.Second {
			connectTimeout = 30 * time.Second // Longer timeout for longer backoffs
		}

		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		err := v.connect(ctx)
		cancel()
		gateArmed = false

		if err == nil {
			atomic.AddInt64(&v.reconnectsOK, 1)
			log.Info("VPN reconnected successfully after %d attempts", consecutiveFailures)
			// Re-probe MTU on reconnect (network change may shift path-MTU). Uses a
			// background context, not the short-lived connect ctx; the probe is
			// self-bounded by its own deadlines.
			v.maybeStartMTUProbe(context.Background(), "reconnect")
			return
		}

		atomic.AddInt64(&v.reconnectsFail, 1)

		if errors.Is(err, strategy.ErrNoServerAnswered) {
			// The gate walked the pool and nobody answered. Doubling the pause
			// here only stretches the time between the pool coming back and us
			// noticing: at the 2-minute cap that was up to 156 s of outage after
			// the provider's line returned. Wait for an answer instead, then
			// dial at once through the gate, which pins whoever answered.
			if poolSilentSince.IsZero() {
				poolSilentSince = time.Now()
			}
			if !v.waitOutSilentPool(err, poolSilentSince) {
				return
			}
			currentDelay = reconnectInitialDelay
			lastNetworkCheck = time.Now()
			if v.manager != nil {
				v.manager.NoteServerSilent()
				gateArmed = v.manager.ConnectivityChecker() != nil
			}
			continue
		}
		poolSilentSince = time.Time{}

		// A cycle that heard nothing waits no longer than the silence cap,
		// whatever the backoff grew to on failures before it.
		currentDelay = capReconnectDelay(currentDelay, err)

		// Classify error type for better logging
		errType := classifyError(err)
		log.Warn("Reconnect failed (%s): %v, next attempt in %v", errType, err, currentDelay)

		v.unblockStrategies()

		// Wait with jitter before next attempt
		select {
		case <-v.stopCh:
			log.Info("Reconnect cancelled (VPN stopped)")
			return
		case <-time.After(addJitter(currentDelay)):
		}

		currentDelay = nextReconnectDelay(currentDelay, err)
	}
}

// unblockStrategies resets the strategies when every one of them is blocked
// (circuit breakers open, confidence on the floor) - the strategies only: the
// network did not change, and what the client learned about the endpoints
// stays (see Manager.ResetStrategyBlocks).
func (v *VPNClient) unblockStrategies() {
	if v.manager != nil && !v.manager.HasAvailableStrategies() {
		log.Warn("All strategies blocked by circuit breakers, resetting...")
		v.manager.ResetStrategyBlocks()
	}
}

// sessionUsefulMin is how long a session's downlink has to keep going for its
// end to say nothing against the strategy that carried it. It is the storm
// detector's short-session line: below it a session dying is what a DPI
// teardown looks like; above it, it is what a server restart or a dead link
// looks like.
const sessionUsefulMin = 20 * time.Second

// deadSessionMax is the endpoint verdict's line, kept apart from
// sessionUsefulMin: a session that ends in silence with its downlink alive for
// less than this died young. The downlink clock is lastRx, and HTTP Polling's
// keepalive feeder moves lastRx for the poll health grace (20 s) after the
// last real poll, so its dead sessions measure 19.83-19.94 s (PR #126 bytecap
// runs) and one 29.86 s; REALITY's measure 0.5-1.7 s. 40 s clears the worst
// of them by 10 s. A useful session lives for minutes.
const deadSessionMax = 40 * time.Second

// sessionDiedYoung reports a session whose downlink stopped within
// deadSessionMax of connecting.
func sessionDiedYoung(connectedAt, lastRx time.Time) bool {
	return !connectedAt.IsZero() && lastRx.Sub(connectedAt) < deadSessionMax
}

// sessionWasUseful reports whether the session carried downlink for at least
// sessionUsefulMin. lastRx, not the moment of disconnect: a tunnel frozen a
// second after it came up still takes readTimeout to be declared dead.
func sessionWasUseful(connectedAt, lastRx time.Time) bool {
	return !connectedAt.IsZero() && lastRx.Sub(connectedAt) >= sessionUsefulMin
}

// markSilence tags err as the server's silence when it came back at or after
// the read deadline the client itself set. Reads only: a write that runs into
// its deadline says the local uplink is stuck (bufferbloat), not that the
// server went quiet.
//
// The error alone does not say so reliably. smux v2, which carries every
// REALITY tunnel, reports its deadline as errors.WithStack(errors.New("timeout"))
// - neither os.ErrDeadlineExceeded nor a net.Error - so on the stand not one of
// fourteen REALITY silences was recognised, and neither the pool walk after a
// silent server (D1) nor the dead-session verdict (D6) ever ran for REALITY.
// The client knows when it armed the deadline; that is the evidence.
func markSilence(err error, deadline time.Time) error {
	if err == nil || time.Now().Before(deadline) {
		return err
	}
	return &silenceError{err: err}
}

// silenceError is a transport error that came back at the client's own
// deadline. It reads like the error it wraps and matches
// strategy.ErrServerSilent.
type silenceError struct{ err error }

func (e *silenceError) Error() string        { return e.err.Error() }
func (e *silenceError) Unwrap() error        { return e.err }
func (e *silenceError) Is(target error) bool { return target == strategy.ErrServerSilent }

// uplinkError is a tunnel write that failed. It reads like the error it
// wraps but matches nothing: a write that runs into its deadline says the
// local uplink is stuck (bufferbloat), not that the server went quiet, and
// on a raw TCP transport (Geneva, Stego, WS) that deadline comes back as a
// net.Error with Timeout(), which serverWentSilent would take for silence.
type uplinkError struct{ err error }

func (e *uplinkError) Error() string { return e.err.Error() }

// uplinkFailed hides a write error's timeout from the silence classifiers.
func uplinkFailed(err error) error { return &uplinkError{err: err} }

// serverWentSilent reports a disconnect caused by a deadline - the server
// stopped answering - as opposed to a close, a reset or a protocol error, all of
// which prove the server was there to send them. HTTP Polling's health grace
// says the same thing in its own words (strategy.ErrServerSilent).
func serverWentSilent(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, strategy.ErrServerSilent) {
		return true
	}
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}

// networkCheckTimeout bounds one connectivity probe from the reconnect loop.
const networkCheckTimeout = 3 * time.Second

// checkNetworkConnectivity answers "is there a network at all", in two steps:
// the server first, then a well-known public host.
//
// The server step goes through the manager's own connectivity gate, which dials
// the pinned endpoint (and its sibling address) on the real transport port.
// This used to be hand-rolled here and additionally dialled :443 and :80 on the
// server's own host - a three-port scan of our own machine, run on a timer, and
// a signature in its own right. It also only ever spoke IPv4, so a v6-only
// endpoint reported "no network" forever.
//
// The second step is unchanged and is what distinguishes "the network is down"
// from "the network is up and the server is not": the caller parks in
// waitForNetworkRestore only for the former.
func (v *VPNClient) checkNetworkConnectivity() bool {
	ctx, cancel := context.WithTimeout(context.Background(), networkCheckTimeout)
	defer cancel()

	if v.manager != nil {
		if checker := v.manager.ConnectivityChecker(); checker != nil {
			if checker.CheckTCP(ctx).HasBasicConnectivity() {
				return true
			}
		} else if v.serverAddr != "" {
			// No gate configured (macOS, benchmarks): one dial of the real
			// address, and nothing else.
			conn, err := net.DialTimeout("tcp", v.serverAddr, networkCheckTimeout)
			if err == nil {
				conn.Close()
				return true
			}
		}
	}

	return probeInternet()
}

// reconnectConnectTimeout bounds one reconnect attempt. A var so tests can
// shorten it.
var reconnectConnectTimeout = 15 * time.Second

// Pool polling while no server answers (see waitForPool). Vars so tests can
// shorten them.
//
// One address per round, rotating through the pool. A round of the whole pool
// in a row - what this did first - was a sequential SYN sweep of every server
// on a strict 17 s period, exactly when the servers are silent while the local
// network works, which is what an IP block looks like: those SYNs cross the
// censor.
//
// The pause between rounds is drawn, not fixed (see poolPause). base is 5 s
// for the first two minutes (a provider's line flapping), then grows by half
// per round up to a minute. A silent dial adds its own poolDialTimeout (3 s)
// before the pause starts. Simulated over the real functions (2000 runs): a
// dial every 4.3-8.0 s in the first two minutes (median 6.2), then every
// 18-63 s (median 41.3, p90 56.7), about 42 dials in the first 15 minutes of
// silence. How late a recovered server is noticed, 15 minutes into the
// silence, coming back at a uniformly random moment (4000 runs): the whole
// pool back (the client's own uplink returning) - median 23 s, worst 61 s; one
// server of two (2 addresses) - median 43 s, p99 100 s, worst 116 s; one
// address of 4 - median 90 s, p99 188 s, worst 220 s. There is no measured
// reference distribution; the point is no grid, no hard minimum gap and fewer
// SYNs the longer the silence.
var (
	poolPollInterval = 5 * time.Second
	poolFastPhase    = 2 * time.Minute
	poolPollMax      = time.Minute
	poolDialTimeout  = 3 * time.Second

	// poolDial opens the poll's one connection. Tests replace it.
	poolDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
)

// poolPollGrowth is the factor the base pause grows by after the fast phase.
const poolPollGrowth = 1.5

// nextPoolBase is the base pause for the next round, given the current one and
// how long the pool has been silent.
func nextPoolBase(cur, silentFor time.Duration) time.Duration {
	if silentFor < poolFastPhase {
		return poolPollInterval
	}
	return min(time.Duration(float64(cur)*poolPollGrowth), poolPollMax)
}

// poolPause draws the actual pause under base: HumpDelay(base/4, 3/4 base,
// base). The ceiling is base, not twice it: with 2 x base (round 3) the
// long-run gap reached 123 s, and a client whose own uplink came back waited up
// to two minutes for the next dial, against 63 s before the pauses were drawn.
// The shape is a hump, not RandomDelay's exponential: that put 40% of the
// pauses in the lowest fifth of the range and made base/2 plus the dial
// timeout a hard minimum gap (round-3 review, P3-18).
func poolPause(base time.Duration) time.Duration {
	return strategy.HumpDelay(base/4, 3*base/4, base)
}

// waitOutSilentPool decides what a "nobody in the pool answers" verdict means
// and waits accordingly. The gateway is the third party that tells the two
// stories apart: if it does not answer either, the network is down and the
// usual network wait applies; if it does, the servers are unreachable from a
// working network and only the pool itself can say when that ends. Returns
// false only when the client was stopped.
func (v *VPNClient) waitOutSilentPool(err error, since time.Time) bool {
	if !probeInternet() {
		if v.manager != nil {
			v.manager.ResetForNetworkChange()
		}
		log.Warn("No network connectivity, waiting for network to restore...")
		return v.waitForNetworkRestore()
	}
	log.Warn("No server in the pool answers (%v) while the local network does - polling the pool instead of backing off", err)
	return v.waitForPool(since)
}

// waitForPool polls the pool, one rotating address per round (see
// poolPollInterval for the schedule), until an address answers, and pins the
// candidate that did. Pinning matters: the reconnect's gate walks the pool from
// the pin, 3 s per silent address, and with several silent addresses ahead of
// the live one its budget ran out before reaching it, so the client found the
// live server here and could not get to it there, round after round.
// Returns false only when the client was stopped.
//
// A server parked for dead sessions that answers is passed over (see
// Manager.PinAnswering), but not for longer than poolDeadParkWait: that park
// doubles up to MaxCooldown, 30 minutes by default, and with nothing else
// answering - a single-server pool - the client would wait it out in full.
func (v *VPNClient) waitForPool(since time.Time) bool {
	base := poolPollInterval
	var parkedSince time.Time // when a dead-session-parked server first answered
	for atomic.LoadInt32(&v.running) == 1 {
		select {
		case <-v.stopCh:
			return false
		case <-time.After(poolPause(base)):
		}
		addr, ok := v.pollOneServer()
		if ok && (v.manager == nil || v.manager.PinAnswering(addr)) {
			log.Info("Server %s answers again after %v of pool silence", addr, time.Since(since).Round(time.Second))
			return true
		}
		if ok {
			if parkedSince.IsZero() {
				parkedSince = time.Now()
			} else if time.Since(parkedSince) >= poolDeadParkWait {
				v.manager.PinParkedAnswering(addr)
				return true
			}
		}
		base = nextPoolBase(base, time.Since(since))
	}
	return false
}

// poolDeadParkWait is how long the pool poll passes over a server parked for
// dead sessions that answers while nothing else does. A var so tests can
// shorten it.
var poolDeadParkWait = 2 * time.Minute

// pollOneServer dials the next address of the pool in rotation, TCP only.
func (v *VPNClient) pollOneServer() (string, bool) {
	var addrs []string
	if v.manager != nil {
		addrs = v.manager.PoolAddrs()
	}
	if len(addrs) == 0 && v.serverAddr != "" {
		addrs = []string{v.serverAddr}
	}
	if len(addrs) == 0 {
		return "", false
	}
	addr := addrs[v.poolRound%len(addrs)]
	v.poolRound++

	ctx, cancel := context.WithTimeout(context.Background(), poolDialTimeout)
	defer cancel()
	conn, err := poolDial(ctx, "tcp", addr)
	if err != nil {
		return "", false
	}
	conn.Close()
	return addr, true
}

// errMeansPathAlive reports whether a dial error still suggests the path is
// up rather than silently dead. An immediate refusal usually means an RST
// came back - packets flowed both ways. A local firewall can fake that with a
// REJECT rule, but the caller only uses "alive" to keep retrying the
// connection instead of parking, which is the safe direction to err in.
// Refusals matter because the gate dials the default-route gateway, and
// consumer routers routinely have port 53 closed.
func errMeansPathAlive(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// dialMeansAlive dials addr and treats both a completed connect and an
// immediate refusal as "the path answers". The dial is protected, so on
// Android it cannot be routed into the tunnel; elsewhere that is a plain dial.
func dialMeansAlive(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), networkCheckTimeout)
	defer cancel()
	conn, err := (&protect.ProtectDialer{}).DialContext(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return true
	}
	return errMeansPathAlive(err)
}

// publicFallbackProbes are the last-resort dial targets when no physical
// gateway was resolved (non-Linux platforms, exotic setups). These addresses
// are routinely part of the installed TUN routes, so while the tunnel is down
// they black-hole - which is why they are probes of last resort, not first.
var publicFallbackProbes = []string{"8.8.8.8:53", "1.1.1.1:53"}

// probeInternet is internetReachable, replaceable in tests: the real one dials
// the host's default gateway.
var probeInternet = internetReachable

// probeLocalLink is localLinkUp, replaceable in tests.
var probeLocalLink = localLinkUp

// gatewayAddrs is physicalGateAddrs, replaceable in tests.
var gatewayAddrs = physicalGateAddrs

// localLinkUp reports whether the client's own link is up, for decisions that
// charge a server: true when a physical default-route gateway answers (Linux:
// the main table, or any table when main has no default, as on Android;
// macOS: the routing socket), or on Android when a public resolver answers
// over the underlying network (linkFallbackProbes). Without either it cannot
// tell and says no. Desktop does not use public resolvers here: they sit
// behind the tunnel's own routes - a coin toss, and up to 6 s of waiting
// before every reconnect - which is fine for internetReachable's "should I
// wait for the network" and not for "may I blame the server".
//
// The addresses of each group are dialled at once, not one after another:
// one silent gateway (an interface-scoped default on macOS, a dead family)
// cost networkCheckTimeout each, and the answer holds up the end of a
// session. The fallback probes go out together for the same reason, and so
// carry no fixed order on the wire.
func localLinkUp() bool {
	if anyDialAlive(gatewayAddrs()) {
		return true
	}
	return anyDialAlive(linkFallbackProbes)
}

// anyDialAlive dials every address at once and reports whether one answered
// (dialMeansAlive), as soon as one does.
func anyDialAlive(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	alive := make(chan bool, len(addrs))
	for _, addr := range addrs {
		go func() { alive <- dialMeansAlive(addr) }()
	}
	for range addrs {
		if <-alive {
			return true
		}
	}
	return false
}

// internetReachable reports whether anything outside answers. It must never
// probe through the VPN tunnel itself: while the tunnel is down its routes
// stay installed, and a probe routed into a dead TUN device reads as "no
// network" - the exact false negative that used to park the reconnect loop
// forever while the physical link was fine (8.8.8.8, 8.8.4.8, 9.9.9.9 and
// 1.1.1.1 are all part of the installed tunnel routes). The default-route
// gateway is probed first precisely because it cannot take the tunnel; public
// resolvers remain the fallback for setups where no gateway was resolved.
// It is deliberately NOT a check of our own server: the caller needs to tell
// a dead link apart from a blocked endpoint, and only a third party can do
// that.
func internetReachable() bool {
	for _, addr := range physicalGateAddrs() {
		if dialMeansAlive(addr) {
			return true
		}
	}
	for _, addr := range publicFallbackProbes {
		conn, err := net.DialTimeout("tcp", addr, networkCheckTimeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// networkParkTimeout caps one wait for "network restore". The wait's own probe
// can be wrong about the network being down, so parking must stay bounded:
// past the cap the caller retries the real connection instead of trusting the
// probe indefinitely.
const networkParkTimeout = 2 * time.Minute

// waitForNetworkRestore waits until network connectivity is restored, at most
// networkParkTimeout. Returns false only when the client was stopped; a
// timeout returns true so the caller goes straight to a real connect attempt -
// the negative verdict that caused the wait can itself be wrong.
func (v *VPNClient) waitForNetworkRestore() bool {
	checkInterval := 5 * time.Second
	deadline := time.Now().Add(networkParkTimeout)
	attempt := 0

	for atomic.LoadInt32(&v.running) == 1 {
		attempt++
		if attempt%12 == 0 { // Every minute
			log.Info("Still waiting for network connectivity (attempt %d)...", attempt)
		}

		select {
		case <-v.stopCh:
			return false
		case <-time.After(checkInterval):
		}

		if v.checkNetworkConnectivity() {
			log.Info("Network connectivity restored after %d checks", attempt)
			return true
		}

		if time.Now().After(deadline) {
			log.Warn("Network still considered down after %v - retrying connection anyway", networkParkTimeout)
			return true
		}
	}
	return false
}

// addJitter adds random jitter to a duration (+/- jitterFactor)
func addJitter(d time.Duration) time.Duration {
	jitter := float64(d) * reconnectJitterFactor * (2*rand.Float64() - 1)
	return d + time.Duration(jitter)
}

// classifyError returns a short description of the error type
func classifyError(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()

	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
		return "timeout"
	}
	if strings.Contains(errStr, "connection refused") {
		return "refused"
	}
	if strings.Contains(errStr, "no route") || strings.Contains(errStr, "unreachable") {
		return "no_route"
	}
	if strings.Contains(errStr, "network is down") || strings.Contains(errStr, "no network") {
		return "network_down"
	}
	if strings.Contains(errStr, "all strategies failed") {
		return "strategies_exhausted"
	}
	if strings.Contains(errStr, "circuit") {
		return "circuit_breaker"
	}
	if strings.Contains(errStr, "EOF") || strings.Contains(errStr, "reset") {
		return "connection_reset"
	}

	return "unknown"
}

// Stop stops the VPN tunnel
func (v *VPNClient) Stop() {
	if !atomic.CompareAndSwapInt32(&v.running, 1, 0) {
		return
	}

	close(v.stopCh)

	// Abort any in-flight connect() dial/handshake. connect() does NOT hold
	// v.mu while dialing, so cancelling its context (and, below, closing the
	// conn) lets Stop() proceed without waiting on a 10-30s network timeout.
	if cancel := v.connCancel.Swap(nil); cancel != nil {
		(*cancel)()
	}

	// Set immediate deadline to unblock any blocking reads before closing.
	v.mu.Lock()
	live := v.conn != nil
	if v.conn != nil {
		v.conn.SetDeadline(time.Now()) // Force immediate timeout
		v.conn.Close()
		v.conn = nil // nothing may be swapped in on top of a stopped client
	}
	endedStrategy, sessionCand, hasSessionCand := v.strategy, v.sessionCand, v.hasSessionCand
	// Data down, not keepalive echoes: a tunnel alive but useless echoes
	// keepalives to the end, and stopping it must not clear its server's
	// backoff (P3-4 of the round-6 review).
	useful := live && sessionWasUseful(v.connectedAt, v.lastData)
	v.mu.Unlock()

	// A session the user stopped after it carried traffic is evidence for its
	// server like any useful one: it ends the server's run of verdicts and its
	// backoff (P3-4 of the round-5 review). Booked as replaced - the tunnel
	// did not die - so nothing counts against the strategy.
	if useful && endedStrategy != nil && v.manager != nil {
		v.manager.SessionEnded(strategy.SessionEnd{Strategy: endedStrategy.ID(), Endpoint: sessionCand,
			HasEndpoint: hasSessionCand, Useful: true, Replaced: true})
	}

	// Unblock TUN read goroutine and close
	v.tun.SetReadDeadline(time.Now())
	v.tun.Close()

	// Through Stats: the packet loops may still be counting.
	pu, pd, bu, bd := v.Stats()
	log.Info("VPN tunnel stopped (packets: up=%d down=%d, bytes: up=%d down=%d)", pu, pd, bu, bd)
}

// Stats returns current VPN statistics
func (v *VPNClient) Stats() (packetsUp, packetsDown, bytesUp, bytesDown int64) {
	return atomic.LoadInt64(&v.packetsUp),
		atomic.LoadInt64(&v.packetsDown),
		atomic.LoadInt64(&v.bytesUp),
		atomic.LoadInt64(&v.bytesDown)
}

// LifecycleStats returns cumulative tunnel lifecycle counters: total successful
// tunnel establishments, successful reconnects and failed reconnect attempts.
// The client's metrics syncer polls these to feed connections_total and
// reconnects_total.
func (v *VPNClient) LifecycleStats() (connects, reconnectsOK, reconnectsFail int64) {
	return atomic.LoadInt64(&v.tunnelConnects),
		atomic.LoadInt64(&v.reconnectsOK),
		atomic.LoadInt64(&v.reconnectsFail)
}

// CurrentStrategy returns the current strategy being used
func (v *VPNClient) CurrentStrategy() strategy.Strategy {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.strategy
}

// RunTUNRelay runs packet relay between TUN device and server connection
// This is used by control socket mode where connection is already established
// If stopCh is nil, creates internal one; if provided, uses external control
func RunTUNRelay(tunDev *TUNDevice, serverConn net.Conn, localIP, remoteIP net.IP) {
	RunTUNRelayWithStop(tunDev, serverConn, localIP, remoteIP, nil)
}

// RelayErrorCallback is called when relay dies due to network error
// Deprecated: use RelayCallbacks instead
type RelayErrorCallback func(reason string)

// RelayCallbacks contains all callbacks for TUN relay events
type RelayCallbacks struct {
	OnError     func(reason string) // Called when relay dies (timeout, read error, etc.)
	OnKeepalive func()              // Called when keepalive received from server
	// OnSessionEnd is called once when the relay's session ends on its own,
	// before OnError: what the session was, for whoever books its end against
	// the strategy and the endpoint. Not called when the owner stopped it.
	OnSessionEnd func(RelaySessionEnd)
	// Strategy carries the session, when known: the stall detector looks for
	// its keepalive counter by it as well as by the conn (echoSourceFor).
	Strategy strategy.Strategy
}

// RelaySessionEnd describes a relay's session that has just ended.
type RelaySessionEnd struct {
	Lifetime time.Duration // from the relay's start
	Reason   string        // what OnError is about to report
	// Degraded is the stall detector's verdict: alive but useless. Stall is
	// how long the oldest demand waited.
	Degraded bool
	Stall    time.Duration
}

// RunTUNRelayWithStop runs packet relay with external stop control
func RunTUNRelayWithStop(tunDev *TUNDevice, serverConn net.Conn, localIP, remoteIP net.IP, externalStopCh chan struct{}) {
	RunTUNRelayWithCallbacks(tunDev, serverConn, localIP, remoteIP, externalStopCh, nil)
}

// RunTUNRelayWithCallback runs packet relay with external stop control and error callback
// Deprecated: use RunTUNRelayWithCallbacks for full event support
func RunTUNRelayWithCallback(tunDev *TUNDevice, serverConn net.Conn, localIP, remoteIP net.IP, externalStopCh chan struct{}, onError RelayErrorCallback) {
	var callbacks *RelayCallbacks
	if onError != nil {
		callbacks = &RelayCallbacks{OnError: onError}
	}
	RunTUNRelayWithCallbacks(tunDev, serverConn, localIP, remoteIP, externalStopCh, callbacks)
}

// RunTUNRelayWithCallbacks runs packet relay with external stop control and full callback support
// Includes proactive dead connection detection (45s timeout) and keepalive event notifications
func RunTUNRelayWithCallbacks(tunDev *TUNDevice, serverConn net.Conn, localIP, remoteIP net.IP, externalStopCh chan struct{}, callbacks *RelayCallbacks) {
	newTUNRelay(tunDev, serverConn, localIP, remoteIP, externalStopCh, callbacks).run()
}

// tunRelay is one relay over a server connection, with a handle that lets
// the TUN side be replaced while it runs.
//
// With an external stop channel the server connection belongs to whoever
// started the relay (the control server's session), not to the relay: a
// relay its owner stopped leaves the connection alone and reports nothing,
// because the owner is either closing the connection itself or handing it
// on. Only a relay that dies on its own - a read or write on the connection
// failing while nobody asked it to stop - closes the connection and reports
// OnError. Without an external stop channel the relay owns the connection
// and always closes it, as before.
type tunRelay struct {
	serverConn net.Conn
	remoteIP   net.IP
	localIP    net.IP
	callbacks  *RelayCallbacks

	stopCh       chan struct{}
	ownerStopped func() bool // the external stop channel was closed
	safeClose    func()

	tun          atomic.Pointer[TUNDevice] // where server->TUN writes go
	lastActivity atomic.Int64

	// stall is the stall detector's state for this relay's session (one
	// relay, one server connection); startedAt is when the session began and
	// degraded the detector's verdict, once given.
	stall     relayStall
	startedAt time.Time
	degraded  atomic.Pointer[sessionDegradedError]

	// firstDev/firstStop are the reader run starts with, fixed at
	// construction: a SwapTUN that lands before run gets going must still
	// find - and stop - the reader of the device it replaces.
	firstDev  *TUNDevice
	firstStop chan struct{}

	mu         sync.Mutex
	readerStop chan struct{} // stops the reader of the current TUN only
	done       chan struct{} // closed when run returns
}

func newTUNRelay(tunDev *TUNDevice, serverConn net.Conn, localIP, remoteIP net.IP, externalStopCh chan struct{}, callbacks *RelayCallbacks) *tunRelay {
	stopCh, safeClose := makeStopChannel(externalStopCh)
	r := &tunRelay{
		serverConn: serverConn,
		localIP:    localIP,
		remoteIP:   remoteIP,
		callbacks:  callbacks,
		stopCh:     stopCh,
		safeClose:  safeClose,
		readerStop: make(chan struct{}),
		done:       make(chan struct{}),
		startedAt:  time.Now(),
	}
	r.ownerStopped = func() bool {
		if externalStopCh == nil {
			return false
		}
		select {
		case <-externalStopCh:
			return true
		default:
			return false
		}
	}
	r.tun.Store(tunDev)
	r.firstDev, r.firstStop = tunDev, r.readerStop
	r.updateActivity()
	return r
}

// startTUNRelay runs a relay in its own goroutine and returns its handle.
func startTUNRelay(tunDev *TUNDevice, serverConn net.Conn, localIP, remoteIP net.IP, externalStopCh chan struct{}, callbacks *RelayCallbacks) *tunRelay {
	r := newTUNRelay(tunDev, serverConn, localIP, remoteIP, externalStopCh, callbacks)
	go r.run()
	return r
}

func (r *tunRelay) updateActivity() { r.lastActivity.Store(time.Now().UnixNano()) }

func (r *tunRelay) idleDuration() time.Duration {
	return time.Since(time.Unix(0, r.lastActivity.Load()))
}

// connFailed is called when a write on the server connection fails. A
// relay its owner did not stop treats that as the connection dying and
// closes it, so the server reader fails at once and the death is reported
// now instead of after the read timeout.
func (r *tunRelay) connFailed() {
	if !r.ownerStopped() {
		r.serverConn.Close()
	}
}

func (r *tunRelay) run() {
	defer close(r.done)
	log.Info("Starting TUN relay (local=%s, remote=%s)", r.localIP, r.remoteIP)

	// Both helpers stop with this relay, not only with its owner: after the
	// relay died on its own nobody may close stopCh for a long time, and a
	// monitor left running would report the same death again 45s later -
	// after a restart, into a control connection that no longer exists.
	go runDeadConnectionMonitor(r.stopCh, r.done, r.safeClose, r.idleDuration, r.callbacks)
	go runKeepaliveSender(r.stopCh, r.done, r.serverConn, r.connFailed)
	go runTUNToServer(r.stopCh, r.firstStop, r.safeClose, r.firstDev, r.serverConn, r.updateActivity, r.connFailed, &r.stall)
	go r.watchStalls()

	errorReason := runServerToTUN(r.stopCh, r.safeClose, &r.tun, r.serverConn, r.remoteIP, r.updateActivity, r.callbacks, &r.stall)
	if d := r.degraded.Load(); d != nil {
		errorReason = "session_degraded: " + d.Error()
	}

	r.safeClose()
	if r.ownerStopped() {
		// The owner stopped us and keeps the connection; whatever the reader
		// returned (its read was cut short on purpose) is not a death.
		log.Info("TUN relay stopped by its owner")
		return
	}
	r.serverConn.Close()
	log.Info("TUN relay stopped (reason: %s)", errorReason)

	if r.callbacks != nil && r.callbacks.OnSessionEnd != nil {
		end := RelaySessionEnd{Lifetime: time.Since(r.startedAt), Reason: errorReason}
		if d := r.degraded.Load(); d != nil {
			end.Degraded, end.Stall = true, d.stall
		}
		r.callbacks.OnSessionEnd(end)
	}
	if r.callbacks != nil && r.callbacks.OnError != nil && errorReason != "" {
		r.callbacks.OnError(errorReason)
	}
}

// SwapTUN moves a running relay onto newDev. The server connection, the
// server reader, the keepalive sender and the dead-connection monitor carry
// on untouched: from the exit's side nothing happens. Server->TUN writes go
// to newDev from now on, a reader for newDev starts, and the reader of the
// previous device is told to stop; the caller closes that device, which
// wakes the reader if it is blocked. Reports false if the relay is no longer
// running, in which case nothing changed.
func (r *tunRelay) SwapTUN(newDev *TUNDevice) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return false
	default:
	}
	if r.ownerStopped() {
		return false
	}
	close(r.readerStop)
	r.readerStop = make(chan struct{})
	r.tun.Store(newDev)
	go runTUNToServer(r.stopCh, r.readerStop, r.safeClose, newDev, r.serverConn, r.updateActivity, r.connFailed, &r.stall)
	return true
}

// makeStopChannel returns the stop channel and a safe-close function.
// If externalStopCh is provided it is used directly; otherwise a new channel is created.
func makeStopChannel(externalStopCh chan struct{}) (chan struct{}, func()) {
	if externalStopCh != nil {
		return externalStopCh, func() {}
	}
	stopCh := make(chan struct{})
	var once sync.Once
	return stopCh, func() { once.Do(func() { close(stopCh) }) }
}

// runDeadConnectionMonitor periodically checks for idle connections and triggers safeClose.
func runDeadConnectionMonitor(stopCh chan struct{}, relayDone <-chan struct{}, safeClose func(), getIdleDuration func() time.Duration, callbacks *RelayCallbacks) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			idle := getIdleDuration()
			if idle > deadConnectionTimeout {
				log.Warn("Connection dead: no activity for %v", idle)
				if callbacks != nil && callbacks.OnError != nil {
					callbacks.OnError(fmt.Sprintf("no_activity: %v", idle))
				}
				safeClose()
				return
			}
		case <-stopCh:
			return
		case <-relayDone:
			return
		}
	}
}

// runKeepaliveSender periodically writes zero-length keepalive frames to serverConn.
func runKeepaliveSender(stopCh chan struct{}, relayDone <-chan struct{}, serverConn net.Conn, connFailed func()) {
	ticker := time.NewTicker(keepaliveInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			keepalive := make([]byte, 4)
			serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := serverConn.Write(keepalive); err != nil {
				log.Debug("Keepalive write error: %v", err)
				connFailed()
				return
			}
			log.Debug("Sent keepalive")
		case <-stopCh:
			return
		case <-relayDone:
			return
		}
	}
}

// runTUNToServer reads IP packets from one TUN device and frames them to
// serverConn. readerStop ends this reader alone (the relay moved to another
// device); stopCh ends the whole relay.
//
// stall, when set, sees every packet on its way up (the stall detector).
func runTUNToServer(stopCh, readerStop chan struct{}, safeClose func(), tunDev *TUNDevice, serverConn net.Conn, updateActivity func(), connFailed func(), stall *relayStall) {
	buf := make([]byte, tunDev.mtu+4)
	pktCount := 0
	for {
		select {
		case <-stopCh:
			log.Debug("TUN->Server: stop signal received")
			return
		case <-readerStop:
			log.Debug("TUN->Server: TUN replaced, reader for the old device exits")
			return
		default:
		}

		n, err := tunDev.Read(buf[4:])
		if err != nil {
			if isTemporaryError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			select {
			case <-readerStop:
				// The device was closed because the relay moved off it.
				log.Debug("TUN->Server: old device closed after swap: %v", err)
				return
			default:
			}
			log.Debug("TUN read error: %v", err)
			safeClose()
			return
		}

		pktCount++
		if pktCount <= 5 || pktCount%100 == 0 {
			log.Debug("TUN->Server: read %d bytes from TUN (pkt #%d)", n, pktCount)
		}

		ClampTCPMSS(buf[4:4+n], tunDev.mtu)
		binary.BigEndian.PutUint32(buf[:4], uint32(n))
		if stall != nil {
			stall.flows.up(buf[4:4+n], time.Now())
		}

		serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := serverConn.Write(buf[:n+4]); err != nil {
			log.Debug("Server write error: %v", err)
			connFailed()
			safeClose()
			return
		}
		updateActivity()
	}
}

// runServerToTUN reads framed packets from serverConn and writes them to the
// relay's current TUN device, re-read per packet so a swap takes effect on
// the next one. Returns an error reason string (empty if stopped intentionally).
//
// stall, when set, sees every packet that reaches the TUN and counts the
// keepalive echoes (the stall detector).
func runServerToTUN(stopCh chan struct{}, safeClose func(), tun *atomic.Pointer[TUNDevice], serverConn net.Conn, remoteIP net.IP, updateActivity func(), callbacks *RelayCallbacks, stall *relayStall) string {
	lenBuf := make([]byte, 4)
	pktCount := 0
	for {
		select {
		case <-stopCh:
			log.Debug("Server->TUN: stop signal received")
			safeClose()
			// NOTE: serverConn is NOT closed here — callers manage its lifecycle.
			log.Info("TUN relay stopped (by stop signal)")
			return ""
		default:
		}

		serverConn.SetReadDeadline(time.Now().Add(readTimeout))
		if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
			log.Debug("Server read error: %v", err)
			return fmt.Sprintf("server_read: %v", err)
		}

		updateActivity()
		pktLen := binary.BigEndian.Uint32(lenBuf)

		if pktLen == 0 {
			log.Debug("Received keepalive from server")
			if stall != nil {
				stall.echoes.Add(1)
			}
			if callbacks != nil && callbacks.OnKeepalive != nil {
				callbacks.OnKeepalive()
			}
			continue
		}

		// A length over the protocol ceiling is not a packet that is too big for
		// this MTU, it is lost framing - or the server's reset signal for a
		// session it no longer has. Checked before anything is allocated: the
		// handler below reads the whole announced length into memory, and a
		// garbage header of 0xffffffff was a 4 GiB allocation. VPNClient's read
		// loop has always disconnected here; this relay now does the same.
		if pktLen > maxFrameLen {
			log.Debug("Frame length %d exceeds protocol max, disconnecting", pktLen)
			return fmt.Sprintf("server_frame_over_ceiling: %d", pktLen)
		}

		tunDev := tun.Load()
		if reason := handleOversizedPacket(tunDev, serverConn, remoteIP, pktLen); reason != "" {
			if reason == "dropped" {
				continue
			}
			return reason
		}

		buf := make([]byte, pktLen)
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			log.Debug("Server read data error: %v", err)
			return fmt.Sprintf("server_read_data: %v", err)
		}

		ClampTCPMSS(buf, tunDev.mtu)

		pktCount++
		if pktCount <= 5 || pktCount%100 == 0 {
			log.Debug("Server->TUN: writing %d bytes to TUN (pkt #%d)", pktLen, pktCount)
		}

		if _, err := tunDev.Write(buf); err != nil {
			log.Debug("TUN write error: %v", err)
		} else if stall != nil {
			stall.flows.down(buf, time.Now())
		}
	}
}

// handleOversizedPacket discards an oversized packet and injects an ICMP Frag Needed.
// Returns "dropped" if the packet was discarded, an error reason string on read failure, or "" if not oversized.
func handleOversizedPacket(tunDev *TUNDevice, serverConn net.Conn, remoteIP net.IP, pktLen uint32) string {
	if pktLen <= uint32(tunDev.mtu) {
		return ""
	}
	log.Debug("Packet too large (%d > MTU %d), dropping and sending ICMP", pktLen, tunDev.mtu)
	oversized := make([]byte, pktLen)
	if _, err := io.ReadFull(serverConn, oversized); err != nil {
		log.Debug("Failed to read oversized packet: %v", err)
		return fmt.Sprintf("server_read_oversized: %v", err)
	}
	icmpPkt := BuildICMPFragNeeded(remoteIP, oversized, uint16(tunDev.mtu))
	if icmpPkt != nil {
		if _, err := tunDev.Write(icmpPkt); err != nil {
			log.Debug("Failed to inject ICMP frag needed: %v", err)
		}
	}
	return "dropped"
}

// sinceOrUnknown renders time.Since(t) for the disconnect log, rounded to
// milliseconds, or "unknown" when t was never set.
func sinceOrUnknown(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return time.Since(t).Round(time.Millisecond).String()
}
