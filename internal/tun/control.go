package tun

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"golang.org/x/sys/unix"
)

// ControlCommand represents commands from Android app
type ControlCommand struct {
	Command string `json:"command"` // "connect", "disconnect", "status", "set_fd", "reconnect", "network_changed"
	TunFd   int    `json:"tun_fd,omitempty"`
	Pid     int    `json:"pid,omitempty"`    // Parent process PID for /proc/PID/fd/N access
	Reason  string `json:"reason,omitempty"` // For network_changed: "wifi_to_lte", "lte_to_wifi", "cell_handoff"
}

// ControlResponse represents response to Android app
type ControlResponse struct {
	Status    string `json:"status"` // "ok", "error", "connected", "waiting_fd"
	Error     string `json:"error,omitempty"`
	IP        string `json:"ip,omitempty"`         // Assigned TUN IP
	ServerIP  string `json:"server_ip,omitempty"`  // Server's TUN IP
	IP6       string `json:"ip6,omitempty"`        // Assigned TUN IPv6 (dual-stack only)
	ServerIP6 string `json:"server_ip6,omitempty"` // Server's TUN IPv6 (dual-stack only)
	// IPv6Removed reports that a reconnect renegotiated the session without
	// dual-stack while the previous one had it. Absent (omitempty) on every
	// other response, so the JSON contract stays additive: a host that does
	// not know the field behaves exactly as before, and one that does can tear
	// the v6 configuration down instead of leaving it pointed at an exit that
	// no longer routes it.
	IPv6Removed bool   `json:"ipv6_removed,omitempty"`
	DNS         string `json:"dns,omitempty"`        // DNS server
	MTU         int    `json:"mtu,omitempty"`        // MTU value
	Routes      string `json:"routes,omitempty"`     // Suggested routes
	Connected   bool   `json:"connected,omitempty"`  // Whether VPN is connected
	Strategy    string `json:"strategy,omitempty"`   // Connection strategy name
	LatencyMs   int64  `json:"latency_ms,omitempty"` // Connection latency in ms
	Attempts    int    `json:"attempts,omitempty"`   // Number of connection attempts
}

// EventMessage represents asynchronous events from Go to Android
// Android distinguishes events from responses by presence of "event" field vs "status" field
type EventMessage struct {
	Event     string `json:"event"`          // "keepalive", "connection_dead", "reconnecting", "connected"
	Timestamp int64  `json:"timestamp"`      // unix milliseconds
	Data      string `json:"data,omitempty"` // optional: latency, strategy name, error reason
}

// ControlServer handles control socket for Android VpnService
type ControlServer struct {
	socketPath string
	listener   net.Listener
	vpnClient  *VPNClient

	// Connection state
	mu              sync.Mutex
	serverConn      net.Conn // Connection to VPN server
	assignedIP      net.IP   // IP assigned by server
	serverIP        net.IP   // Server's TUN IP
	assignedIP6     net.IP   // IPv6 assigned by server (dual-stack only)
	serverIP6       net.IP   // Server's TUN IPv6 (dual-stack only)
	mtu             int
	waitingForFd    bool
	tunFdCh         chan int      // Channel to receive TUN fd
	tunFd           int           // Current TUN fd (for reconnect)
	tunDev          *TUNDevice    // Current TUN device (for reconnect)
	relayStopCh     chan struct{} // Channel to stop current TUN relay
	relay           *tunRelay     // Current relay, for swapping its TUN in place
	relayGeneration int           // Incremented on each relay start/hot-swap; stale OnError callbacks are ignored
	reconnecting    bool          // True when intentionally reconnecting (suppress dead event)

	// sessionGen is bumped by every teardown (disconnect, Close). Handlers
	// that drop cs.mu mid-way (hot-swap, reconnect) compare it after taking
	// the lock back, so a teardown that ran in the gap is not undone by a
	// relay started on top of it.
	sessionGen uint64
	// closed is set first thing in Close, without cs.mu: a command holding
	// the lock checks it before installing anything it built meanwhile.
	closed atomic.Bool

	// life ends when Close starts. Every command's network work runs under a
	// context tied to it, so Close can cut a connect or reconnect short
	// instead of waiting behind cs.mu for it to time out on its own.
	life       context.Context
	lifeCancel context.CancelFunc

	// sockID identifies the socket file this server created, so Close
	// removes it only while the path still points at it (see removeOwnSocket).
	sockID os.FileInfo

	closeOnce sync.Once
	closeErr  error

	// Auto-reconnect state
	autoReconnect     bool          // Enable automatic reconnect on connection loss
	autoReconnectStop chan struct{} // Stop channel for auto-reconnect goroutine

	// Network signal channel - Android notifies us when network is restored
	networkAvailableChan chan struct{} // Buffered channel for network_available signals

	// Control connection for sending events back to Android
	controlConn net.Conn

	// Config for connection
	config *ControlConfig
}

// ReconnectResult is the outcome of a reconnect handshake performed by
// ControlConfig.ReconnectFn.
//
// The reconnect re-runs the full handshake, so the exit may hand out a
// different lease than the one the session started with — and because the
// client's tunnel IPv6 is derived from its IPv4 (pool prefix | v4), a new v4
// implies a new v6. It may also stop offering dual-stack altogether. Both have
// to reach the host: a desktop TUN recomputes the v6 locally, but a host-owned
// interface (Android VpnService, macOS NetworkExtension) cannot, and would
// keep sending on an address the exit no longer routes.
type ReconnectResult struct {
	Conn       net.Conn
	ServerIP   net.IP
	AssignedIP net.IP

	// ServerIP6 / AssignedIP6 carry the re-negotiated dual-stack addresses.
	// Both nil means the exit answered without dual-stack on this reconnect,
	// which the control server reports to the host so it can drop the v6
	// configuration instead of black-holing on it.
	ServerIP6   net.IP
	AssignedIP6 net.IP
}

// ConnectionMetadata holds info about the last connection for Android UI
type ConnectionMetadata struct {
	Strategy  string
	LatencyMs int64
	Attempts  int
}

// ControlConfig holds configuration for control server
type ControlConfig struct {
	ServerAddr string
	Secret     string
	MTU        int
	DNS        string
	Routes     string

	// DualStack opts the TUN handshake into IPv6 dual-stack negotiation
	// (version 0x04 instead of 0x03). Default false preserves the historical
	// behavior byte-for-byte; when the exit does not negotiate dual-stack the
	// response simply carries no IPv6 fields.
	DualStack bool

	ConnectFn  func(ctx context.Context) (assignedIP, serverIP net.IP, conn net.Conn, err error)
	StartVPNFn func(tunFd int, localIP, remoteIP net.IP, conn net.Conn) error

	// ReconnectFn is called on network change to re-establish connection.
	// It receives the current assigned IP to send in handshake and returns a
	// new server connection with the handshake already done.
	ReconnectFn func(ctx context.Context, currentIP net.IP, mtu int) (ReconnectResult, error)

	// GetConnectionInfoFn returns metadata about the last connection (for Android UI)
	GetConnectionInfoFn func() ConnectionMetadata
}

// NewControlServer creates a new control server
func NewControlServer(socketPath string, cfg *ControlConfig) (*ControlServer, error) {
	// Remove existing socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}

	// Make socket accessible
	os.Chmod(socketPath, 0666)

	// The socket file is removed by removeOwnSocket, not by the listener:
	// a UnixListener unlinks its path on Close whoever the file belongs to
	// by then, and after a stop that gave up waiting a newer core may
	// already be listening on the same path.
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	sockID, err := os.Lstat(socketPath)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("stat %s: %w", socketPath, err)
	}

	life, lifeCancel := context.WithCancel(context.Background())
	return &ControlServer{
		socketPath:           socketPath,
		listener:             listener,
		sockID:               sockID,
		life:                 life,
		lifeCancel:           lifeCancel,
		config:               cfg,
		mtu:                  cfg.MTU,
		tunFdCh:              make(chan int, 1),
		networkAvailableChan: make(chan struct{}, 1), // Buffered to avoid blocking Android
	}, nil
}

// opContext returns ctx, also cancelled when Close starts.
func (cs *ControlServer) opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	if cs.life == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(cs.life, cancel)
	return ctx, func() { stop(); cancel() }
}

// Run starts the control server
func (cs *ControlServer) Run(ctx context.Context) error {
	log.Info("Control socket listening on %s", cs.socketPath)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("control server context handler panic: %v", r)
			}
		}()
		<-ctx.Done()
		cs.listener.Close()
	}()

	for {
		conn, err := cs.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			// Close shuts the listener; every Accept after that fails at
			// once, and retrying would spin until ctx is cancelled.
			if cs.closed.Load() {
				return nil
			}
			log.Debug("Accept error: %v", err)
			continue
		}

		go cs.handleConnection(ctx, conn)
	}
}

// handleConnection handles a single control connection
// Uses recvmsg to receive both JSON commands and file descriptors in the same call
func (cs *ControlServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("handleConnection panic: %v", r)
		}
		conn.Close()
		cs.mu.Lock()
		if cs.controlConn == conn {
			cs.controlConn = nil
		}
		cs.mu.Unlock()
	}()

	log.Debug("Control connection from %s", conn.RemoteAddr())

	// Store control connection for sending events back to Android
	cs.mu.Lock()
	cs.controlConn = conn
	cs.mu.Unlock()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		log.Debug("Not a unix connection")
		return
	}

	encoder := json.NewEncoder(conn)

	// The socket is a byte stream: one read may hold several commands, or
	// part of one. Parsing each read as a single JSON value turned the host's
	// network_available + network_changed, written back to back, into a parse
	// error, a closed connection and a full core restart on the host.
	framer := newControlFramer()
	defer framer.release()
	buf := make([]byte, 4096)
	// Room for a few descriptors: the host sends one, and any extra that
	// arrive are closed below rather than left to the kernel's truncation.
	oob := make([]byte, unix.CmsgSpace(4*4))

	for {
		n, oobn, flags, _, err := unixConn.ReadMsgUnix(buf, oob)
		fd := receivedFd(oob[:oobn], flags)
		if n == 0 {
			releaseReceivedFd(fd)
			if err != nil {
				log.Debug("Control read: %v", err)
			}
			return
		}
		msgs, ferr := framer.feed(buf[:n], fd)
		for i, m := range msgs {
			resp, ok := cs.dispatchControl(ctx, m)
			if !ok {
				continue
			}
			if err := encoder.Encode(resp); err != nil {
				log.Debug("Control encode error: %v", err)
				for _, rest := range msgs[i+1:] {
					releaseReceivedFd(rest.fd)
				}
				return
			}
		}
		if ferr != nil {
			log.Warn("Control: %v, closing the connection", ferr)
			return
		}
		if err != nil {
			log.Debug("Control read: %v", err)
			return
		}
	}
}

// receivedFd extracts the descriptor a read carried, -1 if none. The host
// sends at most one per command; any others are closed here.
func receivedFd(oob []byte, flags int) int {
	if flags&unix.MSG_CTRUNC != 0 {
		log.Warn("Control: ancillary data truncated, descriptors beyond the buffer were dropped by the kernel")
	}
	if len(oob) == 0 {
		return -1
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		log.Debug("Failed to parse control message: %v", err)
		return -1
	}
	fd := -1
	for i := range msgs {
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		for _, f := range fds {
			if fd < 0 {
				fd = f
				continue
			}
			log.Warn("Control: extra fd %d in one message, closing it", f)
			releaseReceivedFd(f)
		}
	}
	if fd >= 0 {
		log.Debug("Received fd via SCM_RIGHTS: %d", fd)
	}
	return fd
}

// dispatchControl runs one framed command. ok is false when the bytes were
// valid JSON but not a command; there is no command to answer then, and
// answering anyway would hand the host a response it would pair with its
// next request.
func (cs *ControlServer) dispatchControl(ctx context.Context, m controlMsg) (ControlResponse, bool) {
	fd := m.fd
	var cmd ControlCommand
	if err := json.Unmarshal(m.data, &cmd); err != nil {
		log.Warn("Control: skipping undecodable command: %v (%q)", err, clip(m.data))
		releaseReceivedFd(fd)
		return ControlResponse{}, false
	}

	log.Info("Control command: %s (received_fd=%d)", cmd.Command, fd)

	var resp ControlResponse

	// A received fd belongs to the core from recvmsg on: the kernel
	// installed it for us and the host keeps its own. set_fd and
	// reconnect/network_changed take it over (adoptTunFd); every other
	// command has no use for it, and leaving it open would pin a VPN
	// interface for the life of the process.
	switch cmd.Command {
	case "set_fd":
		resp = cs.handleSetFdWithReceivedFd(ctx, fd)

	case "reconnect", "network_changed":
		resp = cs.handleReconnect(ctx, cmd.Reason, fd)

	default:
		if fd >= 0 {
			log.Warn("Control command %q carried fd %d it does not use, closing it", cmd.Command, fd)
			releaseReceivedFd(fd)
		}
		switch cmd.Command {
		case "connect":
			resp = cs.handleConnect(ctx)
		case "disconnect":
			resp = cs.handleDisconnect()
		case "status":
			resp = cs.handleStatus()
		case "network_available":
			resp = cs.handleNetworkAvailable()
		default:
			resp = ControlResponse{Status: "error", Error: "unknown command"}
		}
	}

	return resp, true
}

// handleConnect connects to VPN server and returns assigned IP
func (cs *ControlServer) handleConnect(ctx context.Context) ControlResponse {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed.Load() {
		return ControlResponse{Status: "error", Error: "control server closed"}
	}

	if cs.assignedIP != nil {
		// Already connected, return existing config
		return ControlResponse{
			Status:    "waiting_fd",
			IP:        cs.assignedIP.String(),
			ServerIP:  cs.serverIP.String(),
			IP6:       ipString(cs.assignedIP6),
			ServerIP6: ipString(cs.serverIP6),
			DNS:       cs.config.DNS,
			MTU:       cs.mtu,
			Routes:    cs.config.Routes,
		}
	}

	// Connect to server
	if cs.config.ConnectFn == nil {
		return ControlResponse{Status: "error", Error: "connect function not configured"}
	}

	// The dial and the handshake run with cs.mu held; opCtx is what lets
	// Close interrupt them rather than wait up to the handshake timeout.
	opCtx, cancel := cs.opContext(ctx)
	defer cancel()

	placeholderIP, _, conn, err := cs.config.ConnectFn(opCtx)
	if err != nil {
		return ControlResponse{Status: "error", Error: err.Error()}
	}
	// A dial deaf to cancellation can return after Close gave up waiting for
	// the lock; what it built is dropped, not installed.
	if cs.closed.Load() {
		conn.Close()
		return ControlResponse{Status: "error", Error: "control server closed"}
	}

	cs.serverConn = conn

	// Perform TUN handshake NOW (before sending waiting_fd to Android).
	// This gives us the real assigned IP, so Android creates TUN with the correct IP
	// from the start — eliminating IP mismatch and the need for hot-swap.
	// NOTE: previously this was done after set_fd to fix "EOF" errors. The EOF was caused
	// by concurrent relay + handshake; here there is no relay yet, so it's safe.
	realAssignedIP, realServerIP, err := cs.performTUNHandshake(opCtx)
	if err != nil {
		conn.Close()
		cs.serverConn = nil
		return ControlResponse{Status: "error", Error: fmt.Sprintf("TUN handshake failed: %v", err)}
	}

	cs.assignedIP = realAssignedIP
	cs.serverIP = realServerIP
	cs.waitingForFd = true

	log.Info("Connected to server, real IP: %s (placeholder was: %s), waiting for TUN fd", realAssignedIP, placeholderIP)

	return ControlResponse{
		Status:    "waiting_fd",
		IP:        realAssignedIP.String(),
		ServerIP:  realServerIP.String(),
		IP6:       ipString(cs.assignedIP6),
		ServerIP6: ipString(cs.serverIP6),
		DNS:       cs.config.DNS,
		MTU:       cs.mtu,
		Routes:    cs.config.Routes,
	}
}

// ipString renders an IP for a ControlResponse, mapping nil to "" so the
// omitempty JSON field stays absent when dual-stack was not negotiated.
func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// handleSetFdWithReceivedFd starts VPN with fd received via SCM_RIGHTS
// The fd arrived over SCM_RIGHTS with the command (see controlFramer)
func (cs *ControlServer) handleSetFdWithReceivedFd(ctx context.Context, fd int) ControlResponse {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.waitingForFd {
		// If relay is already running, perform a hot-swap of the TUN fd instead of rejecting.
		// This happens when Android recreates the VPN interface because the server assigned
		// a different IP than the placeholder used to create the initial interface.
		if cs.serverConn != nil && cs.relayStopCh != nil {
			log.Info("set_fd: relay already running — hot-swapping TUN fd (old=%d, new=%d)", cs.tunFd, fd)
			return cs.hotSwapTunFdLocked(fd)
		}
		releaseReceivedFd(fd)
		return ControlResponse{Status: "error", Error: "not waiting for fd, call connect first"}
	}

	if fd < 0 {
		return ControlResponse{Status: "error", Error: "no fd received with set_fd command"}
	}

	log.Info("Using TUN fd from SCM_RIGHTS: %d", fd)

	tunDev, err := cs.adoptTunFd(fd)
	if err != nil {
		return ControlResponse{Status: "error", Error: fmt.Sprintf("failed to create TUN: %v", err)}
	}
	cs.tunDev = tunDev
	// Save fd for reconnect
	cs.tunFd = fd

	// TUN handshake was already performed in handleConnect (before waiting_fd was sent).
	// Android created TUN with the real IP from the start → no IP mismatch expected.
	log.Info("TUN handshake already done in connect phase, skipping. IP=%s server=%s", cs.assignedIP, cs.serverIP)

	// Start VPN with the received fd
	if cs.config.StartVPNFn != nil {
		if err := cs.config.StartVPNFn(fd, cs.assignedIP, cs.serverIP, cs.serverConn); err != nil {
			return ControlResponse{Status: "error", Error: err.Error()}
		}
	} else {
		// Default: start TUN relay with stop channel and full callbacks
		cs.relayStopCh = make(chan struct{})
		// Disable auto-reconnect in control-socket mode: doAutoReconnect competes with
		// Android's handleControlSocketBroken, creating concurrent relays that race for
		// the server slot and break keepalive echoes. Android manages reconnects via
		// connection_dead event → handleControlSocketBroken.
		cs.autoReconnect = false
		cs.autoReconnectStop = make(chan struct{})
		cs.relayGeneration++
		myGen := cs.relayGeneration

		cs.relay = startTUNRelay(tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
			OnError: func(reason string) {
				cs.mu.Lock()
				current := cs.relayGeneration
				auto := cs.autoReconnect
				cs.mu.Unlock()
				if current != myGen {
					log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myGen, current, reason)
					return
				}
				log.Info("TUN relay died: %s", reason)
				// Start auto-reconnect in background if enabled
				if auto {
					go cs.doAutoReconnect(reason)
				} else {
					cs.sendEvent("connection_dead", reason)
				}
			},
			OnKeepalive: func() {
				cs.sendEvent("keepalive", "")
			},
		})
	}

	cs.waitingForFd = false

	// Get connection metadata for Android UI
	resp := ControlResponse{
		Status:    "connected",
		IP:        cs.assignedIP.String(),
		ServerIP:  cs.serverIP.String(),
		IP6:       ipString(cs.assignedIP6),
		ServerIP6: ipString(cs.serverIP6),
		Connected: true,
	}
	if cs.config.GetConnectionInfoFn != nil {
		info := cs.config.GetConnectionInfoFn()
		resp.Strategy = info.Strategy
		resp.LatencyMs = info.LatencyMs
		resp.Attempts = info.Attempts
	}
	return resp
}

// hotSwapTunFdLocked swaps the TUN fd without reconnecting to the server.
// Called with cs.mu already held. Briefly releases the mutex to let relay goroutines exit.
func (cs *ControlServer) hotSwapTunFdLocked(newFd int) ControlResponse {
	if newFd < 0 {
		return ControlResponse{Status: "error", Error: "invalid fd for hot-swap"}
	}

	// Only the TUN changes; the session - its server connection, the relay
	// reading it, keepalives - stays as it is. This used to stop the relay
	// and start another on the same connection: the stopped relay closed the
	// connection on its way out, so the new one died at once and the host was
	// told connection_dead, which on Android restarts the whole core.
	newTunDev, err := cs.adoptTunFd(newFd)
	if err != nil {
		log.Error("hot-swap: failed to create TUN device: %v", err)
		return ControlResponse{Status: "error", Error: fmt.Sprintf("hot-swap create TUN: %v", err)}
	}
	if cs.relay == nil || !cs.relay.SwapTUN(newTunDev) {
		newTunDev.Close()
		return ControlResponse{Status: "error", Error: "hot-swap: relay is not running"}
	}
	old := cs.tunDev
	cs.tunDev = newTunDev
	cs.tunFd = newFd
	// Wakes the old device's reader, which SwapTUN has already told to stop.
	if old != nil {
		old.Close()
	}

	log.Info("hot-swap complete: relay moved to new TUN fd=%d, session kept (local=%s, remote=%s)", newFd, cs.assignedIP, cs.serverIP)

	resp := ControlResponse{
		Status:    "connected",
		IP:        cs.assignedIP.String(),
		ServerIP:  cs.serverIP.String(),
		IP6:       ipString(cs.assignedIP6),
		ServerIP6: ipString(cs.serverIP6),
		Connected: true,
	}
	if cs.config.GetConnectionInfoFn != nil {
		info := cs.config.GetConnectionInfoFn()
		resp.Strategy = info.Strategy
		resp.LatencyMs = info.LatencyMs
		resp.Attempts = info.Attempts
	}
	return resp
}

// handleDisconnect disconnects VPN
func (cs *ControlServer) handleDisconnect() ControlResponse {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// A relay dying of the teardown below (its server read fails before it
	// sees the stop channel) must not report connection_dead for a session
	// the host ended on purpose.
	cs.sessionGen++
	cs.relayGeneration++

	// Stop the relay and close the TUN copy this process received over
	// SCM_RIGHTS. The host closing its own descriptor does not take the
	// interface down while ours is open, and nothing else closes ours: the
	// relay only ever reads from it.
	cs.releaseTunLocked()

	if cs.serverConn != nil {
		cs.serverConn.Close()
		cs.serverConn = nil
	}

	if cs.vpnClient != nil {
		cs.vpnClient.Stop()
		cs.vpnClient = nil
	}

	cs.assignedIP = nil
	cs.serverIP = nil
	cs.waitingForFd = false

	return ControlResponse{Status: "ok", Connected: false}
}

// handleStatus returns current status
func (cs *ControlServer) handleStatus() ControlResponse {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	resp := ControlResponse{
		Status:    "ok",
		Connected: cs.serverConn != nil && !cs.waitingForFd,
	}

	if cs.assignedIP != nil {
		resp.IP = cs.assignedIP.String()
	}
	if cs.serverIP != nil {
		resp.ServerIP = cs.serverIP.String()
	}

	return resp
}

// handleReconnect handles network change - closes old connection and reconnects
// This is critical for Android where network can change (WiFi→LTE, cell handoff)
// If newFd >= 0, uses the new TUN fd provided by Android (old one may be invalid)
func (cs *ControlServer) handleReconnect(ctx context.Context, reason string, newFd int) ControlResponse {
	cs.mu.Lock()

	if cs.closed.Load() {
		cs.mu.Unlock()
		releaseReceivedFd(newFd)
		return ControlResponse{Status: "error", Error: "control server closed"}
	}
	gen := cs.sessionGen

	log.Info("Network change detected: %s, initiating reconnect (new_fd=%d)", reason, newFd)

	// Set reconnecting flag BEFORE stopping relay to suppress connection_dead events
	// The flag stays true until we start the new relay
	cs.reconnecting = true

	// Send reconnecting event to Android (before releasing lock to ensure order)
	cs.mu.Unlock()
	cs.sendEvent("reconnecting", reason)
	cs.mu.Lock()

	// Stop current TUN relay first (this will also close serverConn)
	if cs.relayStopCh != nil {
		log.Debug("Stopping current TUN relay...")
		close(cs.relayStopCh)
		cs.relayStopCh = nil
		cs.relay = nil
	}

	// Wait a bit for network to stabilize after change
	// This prevents "network unreachable" errors during handoff
	cs.mu.Unlock()
	time.Sleep(500 * time.Millisecond)
	cs.mu.Lock()

	// Close existing server connection (but keep TUN fd!)
	if cs.serverConn != nil {
		cs.serverConn.Close()
		cs.serverConn = nil
	}

	// Release lock temporarily to let relay goroutines exit and call sendEvent
	// (which will be suppressed due to reconnecting=true)
	cs.mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Helper to clear reconnecting flag on error
	clearReconnecting := func() {
		cs.reconnecting = false
		log.Debug("Reconnect failed, reconnecting flag cleared")
	}

	// The lock was dropped three times above. A disconnect or Close in any
	// of those gaps ended the session; reconnecting now would bring back a
	// tunnel the host has stopped, on a fd nobody would ever close.
	if cs.sessionGen != gen {
		releaseReceivedFd(newFd)
		clearReconnecting()
		return ControlResponse{Status: "error", Error: "session torn down during reconnect"}
	}

	// If new fd provided, update TUN device
	if newFd >= 0 {
		log.Info("Using new TUN fd from Android: %d (old fd=%d)", newFd, cs.tunFd)
		// Close old TUN device (fd may already be invalid)
		if cs.tunDev != nil {
			cs.tunDev.Close()
			cs.tunDev = nil
		}
		cs.tunFd = 0

		tunDev, err := cs.adoptTunFd(newFd)
		if err != nil {
			log.Error("Failed to create TUN from new fd: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("failed to create TUN from new fd: %v", err),
			}
		}
		cs.tunDev = tunDev
		cs.tunFd = newFd
		log.Info("Created new TUN device from fd %d", newFd)
	}

	// If not connected yet, nothing to reconnect
	if cs.tunDev == nil || cs.tunFd <= 0 {
		clearReconnecting()
		return ControlResponse{
			Status: "error",
			Error:  "VPN not active, use connect first",
		}
	}

	// ipv6Removed records that this reconnect ended a dual-stack session, so
	// the response can tell the host to tear its v6 configuration down.
	var ipv6Removed bool

	// Use ReconnectFn if available (preferred - handles circuit breaker reset)
	opCtx, cancel := cs.opContext(ctx)
	defer cancel()
	if cs.config.ReconnectFn != nil {
		res, err := cs.config.ReconnectFn(opCtx, cs.assignedIP, cs.mtu)
		if err != nil {
			log.Error("Reconnect failed: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("reconnect failed: %v", err),
			}
		}
		if cs.closed.Load() {
			res.Conn.Close()
			clearReconnecting()
			return ControlResponse{Status: "error", Error: "control server closed"}
		}
		cs.serverConn = res.Conn
		cs.serverIP = res.ServerIP
		// Update assigned IP if server gave us a new one
		if res.AssignedIP != nil && !res.AssignedIP.Equal(net.IPv4zero) {
			if !res.AssignedIP.Equal(cs.assignedIP) {
				log.Info("Server assigned new IP: %s (was: %s)", res.AssignedIP, cs.assignedIP)
				cs.assignedIP = res.AssignedIP
				// Update TUN device with new local IP
				if cs.tunDev != nil {
					cs.tunDev.UpdateLocalIP(res.AssignedIP)
				}
			}
		}
		// The exit re-runs the whole negotiation on a reconnect, so the v6
		// pair can change with the v4 lease or disappear entirely. Track both
		// here — this is the only place the host learns about it, and a stale
		// v6 on the interface black-holes silently while IPv4 keeps working.
		hadIPv6 := cs.assignedIP6 != nil
		if !res.AssignedIP6.Equal(cs.assignedIP6) || !res.ServerIP6.Equal(cs.serverIP6) {
			log.Info("Reconnect dual-stack addresses changed: client %s -> %s, server %s -> %s",
				cs.assignedIP6, res.AssignedIP6, cs.serverIP6, res.ServerIP6)
		}
		cs.assignedIP6 = res.AssignedIP6
		cs.serverIP6 = res.ServerIP6
		ipv6Removed = hadIPv6 && cs.assignedIP6 == nil
		if ipv6Removed {
			log.Warn("Reconnect: the exit no longer offers dual-stack, dropping the tunnel's IPv6")
		}
		log.Info("Reconnected successfully via ReconnectFn (server IP: %s, assigned: %s)", res.ServerIP, cs.assignedIP)
	} else {
		// Fallback: use ConnectFn (less optimal - may need new IP)
		assignedIP, serverIP, conn, err := cs.config.ConnectFn(opCtx)
		if err != nil {
			log.Error("Reconnect failed: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("reconnect failed: %v", err),
			}
		}
		if cs.closed.Load() {
			conn.Close()
			clearReconnecting()
			return ControlResponse{Status: "error", Error: "control server closed"}
		}
		cs.serverConn = conn
		cs.assignedIP = assignedIP
		cs.serverIP = serverIP
		// This path returns a connection without running a TUN handshake, so
		// nothing renegotiated dual-stack. Drop any v6 we were holding rather
		// than carry addresses the new session never agreed on.
		ipv6Removed = cs.assignedIP6 != nil
		cs.assignedIP6 = nil
		cs.serverIP6 = nil
		log.Info("Reconnected via ConnectFn, IP: %s", assignedIP)
	}

	// Restart TUN relay with new server connection and TUN device
	cs.relayStopCh = make(chan struct{})
	cs.relayGeneration++
	myRelayGen := cs.relayGeneration
	cs.relay = startTUNRelay(cs.tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
		OnError: func(reason string) {
			cs.mu.Lock()
			current := cs.relayGeneration
			cs.mu.Unlock()
			if current != myRelayGen {
				log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myRelayGen, current, reason)
				return
			}
			log.Info("TUN relay died: %s, notifying Android", reason)
			cs.sendEvent("connection_dead", reason)
		},
		OnKeepalive: func() {
			cs.sendEvent("keepalive", "")
		},
	})

	// Clear reconnecting flag - we're done, future events should be sent
	cs.reconnecting = false
	log.Debug("Reconnect complete, reconnecting flag cleared")

	// Send connected event to Android with metadata
	var eventData string
	if cs.config.GetConnectionInfoFn != nil {
		info := cs.config.GetConnectionInfoFn()
		eventData = fmt.Sprintf(`{"strategy":"%s","latency_ms":%d,"attempts":%d}`, info.Strategy, info.LatencyMs, info.Attempts)
	}
	cs.mu.Unlock()
	cs.sendEvent("connected", eventData)
	cs.mu.Lock()

	// Get connection metadata for Android UI
	resp := ControlResponse{
		Status:      "connected",
		IP:          cs.assignedIP.String(),
		ServerIP:    cs.serverIP.String(),
		IP6:         ipString(cs.assignedIP6),
		ServerIP6:   ipString(cs.serverIP6),
		IPv6Removed: ipv6Removed,
		Connected:   true,
	}
	if cs.config.GetConnectionInfoFn != nil {
		info := cs.config.GetConnectionInfoFn()
		resp.Strategy = info.Strategy
		resp.LatencyMs = info.LatencyMs
		resp.Attempts = info.Attempts
	}
	return resp
}

// handleNetworkAvailable processes network_available signal from Android
// This signals that Android detected network restoration (via NetworkCallback.onAvailable)
// We signal to any goroutines waiting for network to immediately retry
func (cs *ControlServer) handleNetworkAvailable() ControlResponse {
	log.Info("Received network_available signal from Android - network restored")

	// Signal to any waiting goroutines (non-blocking)
	// This will wake up waitForNetwork() immediately
	select {
	case cs.networkAvailableChan <- struct{}{}:
		log.Debug("Signaled network restoration to waiting goroutines")
	default:
		log.Debug("Network signal channel already has pending signal, skipping")
	}

	return ControlResponse{
		Status: "ok",
		Error:  "",
	}
}

// sendEvent sends an event notification to Android via control connection
// Events: "keepalive", "connection_dead", "reconnecting", "connected"
func (cs *ControlServer) sendEvent(event string, data string) {
	cs.mu.Lock()
	conn := cs.controlConn
	reconnecting := cs.reconnecting
	cs.mu.Unlock()

	// Suppress connection_dead events during intentional reconnect
	if reconnecting && event == "connection_dead" {
		log.Debug("Suppressing %s event during reconnect: %s", event, data)
		return
	}

	if conn == nil {
		log.Debug("Cannot send event %s: no control connection", event)
		return
	}

	msg := EventMessage{
		Event:     event,
		Timestamp: time.Now().UnixMilli(),
		Data:      data,
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		log.Debug("Failed to send event %s: %v", event, err)
	} else {
		log.Info("Sent event to Android: %s (data=%s)", event, data)
	}
}

// closeTeardownWait bounds how long Close waits for cs.mu. The commands that
// hold it for long do network work Close has already cancelled, so the lock
// normally frees at once; the bound is for a dial that ignores cancellation.
const closeTeardownWait = 500 * time.Millisecond

// Close closes the control server: it tears the session down, including the
// TUN descriptor received from the host, and stops accepting connections.
// Safe to call more than once; only the first call does anything.
//
// The parts that need no lock go first and cannot be held up: mark closed,
// cancel the in-flight connect/reconnect, stop listening, remove our socket
// file. The session teardown needs cs.mu; if a command still holds it after
// closeTeardownWait, Close returns and the teardown runs as soon as the lock
// frees (the command, seeing closed, installs nothing on the way out).
func (cs *ControlServer) Close() error {
	cs.closeOnce.Do(func() {
		cs.closed.Store(true)
		if cs.lifeCancel != nil {
			cs.lifeCancel()
		}
		cs.closeErr = cs.listener.Close()
		cs.removeOwnSocket()

		done := make(chan struct{})
		go func() {
			defer close(done)
			cs.stopAutoReconnect()
			cs.handleDisconnect()
		}()
		select {
		case <-done:
		case <-time.After(closeTeardownWait):
			log.Warn("Close: a command still holds the control lock after %v; the session is torn down when it returns", closeTeardownWait)
		}
	})
	return cs.closeErr
}

// removeOwnSocket removes the socket file only while the path still names
// the file this server created. A newer core started on the same path (after
// a stop that gave up waiting for this one) has replaced it by then, and its
// file must stay.
//
// Between the Lstat and the Remove another core could still replace the file
// and lose it. That needs a new core to unlink and bind the path inside a
// window of a few microseconds, while it normally starts well after this one
// was told to stop; the host then sees the socket missing and restarts the
// core again, which is the same outcome as before this check, made rare.
func (cs *ControlServer) removeOwnSocket() {
	if cs.sockID == nil {
		os.Remove(cs.socketPath)
		return
	}
	cur, err := os.Lstat(cs.socketPath)
	if err != nil {
		return
	}
	if !os.SameFile(cur, cs.sockID) {
		log.Info("Control socket %s now belongs to another instance, leaving it", cs.socketPath)
		return
	}
	os.Remove(cs.socketPath)
}

// adoptTunFd turns a TUN descriptor received over SCM_RIGHTS into the device
// the relay reads. On success the device owns the descriptor; on failure it
// has been closed here. Either way the caller must not use the number again.
// Called with cs.mu held.
func (cs *ControlServer) adoptTunFd(fd int) (*TUNDevice, error) {
	// Non-blocking before os.NewFile, so the file lands in the netpoller.
	// For a blocking descriptor os.File.Close cannot interrupt a Read in
	// progress: the close(2) is deferred until that Read returns, and on an
	// idle interface it never does, so the descriptor - and the VPN
	// interface with it - outlives Disconnect. VpnService hands over a
	// blocking descriptor whenever the host called Builder.setBlocking(true).
	// O_NONBLOCK is set on the open file, which the host's descriptor shares;
	// the host does no I/O on it, the core is the only reader and writer.
	if err := unix.SetNonblock(fd, true); err != nil {
		releaseReceivedFd(fd)
		return nil, fmt.Errorf("set TUN fd %d non-blocking: %w", fd, err)
	}
	mtu := cs.mtu
	if mtu == 0 {
		mtu = DefaultMTU
	}
	tunDev, err := CreateTUNFromFd(fd, "tun0", mtu)
	if err != nil {
		releaseReceivedFd(fd)
		return nil, err
	}
	if err := tunDev.ConfigureFromFd(cs.assignedIP, cs.serverIP); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("configure TUN: %w", err)
	}
	return tunDev, nil
}

// releaseTunLocked stops the running relay and closes the TUN device. The
// device is closed through os.File, which is idempotent, and the pointer is
// cleared, so no path can reach the same descriptor twice. Called with cs.mu
// held.
func (cs *ControlServer) releaseTunLocked() {
	if cs.relayStopCh != nil {
		close(cs.relayStopCh)
		cs.relayStopCh = nil
		cs.relay = nil
	}
	if cs.tunDev != nil {
		cs.tunDev.Close()
		cs.tunDev = nil
	}
	cs.tunFd = 0
}

// releaseReceivedFd closes a descriptor received over SCM_RIGHTS that was
// never wrapped in an os.File. The number came from our own recvmsg, so no
// one else holds it; closing it once here is the only close it gets.
func releaseReceivedFd(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

// Auto-reconnect constants
const (
	autoReconnectInitialDelay = 1 * time.Second
	autoReconnectMaxDelay     = 2 * time.Minute
	autoReconnectMultiplier   = 2.0
	autoReconnectJitterFactor = 0.3
)

// doAutoReconnect performs automatic reconnection with exponential backoff
// This runs in a background goroutine when connection is lost
func (cs *ControlServer) doAutoReconnect(reason string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("doAutoReconnect panic: %v", r)
			cs.mu.Lock()
			cs.reconnecting = false
			cs.mu.Unlock()
			cs.sendEvent("connection_dead", fmt.Sprintf("panic: %v", r))
		}
	}()

	cs.mu.Lock()

	// Check if already reconnecting
	if cs.reconnecting {
		cs.mu.Unlock()
		log.Debug("Auto-reconnect already in progress, skipping")
		return
	}

	// Check if we have a valid TUN device
	if cs.tunDev == nil || cs.tunFd <= 0 {
		cs.mu.Unlock()
		log.Warn("Cannot auto-reconnect: no TUN device available")
		cs.sendEvent("connection_dead", reason)
		return
	}

	cs.reconnecting = true
	stopCh := cs.autoReconnectStop
	cs.mu.Unlock()

	log.Info("Starting auto-reconnect (reason: %s)", reason)
	cs.sendEvent("reconnecting", reason)

	// Exponential backoff state
	currentDelay := autoReconnectInitialDelay
	consecutiveFailures := 0
	lastNetworkCheck := time.Time{}

	for {
		consecutiveFailures++

		// Check if we should stop
		select {
		case <-stopCh:
			log.Info("Auto-reconnect cancelled")
			cs.mu.Lock()
			cs.reconnecting = false
			cs.mu.Unlock()
			return
		default:
		}

		// Check network connectivity periodically
		if consecutiveFailures%5 == 0 || time.Since(lastNetworkCheck) > 30*time.Second {
			if !cs.checkNetworkConnectivity() {
				log.Warn("No network connectivity, waiting...")

				// Wait for network with periodic checks
				if !cs.waitForNetwork(stopCh) {
					log.Info("Auto-reconnect cancelled while waiting for network")
					cs.mu.Lock()
					cs.reconnecting = false
					cs.mu.Unlock()
					return
				}

				// Network restored - or the wait timed out, because the "no
				// network" verdict can itself be wrong. Reset backoff and fall
				// through to a real reconnect attempt instead of looping back
				// into the probe, which would just park again.
				currentDelay = autoReconnectInitialDelay
				consecutiveFailures = 1
				log.Info("Resuming reconnect after network wait")
			}
			lastNetworkCheck = time.Now()
		}

		log.Info("Auto-reconnect attempt %d (backoff: %v)...", consecutiveFailures, currentDelay)

		// Try to reconnect using ReconnectFn or ConnectFn
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		success := cs.attemptReconnect(ctx)
		cancel()

		if success {
			log.Info("Auto-reconnect successful after %d attempts", consecutiveFailures)
			cs.mu.Lock()
			cs.reconnecting = false
			cs.mu.Unlock()
			cs.sendEvent("connected", "")
			return
		}

		log.Warn("Auto-reconnect attempt %d failed, next attempt in %v", consecutiveFailures, currentDelay)

		// Wait with jitter
		jitteredDelay := addAutoReconnectJitter(currentDelay)
		select {
		case <-stopCh:
			log.Info("Auto-reconnect cancelled during backoff")
			cs.mu.Lock()
			cs.reconnecting = false
			cs.mu.Unlock()
			return
		case <-time.After(jitteredDelay):
		}

		// Exponential backoff with cap
		currentDelay = time.Duration(float64(currentDelay) * autoReconnectMultiplier)
		if currentDelay > autoReconnectMaxDelay {
			currentDelay = autoReconnectMaxDelay
		}
	}
}

// attemptReconnect tries to reconnect using available methods
func (cs *ControlServer) attemptReconnect(ctx context.Context) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Torn down while the attempt waited for the lock: there is no device to
	// relay on, and a session the host ended must stay ended.
	if cs.closed.Load() || cs.tunDev == nil {
		return false
	}
	ctx, cancel := cs.opContext(ctx)
	defer cancel()

	// Stop any existing relay
	if cs.relayStopCh != nil {
		close(cs.relayStopCh)
		cs.relayStopCh = nil
		cs.relay = nil
	}

	// Close existing server connection
	if cs.serverConn != nil {
		cs.serverConn.Close()
		cs.serverConn = nil
	}

	// Small delay for cleanup
	time.Sleep(100 * time.Millisecond)

	var newConn net.Conn
	var serverIP, assignedIP, serverIP6, assignedIP6 net.IP
	var err error

	// Prefer ReconnectFn (handles circuit breaker reset)
	if cs.config.ReconnectFn != nil {
		var res ReconnectResult
		res, err = cs.config.ReconnectFn(ctx, cs.assignedIP, cs.mtu)
		newConn, serverIP, assignedIP = res.Conn, res.ServerIP, res.AssignedIP
		serverIP6, assignedIP6 = res.ServerIP6, res.AssignedIP6
	} else if cs.config.ConnectFn != nil {
		// No handshake runs on this path, so nothing renegotiated dual-stack:
		// the v6 pair stays nil and is cleared below.
		assignedIP, serverIP, newConn, err = cs.config.ConnectFn(ctx)
	} else {
		log.Error("No reconnect function configured")
		return false
	}

	if err != nil {
		log.Debug("Auto-reconnect attempt failed: %v", err)
		return false
	}

	// Update state
	cs.serverConn = newConn
	cs.serverIP = serverIP
	if assignedIP != nil && !assignedIP.Equal(net.IPv4zero) {
		if !assignedIP.Equal(cs.assignedIP) {
			log.Info("Server assigned new IP: %s (was: %s)", assignedIP, cs.assignedIP)
			cs.assignedIP = assignedIP
			if cs.tunDev != nil {
				cs.tunDev.UpdateLocalIP(assignedIP)
			}
		}
	}
	// The v6 pair follows the v4 lease and can also disappear entirely; the
	// auto-reconnect path has no response to carry it, so at least keep the
	// server's own view of the session honest and emit an event the host can
	// act on rather than silently holding a dead address.
	if !assignedIP6.Equal(cs.assignedIP6) || !serverIP6.Equal(cs.serverIP6) {
		log.Info("Auto-reconnect dual-stack addresses changed: client %s -> %s, server %s -> %s",
			cs.assignedIP6, assignedIP6, cs.serverIP6, serverIP6)
		cs.assignedIP6 = assignedIP6
		cs.serverIP6 = serverIP6
		// Sent from its own goroutine: sendEvent takes cs.mu, which this
		// function holds for its whole body.
		go cs.sendEvent("ipv6_changed", fmt.Sprintf(`{"ip6":"%s","server_ip6":"%s"}`,
			ipString(assignedIP6), ipString(serverIP6)))
	}

	// Start new TUN relay
	cs.relayStopCh = make(chan struct{})
	cs.relayGeneration++
	myAutoGen := cs.relayGeneration
	cs.relay = startTUNRelay(cs.tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
		OnError: func(reason string) {
			cs.mu.Lock()
			current := cs.relayGeneration
			auto := cs.autoReconnect
			cs.mu.Unlock()
			if current != myAutoGen {
				log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myAutoGen, current, reason)
				return
			}
			log.Info("TUN relay died: %s", reason)
			if auto {
				go cs.doAutoReconnect(reason)
			} else {
				cs.sendEvent("connection_dead", reason)
			}
		},
		OnKeepalive: func() {
			cs.sendEvent("keepalive", "")
		},
	})

	log.Info("Auto-reconnect: TUN relay restarted (server IP: %s)", serverIP)
	return true
}

// checkNetworkConnectivity performs a quick TCP check
func (cs *ControlServer) checkNetworkConnectivity() bool {
	// Shared with the reconnect loop. The probe must not enter the tunnel:
	// 8.8.8.8 and 1.1.1.1 are routinely part of the installed TUN routes, so
	// dials to them black-hole while the tunnel is down and read as "no
	// network".
	return internetReachable()
}

// waitForNetwork waits until network connectivity is restored, at most
// networkParkTimeout. Returns false if stopCh is closed; a timeout returns
// true so the caller retries the real connection - the negative verdict that
// caused the wait can itself be wrong (its probes used to enter the dead
// tunnel). Listens to networkAvailableChan for immediate signal from Android.
func (cs *ControlServer) waitForNetwork(stopCh chan struct{}) bool {
	checkInterval := 5 * time.Second
	deadline := time.Now().Add(networkParkTimeout)
	attempt := 0

	for {
		attempt++
		if attempt%12 == 0 {
			log.Info("Still waiting for network (attempt %d)...", attempt)
		}

		select {
		case <-stopCh:
			return false

		case <-cs.networkAvailableChan:
			// Android signaled that network is available via network_available command
			log.Info("Network restoration signaled by Android - exiting wait immediately")
			return true

		case <-time.After(checkInterval):
			// Periodic check as fallback
		}

		if cs.checkNetworkConnectivity() {
			return true
		}

		if time.Now().After(deadline) {
			log.Warn("Network still considered down after %v - retrying reconnect anyway", networkParkTimeout)
			return true
		}
	}
}

// stopAutoReconnect stops any running auto-reconnect goroutine
func (cs *ControlServer) stopAutoReconnect() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.autoReconnect = false
	if cs.autoReconnectStop != nil {
		close(cs.autoReconnectStop)
		cs.autoReconnectStop = nil
	}
}

// SetAutoReconnect enables or disables automatic reconnection
func (cs *ControlServer) SetAutoReconnect(enabled bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.autoReconnect = enabled
	log.Info("Auto-reconnect %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// addAutoReconnectJitter adds random jitter to backoff delay
func addAutoReconnectJitter(d time.Duration) time.Duration {
	jitter := float64(d) * autoReconnectJitterFactor * (2*rand.Float64() - 1)
	return d + time.Duration(jitter)
}

// performTUNHandshake sends TUN mode handshake and receives assigned IP
// This must be called AFTER VPN interface is created (after receiving FD from Android)
// Moved from ConnectFn to fix "handshake read failed: EOF" error
func (cs *ControlServer) performTUNHandshake(ctx context.Context) (assignedIP, serverIP net.IP, err error) {
	if cs.serverConn == nil {
		return nil, nil, fmt.Errorf("no server connection")
	}

	// The response read is bounded by a conn deadline, not by ctx, so a
	// cancelled ctx closes the conn to end it. stop() reporting false means
	// that already happened and the conn is gone.
	conn := cs.serverConn
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// Get MTU from config or use default
	mtu := cs.mtu
	if mtu == 0 {
		mtu = DefaultMTU
	}

	// Send TUN mode handshake
	// Format: [mode:1][localIP:4][mtu:2][version:1]
	// Send 0.0.0.0 to request auto IP assignment
	version := byte(tunHandshakeVersion)
	if cs.config.DualStack {
		version = tunHandshakeVersionDualStack
	}
	handshake := make([]byte, 8)
	handshake[0] = 0x02 // TUN mode
	// localIP = 0.0.0.0 (bytes 1:5 remain zero to request auto assignment)
	binary.BigEndian.PutUint16(handshake[5:7], uint16(mtu))
	handshake[7] = version // v3: auto-MTU probe; v4: + dual-stack

	log.Debug("Sending TUN handshake: mode=0x02, mtu=%d, version=0x%02x", mtu, version)
	if _, err := cs.serverConn.Write(handshake); err != nil {
		return nil, nil, fmt.Errorf("handshake write failed: %w", err)
	}

	// Read the response for the version just sent. readHandshakeResponse reads
	// exactly the response (flags byte, port-hop layout, dual-stack block) and
	// nothing past it, so the relay that follows starts frame-aligned; the conn
	// it returns replaces cs.serverConn because it may carry the first byte of
	// the first frame back to the relay.
	resp, n, next, err := readHandshakeResponse(cs.serverConn, version, time.Now().Add(handshakeReadTimeout))
	if !stop() {
		return nil, nil, fmt.Errorf("handshake interrupted: %w", context.Cause(ctx))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("handshake read failed: %w", err)
	}
	cs.serverConn = next
	// Guard before any indexing: a short response with a nil error would make
	// resp[0] / resp[5:9] below panic, and that panic is swallowed by the
	// recover() in handleConnection — the host then sees the control socket
	// close instead of a {"status":"error"} response, and cs.serverConn is
	// left assigned and open because the caller's error path never runs.
	if n < 9 {
		return nil, nil, fmt.Errorf("handshake response too short: %d bytes", n)
	}
	resp = resp[:n] // Trim to actual response size

	log.Debug("Received TUN handshake response: %d bytes, status=0x%02x", n, resp[0])

	if resp[0] != 0x00 {
		switch resp[0] {
		case 0x01:
			return nil, nil, fmt.Errorf("IP pool exhausted")
		case 0x02:
			return nil, nil, fmt.Errorf("no IP pool configured")
		default:
			return nil, nil, fmt.Errorf("server error: %d", resp[0])
		}
	}

	serverIP = net.IP(resp[1:5])
	assignedIP = net.IP(resp[5:9])

	// Dual-stack: when the exit answered the v0x04 handshake with the
	// dual-stack flag, record the negotiated v6 addresses so the next
	// ControlResponse can hand them to Android (which configures them on the
	// VpnService interface). A declined negotiation leaves both nil and the
	// session is plain v4 — identical to a 0x03 handshake.
	cs.assignedIP6 = nil
	cs.serverIP6 = nil
	if cs.config.DualStack {
		if caps, ok := parseServerCapabilities(resp, n); ok && caps.DualStackEnabled {
			cs.assignedIP6 = caps.ClientIP6
			cs.serverIP6 = caps.ServerIP6
			log.Info("Dual-stack negotiated: client=%s server=%s", caps.ClientIP6, caps.ServerIP6)
		} else {
			log.Warn("Dual-stack requested but the exit did not negotiate IPv6; continuing IPv4-only")
		}
	}

	log.Debug("TUN handshake successful: assigned=%s, server=%s", assignedIP, serverIP)
	return assignedIP, serverIP, nil
}
