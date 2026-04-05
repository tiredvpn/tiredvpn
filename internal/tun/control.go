package tun

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
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
	DNS       string `json:"dns,omitempty"`        // DNS server
	MTU       int    `json:"mtu,omitempty"`        // MTU value
	Routes    string `json:"routes,omitempty"`     // Suggested routes
	Connected bool   `json:"connected,omitempty"`  // Whether VPN is connected
	Strategy  string `json:"strategy,omitempty"`   // Connection strategy name
	LatencyMs int64  `json:"latency_ms,omitempty"` // Connection latency in ms
	Attempts  int    `json:"attempts,omitempty"`   // Number of connection attempts
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
	mtu             int
	waitingForFd    bool
	tunFdCh         chan int      // Channel to receive TUN fd
	tunFd           int           // Current TUN fd (for reconnect)
	tunDev          *TUNDevice    // Current TUN device (for reconnect)
	relayStopCh     chan struct{} // Channel to stop current TUN relay
	relayGeneration int           // Incremented on each relay start/hot-swap; stale OnError callbacks are ignored
	reconnecting    bool          // True when intentionally reconnecting (suppress dead event)

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
	ConnectFn  func(ctx context.Context) (assignedIP, serverIP net.IP, conn net.Conn, err error)
	StartVPNFn func(tunFd int, localIP, remoteIP net.IP, conn net.Conn) error

	// ReconnectFn is called on network change to re-establish connection
	// It receives the current assigned IP to send in handshake
	// Returns new server connection with handshake already done, plus new assigned IP
	ReconnectFn func(ctx context.Context, currentIP net.IP, mtu int) (conn net.Conn, serverIP net.IP, assignedIP net.IP, err error)

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

	return &ControlServer{
		socketPath:           socketPath,
		listener:             listener,
		config:               cfg,
		mtu:                  cfg.MTU,
		tunFdCh:              make(chan int, 1),
		networkAvailableChan: make(chan struct{}, 1), // Buffered to avoid blocking Android
	}, nil
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
				log.Debug("Accept error: %v", err)
				continue
			}
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

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		log.Debug("Failed to get syscall conn: %v", err)
		return
	}

	encoder := json.NewEncoder(conn)

	for {
		// Read message with potential fd using recvmsg
		jsonData, fd, err := recvMessageWithFd(rawConn)
		if err != nil {
			log.Debug("recvMessageWithFd error: %v", err)
			return
		}

		var cmd ControlCommand
		if err := json.Unmarshal(jsonData, &cmd); err != nil {
			log.Debug("JSON unmarshal error: %v (data: %s)", err, string(jsonData))
			return
		}

		log.Info("Control command: %s (received_fd=%d)", cmd.Command, fd)

		var resp ControlResponse

		switch cmd.Command {
		case "connect":
			resp = cs.handleConnect(ctx)

		case "set_fd":
			resp = cs.handleSetFdWithReceivedFd(ctx, fd)

		case "disconnect":
			resp = cs.handleDisconnect()

		case "status":
			resp = cs.handleStatus()

		case "reconnect", "network_changed":
			resp = cs.handleReconnect(ctx, cmd.Reason, fd)

		case "network_available":
			resp = cs.handleNetworkAvailable()

		default:
			resp = ControlResponse{Status: "error", Error: "unknown command"}
		}

		if err := encoder.Encode(resp); err != nil {
			log.Debug("Control encode error: %v", err)
			return
		}
	}
}

// handleConnect connects to VPN server and returns assigned IP
func (cs *ControlServer) handleConnect(ctx context.Context) ControlResponse {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.assignedIP != nil {
		// Already connected, return existing config
		return ControlResponse{
			Status:   "waiting_fd",
			IP:       cs.assignedIP.String(),
			ServerIP: cs.serverIP.String(),
			DNS:      cs.config.DNS,
			MTU:      cs.mtu,
			Routes:   cs.config.Routes,
		}
	}

	// Connect to server
	if cs.config.ConnectFn == nil {
		return ControlResponse{Status: "error", Error: "connect function not configured"}
	}

	placeholderIP, _, conn, err := cs.config.ConnectFn(ctx)
	if err != nil {
		return ControlResponse{Status: "error", Error: err.Error()}
	}

	cs.serverConn = conn

	// Perform TUN handshake NOW (before sending waiting_fd to Android).
	// This gives us the real assigned IP, so Android creates TUN with the correct IP
	// from the start — eliminating IP mismatch and the need for hot-swap.
	// NOTE: previously this was done after set_fd to fix "EOF" errors. The EOF was caused
	// by concurrent relay + handshake; here there is no relay yet, so it's safe.
	realAssignedIP, realServerIP, err := cs.performTUNHandshake()
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
		Status:   "waiting_fd",
		IP:       realAssignedIP.String(),
		ServerIP: realServerIP.String(),
		DNS:      cs.config.DNS,
		MTU:      cs.mtu,
		Routes:   cs.config.Routes,
	}
}

// handleSetFdWithReceivedFd starts VPN with fd received via SCM_RIGHTS
// The fd was already received in recvMessageWithFd along with the JSON command
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
		return ControlResponse{Status: "error", Error: "not waiting for fd, call connect first"}
	}

	if fd < 0 {
		return ControlResponse{Status: "error", Error: "no fd received with set_fd command"}
	}

	log.Info("Using TUN fd from SCM_RIGHTS: %d", fd)

	// Save fd for reconnect
	cs.tunFd = fd

	// Create TUN device from fd (needed for reconnect)
	mtu := cs.mtu
	if mtu == 0 {
		mtu = DefaultMTU
	}
	tunDev, err := CreateTUNFromFd(fd, "tun0", mtu)
	if err != nil {
		return ControlResponse{Status: "error", Error: fmt.Sprintf("failed to create TUN: %v", err)}
	}
	if err := tunDev.ConfigureFromFd(cs.assignedIP, cs.serverIP); err != nil {
		tunDev.Close()
		return ControlResponse{Status: "error", Error: fmt.Sprintf("failed to configure TUN: %v", err)}
	}
	cs.tunDev = tunDev

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

		go RunTUNRelayWithCallbacks(tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
			OnError: func(reason string) {
				cs.mu.Lock()
				stale := cs.relayGeneration != myGen
				cs.mu.Unlock()
				if stale {
					log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myGen, cs.relayGeneration, reason)
					return
				}
				log.Info("TUN relay died: %s", reason)
				// Start auto-reconnect in background if enabled
				if cs.autoReconnect {
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

	// Stop current TUN relay
	if cs.relayStopCh != nil {
		close(cs.relayStopCh)
		cs.relayStopCh = nil
	}

	// Force-unblock any pending serverConn.ReadFull so old Server→TUN goroutine exits quickly.
	// Without this, it stays blocked up to readTimeout (30s), competing with new relay for reads.
	if cs.serverConn != nil {
		cs.serverConn.SetReadDeadline(time.Now())
	}

	// Release mutex briefly so relay goroutines can exit cleanly
	cs.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	cs.mu.Lock()

	// Restore deadline so new relay can use serverConn normally
	if cs.serverConn != nil {
		cs.serverConn.SetReadDeadline(time.Time{})
	}

	// Close old TUN device
	if cs.tunDev != nil {
		cs.tunDev.Close()
		cs.tunDev = nil
	}
	cs.tunFd = newFd

	mtu := cs.mtu
	if mtu == 0 {
		mtu = DefaultMTU
	}
	newTunDev, err := CreateTUNFromFd(newFd, "tun0", mtu)
	if err != nil {
		log.Error("hot-swap: failed to create TUN device: %v", err)
		return ControlResponse{Status: "error", Error: fmt.Sprintf("hot-swap create TUN: %v", err)}
	}
	if err := newTunDev.ConfigureFromFd(cs.assignedIP, cs.serverIP); err != nil {
		newTunDev.Close()
		return ControlResponse{Status: "error", Error: fmt.Sprintf("hot-swap configure TUN: %v", err)}
	}
	cs.tunDev = newTunDev

	// Restart relay with the same server connection
	cs.relayGeneration++
	myGen := cs.relayGeneration
	cs.relayStopCh = make(chan struct{})
	go RunTUNRelayWithCallbacks(cs.tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
		OnError: func(reason string) {
			cs.mu.Lock()
			stale := cs.relayGeneration != myGen
			cs.mu.Unlock()
			if stale {
				log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myGen, cs.relayGeneration, reason)
				return
			}
			log.Info("TUN relay died after hot-swap: %s", reason)
			if cs.autoReconnect {
				go cs.doAutoReconnect(reason)
			} else {
				cs.sendEvent("connection_dead", reason)
			}
		},
		OnKeepalive: func() {
			cs.sendEvent("keepalive", "")
		},
	})

	log.Info("hot-swap complete: TUN relay restarted on new fd=%d (local=%s, remote=%s)", newFd, cs.assignedIP, cs.serverIP)

	resp := ControlResponse{
		Status:    "connected",
		IP:        cs.assignedIP.String(),
		ServerIP:  cs.serverIP.String(),
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

	// If new fd provided, update TUN device
	if newFd >= 0 {
		log.Info("Using new TUN fd from Android: %d (old fd=%d)", newFd, cs.tunFd)
		// Close old TUN device (fd may already be invalid)
		if cs.tunDev != nil {
			cs.tunDev.Close()
			cs.tunDev = nil
		}
		cs.tunFd = newFd

		// Create new TUN device from fd
		mtu := cs.mtu
		if mtu == 0 {
			mtu = DefaultMTU
		}
		tunDev, err := CreateTUNFromFd(newFd, "tun0", mtu)
		if err != nil {
			log.Error("Failed to create TUN from new fd: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("failed to create TUN from new fd: %v", err),
			}
		}
		if err := tunDev.ConfigureFromFd(cs.assignedIP, cs.serverIP); err != nil {
			tunDev.Close()
			log.Error("Failed to configure TUN from new fd: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("failed to configure TUN: %v", err),
			}
		}
		cs.tunDev = tunDev
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

	// Use ReconnectFn if available (preferred - handles circuit breaker reset)
	if cs.config.ReconnectFn != nil {
		newConn, serverIP, assignedIP, err := cs.config.ReconnectFn(ctx, cs.assignedIP, cs.mtu)
		if err != nil {
			log.Error("Reconnect failed: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("reconnect failed: %v", err),
			}
		}
		cs.serverConn = newConn
		cs.serverIP = serverIP
		// Update assigned IP if server gave us a new one
		if assignedIP != nil && !assignedIP.Equal(net.IPv4zero) {
			if !assignedIP.Equal(cs.assignedIP) {
				log.Info("Server assigned new IP: %s (was: %s)", assignedIP, cs.assignedIP)
				cs.assignedIP = assignedIP
				// Update TUN device with new local IP
				if cs.tunDev != nil {
					cs.tunDev.UpdateLocalIP(assignedIP)
				}
			}
		}
		log.Info("Reconnected successfully via ReconnectFn (server IP: %s, assigned: %s)", serverIP, cs.assignedIP)
	} else {
		// Fallback: use ConnectFn (less optimal - may need new IP)
		assignedIP, serverIP, conn, err := cs.config.ConnectFn(ctx)
		if err != nil {
			log.Error("Reconnect failed: %v", err)
			clearReconnecting()
			return ControlResponse{
				Status: "error",
				Error:  fmt.Sprintf("reconnect failed: %v", err),
			}
		}
		cs.serverConn = conn
		cs.assignedIP = assignedIP
		cs.serverIP = serverIP
		log.Info("Reconnected via ConnectFn, IP: %s", assignedIP)
	}

	// Restart TUN relay with new server connection and TUN device
	cs.relayStopCh = make(chan struct{})
	cs.relayGeneration++
	myRelayGen := cs.relayGeneration
	go RunTUNRelayWithCallbacks(cs.tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
		OnError: func(reason string) {
			cs.mu.Lock()
			stale := cs.relayGeneration != myRelayGen
			cs.mu.Unlock()
			if stale {
				log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myRelayGen, cs.relayGeneration, reason)
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
		Status:    "connected",
		IP:        cs.assignedIP.String(),
		ServerIP:  cs.serverIP.String(),
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

// recvMessageWithFd receives a message with optional fd via SCM_RIGHTS
// Returns the data bytes, received fd (-1 if none), and error
// Uses retry loop to handle EAGAIN on non-blocking sockets
// Waits indefinitely for data (or until connection closed)
func recvMessageWithFd(rawConn syscall.RawConn) ([]byte, int, error) {
	var data []byte
	fd := -1
	var recvErr error

	for {
		data = nil
		fd = -1
		recvErr = nil

		err := rawConn.Read(func(sockFd uintptr) bool {
			// Buffer for JSON data (up to 4KB should be enough)
			buf := make([]byte, 4096)

			// Buffer for control message (SCM_RIGHTS) - enough for 1 fd
			oob := make([]byte, unix.CmsgSpace(4))

			n, oobn, _, _, err := unix.Recvmsg(int(sockFd), buf, oob, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					// Non-blocking socket, need to retry
					recvErr = err
					return true // exit callback, will retry in outer loop
				}
				recvErr = fmt.Errorf("recvmsg failed: %w", err)
				return true
			}

			if n == 0 {
				recvErr = fmt.Errorf("connection closed")
				return true
			}

			data = buf[:n]
			log.Debug("Recvmsg: n=%d, oobn=%d, data=%s", n, oobn, string(data))

			// Parse control message if present
			if oobn > 0 {
				msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					log.Debug("Failed to parse control message: %v", err)
				} else if len(msgs) > 0 {
					fds, err := unix.ParseUnixRights(&msgs[0])
					if err != nil {
						log.Debug("Failed to parse unix rights: %v", err)
					} else if len(fds) > 0 {
						fd = fds[0]
						log.Debug("Received fd via SCM_RIGHTS: %d", fd)
					}
				}
			}

			return true
		})

		if err != nil {
			return nil, -1, fmt.Errorf("rawConn.Read failed: %w", err)
		}

		// Check if we got EAGAIN - need to retry (sleep longer to reduce CPU)
		if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Got data or real error - exit loop
		break
	}

	if recvErr != nil {
		return nil, -1, recvErr
	}

	return data, fd, nil
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

// Close closes the control server
func (cs *ControlServer) Close() error {
	// Stop auto-reconnect if running
	cs.stopAutoReconnect()
	cs.handleDisconnect()
	os.Remove(cs.socketPath)
	return cs.listener.Close()
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
				lastNetworkCheck = time.Now()
				log.Warn("No network connectivity, waiting...")

				// Wait for network with periodic checks
				if !cs.waitForNetwork(stopCh) {
					log.Info("Auto-reconnect cancelled while waiting for network")
					cs.mu.Lock()
					cs.reconnecting = false
					cs.mu.Unlock()
					return
				}

				// Network restored, reset backoff
				currentDelay = autoReconnectInitialDelay
				consecutiveFailures = 0
				log.Info("Network restored, resuming reconnect")
				continue
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

	// Stop any existing relay
	if cs.relayStopCh != nil {
		close(cs.relayStopCh)
		cs.relayStopCh = nil
	}

	// Close existing server connection
	if cs.serverConn != nil {
		cs.serverConn.Close()
		cs.serverConn = nil
	}

	// Small delay for cleanup
	time.Sleep(100 * time.Millisecond)

	var newConn net.Conn
	var serverIP, assignedIP net.IP
	var err error

	// Prefer ReconnectFn (handles circuit breaker reset)
	if cs.config.ReconnectFn != nil {
		newConn, serverIP, assignedIP, err = cs.config.ReconnectFn(ctx, cs.assignedIP, cs.mtu)
	} else if cs.config.ConnectFn != nil {
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

	// Start new TUN relay
	cs.relayStopCh = make(chan struct{})
	cs.relayGeneration++
	myAutoGen := cs.relayGeneration
	go RunTUNRelayWithCallbacks(cs.tunDev, cs.serverConn, cs.assignedIP, cs.serverIP, cs.relayStopCh, &RelayCallbacks{
		OnError: func(reason string) {
			cs.mu.Lock()
			stale := cs.relayGeneration != myAutoGen
			cs.mu.Unlock()
			if stale {
				log.Info("TUN relay OnError ignored (stale gen=%d, current=%d): %s", myAutoGen, cs.relayGeneration, reason)
				return
			}
			log.Info("TUN relay died: %s", reason)
			if cs.autoReconnect {
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
	// Try Google DNS as a quick connectivity check
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	// Try Cloudflare DNS
	conn, err = net.DialTimeout("tcp", "1.1.1.1:53", 3*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

// waitForNetwork waits until network connectivity is restored
// Returns false if stopCh is closed
// Listens to networkAvailableChan for immediate signal from Android
func (cs *ControlServer) waitForNetwork(stopCh chan struct{}) bool {
	checkInterval := 5 * time.Second
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
func (cs *ControlServer) performTUNHandshake() (assignedIP, serverIP net.IP, err error) {
	if cs.serverConn == nil {
		return nil, nil, fmt.Errorf("no server connection")
	}

	// Get MTU from config or use default
	mtu := cs.mtu
	if mtu == 0 {
		mtu = DefaultMTU
	}

	// Send TUN mode handshake
	// Format: [mode:1][localIP:4][mtu:2][version:1]
	// Send 0.0.0.0 to request auto IP assignment
	handshake := make([]byte, 8)
	handshake[0] = 0x02 // TUN mode
	// localIP = 0.0.0.0 (bytes 1:5 remain zero to request auto assignment)
	binary.BigEndian.PutUint16(handshake[5:7], uint16(mtu))
	handshake[7] = 0x02 // Version 2: supports full port hopping config

	log.Debug("Sending TUN handshake: mode=0x02, mtu=%d, version=2", mtu)
	if _, err := cs.serverConn.Write(handshake); err != nil {
		return nil, nil, fmt.Errorf("handshake write failed: %w", err)
	}

	// Read response (up to 64 bytes for extended v2 with port hopping config)
	// Minimum 9 bytes: [status:1][serverIP:4][clientIP:4]
	resp := make([]byte, 64)
	n, err := io.ReadAtLeast(cs.serverConn, resp, 9)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake read failed: %w", err)
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

	log.Debug("TUN handshake successful: assigned=%s, server=%s", assignedIP, serverIP)
	return assignedIP, serverIP, nil
}
