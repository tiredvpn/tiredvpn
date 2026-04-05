package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
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

// Keepalive packet marker (zero-length packet signals keepalive)
const keepaliveInterval = 10 * time.Second
const readTimeout = 30 * time.Second           // Must be > keepaliveInterval, detect dead connection faster
const writeTimeout = 30 * time.Second          // Write timeout (was 5s, caused i/o timeouts with bufferbloat)
const deadConnectionTimeout = 45 * time.Second // Proactive dead connection detection timeout

// Reconnect configuration
const (
	reconnectInitialDelay = 1 * time.Second // Start with 1 second
	reconnectMaxDelay     = 2 * time.Minute // Cap at 2 minutes
	reconnectMultiplier   = 2.0             // Double each time
	reconnectJitterFactor = 0.3             // +/- 30% jitter
)

// Port hop reconnect configuration (faster than regular reconnect)
const (
	portHopReconnectTimeout = 5 * time.Second // Quick timeout for port hop
	portHopMaxAttempts      = 3               // Max attempts before falling back to regular reconnect
)

// VPNClient manages the TUN-based VPN connection
// ServerCapabilities contains optional features advertised by server
type ServerCapabilities struct {
	PortHoppingEnabled bool
	PortRangeStart     int
	PortRangeEnd       int
	HopIntervalSec     int    // Hop interval in seconds (0 = use default 60s)
	HopStrategy        string // "random", "sequential", "fibonacci" (empty = "random")
	HopSeed            []byte // Optional seed for deterministic hopping
}

type VPNClient struct {
	tun        *TUNDevice
	manager    *strategy.Manager
	serverAddr string
	localIP    net.IP
	conn       net.Conn
	strategy   strategy.Strategy

	// Stats
	packetsUp   int64
	packetsDown int64
	bytesUp     int64
	bytesDown   int64

	// Control
	running      int32
	reconnecting int32 // Prevents concurrent reconnect attempts
	stopCh       chan struct{}
	mu           sync.Mutex
	lastActive   time.Time // Track last activity for keepalive

	// Server capabilities (received during handshake)
	serverCaps ServerCapabilities

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

	// Android VpnService support
	TunFd       int    // Use existing TUN file descriptor (from VpnService.establish())
	ProtectPath string // Unix socket path for VpnService.protect() calls
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
		// Configure TUN device
		if err := tunDev.Configure(cfg.LocalIP, cfg.RemoteIP, cfg.Routes); err != nil {
			tunDev.Close()
			return nil, err
		}
	}

	return &VPNClient{
		tun:        tunDev,
		manager:    cfg.Manager,
		serverAddr: cfg.ServerAddr,
		localIP:    cfg.LocalIP,
		stopCh:     make(chan struct{}),
	}, nil
}

// Start starts the VPN tunnel
func (v *VPNClient) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&v.running, 0, 1) {
		return nil // Already running
	}

	// Connect to server
	if err := v.connect(ctx); err != nil {
		atomic.StoreInt32(&v.running, 0)
		return err
	}

	// Initialize last activity time
	v.mu.Lock()
	v.lastActive = time.Now()
	v.mu.Unlock()

	// Subscribe to port hop events from strategy manager
	// This ensures VPN reconnects when port hopping changes the server port
	// Uses seamless "make before break" approach to minimize downtime
	if v.manager != nil {
		v.manager.SetPortHopCallback(func(oldPort, newPort int) {
			log.Info("VPN: port hop detected (%d -> %d), initiating seamless reconnect", oldPort, newPort)
			go v.seamlessPortHop(newPort)
		})
	}

	// Start packet forwarding
	go v.readFromTun()
	go v.readFromServer()
	go v.sendKeepalive()

	log.Info("VPN tunnel started")
	return nil
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
			v.handleDisconnect()
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
	newTarget := fmt.Sprintf("%s:%d", host, newPort)

	// Try to establish new connection (make)
	var newConn net.Conn
	var newStrategy strategy.Strategy
	var connectErr error

	for attempt := 1; attempt <= portHopMaxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), portHopReconnectTimeout)

		// Connect to new port using strategy manager
		newConn, newStrategy, connectErr = v.manager.Connect(ctx, newTarget)
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

	// Perform TUN mode handshake on new connection
	handshakeErr := v.performHandshake(newConn)
	if handshakeErr != nil {
		newConn.Close()
		log.Warn("VPN: port hop handshake failed: %v, falling back to force reconnect", handshakeErr)
		v.ForceReconnect()
		return
	}

	// Atomic swap: new connection ready, swap with old (break)
	v.mu.Lock()
	oldConn := v.conn
	v.conn = newConn
	v.strategy = newStrategy
	v.serverAddr = newTarget
	v.lastActive = time.Now()
	v.mu.Unlock()

	// Close old connection after swap
	if oldConn != nil {
		oldConn.Close()
	}

	elapsed := time.Since(start)
	log.Info("VPN: seamless port hop complete in %v (port %d, strategy %s)", elapsed, newPort, newStrategy.Name())
}

// performHandshake performs TUN mode handshake on a connection
// Used by seamlessPortHop to setup new connection before swapping
func (v *VPNClient) performHandshake(conn net.Conn) error {
	// Send TUN mode handshake
	// Format: [mode:1][localIP:4][mtu:2][version:1]
	handshake := make([]byte, 8)
	handshake[0] = 0x02 // TUN mode
	copy(handshake[1:5], v.localIP.To4())
	binary.BigEndian.PutUint16(handshake[5:7], uint16(v.tun.mtu))
	handshake[7] = 0x02 // Version 2: supports full port hopping config

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(handshake); err != nil {
		return fmt.Errorf("handshake write failed: %w", err)
	}

	// Read server response
	resp := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		return fmt.Errorf("handshake read failed: %w", err)
	}
	if n < 9 {
		return fmt.Errorf("invalid server response: got %d bytes", n)
	}
	if resp[0] != 0x00 {
		return fmt.Errorf("server error: status=%d", resp[0])
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

	// Enable raw mode for ConfusedConn if applicable
	if confusedConn, ok := conn.(*strategy.ConfusedConn); ok {
		confusedConn.SetRawMode(true)
	}

	log.Debug("VPN: port hop handshake successful")
	return nil
}

// connect establishes connection to server
func (v *VPNClient) connect(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Close existing connection
	if v.conn != nil {
		v.conn.Close()
	}

	// Connect via strategy manager
	conn, strat, err := v.manager.Connect(ctx, v.serverAddr)
	if err != nil {
		return err
	}

	v.conn = conn
	v.strategy = strat

	// Send TUN mode handshake
	// Format: [mode:1][localIP:4][mtu:2][version:1]
	// If localIP is 0.0.0.0, server will auto-assign an IP
	// version=0x02 means client supports full port hopping config (interval, strategy, seed)
	handshake := make([]byte, 8)
	handshake[0] = 0x02 // TUN mode
	copy(handshake[1:5], v.localIP.To4())
	binary.BigEndian.PutUint16(handshake[5:7], uint16(v.tun.mtu))
	handshake[7] = 0x02 // Version 2: supports full port hopping config

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(handshake); err != nil {
		conn.Close()
		return err
	}

	// Read server response
	// Legacy (9 bytes): [status:1][serverIP:4][clientIP:4]
	// Extended v1 (14 bytes): [status:1][serverIP:4][clientIP:4][flags:1][portStart:2][portEnd:2]
	// Extended v2 (20+ bytes): [status:1][serverIP:4][clientIP:4][flags:1][portStart:2][portEnd:2][hopInterval:4][strategy:1][seedLen:1][seed:0-32]
	resp := make([]byte, 64) // Large enough for v2 with max seed
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		conn.Close()
		return err
	}
	if n < 9 {
		conn.Close()
		return fmt.Errorf("invalid server response: got %d bytes, expected at least 9", n)
	}

	if resp[0] != 0x00 {
		conn.Close()
		switch resp[0] {
		case 0x01:
			return fmt.Errorf("server error: IP pool exhausted")
		case 0x02:
			return fmt.Errorf("server error: no IP pool configured (auto IP not supported)")
		default:
			return fmt.Errorf("server error: status=%d", resp[0])
		}
	}

	// Server sends its TUN IP and assigned client IP
	serverIP := net.IP(resp[1:5])
	assignedIP := net.IP(resp[5:9])
	log.Info("VPN connected via %s (server IP: %s, assigned IP: %s)", strat.Name(), serverIP, assignedIP)

	// Update local IP if server assigned a different one
	if !assignedIP.Equal(v.localIP) && !assignedIP.Equal(net.IPv4zero) {
		log.Info("Server assigned IP: %s (requested: %s)", assignedIP, v.localIP)
		v.localIP = assignedIP
		// Update TUN device with new local IP
		if err := v.tun.UpdateLocalIP(assignedIP); err != nil {
			log.Warn("Failed to update TUN local IP: %v", err)
		}
	}

	// Update TUN peer IP if it changed
	if !serverIP.Equal(v.tun.remoteIP) {
		log.Info("Updating TUN peer IP from %s to %s", v.tun.remoteIP, serverIP)
		if err := v.tun.UpdatePeerIP(serverIP); err != nil {
			log.Warn("Failed to update TUN peer IP: %v", err)
		}
	}

	// Parse extended capabilities if server sent them
	if n >= 14 {
		flags := resp[9]
		portStart := int(binary.BigEndian.Uint16(resp[10:12]))
		portEnd := int(binary.BigEndian.Uint16(resp[12:14]))

		if flags&0x01 != 0 && portStart > 0 && portEnd > portStart {
			v.serverCaps = ServerCapabilities{
				PortHoppingEnabled: true,
				PortRangeStart:     portStart,
				PortRangeEnd:       portEnd,
				HopIntervalSec:     60,       // Default
				HopStrategy:        "random", // Default
			}

			// Parse extended v2 fields if available (20+ bytes)
			if n >= 20 {
				hopInterval := int(binary.BigEndian.Uint32(resp[14:18]))
				strategyByte := resp[18]
				seedLen := int(resp[19])

				if hopInterval > 0 {
					v.serverCaps.HopIntervalSec = hopInterval
				}

				// Decode strategy
				switch strategyByte {
				case 0x00:
					v.serverCaps.HopStrategy = "random"
				case 0x01:
					v.serverCaps.HopStrategy = "sequential"
				case 0x02:
					v.serverCaps.HopStrategy = "fibonacci"
				}

				// Parse seed if present
				if seedLen > 0 && n >= 20+seedLen && seedLen <= 32 {
					v.serverCaps.HopSeed = make([]byte, seedLen)
					copy(v.serverCaps.HopSeed, resp[20:20+seedLen])
					log.Info("Server advertises port hopping: range %d-%d, interval %ds, strategy %s, seed_len %d",
						portStart, portEnd, v.serverCaps.HopIntervalSec, v.serverCaps.HopStrategy, seedLen)
				} else {
					log.Info("Server advertises port hopping: range %d-%d, interval %ds, strategy %s",
						portStart, portEnd, v.serverCaps.HopIntervalSec, v.serverCaps.HopStrategy)
				}
			} else {
				log.Info("Server advertises port hopping: range %d-%d (v1 response)", portStart, portEnd)
			}
		}
	}

	// Enable raw mode for ConfusedConn - VPN mode handles framing itself
	// Without this, ConfusedConn.Read() strips length prefix, then vpn.go tries to read it again
	if confusedConn, ok := conn.(*strategy.ConfusedConn); ok {
		confusedConn.SetRawMode(true)
		log.Debug("Enabled raw mode for ConfusedConn (VPN mode)")
	}

	return nil
}

// GetServerCapabilities returns capabilities received from server during handshake
func (v *VPNClient) GetServerCapabilities() ServerCapabilities {
	return v.serverCaps
}

// sendKeepalive periodically sends keepalive packets to prevent timeout
func (v *VPNClient) sendKeepalive() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("sendKeepalive panic: %v", r)
			v.handleDisconnect()
		}
	}()

	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&v.running) == 0 {
				return
			}

			v.mu.Lock()
			conn := v.conn
			lastActive := v.lastActive
			v.mu.Unlock()

			if conn == nil {
				continue
			}

			// Only send keepalive if no recent activity
			if time.Since(lastActive) >= keepaliveInterval-time.Second {
				// Send zero-length packet as keepalive: [length:4=0]
				keepalivePkt := make([]byte, 4)
				binary.BigEndian.PutUint32(keepalivePkt, 0)

				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(keepalivePkt); err != nil {
					log.Debug("Keepalive write error: %v", err)
					v.handleDisconnect()
				} else {
					log.Debug("Sent keepalive packet")
				}
			}

		case <-v.stopCh:
			return
		}
	}
}

// readFromTun reads packets from TUN and sends to server
func (v *VPNClient) readFromTun() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("readFromTun panic: %v", r)
			v.handleDisconnect()
		}
	}()

	buf := make([]byte, v.tun.mtu+4)
	log.Debug("readFromTun goroutine started, waiting for packets from TUN device")

	for atomic.LoadInt32(&v.running) == 1 {
		log.Debug("Attempting to read from TUN device...")
		n, err := v.tun.Read(buf[4:])
		if err != nil {
			if atomic.LoadInt32(&v.running) == 0 {
				return
			}
			log.Debug("TUN read error: %v", err)
			continue
		}
		dumpEnd := n + 4
		if dumpEnd > 24 {
			dumpEnd = 24
		}
		log.Debug("Read %d bytes from TUN, first 20 bytes: % x", n, buf[4:dumpEnd])

		// Clamp TCP MSS on SYN/SYN-ACK packets to prevent oversized segments
		ClampTCPMSS(buf[4:4+n], v.tun.mtu)

		// Frame packet: [length:4][data:n]
		binary.BigEndian.PutUint32(buf[:4], uint32(n))

		v.mu.Lock()
		conn := v.conn
		v.lastActive = time.Now() // Update activity timestamp
		v.mu.Unlock()

		if conn == nil {
			log.Debug("TUN->Server: conn is nil, dropping %d bytes", n)
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		written, err := conn.Write(buf[:n+4])
		if err != nil {
			log.Debug("Server write error: %v", err)
			v.handleDisconnect()
			continue
		}

		log.Debug("TUN->Server: sent %d bytes (payload=%d) to server", written, n)
		atomic.AddInt64(&v.packetsUp, 1)
		atomic.AddInt64(&v.bytesUp, int64(n))
	}
}

// readFromServer reads packets from server and writes to TUN
func (v *VPNClient) readFromServer() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("readFromServer panic: %v", r)
			v.handleDisconnect()
		}
	}()

	lenBuf := make([]byte, 4)

	for atomic.LoadInt32(&v.running) == 1 {
		v.mu.Lock()
		conn := v.conn
		v.mu.Unlock()

		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Read packet length with extended timeout (keepalive keeps connection alive)
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		nLen, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if atomic.LoadInt32(&v.running) == 0 {
				return
			}
			log.Debug("Server read error: %v", err)
			v.handleDisconnect()
			continue
		}

		pktLen := binary.BigEndian.Uint32(lenBuf)

		// Handle keepalive packet (zero length)
		if pktLen == 0 {
			log.Debug("Received keepalive from server")
			v.mu.Lock()
			v.lastActive = time.Now()
			v.mu.Unlock()
			continue
		}

		log.Debug("Read length header: %d bytes, value=%d (0x%02x %02x %02x %02x)",
			nLen, pktLen, lenBuf[0], lenBuf[1], lenBuf[2], lenBuf[3])

		if pktLen > uint32(v.tun.mtu) {
			// Instead of disconnecting, read and discard the oversized packet
			// and inject ICMP Fragmentation Needed back into the TUN
			log.Debug("Packet too large (%d > MTU %d), dropping and sending ICMP", pktLen, v.tun.mtu)
			oversized := make([]byte, pktLen)
			if _, err := io.ReadFull(conn, oversized); err != nil {
				log.Debug("Failed to read oversized packet: %v", err)
				v.handleDisconnect()
				continue
			}
			// Generate ICMP Fragmentation Needed and inject into TUN
			icmpPkt := BuildICMPFragNeeded(v.tun.remoteIP, oversized, uint16(v.tun.mtu))
			if icmpPkt != nil {
				if _, err := v.tun.Write(icmpPkt); err != nil {
					log.Debug("Failed to inject ICMP frag needed: %v", err)
				}
			}
			continue
		}

		// Read packet data
		buf := make([]byte, pktLen)
		nRead, err := io.ReadFull(conn, buf)
		if err != nil {
			log.Debug("Server read data error: %v", err)
			v.handleDisconnect()
			continue
		}
		if len(buf) >= 8 {
			log.Debug("Read packet data: %d bytes, first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
				nRead, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7])
		} else if len(buf) > 0 {
			log.Debug("Read packet data: %d bytes: % x", nRead, buf)
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
		ClampTCPMSS(actualBuf, v.tun.mtu)

		// Write to TUN
		if len(actualBuf) > 0 {
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
		log.Debug("Successfully wrote %d bytes to TUN", n)

		// Update activity timestamp
		v.mu.Lock()
		v.lastActive = time.Now()
		v.mu.Unlock()

		atomic.AddInt64(&v.packetsDown, 1)
		atomic.AddInt64(&v.bytesDown, int64(pktLen))
	}
}

// handleDisconnect handles connection loss and reconnects with exponential backoff
// and network connectivity detection
func (v *VPNClient) handleDisconnect() {
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

	v.mu.Lock()
	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
	}
	v.mu.Unlock()

	// Update strategy confidence
	if v.strategy != nil && v.manager != nil {
		v.manager.UpdateStrategyConfidence(v.strategy.ID(), false)
	}

	// Initialize exponential backoff
	currentDelay := reconnectInitialDelay
	consecutiveFailures := 0
	lastNetworkCheck := time.Time{}
	networkAvailable := true

	log.Info("VPN disconnected, starting reconnect with exponential backoff")

	// Try to reconnect with exponential backoff
	for atomic.LoadInt32(&v.running) == 1 {
		consecutiveFailures++

		// Check network connectivity periodically (every 10 failures or 30 seconds)
		// This prevents wasting resources when network is down
		if consecutiveFailures%10 == 0 || time.Since(lastNetworkCheck) > 30*time.Second {
			networkAvailable = v.checkNetworkConnectivity()
			lastNetworkCheck = time.Now()

			if !networkAvailable {
				// Reset circuit breakers since failures are due to no network
				if v.manager != nil {
					v.manager.ResetForNetworkChange()
				}
				log.Warn("No network connectivity, waiting for network to restore...")
				v.waitForNetworkRestore()
				// After network restore, reset backoff
				currentDelay = reconnectInitialDelay
				consecutiveFailures = 0
				continue
			}
		}

		log.Info("Reconnecting VPN (attempt %d, backoff %v)...", consecutiveFailures, currentDelay)

		// Use shorter timeout for reconnect attempts
		connectTimeout := 15 * time.Second
		if currentDelay > 30*time.Second {
			connectTimeout = 30 * time.Second // Longer timeout for longer backoffs
		}

		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		err := v.connect(ctx)
		cancel()

		if err == nil {
			log.Info("VPN reconnected successfully after %d attempts", consecutiveFailures)
			return
		}

		// Classify error type for better logging
		errType := classifyError(err)
		log.Warn("Reconnect failed (%s): %v, next attempt in %v", errType, err, currentDelay)

		// If all strategies are blocked (circuit breakers open), reset them
		if v.manager != nil && !v.manager.HasAvailableStrategies() {
			log.Warn("All strategies blocked by circuit breakers, resetting...")
			v.manager.ResetForNetworkChange()
		}

		// Wait with jitter before next attempt
		select {
		case <-v.stopCh:
			log.Info("Reconnect cancelled (VPN stopped)")
			return
		case <-time.After(addJitter(currentDelay)):
		}

		// Exponential backoff with cap
		currentDelay = time.Duration(float64(currentDelay) * reconnectMultiplier)
		if currentDelay > reconnectMaxDelay {
			currentDelay = reconnectMaxDelay
		}
	}
}

// checkNetworkConnectivity performs a quick TCP check to the server
func (v *VPNClient) checkNetworkConnectivity() bool {
	// Try a quick TCP connection to the server port
	host, _, err := net.SplitHostPort(v.serverAddr)
	if err != nil {
		host = v.serverAddr
	}

	// Try common ports that are usually open
	testAddrs := []string{
		v.serverAddr,                  // Original server address
		net.JoinHostPort(host, "443"), // HTTPS
		net.JoinHostPort(host, "80"),  // HTTP
	}

	for _, addr := range testAddrs {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	// Also try Google DNS as a fallback check
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

// waitForNetworkRestore waits until network connectivity is restored
func (v *VPNClient) waitForNetworkRestore() {
	checkInterval := 5 * time.Second
	attempt := 0

	for atomic.LoadInt32(&v.running) == 1 {
		attempt++
		if attempt%12 == 0 { // Every minute
			log.Info("Still waiting for network connectivity (attempt %d)...", attempt)
		}

		select {
		case <-v.stopCh:
			return
		case <-time.After(checkInterval):
		}

		if v.checkNetworkConnectivity() {
			log.Info("Network connectivity restored after %d checks", attempt)
			return
		}
	}
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

	// Set immediate deadline to unblock any blocking reads before closing
	v.mu.Lock()
	if v.conn != nil {
		v.conn.SetDeadline(time.Now()) // Force immediate timeout
		v.conn.Close()
	}
	v.mu.Unlock()

	// Unblock TUN read goroutine and close
	v.tun.SetReadDeadline(time.Now())
	v.tun.Close()

	log.Info("VPN tunnel stopped (packets: up=%d down=%d, bytes: up=%d down=%d)",
		v.packetsUp, v.packetsDown, v.bytesUp, v.bytesDown)
}

// Stats returns current VPN statistics
func (v *VPNClient) Stats() (packetsUp, packetsDown, bytesUp, bytesDown int64) {
	return atomic.LoadInt64(&v.packetsUp),
		atomic.LoadInt64(&v.packetsDown),
		atomic.LoadInt64(&v.bytesUp),
		atomic.LoadInt64(&v.bytesDown)
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
	log.Info("Starting TUN relay (local=%s, remote=%s)", localIP, remoteIP)

	stopCh, safeClose := makeStopChannel(externalStopCh)

	lastActivity := time.Now().UnixNano()
	updateActivity := func() { atomic.StoreInt64(&lastActivity, time.Now().UnixNano()) }
	getIdleDuration := func() time.Duration {
		return time.Since(time.Unix(0, atomic.LoadInt64(&lastActivity)))
	}

	go runDeadConnectionMonitor(stopCh, safeClose, getIdleDuration, callbacks)
	go runKeepaliveSender(stopCh, serverConn)
	go runTUNToServer(stopCh, safeClose, tunDev, serverConn, updateActivity)

	errorReason := runServerToTUN(stopCh, safeClose, tunDev, serverConn, remoteIP, updateActivity, callbacks)

	safeClose()
	serverConn.Close()
	log.Info("TUN relay stopped (reason: %s)", errorReason)

	if callbacks != nil && callbacks.OnError != nil && errorReason != "" {
		callbacks.OnError(errorReason)
	}
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
func runDeadConnectionMonitor(stopCh chan struct{}, safeClose func(), getIdleDuration func() time.Duration, callbacks *RelayCallbacks) {
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
		}
	}
}

// runKeepaliveSender periodically writes zero-length keepalive frames to serverConn.
func runKeepaliveSender(stopCh chan struct{}, serverConn net.Conn) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			keepalive := make([]byte, 4)
			serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := serverConn.Write(keepalive); err != nil {
				log.Debug("Keepalive write error: %v", err)
				return
			}
			log.Debug("Sent keepalive")
		case <-stopCh:
			return
		}
	}
}

// runTUNToServer reads IP packets from the TUN device and frames them to serverConn.
func runTUNToServer(stopCh chan struct{}, safeClose func(), tunDev *TUNDevice, serverConn net.Conn, updateActivity func()) {
	buf := make([]byte, tunDev.mtu+4)
	pktCount := 0
	for {
		select {
		case <-stopCh:
			log.Debug("TUN->Server: stop signal received")
			return
		default:
		}

		n, err := tunDev.Read(buf[4:])
		if err != nil {
			if isTemporaryError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
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

		serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := serverConn.Write(buf[:n+4]); err != nil {
			log.Debug("Server write error: %v", err)
			safeClose()
			return
		}
		updateActivity()
	}
}

// runServerToTUN reads framed packets from serverConn and writes them to the TUN device.
// Returns an error reason string (empty if stopped intentionally).
func runServerToTUN(stopCh chan struct{}, safeClose func(), tunDev *TUNDevice, serverConn net.Conn, remoteIP net.IP, updateActivity func(), callbacks *RelayCallbacks) string {
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
			if callbacks != nil && callbacks.OnKeepalive != nil {
				callbacks.OnKeepalive()
			}
			continue
		}

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
