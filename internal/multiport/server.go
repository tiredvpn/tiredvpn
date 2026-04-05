package multiport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Server manages the multiport UDP server
type Server struct {
	// Configuration
	tcpPort      int
	udpBasePort  int
	udpPortCount int
	maxClients   int

	// Components
	allocator    *PortAllocator
	tcpListener  net.Listener
	udpSockets   map[int]*net.UDPConn // port -> UDP connection
	udpSocketsMu sync.RWMutex

	// Session management
	sessions       map[string]*Session // sessionID -> session
	sessionsByPort map[int]string      // UDP port -> sessionID (for fast lookup)
	sessionsMu     sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Session represents a client session
type Session struct {
	// Identity
	SessionID  string
	ClientID   string
	Allocation *Allocation

	// Buffers
	RecvBuffer *ReceiveBuffer
	SendBuffer *SendBuffer

	// Target connection (for relay)
	TargetConn net.Conn
	TargetMu   sync.Mutex

	// Stats
	CreatedAt    time.Time
	LastActivity time.Time

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// NewServer creates a new multiport server
func NewServer(tcpPort, udpBasePort, udpPortCount, maxClients int) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		tcpPort:        tcpPort,
		udpBasePort:    udpBasePort,
		udpPortCount:   udpPortCount,
		maxClients:     maxClients,
		allocator:      NewPortAllocator(udpBasePort, udpPortCount, maxClients),
		udpSockets:     make(map[int]*net.UDPConn),
		sessions:       make(map[string]*Session),
		sessionsByPort: make(map[int]string),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start starts the server
func (s *Server) Start() error {
	// Start TCP listener for handshake
	tcpAddr := fmt.Sprintf(":%d", s.tcpPort)
	listener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}
	s.tcpListener = listener

	slog.Info("multiport server started",
		"tcpPort", s.tcpPort,
		"udpBasePort", s.udpBasePort,
		"udpPortCount", s.udpPortCount,
		"maxClients", s.maxClients,
	)

	// Accept TCP connections
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// acceptLoop accepts TCP connections for handshake
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				slog.Error("accept error", "error", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleHandshake(conn)
	}
}

// handleHandshake handles TCP handshake with a client
func (s *Server) handleHandshake(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read handshake request
	decoder := json.NewDecoder(conn)
	var req HandshakeRequest
	if err := decoder.Decode(&req); err != nil {
		slog.Error("decode handshake request", "error", err)
		return
	}

	slog.Info("handshake request", "clientID", req.ClientID)

	// Allocate port range
	alloc, err := s.allocator.Allocate(req.ClientID)
	if err != nil {
		slog.Error("allocate ports", "error", err)
		// Send error response
		resp := map[string]string{"error": err.Error()}
		json.NewEncoder(conn).Encode(resp)
		return
	}

	// Create session
	session := s.createSession(req.ClientID, alloc)

	// Send handshake response
	resp := HandshakeResponse{
		StartPort: alloc.PortRange.Start,
		Count:     alloc.PortRange.Count,
		Secret:    alloc.SecretHex(),
		SessionID: alloc.SessionID,
	}

	if err := json.NewEncoder(conn).Encode(&resp); err != nil {
		slog.Error("encode handshake response", "error", err)
		s.closeSession(alloc.SessionID)
		return
	}

	slog.Info("handshake complete",
		"sessionID", alloc.SessionID,
		"portRange", fmt.Sprintf("%d-%d", alloc.PortRange.Start, alloc.PortRange.Start+alloc.PortRange.Count-1),
	)

	// Start UDP listeners for this session
	if err := s.startUDPListeners(session); err != nil {
		slog.Error("start udp listeners", "error", err)
		s.closeSession(alloc.SessionID)
		return
	}

	// Start session handlers
	s.wg.Add(2)
	go s.handleSessionACKs(session)
	go s.handleSessionData(session)
}

// createSession creates a new client session
func (s *Server) createSession(clientID string, alloc *Allocation) *Session {
	ctx, cancel := context.WithCancel(s.ctx)

	session := &Session{
		SessionID:    alloc.SessionID,
		ClientID:     clientID,
		Allocation:   alloc,
		RecvBuffer:   NewReceiveBuffer(0), // Start from seq 0
		SendBuffer:   NewSendBuffer(0),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ctx:          ctx,
		cancel:       cancel,
	}

	s.sessionsMu.Lock()
	s.sessions[alloc.SessionID] = session
	s.sessionsMu.Unlock()

	return session
}

// startUDPListeners starts UDP listeners for a session's port range
func (s *Server) startUDPListeners(session *Session) error {
	portRange := session.Allocation.PortRange

	for i := 0; i < portRange.Count; i++ {
		port := portRange.Start + i

		// Check if already listening
		s.udpSocketsMu.RLock()
		_, exists := s.udpSockets[port]
		s.udpSocketsMu.RUnlock()

		if exists {
			continue
		}

		// Create UDP listener
		addr := &net.UDPAddr{Port: port}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("listen udp port %d: %w", port, err)
		}

		// Set large socket buffers to avoid packet drops (16MB each)
		if err := conn.SetReadBuffer(16 * 1024 * 1024); err != nil {
			return fmt.Errorf("set read buffer for port %d: %w", port, err)
		}
		if err := conn.SetWriteBuffer(16 * 1024 * 1024); err != nil {
			return fmt.Errorf("set write buffer for port %d: %w", port, err)
		}

		// Store socket
		s.udpSocketsMu.Lock()
		s.udpSockets[port] = conn
		s.udpSocketsMu.Unlock()

		// Map port to session
		s.sessionsMu.Lock()
		s.sessionsByPort[port] = session.SessionID
		s.sessionsMu.Unlock()

		// Start receiver
		s.wg.Add(1)
		go s.udpReceiveLoop(port, conn)
	}

	slog.Info("udp listeners started",
		"sessionID", session.SessionID,
		"ports", fmt.Sprintf("%d-%d", portRange.Start, portRange.Start+portRange.Count-1),
	)

	return nil
}

// udpReceiveLoop receives UDP packets on a specific port
func (s *Server) udpReceiveLoop(port int, conn *net.UDPConn) {
	defer s.wg.Done()

	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read packet
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				slog.Error("udp read error", "port", port, "error", err)
				continue
			}
		}

		// Process packet
		s.handleUDPPacket(port, buf[:n], addr, conn)
	}
}

// handleUDPPacket processes a received UDP packet
func (s *Server) handleUDPPacket(port int, data []byte, from *net.UDPAddr, conn *net.UDPConn) {
	// Parse packet
	var pkt Packet
	if err := pkt.Unmarshal(data); err != nil {
		slog.Warn("invalid packet", "port", port, "error", err)
		return
	}

	// Find session by session ID
	sessionID := fmt.Sprintf("%04x", pkt.SessionID) // Convert uint16 to hex string

	s.sessionsMu.RLock()
	session, exists := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !exists {
		// Try to find by port
		s.sessionsMu.RLock()
		fullSessionID, portExists := s.sessionsByPort[port]
		s.sessionsMu.RUnlock()

		if !portExists {
			slog.Warn("no session for port", "port", port, "sessionID", sessionID)
			return
		}

		s.sessionsMu.RLock()
		session, exists = s.sessions[fullSessionID]
		s.sessionsMu.RUnlock()

		if !exists {
			slog.Warn("session not found", "sessionID", fullSessionID)
			return
		}
	}

	// Update last activity
	session.LastActivity = time.Now()

	// Handle ACK packet
	if pkt.Flags&FlagACK != 0 {
		var ack AckPacket
		if err := ack.Unmarshal(data); err != nil {
			slog.Warn("invalid ack packet", "error", err)
			return
		}
		session.SendBuffer.ProcessAck(&ack)
		return
	}

	// Handle data packet
	if pkt.Flags&FlagDATA != 0 {
		session.RecvBuffer.AddPacket(&pkt)
		return
	}

	// Handle FIN packet
	if pkt.Flags&FlagFIN != 0 {
		slog.Info("received FIN", "sessionID", session.SessionID)
		s.closeSession(session.SessionID)
		return
	}
}

// handleSessionACKs sends ACKs for received packets
func (s *Server) handleSessionACKs(session *Session) {
	defer s.wg.Done()

	for {
		select {
		case ack := <-session.RecvBuffer.AckChan():
			// Send ACK packet on first port of range
			if err := s.sendACK(session, ack); err != nil {
				slog.Error("send ack", "error", err)
			}
		case <-session.ctx.Done():
			return
		}
	}
}

// sendACK sends an ACK packet to the client
func (s *Server) sendACK(session *Session, ack *AckPacket) error {
	// Set session ID (first 2 bytes of UUID)
	ack.SessionID = uint16(session.SessionID[0])<<8 | uint16(session.SessionID[1])

	// Marshal ACK
	data, err := ack.Marshal()
	if err != nil {
		return fmt.Errorf("marshal ack: %w", err)
	}

	// Send on first port of range
	port := session.Allocation.PortRange.Start

	s.udpSocketsMu.RLock()
	conn, exists := s.udpSockets[port]
	s.udpSocketsMu.RUnlock()

	if !exists {
		return fmt.Errorf("no socket for port %d", port)
	}

	// TODO: Need client address - store it when receiving first packet
	// For now, just log
	slog.Debug("would send ack", "sessionID", session.SessionID, "ackBase", ack.AckBase)

	_ = conn
	_ = data

	return nil
}

// handleSessionData processes received data and relays to target
func (s *Server) handleSessionData(session *Session) {
	defer s.wg.Done()

	for {
		select {
		case data := <-session.RecvBuffer.ReadyChan():
			// TODO: Relay to target connection
			slog.Debug("received data", "sessionID", session.SessionID, "bytes", len(data))
			_ = data
		case <-session.ctx.Done():
			return
		}
	}
}

// closeSession closes a session and releases resources
func (s *Server) closeSession(sessionID string) {
	s.sessionsMu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		s.sessionsMu.Unlock()
		return
	}
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()

	// Cancel session context
	session.cancel()

	// Close buffers
	session.RecvBuffer.Close()
	session.SendBuffer.Close()

	// Close target connection
	if session.TargetConn != nil {
		session.TargetConn.Close()
	}

	// Release port allocation
	s.allocator.Release(sessionID)

	// Remove port mappings
	portRange := session.Allocation.PortRange
	s.sessionsMu.Lock()
	for i := 0; i < portRange.Count; i++ {
		port := portRange.Start + i
		delete(s.sessionsByPort, port)
	}
	s.sessionsMu.Unlock()

	// Note: We don't close UDP sockets as they may be reused by other sessions

	slog.Info("session closed", "sessionID", sessionID)
}

// Stop stops the server
func (s *Server) Stop() error {
	// Cancel context
	s.cancel()

	// Close TCP listener
	if s.tcpListener != nil {
		s.tcpListener.Close()
	}

	// Close all UDP sockets
	s.udpSocketsMu.Lock()
	for _, conn := range s.udpSockets {
		conn.Close()
	}
	s.udpSocketsMu.Unlock()

	// Close all sessions
	s.sessionsMu.Lock()
	for sessionID := range s.sessions {
		go s.closeSession(sessionID)
	}
	s.sessionsMu.Unlock()

	// Wait for goroutines
	s.wg.Wait()

	slog.Info("server stopped")
	return nil
}

// Stats returns server statistics
type ServerStats struct {
	ActiveSessions int
	TotalPorts     int
	UsedPorts      int
	Allocator      AllocatorStats
}

// Stats returns current server statistics
func (s *Server) Stats() ServerStats {
	s.sessionsMu.RLock()
	activeSessions := len(s.sessions)
	s.sessionsMu.RUnlock()

	s.udpSocketsMu.RLock()
	totalPorts := len(s.udpSockets)
	s.udpSocketsMu.RUnlock()

	return ServerStats{
		ActiveSessions: activeSessions,
		TotalPorts:     totalPorts,
		UsedPorts:      activeSessions * s.udpPortCount,
		Allocator:      s.allocator.Stats(),
	}
}
