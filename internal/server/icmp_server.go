package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpSessionTTL    = 5 * time.Minute
	icmpMaxSessions   = 4096
	icmpReadDeadline  = 30 * time.Second
	icmpWriteDeadline = 10 * time.Second
)

// icmpSession tracks an active ICMP tunnel session.
type icmpSession struct {
	sessionID uint32
	cipher    interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		NonceSize() int
		Overhead() int
	}
	clientAddr *net.IPAddr
	tunnelID   int
	recvCh     chan []byte
	sendCh     chan icmpSendRequest
	lastActive time.Time
	mu         sync.Mutex
}

type icmpSendRequest struct {
	data      []byte
	seq       uint32
	sessionID uint32
}

// ICMPServer receives ICMP Echo Request packets, decrypts tunnel data, and
// relays it through a virtual net.Conn handed to the standard tunnel handler.
// Requires CAP_NET_RAW.
type ICMPServer struct {
	conn    *icmp.PacketConn
	srvCtx  *serverContext
	secret  []byte
	mu      sync.Mutex
	sessions map[uint32]*icmpSession
}

// startICMPServer starts the ICMP listener if EnableICMP is set and CAP_NET_RAW is available.
func startICMPServer(srvCtx *serverContext) {
	srv := &ICMPServer{
		srvCtx:   srvCtx,
		secret:   srvCtx.cfg.Secret,
		sessions: make(map[uint32]*icmpSession),
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Warn("ICMP server: listen failed (need CAP_NET_RAW), skipping: %v", err)
		return
	}
	srv.conn = conn

	log.Info("ICMP server: listening for tunnel packets")
	go srv.cleanupLoop()
	go srv.run()
}

func (s *ICMPServer) run() {
	defer s.conn.Close()
	buf := make([]byte, 1500)
	for {
		s.conn.SetReadDeadline(time.Now().Add(icmpReadDeadline))
		n, peer, err := s.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Debug("ICMP server: read error: %v", err)
			return
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || len(echo.Data) < strategy.TunnelHeaderSize {
			continue
		}

		if binary.BigEndian.Uint16(echo.Data[0:2]) != strategy.ICMPTunnelMagic {
			continue
		}

		peerIP, _, err := net.SplitHostPort(peer.String())
		if err != nil {
			peerIP = peer.String()
		}
		clientAddr := &net.IPAddr{IP: net.ParseIP(peerIP)}

		go s.handlePacket(echo, clientAddr)
	}
}

func (s *ICMPServer) handlePacket(echo *icmp.Echo, clientAddr *net.IPAddr) {
	data := echo.Data
	header := strategy.ParseTunnelHeader(data[:strategy.TunnelHeaderSize])

	session := s.getOrCreateSession(header.SessionID, clientAddr, echo.ID)
	if session == nil {
		return
	}

	// Decrypt payload
	encrypted := data[strategy.TunnelHeaderSize:]
	if len(encrypted) == 0 {
		return
	}
	headerBytes := data[:strategy.TunnelHeaderSize]

	nonce := make([]byte, 24)
	binary.BigEndian.PutUint32(nonce[0:], header.SessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(header.PacketSeq))

	plaintext, err := session.cipher.Open(nil, nonce, encrypted, headerBytes)
	if err != nil {
		log.Debug("ICMP server: decrypt error session=%08x: %v", header.SessionID, err)
		return
	}

	session.mu.Lock()
	session.lastActive = time.Now()
	session.mu.Unlock()

	// Control packet (handshake)
	if header.Flags&strategy.FlagControl != 0 {
		s.sendEchoReply(session, plaintext, strategy.FlagControl, header.PacketSeq+1)
		return
	}

	select {
	case session.recvCh <- plaintext:
	default:
		log.Debug("ICMP server: session=%08x recv buffer full, dropping", header.SessionID)
	}
}

func (s *ICMPServer) getOrCreateSession(sessionID uint32, clientAddr *net.IPAddr, tunnelID int) *icmpSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[sessionID]; ok {
		return sess
	}

	if len(s.sessions) >= icmpMaxSessions {
		log.Warn("ICMP server: max sessions (%d) reached, dropping new session", icmpMaxSessions)
		return nil
	}

	cipher, err := chacha20poly1305.NewX(strategy.DeriveICMPKey(s.secret))
	if err != nil {
		log.Warn("ICMP server: cipher init failed: %v", err)
		return nil
	}

	sess := &icmpSession{
		sessionID:  sessionID,
		cipher:     cipher,
		clientAddr: clientAddr,
		tunnelID:   tunnelID,
		recvCh:     make(chan []byte, 256),
		sendCh:     make(chan icmpSendRequest, 256),
		lastActive: time.Now(),
	}
	s.sessions[sessionID] = sess

	// Spin up a virtual connection and hand it to the raw tunnel handler.
	clientConn, serverConn := net.Pipe()

	go s.sessionSendLoop(sess, clientAddr, tunnelID)
	go s.pipeRecvToConn(sess, serverConn)
	go s.pipeConnToSend(sess, serverConn)

	log.Info("ICMP server: new session=%08x from %s", sessionID, clientAddr)

	connID := atomic.AddUint64(&connCounter, 1)
	logger := log.WithPrefix(fmt.Sprintf("icmp:%d", connID))
	go handleRawTunnel(clientConn, s.srvCtx, logger, "")

	return sess
}

// pipeRecvToConn writes decrypted ICMP data into the pipe that handleRawTunnel reads from.
func (s *ICMPServer) pipeRecvToConn(sess *icmpSession, conn net.Conn) {
	defer conn.Close()
	for {
		select {
		case data, ok := <-sess.recvCh:
			if !ok {
				return
			}
			if _, err := conn.Write(data); err != nil {
				log.Debug("ICMP server: pipe write error session=%08x: %v", sess.sessionID, err)
				return
			}
		}
	}
}

// pipeConnToSend reads from the pipe (data that handleRawTunnel wants to send) and queues it.
func (s *ICMPServer) pipeConnToSend(sess *icmpSession, conn net.Conn) {
	var seq uint32 = 1000
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Debug("ICMP server: pipe read error session=%08x: %v", sess.sessionID, err)
			s.removeSession(sess.sessionID)
			return
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		seq++
		s.sendEchoReply(sess, payload, 0, seq)
	}
}

// sendEchoReply encrypts payload and sends an ICMP Echo Reply to the client.
func (s *ICMPServer) sendEchoReply(sess *icmpSession, data []byte, flags uint8, seq uint32) {
	header := strategy.TunnelHeader{
		Magic:      strategy.ICMPTunnelMagic,
		Version:    strategy.ICMPTunnelVersion,
		Flags:      flags,
		SessionID:  sess.sessionID,
		PacketSeq:  seq,
		PayloadLen: uint16(len(data)),
	}
	headerBytes := strategy.SerializeTunnelHeader(header)

	nonce := make([]byte, 24)
	binary.BigEndian.PutUint32(nonce[0:], sess.sessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(seq))

	encrypted := sess.cipher.Seal(nil, nonce, data, headerBytes)

	payload := make([]byte, strategy.TunnelHeaderSize+len(encrypted))
	copy(payload[0:strategy.TunnelHeaderSize], headerBytes)
	copy(payload[strategy.TunnelHeaderSize:], encrypted)

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   sess.tunnelID,
			Seq:  int(seq & 0xffff),
			Data: payload,
		},
	}

	raw, err := msg.Marshal(nil)
	if err != nil {
		log.Debug("ICMP server: marshal error: %v", err)
		return
	}

	s.conn.SetWriteDeadline(time.Now().Add(icmpWriteDeadline))
	if _, err := s.conn.WriteTo(raw, sess.clientAddr); err != nil {
		log.Debug("ICMP server: send error session=%08x: %v", sess.sessionID, err)
	}
}

// sessionSendLoop is a no-op stub; actual sending happens directly in sendEchoReply.
func (s *ICMPServer) sessionSendLoop(sess *icmpSession, _ *net.IPAddr, _ int) {}

func (s *ICMPServer) removeSession(sessionID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	log.Debug("ICMP server: removed session=%08x", sessionID)
}

func (s *ICMPServer) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, sess := range s.sessions {
			sess.mu.Lock()
			inactive := now.Sub(sess.lastActive) > icmpSessionTTL
			sess.mu.Unlock()
			if inactive {
				delete(s.sessions, id)
				log.Debug("ICMP server: expired session=%08x", id)
			}
		}
		s.mu.Unlock()
	}
}
