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
	// c2sCipher decrypts client-to-server packets (matches client's sendCipher).
	// s2cCipher encrypts server-to-client packets (matches client's recvCipher).
	c2sCipher  cipherAEAD
	s2cCipher  cipherAEAD
	clientAddr *net.IPAddr
	tunnelID   int
	recvCh     chan []byte
	lastActive time.Time
	mu         sync.Mutex
	s2cSeq     uint32 // monotonic counter for all s2c replies; protected by mu
	done       chan struct{}
	once       sync.Once // guards close(done)
}

// cipherAEAD is the minimal AEAD interface used by the server.
type cipherAEAD interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}

// ICMPServer receives ICMP Echo Request packets, decrypts tunnel data, and
// relays it through a virtual net.Conn handed to the standard tunnel handler.
// Requires CAP_NET_RAW.
type ICMPServer struct {
	conn      *icmp.PacketConn
	srvCtx    *serverContext
	masterKey []byte // DeriveICMPKey(cfg.Secret), stable for the process lifetime
	mu        sync.Mutex
	sessions  map[uint32]*icmpSession
}

// startICMPServer starts the ICMP listener if EnableICMP is set and
// CAP_NET_RAW is available. Logs a warning and returns silently if not.
func startICMPServer(srvCtx *serverContext) {
	srv := &ICMPServer{
		srvCtx:    srvCtx,
		masterKey: strategy.DeriveICMPKey(srvCtx.cfg.Secret),
		sessions:  make(map[uint32]*icmpSession),
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
	if len(data) < strategy.TunnelHeaderSize {
		return
	}
	header := strategy.ParseTunnelHeader(data[:strategy.TunnelHeaderSize])

	// --- Authenticate before touching session state ---
	// Derive the c2s key for this sessionID and try to decrypt.
	// An unauthenticated attacker cannot forge a valid ciphertext, so no
	// session is created until this passes.
	encrypted := data[strategy.TunnelHeaderSize:]
	if len(encrypted) == 0 {
		return
	}
	headerBytes := data[:strategy.TunnelHeaderSize]

	c2sKey := strategy.DeriveICMPDirectionalKey(s.masterKey, header.SessionID, "c2s")
	c2sCipher, err := chacha20poly1305.NewX(c2sKey)
	if err != nil {
		return
	}

	nonce := make([]byte, 24)
	binary.BigEndian.PutUint32(nonce[0:], header.SessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(header.PacketSeq))

	plaintext, err := c2sCipher.Open(nil, nonce, encrypted, headerBytes)
	if err != nil {
		// Wrong secret or corrupted packet - silently discard, no session created.
		return
	}

	// Auth passed - now get or create the session.
	session := s.getOrCreateSession(header.SessionID, clientAddr, echo.ID, c2sCipher)
	if session == nil {
		return
	}

	session.mu.Lock()
	session.lastActive = time.Now()
	session.mu.Unlock()

	// Control packet (handshake) — reply and done.
	if header.Flags&strategy.FlagControl != 0 {
		s.sendEchoReply(session, plaintext, strategy.FlagControl, session.nextS2CSeq())
		return
	}

	select {
	case <-session.done:
	case session.recvCh <- plaintext:
	default:
		log.Debug("ICMP server: session=%08x recv buffer full, dropping", header.SessionID)
	}
}

func (s *ICMPServer) getOrCreateSession(
	sessionID uint32,
	clientAddr *net.IPAddr,
	tunnelID int,
	c2sCipher cipherAEAD,
) *icmpSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[sessionID]; ok {
		return sess
	}

	if len(s.sessions) >= icmpMaxSessions {
		log.Warn("ICMP server: max sessions (%d) reached, dropping new session", icmpMaxSessions)
		return nil
	}

	s2cKey := strategy.DeriveICMPDirectionalKey(s.masterKey, sessionID, "s2c")
	s2cCipher, err := chacha20poly1305.NewX(s2cKey)
	if err != nil {
		log.Warn("ICMP server: s2c cipher init failed: %v", err)
		return nil
	}

	sess := &icmpSession{
		sessionID:  sessionID,
		c2sCipher:  c2sCipher,
		s2cCipher:  s2cCipher,
		clientAddr: clientAddr,
		tunnelID:   tunnelID,
		recvCh:     make(chan []byte, 256),
		lastActive: time.Now(),
		s2cSeq:     0,
		done:       make(chan struct{}),
	}
	s.sessions[sessionID] = sess

	// Spin up a virtual connection and hand it to the standard tunnel handler.
	clientConn, serverConn := net.Pipe()

	// BUG 1 fix: close both pipe ends when the session is torn down so that
	// pipeRecvToConn (blocked in conn.Write) and pipeConnToSend (blocked in
	// conn.Read) both unblock immediately and exit.
	go func() {
		<-sess.done
		serverConn.Close()
		clientConn.Close()
	}()

	go s.pipeRecvToConn(sess, serverConn)
	go s.pipeConnToSend(sess, serverConn)

	log.Info("ICMP server: new session=%08x from %s", sessionID, clientAddr)

	connID := atomic.AddUint64(&connCounter, 1)
	logger := log.WithPrefix(fmt.Sprintf("icmp:%d", connID))
	// BUG 2 fix: remove the session when handleRawTunnel returns so that
	// pipeConnToSend is not left blocking on serverConn.Read until TTL eviction.
	// removeSession uses sync.Once internally so duplicate calls are harmless.
	go func() {
		handleRawTunnel(clientConn, s.srvCtx, logger, "")
		s.removeSession(sess.sessionID)
	}()

	return sess
}

// pipeRecvToConn writes decrypted ICMP data into the server end of the pipe
// that handleRawTunnel reads from. Exits when the session is evicted (done closed).
func (s *ICMPServer) pipeRecvToConn(sess *icmpSession, conn net.Conn) {
	defer conn.Close()
	for {
		select {
		case <-sess.done:
			return
		case data := <-sess.recvCh:
			if data == nil {
				return
			}
			if _, err := conn.Write(data); err != nil {
				log.Debug("ICMP server: pipe write error session=%08x: %v", sess.sessionID, err)
				s.removeSession(sess.sessionID)
				return
			}
		}
	}
}

// pipeConnToSend reads from the server end of the pipe (data that
// handleRawTunnel wants to send back to the client) and transmits it as
// ICMP Echo Replies.
func (s *ICMPServer) pipeConnToSend(sess *icmpSession, conn net.Conn) {
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
		s.sendEchoReply(sess, payload, 0, sess.nextS2CSeq())
	}
}

// nextS2CSeq returns the next monotonic sequence number for s2c replies.
// All reply paths (control and data) share this counter so nonces never collide.
func (sess *icmpSession) nextS2CSeq() uint32 {
	sess.mu.Lock()
	sess.s2cSeq++
	seq := sess.s2cSeq
	sess.mu.Unlock()
	return seq
}

// sendEchoReply encrypts payload with the s2c key and sends an ICMP Echo Reply.
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

	encrypted := sess.s2cCipher.Seal(nil, nonce, data, headerBytes)

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

func (s *ICMPServer) removeSession(sessionID uint32) {
	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	if ok {
		// Close done once; pipeRecvToConn and pipeConnToSend select on it.
		sess.once.Do(func() { close(sess.done) })
		log.Debug("ICMP server: removed session=%08x", sessionID)
	}
}

func (s *ICMPServer) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		var expired []*icmpSession
		s.mu.Lock()
		for id, sess := range s.sessions {
			sess.mu.Lock()
			inactive := now.Sub(sess.lastActive) > icmpSessionTTL
			sess.mu.Unlock()
			if inactive {
				expired = append(expired, sess)
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
		for _, sess := range expired {
			sess.once.Do(func() { close(sess.done) })
			log.Debug("ICMP server: expired session=%08x", sess.sessionID)
		}
	}
}
