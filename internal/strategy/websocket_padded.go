package strategy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/padding"
)

// WebSocketPaddedStrategy implements WebSocket transport with Salamander padding
// Priority 8 (high, between HTTP/2 Stego and Traffic Morph)
type WebSocketPaddedStrategy struct {
	manager    *Manager // IPv6/IPv4 transport layer support
	serverAddr string   // Deprecated: use manager.GetServerAddr() instead
	secret     []byte
	wsPath     string
	wsHost     string
}

// NewWebSocketPaddedStrategy creates a new WebSocket Padded strategy
// manager is required for IPv6/IPv4 transport layer support
func NewWebSocketPaddedStrategy(manager *Manager, secret []byte) *WebSocketPaddedStrategy {
	return &WebSocketPaddedStrategy{
		manager:    manager,
		serverAddr: "", // Deprecated: use manager.GetServerAddr() instead
		secret:     secret,
		wsPath:     "/ws",
		wsHost:     "chat.openai.com", // Mimic ChatGPT WebSocket
	}
}

// Name returns human-readable strategy name
func (s *WebSocketPaddedStrategy) Name() string {
	return "WebSocket Salamander"
}

// ID returns strategy identifier
func (s *WebSocketPaddedStrategy) ID() string {
	return "websocket_padded"
}

// Priority returns strategy priority
func (s *WebSocketPaddedStrategy) Priority() int {
	return 8
}

// RequiresServer indicates this strategy needs a server
func (s *WebSocketPaddedStrategy) RequiresServer() bool {
	return true
}

// SupportsUDP returns whether this strategy supports UDP traffic
func (s *WebSocketPaddedStrategy) SupportsUDP() bool {
	return false
}

// Description returns a human-readable description
func (s *WebSocketPaddedStrategy) Description() string {
	return "WebSocket with Salamander padding - high obfuscation transport"
}

// Probe tests if WebSocket Padded strategy is likely to work
func (s *WebSocketPaddedStrategy) Probe(ctx context.Context, target string) error {
	// WebSocket is always available if we have a server
	return nil
}

// Connect establishes a WebSocket Padded connection
func (s *WebSocketPaddedStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("WebSocket Padded: Connecting to %s via %s", target, serverAddr)

	// 1. Establish TLS connection to server (context-aware)
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}

	tlsConfig := &tls.Config{
		ServerName:         s.wsHost,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"tired-ws", "http/1.1"}, // kTLS-enabled ALPN
	}

	tcpConn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("websocket_padded: tcp dial failed: %w", err)
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("websocket_padded: tls handshake failed: %w", err)
	}

	// Set optimizations
	if tc, ok := tlsConn.NetConn().(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// 2. Send WebSocket upgrade request with auth token
	wsKey := generateWebSocketKey()
	authToken := generateAuthToken(s.secret)
	upgradeReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"X-Salamander-Version: 1.0\r\n"+
			"X-Auth-Token: %s\r\n"+
			"User-Agent: Mozilla/5.0 (compatible; TiredVPN/2.0)\r\n"+
			"\r\n",
		s.wsPath, s.wsHost, wsKey, hex.EncodeToString(authToken))

	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket_padded: upgrade request failed: %w", err)
	}

	log.Debug("WebSocket Padded: Sent upgrade request")

	// 3. Read upgrade response
	reader := bufio.NewReader(tlsConn)
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetReadDeadline(deadline)
	} else {
		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket_padded: failed to read status: %w", err)
	}

	if !bytes.Contains([]byte(statusLine), []byte("101")) {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket_padded: upgrade failed: %s", statusLine)
	}

	// Read headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("websocket_padded: failed to read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break // End of headers
		}
	}

	tlsConn.SetReadDeadline(time.Time{})

	log.Info("WebSocket Padded: Upgrade successful")

	// 4. Determine padding level adaptively
	// For now, use Balanced - in production, get from Strategy Manager confidence
	paddingLevel := padding.Balanced

	// 5. Wrap with SalamanderConn
	padder := padding.NewSalamanderPadder(s.secret, paddingLevel)
	salamanderConn := NewSalamanderConn(tlsConn, padder, true) // true = client side

	log.Info("WebSocket Padded: Connection established to %s", target)

	return salamanderConn, nil
}

// SalamanderConn wraps a WebSocket connection with Salamander padding
type SalamanderConn struct {
	conn     net.Conn
	padder   *padding.SalamanderPadder
	isClient bool

	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

// NewSalamanderConn creates a new Salamander-wrapped connection
func NewSalamanderConn(conn net.Conn, padder *padding.SalamanderPadder, isClient bool) *SalamanderConn {
	return &SalamanderConn{
		conn:     conn,
		padder:   padder,
		isClient: isClient,
		readBuf:  make([]byte, 0, 64*1024),
	}
}

// Read implements net.Conn Read
func (sc *SalamanderConn) Read(p []byte) (int, error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

	// Return buffered data first
	if len(sc.readBuf) > 0 {
		n := copy(p, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}

	// Read WebSocket frame
	frame, err := sc.readWebSocketFrame()
	if err != nil {
		return 0, err
	}

	// Decrypt with Salamander
	decrypted, err := sc.padder.Decrypt(frame)
	if err != nil {
		return 0, fmt.Errorf("salamander decrypt failed: %w", err)
	}

	// WebSocket frames have 2-byte length prefix for actual data length
	if len(decrypted) < 2 {
		return 0, errors.New("salamander: decrypted data too short")
	}

	dataLen := int(binary.BigEndian.Uint16(decrypted[0:2]))
	if dataLen > len(decrypted)-2 {
		return 0, errors.New("salamander: invalid data length")
	}

	actualData := decrypted[2 : 2+dataLen]

	// Copy to output buffer
	n := copy(p, actualData)

	// Buffer remainder if any
	if n < len(actualData) {
		sc.readBuf = append(sc.readBuf, actualData[n:]...)
	}

	return n, nil
}

// Write implements net.Conn Write
func (sc *SalamanderConn) Write(p []byte) (int, error) {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	if sc.closed {
		return 0, errors.New("connection closed")
	}

	// Prepend 2-byte length prefix
	dataWithLen := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(dataWithLen[0:2], uint16(len(p)))
	copy(dataWithLen[2:], p)

	// Encrypt with Salamander (adds salt + padding)
	encrypted, err := sc.padder.Encrypt(dataWithLen)
	if err != nil {
		return 0, fmt.Errorf("salamander encrypt failed: %w", err)
	}

	// Build WebSocket binary frame
	frame := sc.buildWebSocketFrame(encrypted)

	// Write to underlying connection
	if _, err := sc.conn.Write(frame); err != nil {
		return 0, err
	}

	return len(p), nil
}

// readWebSocketFrame reads a complete WebSocket frame
func (sc *SalamanderConn) readWebSocketFrame() ([]byte, error) {
	// Read 2-byte header
	header := make([]byte, 2)
	if _, err := io.ReadFull(sc.conn, header); err != nil {
		return nil, err
	}

	fin := (header[0] & 0x80) != 0
	opcode := header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLen := int(header[1] & 0x7F)

	// Check for binary frame
	if opcode != 0x02 && opcode != 0x00 { // Binary or continuation
		if opcode == 0x08 { // Close frame
			return nil, io.EOF
		}
		return nil, fmt.Errorf("unexpected websocket opcode: 0x%02X", opcode)
	}

	// Extended payload length
	switch payloadLen {
	case 126:
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(sc.conn, extLen); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(extLen))
	case 127:
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(sc.conn, extLen); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint64(extLen))
	}

	// Read masking key if present (server → client has no mask)
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(sc.conn, maskKey[:]); err != nil {
			return nil, err
		}
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(sc.conn, payload); err != nil {
		return nil, err
	}

	// Unmask if masked
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	if !fin {
		return nil, errors.New("fragmented frames not supported")
	}

	return payload, nil
}

// buildWebSocketFrame constructs a WebSocket binary frame
func (sc *SalamanderConn) buildWebSocketFrame(payload []byte) []byte {
	var frame bytes.Buffer

	// Byte 0: FIN + RSV + OPCODE (0x82 = FIN + Binary)
	frame.WriteByte(0x82)

	// Byte 1: MASK + Payload length
	payloadLen := len(payload)
	maskBit := byte(0x00)
	if sc.isClient {
		maskBit = 0x80 // Client must mask
	}

	if payloadLen < 126 {
		frame.WriteByte(maskBit | byte(payloadLen))
	} else if payloadLen < 65536 {
		frame.WriteByte(maskBit | 126)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(payloadLen))
		frame.Write(lenBuf)
	} else {
		frame.WriteByte(maskBit | 127)
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(payloadLen))
		frame.Write(lenBuf)
	}

	// Masking key (client only)
	if sc.isClient {
		var maskKey [4]byte
		rand.Read(maskKey[:])
		frame.Write(maskKey[:])

		// Mask payload
		maskedPayload := make([]byte, len(payload))
		for i, b := range payload {
			maskedPayload[i] = b ^ maskKey[i%4]
		}
		frame.Write(maskedPayload)
	} else {
		// Server doesn't mask
		frame.Write(payload)
	}

	return frame.Bytes()
}

// Close closes the connection
func (sc *SalamanderConn) Close() error {
	sc.closeMu.Lock()
	defer sc.closeMu.Unlock()

	if sc.closed {
		return nil
	}

	sc.closed = true

	// Send WebSocket close frame
	closeFrame := []byte{0x88, 0x00} // FIN + Close opcode, 0 length
	sc.conn.Write(closeFrame)

	return sc.conn.Close()
}

// LocalAddr returns local address
func (sc *SalamanderConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (sc *SalamanderConn) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

// SetDeadline sets read/write deadline
func (sc *SalamanderConn) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (sc *SalamanderConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (sc *SalamanderConn) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}

// generateWebSocketKey generates a random Sec-WebSocket-Key
func generateWebSocketKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}
