package tunnel

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// WebSocketTunnel implements tunneling over WebSocket protocol
// Masquerades as legitimate WebSocket connection (e.g., web.telegram.org, yandex.ru)
type WebSocketTunnel struct {
	conn   net.Conn
	reader *bufio.Reader

	config *WebSocketConfig
	mu     sync.Mutex

	readBuf bytes.Buffer
	readMu  sync.Mutex

	closed  bool
	maskKey [4]byte // WebSocket client mask key
}

// WebSocketConfig configures WebSocket tunnel
type WebSocketConfig struct {
	// Host is the Host header (should match SNI)
	Host string

	// Path is the WebSocket path
	Path string

	// Origin header for CORS
	Origin string

	// CustomHeaders for additional masquerading
	CustomHeaders map[string]string

	// UseBinaryFrames uses binary (0x82) vs text (0x81) frames
	UseBinaryFrames bool

	// PingInterval for WebSocket pings
	PingInterval time.Duration

	// MaxFrameSize limits frame size
	MaxFrameSize int
}

// DefaultWebSocketConfig returns default config
func DefaultWebSocketConfig(host string) *WebSocketConfig {
	return &WebSocketConfig{
		Host:            host,
		Path:            "/ws",
		Origin:          fmt.Sprintf("https://%s", host),
		UseBinaryFrames: true,
		PingInterval:    30 * time.Second,
		MaxFrameSize:    1 << 16, // 64KB
		CustomHeaders: map[string]string{
			"User-Agent":               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
			"Accept-Language":          "en-US,en;q=0.9,ru;q=0.8",
			"Accept-Encoding":          "gzip, deflate, br",
			"Cache-Control":            "no-cache",
			"Pragma":                   "no-cache",
			"Sec-WebSocket-Extensions": "permessage-deflate",
		},
	}
}

// WebSocket frame opcodes
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// NewWebSocketTunnel creates a WebSocket tunnel over existing connection
func NewWebSocketTunnel(conn net.Conn, config *WebSocketConfig) (*WebSocketTunnel, error) {
	if config == nil {
		config = DefaultWebSocketConfig("yandex.ru")
	}

	tunnel := &WebSocketTunnel{
		conn:   conn,
		reader: bufio.NewReader(conn),
		config: config,
	}

	// Generate random mask key
	if _, err := rand.Read(tunnel.maskKey[:]); err != nil {
		return nil, err
	}

	// Perform WebSocket handshake
	if err := tunnel.handshake(); err != nil {
		return nil, fmt.Errorf("websocket handshake failed: %w", err)
	}

	// Start ping loop
	if config.PingInterval > 0 {
		go tunnel.pingLoop()
	}

	// Start read loop
	go tunnel.readLoop()

	return tunnel, nil
}

// handshake performs WebSocket upgrade handshake
func (t *WebSocketTunnel) handshake() error {
	// Generate WebSocket key
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	// Build upgrade request
	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", t.config.Path)
	fmt.Fprintf(&req, "Host: %s\r\n", t.config.Host)
	fmt.Fprintf(&req, "Upgrade: websocket\r\n")
	fmt.Fprintf(&req, "Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", wsKey)
	fmt.Fprintf(&req, "Sec-WebSocket-Version: 13\r\n")

	if t.config.Origin != "" {
		fmt.Fprintf(&req, "Origin: %s\r\n", t.config.Origin)
	}

	for name, value := range t.config.CustomHeaders {
		fmt.Fprintf(&req, "%s: %s\r\n", name, value)
	}

	req.WriteString("\r\n")

	// Send request
	if _, err := t.conn.Write(req.Bytes()); err != nil {
		return err
	}

	// Read response
	resp, err := t.reader.ReadString('\n')
	if err != nil {
		return err
	}

	// Check for 101 Switching Protocols
	if len(resp) < 12 {
		return fmt.Errorf("invalid response: %s", resp)
	}

	// Read rest of headers
	for {
		line, err := t.reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		// Validate Sec-WebSocket-Accept if needed
	}

	return nil
}

// Write sends data as WebSocket frame
func (t *WebSocketTunnel) Write(p []byte) (int, error) {
	if t.closed {
		return 0, io.ErrClosedPipe
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Build WebSocket frame
	frame, err := t.buildFrame(p)
	if err != nil {
		return 0, err
	}

	if _, err := t.conn.Write(frame); err != nil {
		return 0, err
	}

	return len(p), nil
}

// buildFrame creates a WebSocket data frame
func (t *WebSocketTunnel) buildFrame(payload []byte) ([]byte, error) {
	payloadLen := len(payload)

	// Frame structure:
	// [0]: FIN(1) + RSV(3) + Opcode(4)
	// [1]: MASK(1) + Payload length(7)
	// [2-3] or [2-9]: Extended payload length (if needed)
	// [+4]: Mask key (always for client)
	// [+N]: Masked payload

	var frame bytes.Buffer

	// First byte: FIN=1, RSV=0, Opcode
	opcode := wsOpBinary
	if !t.config.UseBinaryFrames {
		opcode = wsOpText
	}
	frame.WriteByte(byte(0x80 | opcode)) // FIN + opcode

	// Second byte: MASK=1 + length
	var lengthBytes []byte
	if payloadLen <= 125 {
		frame.WriteByte(byte(0x80 | payloadLen))
	} else if payloadLen <= 65535 {
		frame.WriteByte(0x80 | 126)
		lengthBytes = make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBytes, uint16(payloadLen))
		frame.Write(lengthBytes)
	} else {
		frame.WriteByte(0x80 | 127)
		lengthBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(lengthBytes, uint64(payloadLen))
		frame.Write(lengthBytes)
	}

	// Generate new mask key for each frame
	maskKey := make([]byte, 4)
	if _, err := rand.Read(maskKey); err != nil {
		return nil, err
	}
	frame.Write(maskKey)

	// Mask and write payload
	maskedPayload := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}
	frame.Write(maskedPayload)

	return frame.Bytes(), nil
}

// Read receives data from WebSocket
func (t *WebSocketTunnel) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	if t.readBuf.Len() > 0 {
		return t.readBuf.Read(p)
	}

	// Wait for data
	for i := 0; i < 100; i++ {
		if t.readBuf.Len() > 0 {
			return t.readBuf.Read(p)
		}
		if t.closed {
			return 0, io.EOF
		}
		time.Sleep(10 * time.Millisecond)
	}

	return 0, nil
}

// readLoop reads WebSocket frames
func (t *WebSocketTunnel) readLoop() {
	for !t.closed {
		payload, opcode, err := t.readFrame()
		if err != nil {
			t.closed = true
			return
		}

		switch opcode {
		case wsOpBinary, wsOpText:
			t.readMu.Lock()
			t.readBuf.Write(payload)
			t.readMu.Unlock()

		case wsOpPing:
			// Respond with pong
			t.sendPong(payload)

		case wsOpPong:
			// Ignore pong

		case wsOpClose:
			t.closed = true
			return
		}
	}
}

// readFrame reads a single WebSocket frame
func (t *WebSocketTunnel) readFrame() ([]byte, int, error) {
	// Read first two bytes
	header := make([]byte, 2)
	if _, err := io.ReadFull(t.reader, header); err != nil {
		return nil, 0, err
	}

	// Parse header
	// fin := (header[0] & 0x80) != 0
	opcode := int(header[0] & 0x0F)
	masked := (header[1] & 0x80) != 0
	payloadLen := int(header[1] & 0x7F)

	// Extended payload length
	switch payloadLen {
	case 126:
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(t.reader, extLen); err != nil {
			return nil, 0, err
		}
		payloadLen = int(binary.BigEndian.Uint16(extLen))
	case 127:
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(t.reader, extLen); err != nil {
			return nil, 0, err
		}
		payloadLen = int(binary.BigEndian.Uint64(extLen))
	}

	// Read mask key if present (server->client usually not masked)
	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(t.reader, maskKey); err != nil {
			return nil, 0, err
		}
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(t.reader, payload); err != nil {
		return nil, 0, err
	}

	// Unmask if needed
	if masked {
		for i := 0; i < payloadLen; i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, opcode, nil
}

// pingLoop sends periodic pings
func (t *WebSocketTunnel) pingLoop() {
	ticker := time.NewTicker(t.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if t.closed {
				return
			}
			t.sendPing()
		}
	}
}

// sendPing sends a WebSocket ping frame
func (t *WebSocketTunnel) sendPing() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Ping frame with random payload
	payload := make([]byte, 4)
	rand.Read(payload)

	frame := []byte{
		0x80 | wsOpPing,           // FIN + PING
		0x80 | byte(len(payload)), // MASK + length
	}
	frame = append(frame, t.maskKey[:]...)

	// Mask payload
	maskedPayload := make([]byte, len(payload))
	for i := 0; i < len(payload); i++ {
		maskedPayload[i] = payload[i] ^ t.maskKey[i%4]
	}
	frame = append(frame, maskedPayload...)

	_, err := t.conn.Write(frame)
	return err
}

// sendPong responds to a ping
func (t *WebSocketTunnel) sendPong(payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	frame := []byte{
		0x80 | wsOpPong,           // FIN + PONG
		0x80 | byte(len(payload)), // MASK + length
	}
	frame = append(frame, t.maskKey[:]...)

	// Mask payload
	maskedPayload := make([]byte, len(payload))
	for i := 0; i < len(payload); i++ {
		maskedPayload[i] = payload[i] ^ t.maskKey[i%4]
	}
	frame = append(frame, maskedPayload...)

	_, err := t.conn.Write(frame)
	return err
}

// Close closes the tunnel
func (t *WebSocketTunnel) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true

	// Send close frame
	t.mu.Lock()
	closeFrame := []byte{
		0x80 | wsOpClose, // FIN + CLOSE
		0x80 | 2,         // MASK + length (status code)
	}
	closeFrame = append(closeFrame, t.maskKey[:]...)
	// Status code 1000 (normal closure), masked
	closeFrame = append(closeFrame, 0x03^t.maskKey[0], 0xe8^t.maskKey[1])
	t.conn.Write(closeFrame)
	t.mu.Unlock()

	return t.conn.Close()
}

// LocalAddr returns local address
func (t *WebSocketTunnel) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (t *WebSocketTunnel) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (t *WebSocketTunnel) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// SetReadDeadline sets read deadline
func (t *WebSocketTunnel) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets write deadline
func (t *WebSocketTunnel) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// generateWebSocketAccept generates Sec-WebSocket-Accept header value
func generateWebSocketAccept(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// WebSocketMimics contains paths that look like real WebSocket services
var WebSocketMimics = []struct {
	Host   string
	Path   string
	Origin string
	Desc   string
}{
	{"web.telegram.org", "/apiws", "https://web.telegram.org", "Telegram Web"},
	{"yandex.ru", "/portal/websocket", "https://yandex.ru", "Yandex Portal"},
	{"vk.com", "/wss", "https://vk.com", "VK Messenger"},
	{"mail.ru", "/ws", "https://mail.ru", "Mail.ru"},
	{"discord.com", "/gateway", "https://discord.com", "Discord Gateway"},
	{"slack.com", "/link", "https://slack.com", "Slack"},
}

// Ensure WebSocketTunnel implements net.Conn
var _ net.Conn = (*WebSocketTunnel)(nil)
