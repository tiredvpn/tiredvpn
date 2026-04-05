package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// GRPCTunnel implements tunneling over gRPC-like HTTP/2 connection
// This mimics traffic to googleapis.com / firebaseio.com
type GRPCTunnel struct {
	conn       net.Conn
	framer     *http2.Framer
	encoder    *hpack.Encoder
	encoderBuf bytes.Buffer

	config   *GRPCConfig
	streamID uint32
	mu       sync.Mutex

	readBuf bytes.Buffer
	readMu  sync.Mutex

	closed bool
}

// GRPCConfig configures gRPC tunnel
type GRPCConfig struct {
	// ServiceName mimics a real gRPC service
	// e.g., "google.firestore.v1.Firestore"
	ServiceName string

	// MethodName mimics a real gRPC method
	// e.g., "Listen" (streaming method for Firestore)
	MethodName string

	// Authority is the :authority header (usually same as SNI)
	Authority string

	// UserAgent mimics real gRPC client
	UserAgent string

	// ContentType should be "application/grpc"
	ContentType string

	// GRPCEncoding is typically "identity" or "gzip"
	GRPCEncoding string

	// CustomHeaders for additional masquerading
	CustomHeaders map[string]string

	// EnablePadding adds HTTP/2 padding frames
	EnablePadding bool

	// PaddingSize is the size of padding frames
	PaddingSize int
}

// DefaultGRPCConfig returns config that mimics Firestore streaming
func DefaultGRPCConfig(authority string) *GRPCConfig {
	return &GRPCConfig{
		ServiceName:  "google.firestore.v1.Firestore",
		MethodName:   "Listen",
		Authority:    authority,
		UserAgent:    "grpc-go/1.59.0",
		ContentType:  "application/grpc",
		GRPCEncoding: "identity",
		CustomHeaders: map[string]string{
			"te":                   "trailers",
			"grpc-accept-encoding": "identity,deflate,gzip",
		},
		EnablePadding: true,
		PaddingSize:   100,
	}
}

// NewGRPCTunnel creates a new gRPC tunnel over existing TLS connection
func NewGRPCTunnel(conn net.Conn, config *GRPCConfig) (*GRPCTunnel, error) {
	if config == nil {
		config = DefaultGRPCConfig("firestore.googleapis.com")
	}

	// Create HTTP/2 framer
	framer := http2.NewFramer(conn, conn)

	// Allow large frames for data transfer
	framer.SetMaxReadFrameSize(1 << 24) // 16MB

	tunnel := &GRPCTunnel{
		conn:     conn,
		framer:   framer,
		config:   config,
		streamID: 1, // Client streams use odd numbers
	}

	// Initialize HPACK encoder
	tunnel.encoder = hpack.NewEncoder(&tunnel.encoderBuf)

	// Perform HTTP/2 connection preface and settings
	if err := tunnel.handshake(); err != nil {
		return nil, fmt.Errorf("http2 handshake failed: %w", err)
	}

	// Open gRPC stream
	if err := tunnel.openStream(); err != nil {
		return nil, fmt.Errorf("failed to open gRPC stream: %w", err)
	}

	// Start reading frames in background
	go tunnel.readLoop()

	return tunnel, nil
}

// handshake performs HTTP/2 connection preface
func (t *GRPCTunnel) handshake() error {
	// Client connection preface
	// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS frame
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := t.conn.Write(preface); err != nil {
		return err
	}

	// Send SETTINGS frame
	settings := []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		{ID: http2.SettingInitialWindowSize, Val: 1 << 20}, // 1MB
		{ID: http2.SettingMaxFrameSize, Val: 1 << 16},      // 64KB
		{ID: http2.SettingMaxHeaderListSize, Val: 1 << 16},
	}

	if err := t.framer.WriteSettings(settings...); err != nil {
		return err
	}

	// Read server's SETTINGS
	frame, err := t.framer.ReadFrame()
	if err != nil {
		return err
	}

	if sf, ok := frame.(*http2.SettingsFrame); ok {
		if !sf.IsAck() {
			// ACK server settings
			if err := t.framer.WriteSettingsAck(); err != nil {
				return err
			}
		}
	}

	return nil
}

// openStream opens a gRPC streaming call
func (t *GRPCTunnel) openStream() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Build gRPC path
	path := fmt.Sprintf("/%s/%s", t.config.ServiceName, t.config.MethodName)

	// Encode headers using HPACK
	t.encoderBuf.Reset()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: t.config.Authority},
		{Name: "content-type", Value: t.config.ContentType},
		{Name: "user-agent", Value: t.config.UserAgent},
		{Name: "grpc-encoding", Value: t.config.GRPCEncoding},
		{Name: "te", Value: "trailers"},
	}

	// Add custom headers
	for name, value := range t.config.CustomHeaders {
		headers = append(headers, hpack.HeaderField{Name: name, Value: value})
	}

	for _, hf := range headers {
		if err := t.encoder.WriteField(hf); err != nil {
			return err
		}
	}

	headerBlock := t.encoderBuf.Bytes()

	// Send HEADERS frame
	// EndHeaders=true, EndStream=false (streaming)
	if err := t.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      t.streamID,
		BlockFragment: headerBlock,
		EndHeaders:    true,
		EndStream:     false,
	}); err != nil {
		return err
	}

	return nil
}

// Write sends data as gRPC message
func (t *GRPCTunnel) Write(p []byte) (int, error) {
	if t.closed {
		return 0, io.ErrClosedPipe
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// gRPC message format:
	// [compression flag: 1 byte][message length: 4 bytes][message data]
	grpcFrame := make([]byte, 5+len(p))
	grpcFrame[0] = 0 // No compression
	binary.BigEndian.PutUint32(grpcFrame[1:5], uint32(len(p)))
	copy(grpcFrame[5:], p)

	// Send as DATA frame
	if err := t.framer.WriteData(t.streamID, false, grpcFrame); err != nil {
		return 0, err
	}

	// Optional: send padding frame for traffic analysis resistance
	if t.config.EnablePadding && t.config.PaddingSize > 0 {
		padding := make([]byte, t.config.PaddingSize)
		// Send as separate DATA frame with padding
		// (HTTP/2 frames can have padding)
		_ = t.framer.WriteData(t.streamID, false, padding)
	}

	return len(p), nil
}

// Read receives data from gRPC stream
func (t *GRPCTunnel) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	// Try to read from buffer first
	if t.readBuf.Len() > 0 {
		return t.readBuf.Read(p)
	}

	// Wait for data (simplified - production would use channels)
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

// readLoop reads frames from connection
func (t *GRPCTunnel) readLoop() {
	for !t.closed {
		frame, err := t.framer.ReadFrame()
		if err != nil {
			t.closed = true
			return
		}

		switch f := frame.(type) {
		case *http2.DataFrame:
			// Extract gRPC message from DATA frame
			data := f.Data()
			if len(data) > 5 {
				// Skip gRPC header (5 bytes)
				msgLen := binary.BigEndian.Uint32(data[1:5])
				if int(msgLen)+5 <= len(data) {
					t.readMu.Lock()
					t.readBuf.Write(data[5 : 5+msgLen])
					t.readMu.Unlock()
				}
			}

		case *http2.WindowUpdateFrame:
			// Handle flow control
			// (simplified - production needs proper window management)

		case *http2.PingFrame:
			// Respond to pings
			if !f.IsAck() {
				t.mu.Lock()
				_ = t.framer.WritePing(true, f.Data)
				t.mu.Unlock()
			}

		case *http2.GoAwayFrame:
			t.closed = true
			return

		case *http2.RSTStreamFrame:
			t.closed = true
			return

		case *http2.SettingsFrame:
			if !f.IsAck() {
				t.mu.Lock()
				_ = t.framer.WriteSettingsAck()
				t.mu.Unlock()
			}
		}
	}
}

// Close closes the tunnel
func (t *GRPCTunnel) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true

	t.mu.Lock()
	defer t.mu.Unlock()

	// Send RST_STREAM to close the stream gracefully
	_ = t.framer.WriteRSTStream(t.streamID, http2.ErrCodeCancel)

	return t.conn.Close()
}

// LocalAddr returns local address
func (t *GRPCTunnel) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (t *GRPCTunnel) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (t *GRPCTunnel) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// SetReadDeadline sets read deadline
func (t *GRPCTunnel) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets write deadline
func (t *GRPCTunnel) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// GRPCServiceMimics contains real Google gRPC services for masquerading
var GRPCServiceMimics = []struct {
	Service string
	Method  string
	Auth    string
	Desc    string
}{
	{"google.firestore.v1.Firestore", "Listen", "firestore.googleapis.com", "Firestore realtime"},
	{"google.firestore.v1.Firestore", "Write", "firestore.googleapis.com", "Firestore write"},
	{"google.pubsub.v1.Subscriber", "StreamingPull", "pubsub.googleapis.com", "PubSub streaming"},
	{"google.cloud.speech.v1.Speech", "StreamingRecognize", "speech.googleapis.com", "Speech streaming"},
	{"google.cloud.bigquery.storage.v1.BigQueryRead", "ReadRows", "bigquerystorage.googleapis.com", "BigQuery"},
	{"google.cloud.aiplatform.v1.PredictionService", "StreamingPredict", "aiplatform.googleapis.com", "AI Platform"},
	{"google.longrunning.Operations", "GetOperation", "longrunning.googleapis.com", "Long running ops"},
	{"grpc.health.v1.Health", "Watch", "health.googleapis.com", "Health check"},
}

// Ensure GRPCTunnel implements net.Conn
var _ net.Conn = (*GRPCTunnel)(nil)

// GRPCDialer creates gRPC tunnels
type GRPCDialer struct {
	config *GRPCConfig
}

// NewGRPCDialer creates a new dialer
func NewGRPCDialer(config *GRPCConfig) *GRPCDialer {
	return &GRPCDialer{config: config}
}

// Dial establishes a gRPC tunnel
func (d *GRPCDialer) Dial(network, address string) (net.Conn, error) {
	// First establish TLS connection with proper fingerprint
	// (This would use internal/tls package)
	tcpConn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Wrap with gRPC tunnel
	return NewGRPCTunnel(tcpConn, d.config)
}
