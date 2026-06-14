package evasion

import (
	"io"
	"net"
	"sync"
	"time"
)

// FragmentationConfig configures TCP fragmentation attack
type FragmentationConfig struct {
	// FragmentSize is the size of each TCP segment
	// Smaller = more fragments = harder for DPI to reassemble
	FragmentSize int

	// SplitPosition is where to split the SNI within ClientHello
	// 0 = split at first byte, 1 = after first byte, etc.
	// Splitting SNI across fragments defeats signature matching
	SplitPosition int

	// Delay between fragments (optional)
	// Some DPIs have short reassembly timeouts (TSPU: 5 seconds)
	FragmentDelay time.Duration
}

// DefaultFragmentationConfig returns default config
func DefaultFragmentationConfig() *FragmentationConfig {
	return &FragmentationConfig{
		FragmentSize:  2,
		SplitPosition: 1,
		FragmentDelay: 0,
	}
}

// FragmentedWriter wraps a connection and fragments writes
type FragmentedWriter struct {
	conn           net.Conn
	config         *FragmentationConfig
	mu             sync.Mutex
	firstWriteDone bool
}

// NewFragmentedWriter creates a fragmented writer
func NewFragmentedWriter(conn net.Conn, config *FragmentationConfig) *FragmentedWriter {
	if config == nil {
		config = DefaultFragmentationConfig()
	}
	return &FragmentedWriter{
		conn:   conn,
		config: config,
	}
}

// Write implements io.Writer with TCP fragmentation
func (f *FragmentedWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Only fragment first write (ClientHello)
	// Subsequent writes are passed through normally
	if f.firstWriteDone {
		return f.conn.Write(p)
	}
	f.firstWriteDone = true

	// Check if this looks like TLS ClientHello
	if !isTLSClientHello(p) {
		return f.conn.Write(p)
	}

	// Fragment the ClientHello
	return f.writeFragmented(p)
}

// writeFragmented sends data in small TCP segments
func (f *FragmentedWriter) writeFragmented(data []byte) (int, error) {
	totalWritten := 0
	fragSize := f.config.FragmentSize

	for offset := 0; offset < len(data); {
		end := offset + fragSize
		if end > len(data) {
			end = len(data)
		}

		fragment := data[offset:end]

		// Write fragment
		n, err := f.conn.Write(fragment)
		totalWritten += n

		if err != nil {
			return totalWritten, err
		}

		// Apply delay between fragments if configured
		if f.config.FragmentDelay > 0 && end < len(data) {
			time.Sleep(f.config.FragmentDelay)
		}

		offset = end
	}

	return totalWritten, nil
}

// isTLSClientHello checks if data looks like TLS ClientHello
func isTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// TLS Record: ContentType(1) + Version(2) + Length(2) + Handshake
	// ContentType 0x16 = Handshake
	// Handshake type 0x01 = ClientHello
	return data[0] == 0x16 && // Handshake
		data[1] == 0x03 && // TLS major version
		data[5] == 0x01 // ClientHello handshake type
}

// NetConn returns the underlying connection. It lets kTLS (and other
// optimizations) unwrap past the fragmentation layer to reach the raw
// *net.TCPConn — fragmentation only applies to the first write (ClientHello),
// so the underlying conn is safe to operate on directly in the relay phase.
func (f *FragmentedWriter) NetConn() net.Conn {
	return f.conn
}

// Read passes through to underlying connection
func (f *FragmentedWriter) Read(p []byte) (int, error) {
	return f.conn.Read(p)
}

// Close closes the underlying connection
func (f *FragmentedWriter) Close() error {
	return f.conn.Close()
}

// LocalAddr returns local address
func (f *FragmentedWriter) LocalAddr() net.Addr {
	return f.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (f *FragmentedWriter) RemoteAddr() net.Addr {
	return f.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (f *FragmentedWriter) SetDeadline(t time.Time) error {
	return f.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (f *FragmentedWriter) SetReadDeadline(t time.Time) error {
	return f.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (f *FragmentedWriter) SetWriteDeadline(t time.Time) error {
	return f.conn.SetWriteDeadline(t)
}

// Ensure FragmentedWriter implements necessary interfaces
var _ io.ReadWriter = (*FragmentedWriter)(nil)
var _ net.Conn = (*FragmentedWriter)(nil)
