package ktls

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

// Conn wraps a TLS connection after kTLS is enabled.
// After kTLS is enabled, we can use the underlying TCP connection directly
// because the kernel handles encryption/decryption transparently.
type Conn struct {
	tcpConn *net.TCPConn
	tlsConn *tls.Conn
}

// NewConn creates a new kTLS connection wrapper.
// It extracts the underlying TCP connection.
func NewConn(tlsConn *tls.Conn) (*Conn, error) {
	// Get underlying TCP connection
	netConn := tlsConn.NetConn()
	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		return nil, &net.OpError{Op: "ktls", Err: net.UnknownNetworkError("not a TCP connection")}
	}

	return &Conn{
		tcpConn: tcpConn,
		tlsConn: tlsConn,
	}, nil
}

// Read reads data from the connection.
// kTLS kernel will decrypt data automatically.
// We use the TCP connection directly - kernel handles decryption.
func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.tcpConn.Read(b)
	if err != nil {
		return n, err
	}
	// Handle EOF properly
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// Write writes data to the connection.
// kTLS kernel will encrypt data automatically.
// We use the TCP connection directly - kernel handles encryption.
func (c *Conn) Write(b []byte) (n int, err error) {
	return c.tcpConn.Write(b)
}

// Close closes the underlying TCP connection.
func (c *Conn) Close() error {
	return c.tcpConn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

// SetDeadline sets read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}

// ConnectionState returns the original TLS connection state.
// This is safe because it only returns immutable state information.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.tlsConn.ConnectionState()
}
