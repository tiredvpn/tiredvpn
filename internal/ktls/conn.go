package ktls

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

var firstEnableLog sync.Once

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

// ReadFrom and WriteTo unlock the kernel's native TCP splice fast path for
// relay copies (io.Copy/io.CopyBuffer prefer these over the buffered
// Read+Write loop). *net.TCPConn already implements io.ReaderFrom with a
// Linux splice(2) fast path when both ends are real TCP sockets - but that
// fast path never fired for kTLS relays because this wrapper only exposed
// Read/Write, forcing every byte through a userspace copy loop regardless of
// buffer size. Splicing is safe post-kTLS-enable: the kernel ULP transparently
// decrypts on the way in and encrypts on the way out, so from read()/write()/
// splice()'s point of view both ends are always plaintext - splicing moves
// the exact same bytes Read/Write would have, just without the round-trip.
//
// Both directions are implemented because io.copyBuffer checks src.(WriterTo)
// before dst.(ReaderFrom): a *Conn only as the copy source (e.g. relaying
// into a plain upstream *net.TCPConn) needs WriteTo to reach the fast path;
// a *Conn only as the destination needs ReadFrom.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if kc, ok := r.(*Conn); ok {
		r = kc.tcpConn
	}
	return c.tcpConn.ReadFrom(r)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if kc, ok := w.(*Conn); ok {
		w = kc.tcpConn
	}
	if rf, ok := w.(io.ReaderFrom); ok {
		return rf.ReadFrom(c.tcpConn)
	}
	return io.Copy(w, c.tcpConn)
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

// TryEnable attempts to upgrade the connection to kTLS for the kernel-offloaded
// data phase. It is safe to call with any net.Conn:
//
//   - if conn is already a *ktls.Conn, it is returned unchanged.
//   - if conn is a *tls.Conn whose TLS records have been fully drained from
//     the TLS-stack buffer (i.e. the next read will hit raw socket), Enable is
//     called and the *Conn wrapper is returned.
//   - otherwise the original conn is returned unchanged. This covers both
//     non-TLS conns and *tls.Conn values for which Enable returns nil (kernel
//     TLS unsupported or cipher not offloadable); in the latter case the
//     original *tls.Conn remains valid for continued TLS-stack I/O.
//
// label identifies the call site for log output ("tired-raw", "tired-confusion", ...).
//
// Callers must invoke this AFTER all protocol-level auth/header bytes have been
// read or written through the *tls.Conn — otherwise residual decrypted bytes
// in the TLS stack's buffer are lost when the kernel takes over the socket.
func TryEnable(conn net.Conn, label string) net.Conn {
	if _, ok := conn.(*Conn); ok {
		return conn
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn
	}
	if k := Enable(tlsConn); k != nil {
		firstEnableLog.Do(func() {
			log.Info("kTLS enabled (first activation, label=%s); subsequent activations at debug level", label)
		})
		log.Debug("kTLS enabled for %s (relay phase)", label)
		return k
	}
	log.Debug("kTLS unavailable for %s, using TLS stack", label)
	return conn
}
