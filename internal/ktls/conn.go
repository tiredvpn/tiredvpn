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

	// rxMu serialises readers: pending and rx are receive-side state that
	// concurrent Read calls would otherwise corrupt. Writers never take it.
	rxMu sync.Mutex

	// pending is application data crypto/tls decrypted before the handover
	// (see Enable); Read returns it before touching the socket.
	pending []byte

	// Receive state for records the kernel hands up with a non-data content
	// type (see readSocket).
	rx recvState
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
//
// Read is safe to call from several goroutines; calls are serialised.
func (c *Conn) Read(b []byte) (n int, err error) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	if len(c.pending) > 0 {
		n = copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if len(b) == 0 {
		return 0, nil
	}
	return c.readSocket(b)
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
//
// Data left over from the handover (pending) is written out first. Splicing
// goes straight to the socket, so a non-data TLS record arriving mid-splice
// fails the copy instead of being handled as in Read.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	var head int64
	if kc, ok := r.(*Conn); ok {
		n, err := kc.flushPending(c.tcpConn)
		head = n
		if err != nil {
			return head, err
		}
		r = kc.tcpConn
	}
	n, err := c.tcpConn.ReadFrom(r)
	return head + n, err
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	head, err := c.flushPending(w)
	if err != nil {
		return head, err
	}
	if kc, ok := w.(*Conn); ok {
		w = kc.tcpConn
	}
	var n int64
	if rf, ok := w.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(c.tcpConn)
	} else {
		n, err = io.Copy(w, c.tcpConn)
	}
	return head + n, err
}

// flushPending writes out data left over from the handover, if any.
func (c *Conn) flushPending(w io.Writer) (int64, error) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	if len(c.pending) == 0 {
		return 0, nil
	}
	n, err := w.Write(c.pending)
	c.pending = c.pending[n:]
	return int64(n), err
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
//   - if conn is a *tls.Conn, Enable is called and, if it succeeds, the *Conn
//     wrapper is returned.
//   - otherwise the original conn is returned unchanged. This covers both
//     non-TLS conns and *tls.Conn values for which Enable returns nil (kernel
//     TLS unsupported or cipher not offloadable); in the latter case the
//     original *tls.Conn remains valid for continued TLS-stack I/O.
//
// label identifies the call site for log output ("tired-raw", "tired-confusion", ...).
//
// Input crypto/tls has read ahead of the caller - a session ticket, part of
// the next record, decrypted bytes not yet returned - is carried over by
// Enable, so nothing is lost whenever this is called.
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
