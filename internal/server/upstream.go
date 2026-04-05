package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	// "github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// UpstreamDialer connects to target servers through an upstream TiredVPN server
type UpstreamDialer struct {
	upstreamAddr   string
	upstreamSecret []byte
	coverHost      string
	tlsConfig      *tls.Config

	// TLS session cache for faster reconnects
	sessionCache tls.ClientSessionCache
	sessionMu    sync.Mutex
}

// NewUpstreamDialer creates a new dialer for upstream mode
func NewUpstreamDialer(addr string, secret []byte) *UpstreamDialer {
	// Create a session cache for TLS resumption
	sessionCache := tls.NewLRUClientSessionCache(32)

	return &UpstreamDialer{
		upstreamAddr:   addr,
		upstreamSecret: secret,
		coverHost:      "api.googleapis.com",
		sessionCache:   sessionCache,
		tlsConfig: &tls.Config{
			// InsecureSkipVerify is intentional: the upstream TiredVPN server presents a
			// certificate for the cover domain (e.g. api.googleapis.com) which it does
			// not actually own — this is required for DPI evasion. Server identity is
			// verified at the application layer via HMAC-based HTTP/2 stego handshake.
			// TODO: implement certificate pinning for the upstream server's actual cert.
			InsecureSkipVerify:     true, //nolint:gosec
			ServerName:             "api.googleapis.com",
			NextProtos:             []string{"h2"},
			ClientSessionCache:     sessionCache,
			SessionTicketsDisabled: false,
		},
	}
}

// Dial connects to the target address through the upstream TiredVPN server
// Returns a net.Conn that transparently tunnels through the upstream
func (d *UpstreamDialer) Dial(ctx context.Context, targetAddr string) (net.Conn, error) {
	log.Debug("Upstream dial to %s via %s", targetAddr, d.upstreamAddr)

	// Get timeout from context or use default
	deadline, hasDeadline := ctx.Deadline()
	timeout := 30 * time.Second
	if hasDeadline {
		timeout = time.Until(deadline)
	}

	// 1. Establish TLS connection to upstream with TCP optimizations
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	// Dial TCP first to set options before TLS
	tcpConn, err := dialer.DialContext(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return nil, err
	}

	// Set TCP optimizations
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) // Disable Nagle's algorithm
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		// Set buffer sizes for better throughput
		tc.SetReadBuffer(64 * 1024)
		tc.SetWriteBuffer(64 * 1024)
	}

	// TLS handshake on the optimized TCP connection
	tlsConn := tls.Client(tcpConn, d.tlsConfig)

	// Set deadline for handshake
	if hasDeadline {
		tlsConn.SetDeadline(deadline)
	} else {
		tlsConn.SetDeadline(time.Now().Add(timeout))
	}

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}

	// Try to enable kTLS after successful handshake
	// TODO: kTLS disabled temporarily due to TLS record corruption
	// ktls.Enable(tlsConn)

	// Clear deadline after handshake
	tlsConn.SetDeadline(time.Time{})

	// Log session resumption
	state := tlsConn.ConnectionState()
	if state.DidResume {
		log.Debug("TLS session resumed for %s", d.upstreamAddr)
	} else {
		log.Debug("TLS full handshake for %s", d.upstreamAddr)
	}

	// Verify HTTP/2 was negotiated
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, errors.New("HTTP/2 not negotiated with upstream")
	}

	// 2. Create HTTP/2 Stego connection (reuse client implementation)
	stegoConn := strategy.NewHTTP2StegoConn(tlsConn, d.upstreamSecret, true, strategy.NaivePaddingStandard)

	// 3. Perform handshake (sends auth headers)
	if err := stegoConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// 4. Send target address (same protocol as regular client)
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	if _, err := stegoConn.Write(addrPacket); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// 5. Read response (0x00 = success, 0x01 = failure)
	resp := make([]byte, 1)
	if _, err := stegoConn.Read(resp); err != nil {
		tlsConn.Close()
		return nil, err
	}

	if resp[0] != 0x00 {
		tlsConn.Close()
		return nil, errors.New("upstream failed to connect to target")
	}

	log.Debug("Upstream connection established to %s", targetAddr)

	// Return the stego connection - it implements net.Conn
	// Read/Write will automatically handle HTTP/2 stego framing
	return stegoConn, nil
}

// DialTimeout is a convenience wrapper with explicit timeout
func (d *UpstreamDialer) DialTimeout(targetAddr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.Dial(ctx, targetAddr)
}

// Close releases resources
func (d *UpstreamDialer) Close() error {
	// Session cache will be garbage collected
	return nil
}
