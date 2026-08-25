package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	// "github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// defaultUpstreamSockBuf is the SO_RCVBUF/SO_SNDBUF size set on the TCP
// connection to the upstream exit. Each live relay bridge commits these buffers,
// so on a relay node this is a direct per-connection memory multiplier. 512KB is
// ample for the BDP at the current throughput ceiling even on a ~500ms upstream;
// the previous 4MB (= 8MB read+write per dial) was the main relay OOM amplifier.
const defaultUpstreamSockBuf = 512 * 1024

// UpstreamDialer connects to target servers through an upstream TiredVPN server
type UpstreamDialer struct {
	upstreamAddr   string
	upstreamSecret []byte
	coverHost      string
	tlsConfig      *tls.Config

	// sockBufBytes is the SO_RCVBUF/SO_SNDBUF applied to each upstream TCP dial.
	// 0 falls back to defaultUpstreamSockBuf. Overridable via Config to tune
	// relay memory without a rebuild.
	sockBufBytes int

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
		sockBufBytes:   defaultUpstreamSockBuf,
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

// connectStego establishes the TLS + HTTP/2 stego session to the upstream and
// completes the stego handshake. It is shared by Dial (address-proxy mode) and
// DialTUN (multi-hop TUN bridge). Returns the live stego conn and the underlying
// tls.Conn (caller closes the latter on any post-handshake failure).
func (d *UpstreamDialer) connectStego(ctx context.Context) (net.Conn, *tls.Conn, error) {
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
		return nil, nil, err
	}

	// Set TCP optimizations
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) // Disable Nagle's algorithm
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		// Bound the per-dial socket buffers. On a relay each live bridge commits
		// these, so they are a direct memory multiplier; 512KB covers the BDP at
		// the current throughput ceiling without the old 4MB blowup.
		sockBuf := d.sockBufBytes
		if sockBuf <= 0 {
			sockBuf = defaultUpstreamSockBuf
		}
		tc.SetReadBuffer(sockBuf)
		tc.SetWriteBuffer(sockBuf)
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
		return nil, nil, err
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
		return nil, nil, errors.New("HTTP/2 not negotiated with upstream")
	}

	// Send the protocol discriminator FIRST so the upstream routes us via
	// handleTLSConnection -> protocol.TypeStego. Without this the upstream reads
	// the first stego byte as the dispatch type, fails to authenticate the relay,
	// and the multi-hop tunnel never establishes. Mirrors strategy/stego.go.
	if err := protocol.WriteDispatch(tlsConn, protocol.TypeStego); err != nil {
		tlsConn.Close()
		return nil, nil, err
	}

	// Create HTTP/2 Stego connection (reuse client implementation)
	stegoConn := strategy.NewHTTP2StegoConn(tlsConn, d.upstreamSecret, true, strategy.NaivePaddingStandard)

	// Perform handshake (sends auth headers)
	if err := stegoConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, nil, err
	}

	return stegoConn, tlsConn, nil
}

// Dial connects to the target address through the upstream TiredVPN server
// Returns a net.Conn that transparently tunnels through the upstream
func (d *UpstreamDialer) Dial(ctx context.Context, targetAddr string) (net.Conn, error) {
	log.Debug("Upstream dial to %s via %s", targetAddr, d.upstreamAddr)

	stegoConn, tlsConn, err := d.connectStego(ctx)
	if err != nil {
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

// DialTUN opens a multi-hop TUN tunnel to the upstream server and performs the
// HTTP/2 stego TUN handshake (the same one a native TUN client performs). It is
// used by a relay node (-upstream set) to forward a downstream client's raw IP
// packets to the upstream exit instead of terminating them on the relay's local
// TUN. tunHandshake is the [localIP:4][mtu:2][version:1] payload received from the
// downstream client (without the leading 0x02 mode byte).
//
// origin identifies the downstream client (its address, or the origin a relay
// further down already attached) and is appended to the setup payload so the
// exit can tell two clients sharing one secret apart. Upstreams that predate the
// extension parse the fixed handshake and ignore the trailer.
//
// Returns the live stego conn (a transparent byte stream over which [len:4][pkt:N]
// frames flow in both directions, exactly as between a native client and exit) and
// the upstream's full raw handshake response — the version-dependent base layout
// [status:1][serverIP:4][clientIP:4][flags:1]... plus the trailing 32-byte
// dual-stack block [serverIP6:16][clientIP6:16] when the exit negotiated it.
func (d *UpstreamDialer) DialTUN(ctx context.Context, tunHandshake []byte, origin string) (net.Conn, []byte, error) {
	log.Debug("Upstream TUN dial via %s", d.upstreamAddr)

	stegoConn, tlsConn, err := d.connectStego(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Send the TUN-mode setup over the stego stream. The upstream's setupH2Tunnel
	// dispatches on the leading 0x02 mode byte to setupH2TUNTunnel, which parses the
	// remaining [localIP:4][mtu:2][version:1].
	setup := make([]byte, 1+len(tunHandshake))
	setup[0] = 0x02 // TUN mode
	copy(setup[1:], tunHandshake)
	setup = appendTUNOrigin(setup, origin)
	if _, err := stegoConn.Write(setup); err != nil {
		tlsConn.Close()
		return nil, nil, err
	}

	// Read the handshake response. The upstream frames it as a single stego
	// payload, so one Read returns the version-dependent base layout; when the
	// flags byte advertises dual-stack, ReadTUNHandshakeResponse additionally
	// consumes the trailing 32-byte [serverIP6:16][clientIP6:16] block. The
	// full raw response (base + block) is returned so callers can forward it
	// to the downstream client verbatim. An old exit never sets the dual-stack
	// flag, so its response is read exactly as before (base only, no extra
	// read). This also fixes a latent desync: the previous fixed 9-byte read
	// left the tail of an extended (port-hop) response in the stream.
	//
	// Deployment-order note — an old relay in the chain CORRUPTS the session,
	// it does not degrade it. The relay forwards the CLIENT's handshake
	// version upstream verbatim, so a new exit answers a v0x04 client with the
	// dual-stack flag and the 32-byte v6 block even when the hop in between is
	// old. That hop reads a fixed 9 bytes, hands those nine to the client and
	// then starts a transparent byte bridge, so the unread flags byte and the
	// v6 block travel downstream as tunnel payload: the client either misses
	// the flag (and the 33 stray bytes are parsed as a [len:4] frame header,
	// desyncing the stream) or picks it up out of a coalesced read — the
	// outcome depends on segmentation, not on any fallback path. The same is
	// true of every extended response shape (port-hop v1/v2, MTU-probe flags),
	// which is what the full-response read above fixes for NEW relays.
	//
	// There is no in-band way for the exit to detect an old hop while keeping
	// the request format backward compatible: an old relay copies everything
	// ahead of the TRO1 origin trailer verbatim and rewrites only the trailer
	// itself, so a capability marker in the prefix gets replayed unchanged
	// (false "chain is new"), and a marker that replaces the trailer costs an
	// old exit the origin it needs for per-client lease keys. Only deployment
	// order protects the chain: upgrade every exit and every relay BEFORE
	// enabling `-tun-ipv6 dual` on clients.
	resp, err := tun.ReadTUNHandshakeResponse(stegoConn)
	if err != nil {
		tlsConn.Close()
		return nil, nil, err
	}
	if len(resp) < 9 {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("short upstream TUN handshake response: %d bytes", len(resp))
	}

	if resp[0] != 0x00 {
		tlsConn.Close()
		return nil, nil, errors.New("upstream rejected TUN handshake")
	}

	log.Debug("Upstream TUN tunnel established (assigned IP=%s)", net.IP(resp[5:9]))
	return stegoConn, resp, nil
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
