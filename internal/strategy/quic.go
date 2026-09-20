package strategy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/padding"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"golang.org/x/crypto/hkdf"
)

// The QUIC auth frame and ack, version 2.
//
// v1 opened the first stream with the ASCII literal "QVPN" and answered with
// "QACK". Constant magic in the first four bytes a peer reads is a fingerprint
// to anyone terminating the stream, and it made the ALPN "tiredvpn" (below) a
// matching giveaway one Initial-decrypt away.
//
// v2 removes both literals. The client frame is [nonce][marker][token]: the
// nonce is fresh per connection so the opening bytes are never repeated, the
// marker is HKDF(secret, nonce) and proves knowledge of the secret, and the
// 32-byte time-boxed token stays for the replay window it already gave. The
// server answers [marker][proof] with a marker derived the other direction so a
// captured client marker cannot be echoed back to pass for the server.
//
// The marker LENGTH is derived from the nonce alone, not from (secret, nonce)
// as the confusion marker is. Two constraints force this: the server has to
// parse the frame before it knows which of several candidate secrets it is,
// and the QUIC stream is fully encrypted so there is no observer to hide the
// length from. The confusion marker hides its length because it sits in a
// cleartext carrier; here there is nothing to hide it from, and a length the
// server can compute from the public nonce lets it read exactly the right
// number of bytes without over-reading into the tunnel stream.
//
// There is no transitional mode. A 1.10.x client sends "QVPN", the marker check
// fails, and the connection is dropped.
const (
	quicNonceLen   = 16
	quicMarkerMin  = 16
	quicMarkerSpan = 16

	quicClientMarkerLabel = "tiredvpn-quic-client-marker-v2"
	quicServerMarkerLabel = "tiredvpn-quic-server-marker-v2"
)

// quicMarkerLen derives the marker length from the nonce. It is flat over
// [16,32) because nonce[0] is uniform; there is no measured population to check
// that shape against (verification rule 3), recorded here on purpose.
func quicMarkerLen(nonce []byte) int {
	if len(nonce) == 0 {
		return quicMarkerMin
	}
	return quicMarkerMin + int(nonce[0])%quicMarkerSpan
}

// quicMarker derives the keyed marker for one direction from the secret and the
// connection's nonce.
func quicMarker(secret, nonce []byte, label string) []byte {
	if len(secret) == 0 {
		return nil
	}
	r := hkdf.New(sha256.New, secret, nonce, []byte(label))
	out := make([]byte, quicMarkerLen(nonce))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil
	}
	return out
}

func quicClientMarker(secret, nonce []byte) []byte {
	return quicMarker(secret, nonce, quicClientMarkerLabel)
}

func quicServerMarker(secret, nonce []byte) []byte {
	return quicMarker(secret, nonce, quicServerMarkerLabel)
}

// QUICNonceLen is the per-connection nonce length, exported for the wire tests.
const QUICNonceLen = quicNonceLen

// QUICMarkerLen returns the marker length for a captured nonce. Exported so the
// wire-signature tests can locate the marker and pin its length distribution.
func QUICMarkerLen(nonce []byte) int { return quicMarkerLen(nonce) }

// QUICClientMarker recomputes the client->server marker for a nonce.
func QUICClientMarker(secret, nonce []byte) []byte {
	return quicMarker(secret, nonce, quicClientMarkerLabel)
}

// QUICServerMarker recomputes the server->client marker for a nonce.
func QUICServerMarker(secret, nonce []byte) []byte {
	return quicMarker(secret, nonce, quicServerMarkerLabel)
}

// QUICStrategy implements QUIC-based tunneling with DPI evasion
// QUIC is harder to block because:
// 1. Uses UDP (DPI state tables are smaller)
// 2. Encrypted from first packet (no cleartext handshake)
// 3. Connection migration makes blocking harder
// 4. Multiplexed streams over single connection
type QUICStrategy struct {
	manager *Manager // IPv6/IPv4 transport layer support
	secret  []byte
	port    int

	// Salamander obfuscation (optional)
	useSalamander  bool
	salamanderPort int // Separate port for Salamander QUIC (default: 8443)

	// SNI fragmentation for GFW bypass
	sniFragmentEnabled bool
	sniFragmentConfig  *evasion.QUICFragmentConfig
}

// NewQUICStrategy creates a new QUIC strategy
// manager is required for IPv6/IPv4 transport layer support
func NewQUICStrategy(manager *Manager, secret []byte, port int) *QUICStrategy {
	return &QUICStrategy{
		manager:        manager,
		secret:         secret,
		port:           port,
		useSalamander:  false,
		salamanderPort: 8443,
	}
}

// NewQUICSalamanderStrategy creates a QUIC strategy with Salamander obfuscation
// manager is required for IPv6/IPv4 transport layer support
func NewQUICSalamanderStrategy(manager *Manager, secret []byte, port int) *QUICStrategy {
	return &QUICStrategy{
		manager:        manager,
		secret:         secret,
		port:           port,
		useSalamander:  true,
		salamanderPort: port, // Use provided port
	}
}

// SetSNIFragmentation enables SNI fragmentation for GFW bypass
func (s *QUICStrategy) SetSNIFragmentation(enabled bool, config *evasion.QUICFragmentConfig) {
	s.sniFragmentEnabled = enabled
	if config == nil {
		s.sniFragmentConfig = evasion.DefaultQUICFragmentConfig()
	} else {
		s.sniFragmentConfig = config
	}
}

func (s *QUICStrategy) Name() string {
	if s.useSalamander {
		return "QUIC Salamander"
	}
	return "QUIC Tunnel"
}

func (s *QUICStrategy) ID() string {
	if s.useSalamander {
		return "quic_salamander"
	}
	return "quic"
}

func (s *QUICStrategy) Priority() int {
	if s.useSalamander {
		return 4 // Highest - Salamander is default server mode
	}
	return 5 // High priority - QUIC is hard to block
}

func (s *QUICStrategy) Description() string {
	if s.useSalamander {
		return "QUIC with Salamander padding - default server mode, per-client secret support"
	}
	return "QUIC-based tunnel over UDP with version spoofing (uses draft-29 to bypass TSPU)"
}

func (s *QUICStrategy) RequiresServer() bool {
	return true
}

// Probe tests if QUIC can reach the server
func (s *QUICStrategy) Probe(ctx context.Context, target string) error {
	// Get server address (IPv6/IPv4 with automatic fallback)
	addr := s.manager.GetServerAddr(ctx)
	log.Debug("QUIC Probe: Using server address: %s", addr)

	// Use "udp" (not "udp4") to support both IPv4 and IPv6
	// Create protected dialer to avoid VPN routing loop on Android
	dialer := &protect.ProtectDialer{
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	}
	conn, err := dialer.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP dial failed: %w", err)
	}
	defer conn.Close()

	// Send a minimal QUIC-like probe packet
	probe := s.buildProbePacket()
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(probe); err != nil {
		return fmt.Errorf("probe write failed: %w", err)
	}

	// We don't expect a response (server might not understand our probe)
	// Success = no ICMP unreachable within timeout
	// Use short timeout - ICMP unreachable comes back quickly if port is blocked
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	if err != nil {
		// Timeout is OK - server just didn't respond to probe
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil // Success - no blocking detected
		}
		// ICMP unreachable would be immediate error
	}

	return nil
}

// buildProbePacket creates a QUIC-like probe that won't trigger DPI
func (s *QUICStrategy) buildProbePacket() []byte {
	packet := make([]byte, 100)

	// Use draft-29 version (less likely to be blocked)
	packet[0] = 0xc0                                    // Long header, Initial
	binary.BigEndian.PutUint32(packet[1:5], 0xff00001d) // QUIC draft-29

	// Random connection IDs
	rand.Read(packet[5:])

	return packet
}

// Connect establishes a QUIC connection
func (s *QUICStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	addr := s.manager.GetServerAddr(ctx)
	secret := dialSecret(ctx, s.secret)

	// Use Salamander port if enabled
	if s.useSalamander {
		// Replace port in address
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		// Preserve IPv6 bracket notation
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			addr = fmt.Sprintf("[%s]:%d", host, s.salamanderPort)
		} else {
			addr = fmt.Sprintf("%s:%d", host, s.salamanderPort)
		}
		log.Debug("QUIC Salamander: Using server address %s", addr)
	} else {
		log.Debug("QUIC: Using server address %s", addr)
	}

	// Create QUIC config with evasion settings
	quicConfig := &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 100,
		// Enable 0-RTT for faster reconnection
		Allow0RTT: true,
	}

	// TLS config - we'll use whitelisted SNI
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.selectSNI(),
		// Advertise the RFC 9114 HTTP/3 token: the ALPN in a QUIC ClientHello is
		// readable one Initial-decrypt away, so it must name a protocol other
		// peers use, not the deployment. The tunnel discriminator moved into the
		// encrypted 1-RTT stream (the keyed auth-frame marker above).
		NextProtos: []string{"h3"},
	}

	// If using Salamander, create wrapped UDP connection
	var conn *quic.Conn
	var err error

	if s.useSalamander {
		// Auto-detect IPv6 vs IPv4 for UDP
		network := "udp4"
		listenAddr := "0.0.0.0:0"
		if strings.Contains(addr, "[") { // IPv6 format: [2001:db8::1]:443
			network = "udp6"
			listenAddr = "[::]:0"
			log.Debug("QUIC Salamander: Using IPv6 transport")
		} else {
			log.Debug("QUIC Salamander: Using IPv4 transport")
		}

		// Create UDP connection manually
		udpConn, err := net.ListenPacket(network, listenAddr)
		if err != nil {
			return nil, fmt.Errorf("QUIC Salamander: UDP listen failed: %w", err)
		}

		// Protect socket from VPN routing (Android)
		if conn, ok := udpConn.(net.Conn); ok {
			if err := protect.ProtectConn(conn); err != nil {
				udpConn.Close()
				return nil, fmt.Errorf("QUIC Salamander: socket protect failed: %w", err)
			}
		}

		// Wrap with Salamander
		padder := padding.NewSalamanderPadder(secret, padding.Balanced)
		salamanderConn := padding.NewSalamanderPacketConn(udpConn, padder)

		// Parse server address (use generic "udp" to support both IPv4/IPv6)
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			salamanderConn.Close()
			return nil, fmt.Errorf("QUIC Salamander: address resolve failed: %w", err)
		}

		// Dial QUIC with wrapped connection
		conn, err = quic.Dial(ctx, salamanderConn, udpAddr, tlsConfig, quicConfig)
		if err != nil {
			salamanderConn.Close()
			return nil, fmt.Errorf("QUIC Salamander dial failed: %w", err)
		}

		log.Debug("QUIC Salamander: connection established with padding")
	} else if s.sniFragmentEnabled {
		// Auto-detect IPv6 vs IPv4 for UDP
		network := "udp4"
		listenAddr := "0.0.0.0:0"
		if strings.Contains(addr, "[") { // IPv6 format: [2001:db8::1]:443
			network = "udp6"
			listenAddr = "[::]:0"
			log.Debug("QUIC SNI fragment: Using IPv6 transport")
		} else {
			log.Debug("QUIC SNI fragment: Using IPv4 transport")
		}

		// QUIC with SNI fragmentation for GFW bypass
		udpConn, err := net.ListenPacket(network, listenAddr)
		if err != nil {
			return nil, fmt.Errorf("QUIC SNI fragment: UDP listen failed: %w", err)
		}

		// Protect socket from VPN routing (Android)
		if conn, ok := udpConn.(net.Conn); ok {
			if err := protect.ProtectConn(conn); err != nil {
				udpConn.Close()
				return nil, fmt.Errorf("QUIC SNI fragment: socket protect failed: %w", err)
			}
		}

		// Wrap with SNI fragmenter
		fragmentConn := evasion.NewQUICFragmentPacketConn(udpConn, s.sniFragmentConfig)

		// Parse server address (use generic "udp" to support both IPv4/IPv6)
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			fragmentConn.Close()
			return nil, fmt.Errorf("QUIC SNI fragment: address resolve failed: %w", err)
		}

		// Dial QUIC with fragmented connection
		conn, err = quic.Dial(ctx, fragmentConn, udpAddr, tlsConfig, quicConfig)
		if err != nil {
			fragmentConn.Close()
			return nil, fmt.Errorf("QUIC SNI fragment dial failed: %w", err)
		}

		log.Debug("QUIC SNI fragmentation: connection established")
	} else {
		// Normal QUIC dial with protected socket
		// Auto-detect IPv6 vs IPv4 for UDP
		network := "udp4"
		listenAddr := "0.0.0.0:0"
		if strings.Contains(addr, "[") { // IPv6 format: [2001:db8::1]:443
			network = "udp6"
			listenAddr = "[::]:0"
			log.Debug("QUIC: Using IPv6 transport")
		} else {
			log.Debug("QUIC: Using IPv4 transport")
		}

		// Create UDP connection manually
		udpConn, err := net.ListenPacket(network, listenAddr)
		if err != nil {
			return nil, fmt.Errorf("QUIC: UDP listen failed: %w", err)
		}

		// Protect socket from VPN routing (Android)
		if connCast, ok := udpConn.(net.Conn); ok {
			if err := protect.ProtectConn(connCast); err != nil {
				udpConn.Close()
				return nil, fmt.Errorf("QUIC: socket protect failed: %w", err)
			}
		}

		// Parse server address
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("QUIC: address resolve failed: %w", err)
		}

		// Dial QUIC with protected connection
		conn, err = quic.Dial(ctx, udpConn, udpAddr, tlsConfig, quicConfig)
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("QUIC dial failed: %w", err)
		}
	}

	log.Debug("QUIC connection established, opening stream")

	// Open a bidirectional stream for data
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(1, "stream open failed")
		return nil, fmt.Errorf("stream open failed: %w", err)
	}

	// Perform authentication handshake
	quicConn := &QUICConn{
		Conn:   conn,
		stream: stream,
		secret: secret,
	}

	if err := quicConn.Handshake(); err != nil {
		conn.CloseWithError(2, "handshake failed")
		return nil, fmt.Errorf("QUIC handshake failed: %w", err)
	}

	log.Info("QUIC tunnel established to %s", addr)
	return quicConn, nil
}

// selectSNI chooses a whitelisted SNI for the connection
func (s *QUICStrategy) selectSNI() string {
	// Whitelisted domains that use QUIC and shouldn't be blocked
	snis := []string{
		"www.google.com",
		"www.youtube.com",
		"drive.google.com",
		"docs.google.com",
		"mail.google.com",
	}

	// Deterministic selection based on time (changes hourly)
	hour := time.Now().Hour()
	return snis[hour%len(snis)]
}

// extractHost extracts hostname from target address
func (s *QUICStrategy) extractHost(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return host
}

// QUICConn wraps a QUIC connection to implement net.Conn
type QUICConn struct {
	*quic.Conn
	stream *quic.Stream
	secret []byte

	mu     sync.Mutex
	closed bool
}

// Handshake performs authentication
func (c *QUICConn) Handshake() error {
	// Generate time-based auth token
	token := c.generateAuthToken()

	// Fresh per-connection nonce keys the marker and never repeats the opening
	// bytes across connections.
	var nonce [quicNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("auth nonce: %w", err)
	}
	marker := quicClientMarker(c.secret, nonce[:])
	if marker == nil {
		return errors.New("auth marker derivation failed")
	}

	// Send auth frame: [nonce:16][marker:L][token:32]
	authFrame := make([]byte, 0, len(nonce)+len(marker)+len(token))
	authFrame = append(authFrame, nonce[:]...)
	authFrame = append(authFrame, marker...)
	authFrame = append(authFrame, token...)

	c.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.stream.Write(authFrame); err != nil {
		return fmt.Errorf("auth write failed: %w", err)
	}

	// Read server ack: [marker:L][proof:16]. The marker length is derived from
	// our own nonce, so we know exactly how many bytes to read.
	markerLen := quicMarkerLen(nonce[:])
	c.stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack := make([]byte, markerLen+16)
	if _, err := io.ReadFull(c.stream, ack); err != nil {
		return fmt.Errorf("auth read failed: %w", err)
	}

	// Verify the server's answering marker and its keyed proof.
	expectedMarker := quicServerMarker(c.secret, nonce[:])
	if expectedMarker == nil || !hmac.Equal(ack[:markerLen], expectedMarker) {
		return errors.New("invalid server ack")
	}
	expectedDerived := c.deriveKey("server-ack")[:16]
	if !hmac.Equal(ack[markerLen:markerLen+16], expectedDerived) {
		return errors.New("server verification failed")
	}

	// Clear deadlines
	c.stream.SetDeadline(time.Time{})

	return nil
}

func (c *QUICConn) generateAuthToken() []byte {
	// Time-based token (1-minute window)
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60))

	h := hmac.New(sha256.New, c.secret)
	h.Write(timestamp)
	h.Write([]byte("quic-auth"))
	return h.Sum(nil)
}

func (c *QUICConn) deriveKey(context string) []byte {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(context))
	return h.Sum(nil)
}

// Read implements net.Conn
func (c *QUICConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

// Write implements net.Conn
func (c *QUICConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

// Close implements net.Conn
func (c *QUICConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.stream.Close()
	return c.CloseWithError(0, "client closed")
}

// LocalAddr implements net.Conn
func (c *QUICConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr implements net.Conn
func (c *QUICConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline implements net.Conn
func (c *QUICConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (c *QUICConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (c *QUICConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// hmacEqual performs constant-time comparison
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal(a, b)
}

// Ensure interface compliance
var _ net.Conn = (*QUICConn)(nil)

// ============================================================================
// QUIC Server Handler
// ============================================================================

// SecretInfo holds client secret info for per-client authentication
type SecretInfo struct {
	Secret   []byte
	ClientID string
	Name     string
}

// QUICServerConfig configures QUIC server
type QUICServerConfig struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	Secret     []byte // Global fallback secret

	// GetClientSecrets returns list of per-client secrets for authentication
	// If nil, only global Secret is used
	GetClientSecrets func() []SecretInfo

	// SNIFragmentReassembly enables reassembly of fragmented Initial packets
	// This is required to accept connections from clients using -quic-sni-frag
	SNIFragmentReassembly bool

	// Multi-port support for port hopping
	// If Ports is non-empty, ListenAddr is ignored and server listens on all specified ports
	Ports []int // List of UDP ports to listen on
}

// QUICServer handles QUIC connections
type QUICServer struct {
	config    QUICServerConfig
	listener  *quic.Listener   // Single port mode
	listeners []*quic.Listener // Multi-port mode

	mu       sync.Mutex
	running  bool
	stopChan chan struct{}
}

// NewQUICServer creates a QUIC server
func NewQUICServer(config QUICServerConfig) *QUICServer {
	return &QUICServer{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// Start starts the QUIC server
func (s *QUICServer) Start(ctx context.Context, handler func(net.Conn)) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Match a real HTTP/3 endpoint's ALPN; the tunnel is told apart by the
		// keyed marker inside the encrypted stream, not by this token.
		NextProtos: []string{"h3"},
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 100,
		Allow0RTT:             true,
	}

	// Check if multi-port mode is requested
	if len(s.config.Ports) > 0 {
		return s.startMultiPort(ctx, handler, tlsConfig, quicConfig)
	}

	// Single port mode
	return s.startSinglePort(ctx, handler, tlsConfig, quicConfig)
}

// startSinglePort starts QUIC server on a single port
func (s *QUICServer) startSinglePort(ctx context.Context, handler func(net.Conn), tlsConfig *tls.Config, quicConfig *quic.Config) error {
	// Create UDP listener
	udpConn, err := net.ListenPacket("udp4", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	// Wrap with obfuscation
	wrappedConn := s.wrapPacketConn(udpConn)

	// Create QUIC listener over wrapped UDP
	tr := &quic.Transport{Conn: wrappedConn}
	listener, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		wrappedConn.Close()
		return fmt.Errorf("failed to listen QUIC: %w", err)
	}
	s.listener = listener

	log.Info("QUIC server listening on %s", s.config.ListenAddr)

	go s.acceptLoop(ctx, handler, listener)
	return nil
}

// startMultiPort starts QUIC server on multiple ports
func (s *QUICServer) startMultiPort(ctx context.Context, handler func(net.Conn), tlsConfig *tls.Config, quicConfig *quic.Config) error {
	s.listeners = make([]*quic.Listener, 0, len(s.config.Ports))

	successCount := 0
	for _, port := range s.config.Ports {
		addr := fmt.Sprintf("0.0.0.0:%d", port)

		udpConn, err := net.ListenPacket("udp4", addr)
		if err != nil {
			log.Warn("QUIC: failed to listen on UDP port %d: %v (skipping)", port, err)
			continue
		}

		// Wrap with obfuscation
		wrappedConn := s.wrapPacketConn(udpConn)

		// Create QUIC listener
		tr := &quic.Transport{Conn: wrappedConn}
		listener, err := tr.Listen(tlsConfig, quicConfig)
		if err != nil {
			wrappedConn.Close()
			log.Warn("QUIC: failed to start listener on port %d: %v (skipping)", port, err)
			continue
		}

		s.listeners = append(s.listeners, listener)
		successCount++

		// Start accept loop for this listener
		go s.acceptLoop(ctx, handler, listener)
	}

	if successCount == 0 {
		return fmt.Errorf("failed to start QUIC on any port")
	}

	log.Info("QUIC server listening on %d UDP ports (range: %d-%d)", successCount, s.config.Ports[0], s.config.Ports[len(s.config.Ports)-1])

	return nil
}

// wrapPacketConn wraps UDP connection with obfuscation (Salamander or SNI reassembly)
func (s *QUICServer) wrapPacketConn(udpConn net.PacketConn) net.PacketConn {
	wrappedConn := udpConn

	// SNI fragment reassembly and Salamander are mutually exclusive obfuscation methods
	if s.config.SNIFragmentReassembly {
		// SNI fragmentation mode: reassemble fragments, no Salamander padding
		wrappedConn = evasion.NewQUICReassemblyPacketConn(wrappedConn, nil)
		log.Debug("QUIC server: SNI fragment reassembly enabled on %s", udpConn.LocalAddr())
	} else {
		// Salamander mode: expect padded packets (default)
		// Use multi-secret Salamander to support per-client secrets
		var secretProvider padding.SecretProvider
		if s.config.GetClientSecrets != nil {
			secretProvider = func() [][]byte {
				secrets := s.config.GetClientSecrets()
				result := make([][]byte, len(secrets))
				for i, info := range secrets {
					result[i] = info.Secret
				}
				return result
			}
		}
		wrappedConn = padding.NewMultiSecretSalamanderPacketConn(
			wrappedConn,
			s.config.Secret,
			padding.Balanced,
			secretProvider,
		)
	}

	return wrappedConn
}

func (s *QUICServer) acceptLoop(ctx context.Context, handler func(net.Conn), listener *quic.Listener) {
	const (
		acceptBackoffMin    = 10 * time.Millisecond
		acceptBackoffMax    = 5 * time.Second
		acceptDegradedAfter = 50 // consecutive errors before logging degradation
	)

	backoff := acceptBackoffMin
	consecutiveErrors := 0
	degradedLogged := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			consecutiveErrors++
			log.Warn("QUIC accept error (consecutive=%d, backoff=%s): %v", consecutiveErrors, backoff, err)

			// Persistent failure: warn once at ERROR level so it's visible in prod,
			// but keep serving TCP — do not panic or exit the process.
			if consecutiveErrors >= acceptDegradedAfter && !degradedLogged {
				log.Error("QUIC listener degraded: %d consecutive Accept errors, last: %v (TCP unaffected)", consecutiveErrors, err)
				degradedLogged = true
			}

			// Interruptible backoff so shutdown does not hang.
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-s.stopChan:
				timer.Stop()
				return
			case <-timer.C:
			}

			// Exponential backoff with cap.
			if backoff < acceptBackoffMax {
				backoff *= 2
				if backoff > acceptBackoffMax {
					backoff = acceptBackoffMax
				}
			}
			continue
		}

		// Successful Accept: reset backoff and degradation state.
		backoff = acceptBackoffMin
		consecutiveErrors = 0
		degradedLogged = false

		go s.handleConnection(ctx, conn, handler)
	}
}

func (s *QUICServer) handleConnection(ctx context.Context, conn *quic.Conn, handler func(net.Conn)) {
	defer conn.CloseWithError(0, "connection closed")

	// Accept stream from client
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Debug("Failed to accept stream: %v", err)
		return
	}

	// Create server-side QUICConn
	serverConn := &QUICServerConn{
		Conn:             conn,
		stream:           stream,
		globalSecret:     s.config.Secret,
		getClientSecrets: s.config.GetClientSecrets,
	}

	// Verify client authentication
	if err := serverConn.VerifyClient(); err != nil {
		log.Warn("QUIC client auth failed: %v", err)
		return
	}

	log.Info("QUIC client authenticated from %s", conn.RemoteAddr())

	// Hand off to application handler
	handler(serverConn)
}

// Stop stops the QUIC server
func (s *QUICServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false

	close(s.stopChan)

	// Close single port listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Close multi-port listeners
	for _, listener := range s.listeners {
		if listener != nil {
			listener.Close()
		}
	}

	return nil
}

// QUICServerConn is the server-side QUIC connection
type QUICServerConn struct {
	*quic.Conn
	stream           *quic.Stream
	secret           []byte // Will be set to the authenticated secret
	globalSecret     []byte // Fallback secret
	getClientSecrets func() []SecretInfo

	// Authenticated client info (set after VerifyClient)
	ClientID   string
	ClientName string

	// ClientIDFromRegistry records where ClientID came from. A registry client
	// has its own secret and its own id, so that id identifies one client. The
	// global-secret fallback gives every client the same id, and a caller that
	// keys anything per client on it - an IP-pool lease, for one - has to know
	// the difference. The zero value is the shared case on purpose.
	ClientIDFromRegistry bool

	mu     sync.Mutex
	closed bool
}

// VerifyClient verifies client authentication against per-client secrets and global secret
func (c *QUICServerConn) VerifyClient() error {
	// Read auth frame: [nonce:16][marker:L][token:32]. The nonce comes first and
	// its byte fixes the marker length, so the frame can be parsed before any
	// secret is known.
	c.stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var nonce [quicNonceLen]byte
	if _, err := io.ReadFull(c.stream, nonce[:]); err != nil {
		return fmt.Errorf("auth read failed: %w", err)
	}
	markerLen := quicMarkerLen(nonce[:])
	rest := make([]byte, markerLen+32)
	if _, err := io.ReadFull(c.stream, rest); err != nil {
		return fmt.Errorf("auth read failed: %w", err)
	}
	clientMarker := rest[:markerLen]
	clientToken := rest[markerLen : markerLen+32]

	// A secret authenticates only if it produces both the keyed marker and a
	// token inside the time window: the marker binds the connection's nonce,
	// the token bounds replay.
	verifyWithSecret := func(secret []byte) bool {
		want := quicClientMarker(secret, nonce[:])
		if want == nil || !hmac.Equal(clientMarker, want) {
			return false
		}
		for offset := int64(-1); offset <= 1; offset++ {
			if hmac.Equal(clientToken, c.generateAuthTokenWithSecret(secret, offset)) {
				return true
			}
		}
		return false
	}

	// 1. Try per-client secrets first
	if c.getClientSecrets != nil {
		for _, info := range c.getClientSecrets() {
			if verifyWithSecret(info.Secret) {
				c.secret = info.Secret
				c.ClientID = info.ClientID
				c.ClientIDFromRegistry = true
				c.ClientName = info.Name
				log.Info("QUIC authenticated (client: %s, id: %s)", info.Name, info.ClientID)
				return c.sendAck(nonce[:])
			}
		}
	}

	// 2. Fallback to global secret
	if len(c.globalSecret) > 0 && verifyWithSecret(c.globalSecret) {
		c.secret = c.globalSecret
		c.ClientID = "global"
		c.ClientName = "global"
		log.Info("QUIC authenticated (global secret)")
		return c.sendAck(nonce[:])
	}

	return errors.New("token verification failed")
}

// sendAck sends the authentication acknowledgment: [marker:L][proof:16], keyed
// to the same nonce the client chose but derived in the server direction.
func (c *QUICServerConn) sendAck(nonce []byte) error {
	marker := quicServerMarker(c.secret, nonce)
	if marker == nil {
		return errors.New("server marker derivation failed")
	}
	ack := make([]byte, 0, len(marker)+16)
	ack = append(ack, marker...)
	ack = append(ack, c.deriveKey("server-ack")[:16]...)

	c.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.stream.Write(ack); err != nil {
		return fmt.Errorf("ack write failed: %w", err)
	}

	c.stream.SetDeadline(time.Time{})
	return nil
}

func (c *QUICServerConn) generateAuthToken(minuteOffset int64) []byte {
	return c.generateAuthTokenWithSecret(c.secret, minuteOffset)
}

func (c *QUICServerConn) generateAuthTokenWithSecret(secret []byte, minuteOffset int64) []byte {
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60+minuteOffset))

	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("quic-auth"))
	return h.Sum(nil)
}

func (c *QUICServerConn) deriveKey(context string) []byte {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(context))
	return h.Sum(nil)
}

// Read implements net.Conn
func (c *QUICServerConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

// Write implements net.Conn
func (c *QUICServerConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

// Close implements net.Conn
func (c *QUICServerConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.stream.Close()
	return c.CloseWithError(0, "server closed")
}

// LocalAddr implements net.Conn
func (c *QUICServerConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr implements net.Conn
func (c *QUICServerConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline implements net.Conn
func (c *QUICServerConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (c *QUICServerConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (c *QUICServerConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// Ensure interface compliance
var _ net.Conn = (*QUICServerConn)(nil)
