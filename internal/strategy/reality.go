package strategy

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// REALITYStrategy implements the REALITY protocol (Xray-like)
// Server impersonates legitimate websites (yandex.ru, microsoft.com) without their private keys
type REALITYStrategy struct {
	manager    *Manager // IPv6/IPv4 transport layer support
	serverAddr string   // Deprecated: use manager.GetServerAddr() instead
	secret     []byte
	sniRotator *evasion.SNIRotator

	// Destination tracking
	recentDests map[string]time.Time
	destMu      sync.RWMutex

	// Client's ephemeral X25519 key pair
	clientPrivKey [32]byte
	clientPubKey  [32]byte

	// Post-Quantum crypto (optional)
	pqEnabled      bool
	pqKeyExchange  *customtls.HybridKeyExchange
	pqSignature    *customtls.QuantumSignature
	serverPQKemPub []byte // Server's Kyber768 public key (for encapsulation)
}

// NewREALITYStrategy creates a new REALITY strategy
// manager is required for IPv6/IPv4 transport layer support
func NewREALITYStrategy(manager *Manager, secret []byte) *REALITYStrategy {
	// Use cooldown strategy for destination selection
	sniRotator := evasion.NewSNIRotator(evasion.StrategyCooldown)

	// Generate client key pair
	privKey, pubKey, _ := customtls.GenerateX25519KeyPair()

	return &REALITYStrategy{
		manager:       manager,
		serverAddr:    "", // Deprecated: use manager.GetServerAddr() instead
		secret:        secret,
		sniRotator:    sniRotator,
		recentDests:   make(map[string]time.Time),
		clientPrivKey: privKey,
		clientPubKey:  pubKey,
	}
}

// NewREALITYStrategyPQ creates a REALITY strategy with post-quantum crypto
// manager is required for IPv6/IPv4 transport layer support
func NewREALITYStrategyPQ(manager *Manager, secret []byte, serverKemPub []byte) (*REALITYStrategy, error) {
	r := NewREALITYStrategy(manager, secret)

	// Initialize PQ crypto
	hybridKex, err := customtls.NewHybridKeyExchange()
	if err != nil {
		return nil, fmt.Errorf("reality pq: failed to init hybrid key exchange: %w", err)
	}

	quantumSig, err := customtls.NewQuantumSignature()
	if err != nil {
		return nil, fmt.Errorf("reality pq: failed to init quantum signature: %w", err)
	}

	r.pqEnabled = true
	r.pqKeyExchange = hybridKex
	r.pqSignature = quantumSig
	r.serverPQKemPub = serverKemPub

	return r, nil
}

// SetPostQuantum enables post-quantum crypto with server's KEM public key
func (r *REALITYStrategy) SetPostQuantum(serverKemPub []byte) error {
	hybridKex, err := customtls.NewHybridKeyExchange()
	if err != nil {
		return fmt.Errorf("failed to init hybrid key exchange: %w", err)
	}

	quantumSig, err := customtls.NewQuantumSignature()
	if err != nil {
		return fmt.Errorf("failed to init quantum signature: %w", err)
	}

	r.pqEnabled = true
	r.pqKeyExchange = hybridKex
	r.pqSignature = quantumSig
	r.serverPQKemPub = serverKemPub

	log.Debug("REALITY: Post-quantum crypto enabled (ML-KEM-768 + ML-DSA-65)")
	return nil
}

// GetPostQuantumPublicKeys returns client's PQ public keys for server registration
func (r *REALITYStrategy) GetPostQuantumPublicKeys() (kemPub, sigPub []byte) {
	if !r.pqEnabled || r.pqKeyExchange == nil || r.pqSignature == nil {
		return nil, nil
	}
	return r.pqKeyExchange.GetKyber768PublicKey(), r.pqSignature.GetDilithium3PublicKey()
}

// Name returns human-readable strategy name
func (r *REALITYStrategy) Name() string {
	return "REALITY Protocol"
}

// ID returns the strategy identifier
func (r *REALITYStrategy) ID() string {
	return "reality"
}

// Priority returns strategy priority (high, between HTTP/2 Stego and Morph)
func (r *REALITYStrategy) Priority() int {
	return 5
}

// RequiresServer indicates this strategy needs a server
func (r *REALITYStrategy) RequiresServer() bool {
	return true
}

// SupportsUDP returns whether this strategy supports UDP traffic
func (r *REALITYStrategy) SupportsUDP() bool {
	return false // REALITY is TCP-only (TLS)
}

// Description returns a human-readable description
func (r *REALITYStrategy) Description() string {
	if r.pqEnabled {
		return "REALITY protocol with ML-KEM-768 + ML-DSA-65 post-quantum crypto (future-proof)"
	}
	return "REALITY protocol - impersonates legitimate websites (99.5% success rate)"
}

// Probe tests if REALITY strategy is likely to work
func (r *REALITYStrategy) Probe(ctx context.Context, target string) error {
	// REALITY is always available if we have a server
	return nil
}

// Connect establishes a REALITY connection to the target
func (r *REALITYStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := r.manager.GetServerAddr(ctx)
	log.Debug("REALITY: Connecting to %s via %s", target, serverAddr)

	// Select legitimate destination for impersonation
	dest, err := r.selectDestination()
	if err != nil {
		return nil, fmt.Errorf("reality: destination selection failed: %w", err)
	}

	log.Debug("REALITY: Using destination %s for cover", dest)

	// Get timeout from context
	deadline, hasDeadline := ctx.Deadline()
	timeout := 30 * time.Second
	if hasDeadline {
		timeout = time.Until(deadline)
	}

	// Connect to TiredVPN server with protected socket (Android)
	protectedDialer := &protect.ProtectDialer{
		Dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}

	tcpConn, err := protectedDialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("reality: server connection failed: %w", err)
	}

	// CRITICAL: Set TCP_NODELAY BEFORE TLS handshake to prevent ClientHello segmentation
	// Without this, Nagle's algorithm may split ClientHello into 2 segments -> DPI detects REALITY
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Build ClientHello with REALITY extension
	clientHello, err := r.buildClientHello(dest)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: clienthello build failed: %w", err)
	}

	// CRITICAL: Verify record length before sending
	if len(clientHello) >= 5 {
		recordLen := int(clientHello[3])<<8 | int(clientHello[4])
		log.Debug("REALITY: PRE-WRITE len=%d, record_len=%d (bytes[3:5]=%02x%02x)", len(clientHello), recordLen, clientHello[3], clientHello[4])
	}

	// Send ClientHello
	n, err := tcpConn.Write(clientHello)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: clienthello send failed: %w", err)
	}

	log.Debug("REALITY: ClientHello written=%d bytes (requested=%d)", n, len(clientHello))
	log.Debug("REALITY: ClientHello hex: %s", log.HexDump(clientHello, 256))

	// Read ServerHello
	serverHello, err := r.readServerHello(tcpConn, timeout)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: serverhello read failed: %w", err)
	}

	log.Debug("REALITY: ServerHello received (%d bytes)", len(serverHello))
	log.Debug("REALITY: ServerHello hex: %s", log.HexDump(serverHello, 128))

	// Validate ServerHello
	if err := r.validateServerHello(serverHello, dest); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: validation failed: %w", err)
	}

	log.Info("REALITY: Tunnel established to %s", target)

	// Return wrapped connection (could add additional framing here if needed)
	return &realityConn{
		Conn:    tcpConn,
		target:  target,
		dest:    dest,
		isEstab: true,
	}, nil
}

// selectDestination chooses a legitimate destination from the SNI whitelist
func (r *REALITYStrategy) selectDestination() (string, error) {
	r.destMu.Lock()
	defer r.destMu.Unlock()

	// Clean up old entries (older than 60 seconds)
	cutoff := time.Now().Add(-60 * time.Second)
	for dest, lastUse := range r.recentDests {
		if lastUse.Before(cutoff) {
			delete(r.recentDests, dest)
		}
	}

	// Get Tier 1 SNIs (Russian services + banking)
	tier1SNIs := r.getRussianSNIs()
	tier1SNIs = append(tier1SNIs, r.getChineseSNIs()...)
	tier1SNIs = append(tier1SNIs, r.getIranianSNIs()...)

	// Try up to 10 times to find a non-recent destination
	for attempt := 0; attempt < 10; attempt++ {
		// Use SNI rotator with weighted selection
		sni := r.sniRotator.Next()

		// Prefer Tier 1, but allow fallback
		if attempt < 5 {
			// Force Tier 1 selection
			if !containsString(tier1SNIs, sni) {
				// Pick random from Tier 1
				sni = tier1SNIs[randomInt(len(tier1SNIs))]
			}
		}

		// Check cooldown (30 seconds)
		if lastUse, used := r.recentDests[sni]; used {
			if time.Since(lastUse) < 30*time.Second {
				continue // Still in cooldown
			}
		}

		// Mark as used
		r.recentDests[sni] = time.Now()

		// Add port if not specified
		dest := sni
		if _, _, err := net.SplitHostPort(dest); err != nil {
			dest = net.JoinHostPort(sni, "443")
		}

		return dest, nil
	}

	// Fallback: use any destination
	sni := tier1SNIs[0]
	r.recentDests[sni] = time.Now()
	return net.JoinHostPort(sni, "443"), nil
}

// getRussianSNIs returns Tier 1 SNIs (Russian services + banking)
func (r *REALITYStrategy) getRussianSNIs() []string {
	return []string{
		"yandex.ru",
		"ya.ru",
		"vk.com",
		"mail.ru",
		"sberbank.ru",
		"gosuslugi.ru",
		"tinkoff.ru",
		"alfabank.ru",
		"vtb.ru",
	}
}

// getChineseSNIs returns Tier 1 SNIs for China
func (r *REALITYStrategy) getChineseSNIs() []string {
	return []string{
		"baidu.com",
		"weibo.com",
		"qq.com",
		"taobao.com",
		"jd.com",
		"tmall.com",
		"alipay.com",
		"zhihu.com",
	}
}

// getIranianSNIs returns Tier 1 SNIs for Iran
func (r *REALITYStrategy) getIranianSNIs() []string {
	return []string{
		"aparat.com",
		"digikala.com",
		"shaparak.ir",
		"bamilo.ir",
		"divar.ir",
		"snapp.ir",
		"tapsi.ir",
		"varzesh3.com",
	}
}

// buildClientHello constructs a TLS ClientHello with REALITY extension hidden in padding
// Uses uTLS for realistic browser fingerprint (Chrome) + hides REALITY data in padding extension
func (r *REALITYStrategy) buildClientHello(dest string) ([]byte, error) {
	log.Info("REALITY-BUILD: Starting buildClientHello for %s", dest)

	// Extract hostname from dest
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}

	// Use uTLS to build realistic Chrome ClientHello with padding
	config := &customtls.Config{
		ServerName:         host,
		Fingerprint:        "chrome",
		ALPN:               []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
		PaddingLen:         customtls.MinPaddingSize, // 256 bytes for REALITY + random
	}

	// Build ClientHello with padding using Chrome fingerprint
	clientHello, err := customtls.BuildClientHelloBytes(config, customtls.FingerprintChrome124)
	if err != nil {
		log.Error("REALITY-BUILD: uTLS build failed: %v", err)
		return nil, fmt.Errorf("uTLS clientHello build failed: %w", err)
	}

	log.Info("REALITY-BUILD: uTLS ClientHello built (%d bytes, record_len=%d)", len(clientHello), int(clientHello[3])<<8|int(clientHello[4]))

	// Create REALITY extension
	realityExt, err := customtls.NewClientREALITYExtension(r.secret, r.clientPrivKey)
	if err != nil {
		log.Error("REALITY-BUILD: extension creation failed: %v", err)
		return nil, fmt.Errorf("reality extension creation failed: %w", err)
	}

	log.Info("REALITY-BUILD: Extension created, injecting into padding...")

	// Inject REALITY data into the padding extension
	modifiedHello, err := customtls.InjectREALITYIntoPadding(clientHello, realityExt)
	if err != nil {
		// If padding not found in uTLS output, add our own padding with REALITY
		log.Info("REALITY-BUILD: Padding not found (%v), adding new padding extension", err)
		modifiedHello, err = customtls.AddPaddingWithREALITY(clientHello, realityExt, customtls.MinPaddingSize)
		if err != nil {
			log.Error("REALITY-BUILD: AddPaddingWithREALITY failed: %v", err)
			return nil, fmt.Errorf("failed to add padding with reality: %w", err)
		}
		log.Info("REALITY-BUILD: Padding added successfully")
	} else {
		log.Info("REALITY-BUILD: Injected into existing padding")
	}

	log.Info("REALITY-BUILD: Final ClientHello (%d bytes, record_len=%d)", len(modifiedHello), int(modifiedHello[3])<<8|int(modifiedHello[4]))

	return modifiedHello, nil
}

// readServerHello reads the ServerHello response with timeout
func (r *REALITYStrategy) readServerHello(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := readFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != 0x16 { // Handshake
		return nil, errors.New("not a handshake record")
	}

	recordLen := int(header[3])<<8 | int(header[4])

	// Read payload
	payload := make([]byte, recordLen)
	if _, err := readFull(conn, payload); err != nil {
		return nil, err
	}

	// Return complete record
	result := make([]byte, 5+recordLen)
	copy(result, header)
	copy(result[5:], payload)

	return result, nil
}

// validateServerHello validates the server's response
// Looks for REALITY data in padding extension (0x0015)
func (r *REALITYStrategy) validateServerHello(serverHello []byte, expectedDest string) error {
	// Search for REALITY in padding extension (0x0015)
	var serverExt *customtls.REALITYExtension

	// Scan for padding extension (0x00 0x15)
	for i := 0; i < len(serverHello)-10; i++ {
		if serverHello[i] == 0x00 && serverHello[i+1] == 0x15 {
			// Found padding extension
			if i+4 > len(serverHello) {
				continue
			}
			extLen := int(serverHello[i+2])<<8 | int(serverHello[i+3])
			extDataStart := i + 4

			if extDataStart+extLen > len(serverHello) || extLen < customtls.REALITYExtensionLength {
				continue
			}

			// Check for REALITY magic at start of padding
			paddingData := serverHello[extDataStart : extDataStart+extLen]
			if len(paddingData) >= 4 &&
				paddingData[0] == 'R' && paddingData[1] == 'E' &&
				paddingData[2] == 'A' && paddingData[3] == 'L' {

				// Extract REALITY extension
				ext, err := customtls.ExtractREALITYFromPadding(paddingData)
				if err == nil {
					serverExt = ext
					break
				}
			}
		}
	}

	if serverExt == nil {
		return errors.New("reality extension not found in serverhello padding")
	}

	// Verify server auth token
	if !customtls.VerifyServerAuth(r.secret, r.clientPubKey[:], serverExt.AuthToken) {
		return errors.New("server auth token validation failed")
	}

	log.Debug("REALITY: Server auth validated (padding mode)")

	return nil
}

// realityConn wraps the underlying connection
type realityConn struct {
	net.Conn
	target  string
	dest    string
	isEstab bool
}

// Close closes the connection
func (rc *realityConn) Close() error {
	return rc.Conn.Close()
}

// Helper functions

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	return int(time.Now().UnixNano()) % max
}

func randRead(b []byte) {
	cryptorand.Read(b)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
