package strategy

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/xtaci/smux"
	"golang.org/x/crypto/hkdf"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// REALITYStrategy implements the REALITY protocol (Xray-like)
// Server impersonates legitimate websites (yandex.ru, microsoft.com) without their private keys
type REALITYStrategy struct {
	manager    *Manager // IPv6/IPv4 transport layer support
	secret     []byte
	sniRotator *evasion.SNIRotator

	// Destination tracking
	destPool    []string // the derived donor pool, in rotator order
	recentDests map[string]time.Time
	destMu      sync.RWMutex

	// Client's ephemeral X25519 key pair
	clientPrivKey [32]byte
	clientPubKey  [32]byte

	// fingerprint names the uTLS browser profile used to build the ClientHello.
	// Fixed for the lifetime of the strategy: switching profiles mid-session is
	// itself a detection signal (see handshakeGate), so this is set once at
	// construction and never rotated.
	fingerprint string

	// gate serialises TLS handshakes per donor SNI. See handshake_gate.go.
	gate *handshakeGate

	// Post-Quantum crypto (optional)
	pqEnabled      bool
	pqKeyExchange  *customtls.HybridKeyExchange
	pqSignature    *customtls.QuantumSignature
	serverPQKemPub []byte // Server's Kyber768 public key (for encapsulation)
}

// realityConn owns the full per-request stack: TCP connection → ChaCha20/TLS
// framing → smux session → the single stream handed to the caller. Closing it
// tears down the whole stack, so every Connect() is fully self-contained and
// closing one caller's connection can never disturb another's.
type realityConn struct {
	net.Conn               // the smux stream (Read/Write/Deadlines)
	sess     *smux.Session // owns the smux session over the data conn
	tcpConn  net.Conn      // underlying TCP, closed last
}

func (c *realityConn) Close() error {
	streamErr := c.Conn.Close()
	c.sess.Close()
	c.tcpConn.Close()
	return streamErr
}

// NewREALITYStrategy creates a new REALITY strategy
// manager is required for IPv6/IPv4 transport layer support
func NewREALITYStrategy(manager *Manager, secret []byte) *REALITYStrategy {
	// Use "developer" category (github.com et al.) as the primary cover pool.
	// Empirically, TSPU (Russia) does NOT validate these domains' IPs against the
	// real server address — so TLS ClientHello with github.com SNI reaches the
	// VPN server without being RST'd. Microsoft/Azure domains are blocked
	// because TSPU whitelists their IP ranges and rejects mismatches.
	developerPool := make([]string, 0, 8)
	for _, entry := range evasion.WhitelistedSNIs {
		if entry.Category == "developer" {
			developerPool = append(developerPool, entry.SNI)
		}
	}
	subPool := derivePool(developerPool, secret, len(developerPool))
	if len(subPool) == 0 {
		// Fallback to the legacy Tier 1 list if derivation yields nothing.
		subPool = getRussianSNIsStatic()
	}

	// Use cooldown strategy for destination selection over the derived subpool
	sniRotator := evasion.NewSNIRotatorWithPool(subPool, evasion.StrategyCooldown)

	// Generate client key pair
	privKey, pubKey, _ := customtls.GenerateX25519KeyPair()

	return &REALITYStrategy{
		manager:       manager,
		secret:        secret,
		sniRotator:    sniRotator,
		destPool:      subPool,
		recentDests:   make(map[string]time.Time),
		clientPrivKey: privKey,
		clientPubKey:  pubKey,
		fingerprint:   customtls.DefaultFingerprintName,
		gate:          newHandshakeGate(),
	}
}

// SetFingerprint selects the uTLS browser profile used for the ClientHello.
// An empty or unknown name keeps the default profile and logs a warning; the
// alternative — silently dialing with a profile the operator did not ask for —
// makes a config typo indistinguishable from a working setup.
//
// Call this before the first Connect: the profile is deliberately stable for
// the lifetime of the strategy, because changing fingerprint after a censor has
// throttled a SNI escalates a 120 s freeze into a 600 s block of all TLS.
func (r *REALITYStrategy) SetFingerprint(name string) {
	if name == "" {
		return
	}
	if _, ok := customtls.LookupFingerprint(name); !ok {
		log.Warn("REALITY: unknown TLS fingerprint %q, using %q (available: %v)",
			name, customtls.DefaultFingerprintName, customtls.FingerprintNames())
		return
	}
	r.fingerprint = name
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
	// Shallow reachability check: a plain TCP connect against the same address
	// Connect uses (no TLS, no REALITY handshake). A full REALITY handshake here,
	// multiplied across ProbeAll's parallel strategies and periodic reprobes,
	// would hammer server admission control and defeat the point of probing.
	serverAddr := r.manager.GetServerAddr(ctx)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Connect establishes a REALITY connection to the target.
// Connect dials a new REALITY connection for each request and returns a
// self-contained conn (see realityConn): the returned conn owns its own TCP,
// framing and smux session, and closing it tears down only that stack.
//
// Smux session reuse is intentionally disabled: TSPU (Russian DPI) throttles
// the underlying TCP after the first stream finishes, so any subsequent stream
// on the same TCP arrives after an idle gap and gets dropped. A fresh TCP per
// request avoids this — at the cost of one REALITY handshake (~200ms) each time.
//
// The strategy holds NO shared session state: multiple callers (TUN tunnel,
// proxy pool, health checker) dial concurrently, and one caller closing its
// conn must never close another's TCP. A prior implementation kept a single
// r.muxSess/r.muxConn on the strategy and closed it on every new Connect, which
// silently tore down a live tunnel whenever a second caller dialed — the root
// cause of the reconnect storm.
func (r *REALITYStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	return r.connect(ctx, target, nil)
}

// connect performs the full REALITY dial + handshake. When wrapFirstFlight is
// non-nil it wraps the raw TCP conn to produce the writer the ClientHello first
// flight is sent through; every other I/O (ServerHello read, ChaCha framing,
// smux) uses the raw TCP conn directly. The seqovl strategy uses this hook to
// prepend a decoy TLS record before the real first flight without duplicating
// the handshake. wrapFirstFlight == nil is the plain REALITY path.
func (r *REALITYStrategy) connect(ctx context.Context, target string, wrapFirstFlight func(net.Conn) net.Conn) (net.Conn, error) {
	// New TCP connection + REALITY handshake + smux negotiation.
	serverAddr := r.manager.GetServerAddr(ctx)
	log.Debug("REALITY: Connecting to %s via %s", target, serverAddr)

	dest, err := r.selectDestination()
	if err != nil {
		return nil, fmt.Errorf("reality: destination selection failed: %w", err)
	}

	log.Debug("REALITY: Using destination %s for cover", dest)

	// Handshake discipline: hold the per-SNI gate for the whole handshake, so
	// concurrency is measured over handshakes actually in flight and the spacing
	// is measured between handshake starts. See handshake_gate.go for the
	// censor behaviour this defends against.
	sniKey, _, err := net.SplitHostPort(dest)
	if err != nil {
		sniKey = dest
	}
	releaseGate, err := r.gate.acquire(ctx, sniKey)
	if err != nil {
		return nil, fmt.Errorf("reality: handshake gate: %w", err)
	}
	defer releaseGate()

	deadline, hasDeadline := ctx.Deadline()
	timeout := 30 * time.Second
	if hasDeadline {
		timeout = time.Until(deadline)
	} else {
		// No caller deadline: still need an absolute time for the hard
		// handshake deadline set below.
		deadline = time.Now().Add(timeout)
	}

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

	// CRITICAL: Set TCP_NODELAY BEFORE TLS handshake to prevent ClientHello segmentation.
	// Without this, Nagle's algorithm may split ClientHello into 2 segments → DPI detects REALITY.
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Hard deadline covering the ENTIRE handshake (ClientHello write, ServerHello
	// read, mux negotiate, smux setup below). Without this, a DPI black-hole that
	// silently drops our bytes after the dial succeeds - exactly the threat
	// REALITY exists to survive - leaves tcpConn.Write()/Read() blocked forever
	// with no deadline. On Android that hang propagates all the way up through
	// the JNI-triggered connect goroutine, so the app never gets a "connected"
	// or "error" callback and appears permanently stuck.
	if err := tcpConn.SetDeadline(deadline); err != nil {
		log.Debug("REALITY: SetDeadline failed: %v", err)
	}

	// Watch ctx: a bare SetDeadline only fires once the deadline elapses, so if
	// the caller cancels ctx early (e.g. user hits disconnect mid-handshake) the
	// blocked Read/Write would otherwise sit until the full timeout instead of
	// waking up immediately. Force-closing the conn is the only way to wake a
	// blocked syscall.Read/Write on cancellation - ctx.Done() alone does not.
	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	go func() {
		select {
		case <-ctx.Done():
			tcpConn.Close()
		case <-handshakeDone:
		}
	}()

	clientHello, err := r.buildClientHello(dest)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: clienthello build failed: %w", err)
	}

	if len(clientHello) >= 5 {
		recordLen := int(clientHello[3])<<8 | int(clientHello[4])
		log.Debug("REALITY: PRE-WRITE len=%d, record_len=%d (bytes[3:5]=%02x%02x)", len(clientHello), recordLen, clientHello[3], clientHello[4])
	}

	// Send ClientHello with SNI-aware fragmentation to bypass stateless DPI.
	// TCP_NODELAY ensures each Write() becomes its own TCP segment.
	//
	// Strategy: split the first fragment so it ends in the MIDDLE of the SNI
	// hostname. No single segment contains the complete SNI string, so DPI
	// doing per-segment SNI matching (Russia's TSPU style) cannot identify it.
	const chelloFragmentSize = 200
	sniHost, _, _ := net.SplitHostPort(dest)
	firstFragEnd := sniFragmentSplitPoint(clientHello, sniHost, chelloFragmentSize)

	// Route the ClientHello first flight through the optional wrapper (seqovl
	// prepends its decoy record here). Plain REALITY writes straight to tcpConn.
	writeConn := net.Conn(tcpConn)
	if wrapFirstFlight != nil {
		writeConn = wrapFirstFlight(tcpConn)
	}

	totalWritten := 0
	fragments := 0

	sendFrag := func(b []byte) error {
		nw, werr := writeConn.Write(b)
		totalWritten += nw
		fragments++
		return werr
	}

	// First fragment: ends mid-SNI (or before extensions if SNI not found)
	if err := sendFrag(clientHello[:firstFragEnd]); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: clienthello send failed: %w", err)
	}
	// Remaining fragments: 200-byte chunks
	for start := firstFragEnd; start < len(clientHello); start += chelloFragmentSize {
		end := start + chelloFragmentSize
		if end > len(clientHello) {
			end = len(clientHello)
		}
		if err := sendFrag(clientHello[start:end]); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("reality: clienthello send failed: %w", err)
		}
	}

	log.Debug("REALITY: ClientHello written=%d bytes (requested=%d, fragments=%d, firstFrag=%d)", totalWritten, len(clientHello), fragments, firstFragEnd)
	log.Debug("REALITY: ClientHello hex: %s", log.HexDump(clientHello, 256))

	serverHello, err := r.readServerHello(tcpConn, timeout)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: serverhello read failed: %w", err)
	}

	log.Debug("REALITY: ServerHello received (%d bytes)", len(serverHello))
	log.Debug("REALITY: ServerHello hex: %s", log.HexDump(serverHello, 128))

	// A HelloRetryRequest here never comes from our own server — it can only be
	// an in-path probe or the real donor. See handleHelloRetryRequest for what
	// we do about it and what we still cannot do.
	if isHelloRetryRequest(serverHello) {
		r.handleHelloRetryRequest(tcpConn, dest)
		tcpConn.Close()
		return nil, errHelloRetryRequest
	}

	if err := r.validateServerHello(serverHello, dest); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: validation failed: %w", err)
	}

	// Negotiate smux mode with the server.
	if err := protocol.WriteDispatch(tcpConn, protocol.TypeMux); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: mux negotiate: %w", err)
	}

	// Wrap TCP in a chacha20-over-TLS-record framing layer so TSPU sees
	// a normal TLS Application Data stream instead of raw smux bytes.
	// Without this, TSPU throttles the connection after ~600 bytes.
	dataConn, err := NewRealityDataConn(tcpConn, r.secret, r.clientPubKey[:], true)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: data conn init: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	newSess, err := smux.Client(dataConn, smuxCfg)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reality: smux client: %w", err)
	}

	stream, err := newSess.OpenStream()
	if err != nil {
		newSess.Close()
		tcpConn.Close()
		return nil, fmt.Errorf("reality: first mux stream: %w", err)
	}

	// Handshake finished successfully: clear the hard handshake deadline before
	// handing the connection off. The stream now outlives this deadline's
	// window (it's a live tunnel, not a bounded handshake), and callers such as
	// pool.PooledRelay already manage their own per-operation deadlines.
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		log.Debug("REALITY: clearing deadline failed: %v", err)
	}

	log.Info("REALITY: Mux session established to %s via %s", target, dest)
	return &realityConn{Conn: stream, sess: newSess, tcpConn: tcpConn}, nil
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

	// The rotator is already seeded from the per-user derived subpool
	// (see NewREALITYStrategy / derivePool), so no Tier 1 forcing is needed here.

	// Try up to 10 times to find a non-recent destination
	for attempt := 0; attempt < 10; attempt++ {
		// Use SNI rotator over the derived subpool
		sni := r.sniRotator.Next()

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

	// Every donor is inside its cooldown window. Pick the least recently used
	// one rather than a fixed fallback: the previous code returned
	// getRussianSNIsStatic()[0] here, so under any sustained load — which with
	// a four-domain donor pool and a fresh handshake per CONNECT arrives fast —
	// every dial past the first few piled onto yandex.ru. That is precisely the
	// burst pattern the per-SNI freeze looks for, manufactured by us.
	sni := r.leastRecentlyUsedDestLocked()
	r.recentDests[sni] = time.Now()
	return net.JoinHostPort(sni, "443"), nil
}

// leastRecentlyUsedDestLocked returns the donor SNI whose last use is furthest
// in the past. Callers must hold destMu.
func (r *REALITYStrategy) leastRecentlyUsedDestLocked() string {
	pool := r.destPool
	if len(pool) == 0 {
		pool = getRussianSNIsStatic()
	}

	var (
		best    string
		bestUse time.Time
	)
	for _, sni := range pool {
		lastUse, used := r.recentDests[sni]
		if !used {
			// Never used at all: nothing can be less recent than that.
			return sni
		}
		if best == "" || lastUse.Before(bestUse) {
			best, bestUse = sni, lastUse
		}
	}
	return best
}

// derivePool derives a deterministic per-user subpool of size n from globalPool.
//
// Blast-radius-min T2: a sub-key is derived from the user's secret via
// HKDF-SHA256 (salt="tiredvpn-rotation-v1", info="subpool"). The global pool is
// then sorted by HMAC-SHA256(K_sub, domain) and the top-n entries are returned.
// This gives each user a stable, secret-specific donor set: domains used by one
// user reveal nothing about another user's set.
func derivePool(globalPool []string, secret []byte, n int) []string {
	if len(globalPool) == 0 {
		return nil
	}

	// K_sub = HKDF-SHA256(secret, salt, info)
	kSub := make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, []byte("tiredvpn-rotation-v1"), []byte("subpool"))
	if _, err := io.ReadFull(kdf, kSub); err != nil {
		// HKDF over SHA-256 never fails for a 32-byte read, but stay safe.
		return globalPool
	}

	// Copy so we don't mutate the caller's slice ordering.
	pool := make([]string, len(globalPool))
	copy(pool, globalPool)

	sort.SliceStable(pool, func(i, j int) bool {
		return hmacScore(kSub, pool[i]) < hmacScore(kSub, pool[j])
	})

	if n > len(pool) {
		n = len(pool)
	}
	return pool[:n]
}

// hmacScore returns the first 8 bytes of HMAC-SHA256(key, domain) as a uint64.
func hmacScore(key []byte, domain string) uint64 {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	sum := mac.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// getRussianSNIsStatic is the package-level fallback Tier 1 list, used during
// construction (before a receiver exists) and as a last-resort destination.
func getRussianSNIsStatic() []string {
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
// Uses uTLS for a realistic browser fingerprint + hides REALITY data in padding extension.
// The profile comes from configuration (see SetFingerprint); it is fixed for the
// lifetime of the strategy, never rotated per connection.
func (r *REALITYStrategy) buildClientHello(dest string) ([]byte, error) {
	log.Info("REALITY-BUILD: Starting buildClientHello for %s", dest)

	// Extract hostname from dest
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}

	fp, _ := customtls.LookupFingerprint(r.fingerprint)

	config := &customtls.Config{
		ServerName:         host,
		Fingerprint:        r.fingerprint,
		ALPN:               []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
		PaddingLen:         customtls.MinPaddingSize, // 256 bytes for REALITY + random
	}

	clientHello, err := customtls.BuildClientHelloBytes(config, fp)
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

// readServerHello reads the ServerHello response.
//
// The caller (Connect) already sets a single absolute SetDeadline() covering
// the whole handshake, so this does not set its own read deadline - doing so
// here used to both extend the deadline past the caller's original timeout
// and then clear it entirely on return (SetReadDeadline(zero)), which left
// every subsequent read in the handshake (mux negotiate, smux setup) with no
// deadline at all.
func (r *REALITYStrategy) readServerHello(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = timeout // deadline is owned by Connect(); kept for API stability

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

	// Scan for padding extension (0x00 0x15). The V1 wire format has no magic
	// marker — the padding starts directly with [PubKey:32][AuthToken:32], so we
	// extract any candidate and let VerifyServerAuth below confirm it.
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

			// Extract REALITY extension from start of padding (no magic check).
			paddingData := serverHello[extDataStart : extDataStart+extLen]
			ext, err := customtls.ExtractREALITYFromPadding(paddingData)
			if err == nil && customtls.VerifyServerAuth(r.secret, r.clientPubKey[:], ext.AuthToken) {
				serverExt = ext
				break
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
	var b [8]byte
	cryptorand.Read(b[:]) //nolint:errcheck // crypto/rand.Read never fails on Linux
	return int(uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24) % max
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

// sniFragmentSplitPoint returns the byte offset where the first ClientHello
// fragment should end, chosen to fall in the middle of the SNI hostname.
// Searching only within the TLS extensions section avoids false positives in
// random bytes (ClientHello.Random, session ID, key share values).
// If the SNI is not found, returns defaultSize as a safe fallback.
//
// Uses proper TLS extension-type walking (finds ext type 0x0000) rather than raw
// byte search to avoid false positives inside key_share data (kyber768, ~1152 bytes
// of semi-random bytes that can contain any short hostname as a substring).
func sniFragmentSplitPoint(clientHello []byte, sniHost string, defaultSize int) int {
	if len(sniHost) < 2 {
		return defaultSize
	}
	nameStart, nameLen, ok := walkSNIHostname(clientHello)
	if !ok {
		log.Debug("REALITY: SNI ext not found, using default fragment size %d", defaultSize)
		return defaultSize
	}
	mid := nameStart + nameLen/2
	log.Debug("REALITY: SNI ext name at %d len=%d, splitting at mid=%d", nameStart, nameLen, mid)
	return mid
}
