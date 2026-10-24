package strategy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// NaivePaddingMode defines the padding strategy (inspired by NaiveProxy)
type NaivePaddingMode int

const (
	// NaivePaddingMinimal adds minimal overhead (5-10% padding, optimized for speed)
	NaivePaddingMinimal NaivePaddingMode = iota
	// NaivePaddingStandard adds balanced padding (15-25% overhead, good balance)
	NaivePaddingStandard
	// NaivePaddingParanoid adds aggressive padding (30-50% overhead, maximum security)
	NaivePaddingParanoid
)

// String returns the string representation of padding mode
func (m NaivePaddingMode) String() string {
	switch m {
	case NaivePaddingMinimal:
		return "Minimal"
	case NaivePaddingStandard:
		return "Standard"
	case NaivePaddingParanoid:
		return "Paranoid"
	default:
		return "Unknown"
	}
}

// HTTP2StegoStrategy hides VPN data within legitimate HTTP/2 frames
// Uses custom headers, DATA frames with steganographic encoding
type HTTP2StegoStrategy struct {
	manager     *Manager // Reference to Manager for IPv6/IPv4 support
	secret      []byte
	coverHost   string // Host to impersonate (e.g., "www.googleapis.com")
	paddingMode NaivePaddingMode

	// ECH configuration (optional)
	echEnabled    bool
	echConfigList []byte
	echPublicName string
}

// NewHTTP2StegoStrategy creates a new HTTP/2 steganography strategy
// manager is required for IPv6/IPv4 transport layer support
func NewHTTP2StegoStrategy(manager *Manager, secret []byte, coverHost string) *HTTP2StegoStrategy {
	return &HTTP2StegoStrategy{
		manager:     manager,
		secret:      secret,
		coverHost:   coverHost,
		paddingMode: NaivePaddingMinimal, // Default to minimal for low latency
	}
}

// NewHTTP2StegoStrategyWithPadding creates a strategy with specific padding mode
// manager is required for IPv6/IPv4 transport layer support
func NewHTTP2StegoStrategyWithPadding(manager *Manager, secret []byte, coverHost string, mode NaivePaddingMode) *HTTP2StegoStrategy {
	return &HTTP2StegoStrategy{
		manager:     manager,
		secret:      secret,
		coverHost:   coverHost,
		paddingMode: mode,
	}
}

// NewHTTP2StegoStrategyWithECH creates a strategy with ECH support
// manager is required for IPv6/IPv4 transport layer support
func NewHTTP2StegoStrategyWithECH(manager *Manager, secret []byte, coverHost string, echConfigList []byte, echPublicName string) *HTTP2StegoStrategy {
	return &HTTP2StegoStrategy{
		manager:       manager,
		secret:        secret,
		coverHost:     coverHost,
		paddingMode:   NaivePaddingStandard,
		echEnabled:    len(echConfigList) > 0,
		echConfigList: echConfigList,
		echPublicName: echPublicName,
	}
}

// SetECH enables ECH for this strategy
func (s *HTTP2StegoStrategy) SetECH(configList []byte, publicName string) {
	s.echEnabled = len(configList) > 0
	s.echConfigList = configList
	s.echPublicName = publicName
}

func (s *HTTP2StegoStrategy) Name() string {
	return "HTTP/2 Steganography"
}

func (s *HTTP2StegoStrategy) ID() string {
	return "http2_stego"
}

func (s *HTTP2StegoStrategy) Priority() int {
	return 7 // Medium-high priority (works in SOCKS5 mode)
}

func (s *HTTP2StegoStrategy) Description() string {
	return "Hides tunnel data within legitimate HTTP/2 frames with NaiveProxy-style padding (" + s.paddingMode.String() + " mode)"
}

func (s *HTTP2StegoStrategy) RequiresServer() bool {
	return true
}

func (s *HTTP2StegoStrategy) Probe(ctx context.Context, target string) error {
	// Use protected dialer to avoid VPN routing loop on Android
	protectedDialer := &protect.ProtectDialer{
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	}
	conn, err := protectedDialer.Dial("tcp", target)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *HTTP2StegoStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := s.manager.GetServerAddr(ctx)
	secret := dialSecret(ctx, s.secret)

	// Cover host doubles as the TLS SNI and the HTTP/2 :authority. Picking it per
	// connection from the shared whitelist (rather than a build-time constant or
	// an hour-of-day index that moves every client at once) keeps the SNI a
	// donor TSPU does not IP-range-check against us, and keeps the two views of
	// the same name - the cleartext SNI and the encrypted :authority - agreeing.
	// A caller that pinned a cover host in config keeps it.
	coverHost := s.coverHost
	if coverHost == "" {
		coverHost = stegoCoverRotator.Next()
	}
	log.Debug("HTTP/2 Stego: Using server address: %s (cover %s)", serverAddr, coverHost)

	// Establish TLS connection with standard ALPN.
	// Protocol type is sent as the first encrypted byte after handshake,
	// so DPI sees no "tired-*" fingerprint in the ClientHello.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         coverHost,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: s.manager.TLSSessionCache(), // resume across reconnects
	}

	var conn *tls.Conn
	var err error

	// Use context-aware dialing with socket protection (Android)
	protectedDialer := &protect.ProtectDialer{
		Dialer: &net.Dialer{},
	}

	// Use ECH if enabled
	if s.echEnabled && len(s.echConfigList) > 0 {
		tlsConfig.MinVersion = tls.VersionTLS13 // ECH requires TLS 1.3
		tlsConfig.EncryptedClientHelloConfigList = s.echConfigList

		tcpConn, dialErr := protectedDialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}

		conn = tls.Client(tcpConn, tlsConfig)
		if err = conn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			// Fallback to non-ECH on failure
			tlsConfig.EncryptedClientHelloConfigList = nil
			tcpConn2, dialErr := protectedDialer.DialContext(ctx, "tcp", serverAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			conn = tls.Client(tcpConn2, tlsConfig)
			if err = conn.HandshakeContext(ctx); err != nil {
				tcpConn2.Close()
				return nil, err
			}
		}
	} else {
		tcpConn, dialErr := protectedDialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}
		conn = tls.Client(tcpConn, tlsConfig)
		if err = conn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, err
		}
	}

	// Verify HTTP/2 was negotiated
	alpn := conn.ConnectionState().NegotiatedProtocol
	if alpn != "h2" && alpn != "http/1.1" {
		conn.Close()
		return nil, errors.New("HTTP/2 not negotiated")
	}

	// Send protocol discriminator so server can route without ALPN fingerprints
	if err := protocol.WriteDispatch(conn, protocol.TypeStego); err != nil {
		conn.Close()
		return nil, fmt.Errorf("stego dispatch: %w", err)
	}

	// Capture the TLS session exporter for auth-token binding (S22) BEFORE the
	// kTLS handover — once the kernel owns the socket the *tls.Conn no longer
	// reflects live keys.
	ekm, err := sessionExporterKey(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("stego: export keying material: %w", err)
	}

	// Try to enable kTLS for kernel TLS offload (reduces CPU usage)
	var finalConn net.Conn = conn
	if ktlsConn := ktls.Enable(conn); ktlsConn != nil {
		log.Debug("kTLS enabled for HTTP/2 Stego connection")
		finalConn = ktlsConn
	}

	// Create steganographic connection with padding mode
	stegoConn := NewHTTP2StegoConn(finalConn, secret, true, s.paddingMode, ekm)
	stegoConn.coverHost = coverHost // :authority tracks the SNI we opened with

	// Perform initial handshake, bounded by the caller's context so a
	// non-responding server can't hold this strategy past the strategy
	// manager's own per-attempt timeout (waitForServerAck used a hardcoded
	// 30s deadline regardless of ctx, which on Android - connectTimeout=10s -
	// let one stalled HTTP/2-stego attempt block the entire sequential
	// strategy race for up to 30s).
	if err := stegoConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return stegoConn, nil
}

// HTTP2StegoConn implements net.Conn with HTTP/2 steganography
type HTTP2StegoConn struct {
	net.Conn

	// ownerWD is the write deadline the conn's owner last set; wdMu guards
	// it apart from mu, which a blocked write holds, together with every
	// change of the socket's write deadline. closing is set by Close, which
	// owns the write deadline from then on.
	wdMu    sync.Mutex
	ownerWD time.Time
	closing bool

	// writeFailed is set once a write on the conn failed (stegoWriter).
	writeFailed atomic.Bool

	// lastWrite is a stegoMono stamp of the last frame the conn put on the
	// wire, whoever wrote it; lastOwnerWrite of the last data its owner
	// wrote (Write). Zero before the first.
	lastWrite      atomic.Int64
	lastOwnerWrite atomic.Int64

	// closed is closed by Close; KeepAlive ends with it.
	closed    chan struct{}
	closeOnce sync.Once

	secret      []byte
	isClient    bool
	paddingMode NaivePaddingMode
	coverHost   string // HTTP/2 :authority; set to the SNI so the two agree

	// ekm is the TLS session exporter the auth token is bound to (S22). It is
	// captured from the *tls.Conn before any kTLS offload and set via the
	// constructor. nil only for the non-TLS test pipes, where both ends agree
	// on nil; a live TLS session must always carry its exporter here.
	ekm []byte

	// HTTP/2 framing
	framer *http2.Framer

	// HPACK encoder/decoder
	hpackBuf bytes.Buffer
	hpackEnc *hpack.Encoder
	hpackDec *hpack.Decoder

	// Stream management
	nextStreamID     uint32
	persistentStream uint32 // For TUN mode - reuse same stream
	mu               sync.Mutex

	// Read buffer for reassembling data
	readBuf bytes.Buffer

	// Covert channel state
	methodCounter uint32
	paddingKey    []byte

	// Fast path optimization for TUN mode
	tunMode       bool         // Enable optimized TUN mode
	writeBuf      bytes.Buffer // Buffer for batching small writes
	lastWriteTime time.Time    // Last write timestamp for batch timeout
	batchTimer    *time.Timer  // Timer for flushing batched writes

	// HTTP/2 flow-control (atomic, no mutex needed)
	// recvConsumed: DATA bytes consumed by Read but not yet acknowledged via WINDOW_UPDATE.
	// Flushed lazily at the start of each Write to prevent peer stalling after 64 KB.
	recvConsumed int64
}

// NewHTTP2StegoConn creates a new steganographic HTTP/2 connection.
//
// ekm is the TLS session exporter the auth token is bound to (S22). Callers over
// a real TLS session must capture it from the *tls.Conn before any kTLS offload
// (see sessionExporterKey) and pass it here; the non-TLS test pipes pass nil on
// both ends.
func NewHTTP2StegoConn(conn net.Conn, secret []byte, isClient bool, paddingMode NaivePaddingMode, ekm []byte) *HTTP2StegoConn {
	sc := &HTTP2StegoConn{
		Conn:        conn,
		secret:      secret,
		isClient:    isClient,
		paddingMode: paddingMode,
		ekm:         ekm,
		closed:      make(chan struct{}),
	}

	// Initialize HTTP/2 framer
	sc.framer = http2.NewFramer(stegoWriter{sc}, conn)
	sc.framer.AllowIllegalWrites = true
	sc.framer.AllowIllegalReads = true

	// Initialize HPACK
	sc.hpackEnc = hpack.NewEncoder(&sc.hpackBuf)
	sc.hpackDec = hpack.NewDecoder(4096, nil)

	// Client starts with odd stream IDs
	if isClient {
		sc.nextStreamID = 1
		// Rate limiter disabled - was causing 80 KB/s bottleneck
	} else {
		sc.nextStreamID = 2
	}

	// Derive padding key from secret
	sc.paddingKey = deriveKey(secret, "padding-key")

	// Enable TUN mode optimizations (detect based on padding mode)
	// Minimal padding = high performance TUN mode
	sc.tunMode = (paddingMode == NaivePaddingMinimal)

	// Allocate persistent stream for TUN mode
	if sc.tunMode {
		sc.persistentStream = sc.allocateStreamID()
	}

	return sc
}

// Handshake performs HTTP/2 connection preface and initial exchange
func (sc *HTTP2StegoConn) Handshake() error {
	return sc.HandshakeContext(context.Background())
}

// HandshakeContext is Handshake with a caller-supplied deadline. If ctx has a
// deadline earlier than the default 30s server-ack wait, that earlier
// deadline wins - so a strategy manager racing multiple strategies with a
// shorter per-attempt timeout (e.g. Android's connectTimeout) can actually
// cut this strategy off instead of it silently running past the race.
func (sc *HTTP2StegoConn) HandshakeContext(ctx context.Context) error {
	if sc.isClient {
		// Send HTTP/2 connection preface
		_, err := sc.Conn.Write([]byte(http2.ClientPreface))
		if err != nil {
			return err
		}

		// Send SETTINGS frame with a large initial window so downloads over
		// high-RTT links are not capped by the default 64 KB flow-control window.
		if err := sc.framer.WriteSettings(stegoInitialSettings()...); err != nil {
			return err
		}

		// Send initial covert handshake in HEADERS
		if err := sc.sendCovertHandshake(); err != nil {
			return err
		}

		// Wait for server response
		return sc.waitForServerAck(ctx)
	}

	// Server side handshake
	return sc.handleClientHandshake()
}

// sendCovertHandshake sends authentication via HEADERS with custom headers
func (sc *HTTP2StegoConn) sendCovertHandshake() error {
	streamID := sc.allocateStreamID()

	// Generate auth token bound to this TLS session (S22).
	authToken := generateAuthTokenBound(sc.secret, sc.ekm)

	// Encode in HEADERS
	sc.hpackBuf.Reset()

	// Required pseudo-headers for valid HTTP/2
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: "/grpc.health.v1.Health/Check"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: sc.authority()})

	// Standard headers
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "grpc-go/1.60.0"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})

	// Covert auth in custom headers (looks like API tokens)
	sc.hpackEnc.WriteField(hpack.HeaderField{
		Name:  "x-goog-api-key",
		Value: encodeToHex(authToken[:16]),
	})
	sc.hpackEnc.WriteField(hpack.HeaderField{
		Name:  "x-goog-request-id",
		Value: encodeToHex(authToken[16:]),
	})

	return sc.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: sc.hpackBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

// waitForServerAck waits for server acknowledgment. The read deadline is
// 30s by default, but shrinks to ctx's deadline when the caller asked for
// less - see HandshakeContext.
func (sc *HTTP2StegoConn) waitForServerAck(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	sc.SetReadDeadline(deadline)
	defer sc.SetReadDeadline(time.Time{})

	for {
		frame, err := sc.framer.ReadFrame()
		if err != nil {
			return err
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				// Send SETTINGS ACK
				sc.framer.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			// Server ack encoded in HEADERS response
			if sc.verifyServerAckHeaders(f) {
				return nil
			}
		case *http2.DataFrame:
			// Server might send ack in DATA
			if sc.verifyServerAckData(f) {
				return nil
			}
		case *http2.WindowUpdateFrame:
			// Ignore window updates
			continue
		}
	}
}

// verifyServerAckHeaders checks if HEADERS frame contains valid server ack
func (sc *HTTP2StegoConn) verifyServerAckHeaders(f *http2.HeadersFrame) bool {
	var foundAck bool

	sc.hpackDec.SetEmitFunc(func(hf hpack.HeaderField) {
		if hf.Name == "x-goog-correlation-id" {
			raw := decodeFromHex(hf.Value)
			if len(raw) >= stegoAckNonceLen+16 {
				nonce := raw[:stegoAckNonceLen]
				proof := raw[stegoAckNonceLen : stegoAckNonceLen+16]
				if hmac.Equal(proof, serverAckMaterial(sc.secret, nonce)[:16]) {
					foundAck = true
				}
			}
		}
	})

	sc.hpackDec.Write(f.HeaderBlockFragment())
	return foundAck
}

// verifyServerAckData checks DATA frame for ack magic
func (sc *HTTP2StegoConn) verifyServerAckData(f *http2.DataFrame) bool {
	data := f.Data()
	if len(data) >= stegoAckNonceLen+8 {
		nonce := data[:stegoAckNonceLen]
		proof := data[stegoAckNonceLen : stegoAckNonceLen+8]
		return hmac.Equal(proof, serverAckMaterial(sc.secret, nonce)[:8])
	}
	return false
}

// handleClientHandshake processes client handshake (server side)
func (sc *HTTP2StegoConn) handleClientHandshake() error {
	// Read connection preface
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(sc.Conn, preface); err != nil {
		return err
	}

	if string(preface) != http2.ClientPreface {
		return errors.New("invalid HTTP/2 preface")
	}

	// Send server SETTINGS with a large initial window (see client side).
	if err := sc.framer.WriteSettings(stegoInitialSettings()...); err != nil {
		return err
	}

	// Read and verify client auth
	sc.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer sc.SetReadDeadline(time.Time{})

	for {
		frame, err := sc.framer.ReadFrame()
		if err != nil {
			return err
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				sc.framer.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			// Extract and verify auth from headers
			if sc.verifyClientAuth(f) {
				return sc.sendServerAck(f.StreamID)
			}
			return errors.New("authentication failed")
		}
	}
}

// verifyClientAuth verifies client authentication from HEADERS
func (sc *HTTP2StegoConn) verifyClientAuth(f *http2.HeadersFrame) bool {
	var apiKey, requestID string

	sc.hpackDec.SetEmitFunc(func(hf hpack.HeaderField) {
		switch hf.Name {
		case "x-goog-api-key":
			apiKey = hf.Value
		case "x-goog-request-id":
			requestID = hf.Value
		}
	})

	sc.hpackDec.Write(f.HeaderBlockFragment())

	if apiKey == "" || requestID == "" {
		return false
	}

	// Reconstruct auth token
	apiKeyBytes := decodeFromHex(apiKey)
	requestIDBytes := decodeFromHex(requestID)

	if len(apiKeyBytes) < 16 || len(requestIDBytes) < 16 {
		return false
	}

	receivedToken := append(apiKeyBytes[:16], requestIDBytes[:16]...)

	return verifyAuthTokenBound(sc.secret, sc.ekm, receivedToken)
}

// sendServerAck sends acknowledgment to client
func (sc *HTTP2StegoConn) sendServerAck(streamID uint32) error {
	// Send HEADERS response with ack
	sc.hpackBuf.Reset()

	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})

	// Bind the ack to a fresh nonce: value = hex(nonce || proof). A static
	// deriveKey(secret,"server-ack") was one proof for the life of the secret.
	var ackNonce [stegoAckNonceLen]byte
	if _, err := rand.Read(ackNonce[:]); err != nil {
		return err
	}
	ackVal := make([]byte, 0, stegoAckNonceLen+16)
	ackVal = append(ackVal, ackNonce[:]...)
	ackVal = append(ackVal, serverAckMaterial(sc.secret, ackNonce[:])[:16]...)
	sc.hpackEnc.WriteField(hpack.HeaderField{
		Name:  "x-goog-correlation-id",
		Value: encodeToHex(ackVal),
	})

	return sc.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: sc.hpackBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

// stegoInitialWindow is the HTTP/2 flow-control window we advertise (4 MB).
// On a 150 ms RTT link the default 64 KB window caps throughput at ~3.4 Mbps;
// 4 MB lifts that ceiling to well above the 80 Mbps link rate (BDP at 150 ms,
// 80 Mbps is ~1.5 MB, so 4 MB leaves comfortable headroom).
const stegoInitialWindow = 4 * 1024 * 1024

// windowUpdateThreshold is how many consumed (read) bytes may accumulate before
// we proactively return WINDOW_UPDATE credit to the peer, instead of waiting for
// the next Write. Keeping it well below the window prevents download stalls.
const windowUpdateThreshold = 256 * 1024

// stegoInitialSettings returns the SETTINGS we send during the handshake.
func stegoInitialSettings() []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingInitialWindowSize, Val: stegoInitialWindow},
	}
}

// flushWindowUpdate sends accumulated WINDOW_UPDATE credits back to the peer.
// Must be called while sc.mu is held (framer is not concurrent-safe for writes).
func (sc *HTTP2StegoConn) flushWindowUpdate() {
	consumed := atomic.SwapInt64(&sc.recvConsumed, 0)
	if consumed <= 0 {
		return
	}
	inc := uint32(consumed)
	sc.framer.WriteWindowUpdate(0, inc) // connection-level
	if sc.persistentStream != 0 {
		sc.framer.WriteWindowUpdate(sc.persistentStream, inc) // stream-level
	}
}

// proactiveFlushWindowUpdate flushes WINDOW_UPDATE credit from the read path when
// accumulated consumed bytes exceed windowUpdateThreshold. Called by Read so that
// download-heavy streams (where Write is rare) keep the peer's send window open.
// Acquires sc.mu itself since the caller does not hold it.
func (sc *HTTP2StegoConn) proactiveFlushWindowUpdate() {
	if atomic.LoadInt64(&sc.recvConsumed) < windowUpdateThreshold {
		return
	}
	sc.mu.Lock()
	sc.readPathWrite(sc.flushWindowUpdate)
	sc.mu.Unlock()
}

// stegoReadPathWriteTimeout bounds a write the read path makes on its own:
// WINDOW_UPDATE credit, a SETTINGS ack. Atomic so tests in other packages
// can scale it (SetStegoReadPathWriteTimeout).
var stegoReadPathWriteTimeoutNs atomic.Int64

func init() { stegoReadPathWriteTimeoutNs.Store(int64(10 * time.Second)) }

func stegoReadPathWriteTimeout() time.Duration {
	return time.Duration(stegoReadPathWriteTimeoutNs.Load())
}

// SetStegoReadPathWriteTimeout replaces the read path's write deadline for
// a test and returns the old one.
func SetStegoReadPathWriteTimeout(d time.Duration) time.Duration {
	return time.Duration(stegoReadPathWriteTimeoutNs.Swap(int64(d)))
}

// SetWriteDeadline records the owner's write deadline and sets it: the
// conn's own writes (readPathWrite, Close) put it back when they are done.
// The record and the socket change together under wdMu, so a restore can
// never put back a deadline the owner has since replaced (P3-1 of the
// round-9 review).
func (sc *HTTP2StegoConn) SetWriteDeadline(t time.Time) error {
	sc.wdMu.Lock()
	defer sc.wdMu.Unlock()
	sc.ownerWD = t
	return sc.Conn.SetWriteDeadline(t)
}

// SetDeadline is SetWriteDeadline and SetReadDeadline together, recorded the
// same way.
func (sc *HTTP2StegoConn) SetDeadline(t time.Time) error {
	sc.wdMu.Lock()
	defer sc.wdMu.Unlock()
	sc.ownerWD = t
	return sc.Conn.SetDeadline(t)
}

// stegoRestoreHook, when a test sets it, runs in restoreOwnerWD: at "enter"
// before wdMu is taken, at "apply" with wdMu held, before the deadline is
// put back. Nil in production.
var stegoRestoreHook atomic.Pointer[func(at string)]

// restoreOwnerWD puts back the write deadline the conn's owner last set,
// zero for an owner that sets none. Once Close has bounded the conn's last
// writes it leaves that bound alone: putting back an owner's zero there let
// the GOAWAY wait forever on a peer that stopped reading (P3-2 of the
// round-9 review).
func (sc *HTTP2StegoConn) restoreOwnerWD() {
	if f := stegoRestoreHook.Load(); f != nil {
		(*f)("enter")
	}
	sc.wdMu.Lock()
	defer sc.wdMu.Unlock()
	if sc.closing {
		return
	}
	if f := stegoRestoreHook.Load(); f != nil {
		(*f)("apply")
	}
	_ = sc.Conn.SetWriteDeadline(sc.ownerWD)
}

// stegoWriter is the framer's writer: the conn's writes, with a failed one
// recorded for Close.
type stegoWriter struct{ sc *HTTP2StegoConn }

func (w stegoWriter) Write(p []byte) (int, error) {
	n, err := w.sc.Conn.Write(p)
	if err != nil {
		w.sc.writeFailed.Store(true)
	} else {
		w.sc.lastWrite.Store(stegoMono())
	}
	return n, err
}

// stegoMonoBase anchors stegoMono to the monotonic clock.
var stegoMonoBase = time.Now()

// stegoMono is a monotonic stamp, in nanoseconds since stegoMonoBase; never 0.
func stegoMono() int64 { return int64(time.Since(stegoMonoBase)) + 1 }

// SinceOwnerWrite is how long ago the conn's owner last wrote data on it,
// and false before the first time. The conn's own frames - flow-control
// credit, a keepalive - do not count.
func (sc *HTTP2StegoConn) SinceOwnerWrite() (time.Duration, bool) {
	at := sc.lastOwnerWrite.Load()
	if at == 0 {
		return 0, false
	}
	return time.Duration(stegoMono() - at), true
}

// KeepAlive feeds the peer's read deadline on a conn whose owner may write
// nothing for minutes: a relay's upstream leg carrying a sparse download,
// whose exit closes a connection after 60 s without a frame. Whenever
// nothing has gone out on the conn for quiet() - redrawn after each one - it
// writes an empty stego DATA frame: no payload, cover as on any frame. The
// frame does not touch the byte stream the owner writes, so it needs no
// frame boundary of the owner's; an exit of any version reads it, which
// feeds its deadline, and finds nothing to deliver.
//
// Not before the owner's first write: the exit takes the first payload on a
// connection as the tunnel's setup, and an empty one would be a broken
// setup. alive, when set, is asked before each keepalive: while it says
// the owner's client is gone, none goes, and the exit's deadline ends the
// leg as before. sent, when set, is told of each keepalive written.
//
// It returns when the conn is closed or a keepalive cannot be written.
func (sc *HTTP2StegoConn) KeepAlive(quiet func() time.Duration, alive func() bool, sent func()) {
	q := quiet()
	timer := time.NewTimer(q)
	defer timer.Stop()
	for {
		select {
		case <-sc.closed:
			return
		case <-timer.C:
		}
		silent := time.Duration(stegoMono() - sc.lastWrite.Load())
		if silent >= q {
			if sc.lastOwnerWrite.Load() != 0 && (alive == nil || alive()) {
				if err := sc.writeKeepalive(); err != nil {
					return
				}
				if sent != nil {
					sent()
				}
			}
			q = quiet()
			silent = 0
		}
		timer.Reset(max(q-silent, 10*time.Millisecond))
	}
}

// writeKeepalive writes an empty stego DATA frame, under a write deadline
// of its own like the read path's writes (readPathWrite).
func (sc *HTTP2StegoConn) writeKeepalive() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var err error
	sc.readPathWrite(func() {
		if sc.tunMode {
			_, err = sc.writeViaDataFast(nil)
		} else {
			_, err = sc.writeViaData(nil)
		}
	})
	return err
}

// readPathWrite runs write, a write the read path makes on its own, under a
// deadline of its own. The caller's last deadline belongs to the caller's
// last write and may long have passed: a one-way download writes nothing
// else, and a WINDOW_UPDATE flush that hit a stale deadline failed, which
// tls.Conn makes permanent - every later write on the conn failed and the
// tunnel died (P2-1 of the round-7 review).
//
// The owner's deadline is put back afterwards. Left at now+10s it broke the
// owners that set none - the relay's TUN bridge and its proxy relays write
// upstream without a deadline - and the first write up more than 10 s after
// a download failed for good (P1-1 of the round-8 review). Must be called
// with sc.mu held.
func (sc *HTTP2StegoConn) readPathWrite(write func()) {
	sc.wdMu.Lock()
	if !sc.closing {
		_ = sc.Conn.SetWriteDeadline(time.Now().Add(stegoReadPathWriteTimeout()))
	}
	sc.wdMu.Unlock()
	write()
	sc.restoreOwnerWD()
}

// Write sends data using various steganographic channels
func (sc *HTTP2StegoConn) Write(p []byte) (int, error) {
	// Fast path for TUN mode - optimized for low latency
	if sc.tunMode {
		return sc.writeFast(p)
	}

	// Standard path with full steganography
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.flushWindowUpdate()

	written := 0

	for written < len(p) {
		remaining := len(p) - written
		method := sc.selectCovertMethod()

		var n int
		var err error

		switch method {
		case covertMethodHeaders:
			n, err = sc.writeViaHeaders(p[written:])
		case covertMethodData:
			n, err = sc.writeViaData(p[written:])
		case covertMethodPaddedData:
			n, err = sc.writeViaPaddedData(p[written:])
		default:
			n, err = sc.writeViaData(p[written:])
		}

		if err != nil {
			return written, err
		}

		// Minimum progress to avoid infinite loop
		if n == 0 {
			n = minInt(remaining, 100)
		}
		written += n
	}
	if written > 0 {
		sc.lastOwnerWrite.Store(stegoMono())
	}

	return written, nil
}

// writeFast is optimized fast path for TUN mode (low latency)
func (sc *HTTP2StegoConn) writeFast(p []byte) (int, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.flushWindowUpdate()
	n, err := sc.writeViaDataFast(p)
	if n > 0 {
		sc.lastOwnerWrite.Store(stegoMono())
	}
	return n, err
}

type covertMethod int

const (
	covertMethodHeaders covertMethod = iota
	covertMethodData
	covertMethodPaddedData
)

// selectCovertMethod chooses which steganographic channel to use
func (sc *HTTP2StegoConn) selectCovertMethod() covertMethod {
	sc.methodCounter++

	// Use only DATA frame methods - server doesn't extract from headers yet
	// Rotate between padded and raw data for traffic analysis resistance
	if sc.methodCounter%2 == 0 {
		return covertMethodPaddedData
	}
	return covertMethodData
}

// writeViaHeaders hides data in custom HTTP headers.
//
// Currently unreachable: selectCovertMethod never returns covertMethodHeaders
// (the server does not yet extract covert data from headers), so the
// covertMethodHeaders dispatch case is dead. Kept for when header-channel
// extraction lands on the server side; do not remove without also wiring up
// selectCovertMethod and the server-side reader.
func (sc *HTTP2StegoConn) writeViaHeaders(data []byte) (int, error) {
	streamID := sc.allocateStreamID()

	// Encode up to 100 bytes in header values
	chunkSize := minInt(len(data), 100)

	sc.hpackBuf.Reset()

	// Required pseudo-headers
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: "/api/v1/telemetry"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: sc.authority()})

	// Standard headers
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "grpc-go/1.60.0"})

	// Covert data in custom headers (looks like API parameters)
	covertHeaders := []struct {
		name   string
		maxLen int
	}{
		{"x-request-id", 32},
		{"x-correlation-id", 32},
		{"x-trace-id", 32},
		{"x-span-id", 16},
	}

	offset := 0
	for _, h := range covertHeaders {
		if offset >= chunkSize {
			break
		}

		headerLen := minInt(chunkSize-offset, h.maxLen/2) // Hex doubles size
		headerValue := encodeToHex(data[offset : offset+headerLen])
		sc.hpackEnc.WriteField(hpack.HeaderField{Name: h.name, Value: headerValue})
		offset += headerLen
	}

	if err := sc.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: sc.hpackBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return 0, err
	}

	return offset, nil
}

// The stego DATA-frame marker, version 2.
//
// v1 opened every covert DATA frame with the ASCII literal "TIRD". A literal at
// offset 0 of every DATA payload is a constant that anything seeing the HTTP/2
// framing (our own server, a TLS-terminating middlebox, a CDN we tunnel
// through) reads without decrypting a session key. Real gRPC - which this is
// dressed as - opens with a 1-byte compressed flag and a 4-byte length, not a
// four-byte tag repeated on every frame.
//
// v2 replaces the literal with [nonce][marker] where marker is HKDF(secret,
// nonce) of a length ALSO derived from (secret, nonce). The reader holds the one
// authenticated secret for the connection and always has the full DATA-frame
// payload in hand (the framer delivers a whole frame), so it recomputes the
// marker and checks the prefix; a foreign or cover DATA frame simply fails the
// match and is dropped, exactly as a non-"TIRD" frame was dropped before. The
// nonce is fresh per frame, so no two frames - and no two connections - open
// with the same bytes.
//
// There is no transitional mode. A 1.10.x client opens with "TIRD", the frame
// fails the marker check, and its payload is dropped.
const (
	// stegoNonceLen is the per-frame nonce prefix. 8 bytes keeps the per-frame
	// overhead small while making a repeated opening prefix astronomically
	// unlikely.
	stegoNonceLen = 8

	// stegoMarkerMinLen / stegoMarkerSpan bound the marker length. The length is
	// derived from (secret, nonce), so it is not a field on the wire; the marker
	// is flat over [8,24). Like the confusion marker, there is no measured
	// population of "real" opaque-body lengths to check that shape against - the
	// marker sits inside an HTTP/2 DATA payload that also carries our own cover
	// padding - so the answer to "what distribution is this checked against" is
	// "nothing", recorded here on purpose (verification rule 3).
	stegoMarkerMinLen = 8
	stegoMarkerSpan   = 16

	stegoC2SMarkerLabel = "tiredvpn-stego-c2s-marker-v2"
	stegoS2CMarkerLabel = "tiredvpn-stego-s2c-marker-v2"
)

// stegoMarker derives the variable-length keyed marker for one direction from
// the secret and a per-frame nonce.
func stegoMarker(secret, nonce []byte, label string) []byte {
	if len(secret) == 0 {
		return nil
	}
	r := hkdf.New(sha256.New, secret, nonce, []byte(label))
	var lenByte [1]byte
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return nil
	}
	markerLen := stegoMarkerMinLen + int(lenByte[0])%stegoMarkerSpan
	out := make([]byte, markerLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil
	}
	return out
}

// stegoFrameHeader returns a fresh [nonce][marker] prefix for one direction.
func stegoFrameHeader(secret []byte, label string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("stego: empty secret")
	}
	var nonce [stegoNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	marker := stegoMarker(secret, nonce[:], label)
	if marker == nil {
		return nil, errors.New("stego: marker derivation failed")
	}
	hdr := make([]byte, 0, stegoNonceLen+len(marker))
	hdr = append(hdr, nonce[:]...)
	hdr = append(hdr, marker...)
	return hdr, nil
}

// matchStegoFrame checks the keyed prefix of a DATA-frame payload for one
// direction and returns the offset past [nonce][marker]. It returns the offset
// rather than taking a length because the marker length is itself derived from
// the secret: a peer without the secret cannot say where the marker ends.
func matchStegoFrame(secret, data []byte, label string) (int, bool) {
	if len(secret) == 0 || len(data) < stegoNonceLen+stegoMarkerMinLen {
		return 0, false
	}
	nonce := data[:stegoNonceLen]
	want := stegoMarker(secret, nonce, label)
	if len(want) == 0 {
		return 0, false
	}
	off := stegoNonceLen + len(want)
	if len(data) < off {
		return 0, false
	}
	if !hmac.Equal(data[stegoNonceLen:off], want) {
		return 0, false
	}
	return off, true
}

// StegoNonceLen is the per-frame nonce prefix length, exported so the server's
// manual DATA-frame path and the wire tests can locate the nonce.
const StegoNonceLen = stegoNonceLen

// StegoTunCoverLen is stegoTunCoverLen exported for the server's manual
// server->client DATA-frame path, so both directions quantise record lengths
// the same way instead of the server appending a fixed 30-byte cover run.
func StegoTunCoverLen(baseLen int) int { return stegoTunCoverLen(baseLen) }

// StegoClientMarker recomputes the client->server (c2s) marker for a captured
// nonce. Exported for the wire-signature tests that pin the length distribution.
func StegoClientMarker(secret, nonce []byte) []byte {
	return stegoMarker(secret, nonce, stegoC2SMarkerLabel)
}

// StegoServerMarker recomputes the server->client (s2c) marker for a nonce.
func StegoServerMarker(secret, nonce []byte) []byte {
	return stegoMarker(secret, nonce, stegoS2CMarkerLabel)
}

// BuildStegoServerFrameHeader returns a fresh server->client [nonce][marker]
// prefix. The server's manual HTTP/2 path (which does not use HTTP2StegoConn)
// calls this so its frames carry the same keyed marker a client expects.
func BuildStegoServerFrameHeader(secret []byte) ([]byte, error) {
	return stegoFrameHeader(secret, stegoS2CMarkerLabel)
}

// MatchStegoClientFrame checks the keyed prefix of a client->server DATA-frame
// payload and returns the offset past [nonce][marker]. Used by the server's
// manual HTTP/2 path to recognise an authenticated client's covert frames.
func MatchStegoClientFrame(secret, data []byte) (int, bool) {
	return matchStegoFrame(secret, data, stegoC2SMarkerLabel)
}

// writeMarkerLabel / readMarkerLabel pick the direction label so a client keys
// its outbound frames c2s and reads inbound s2c, and a server does the reverse.
func (sc *HTTP2StegoConn) writeMarkerLabel() string {
	if sc.isClient {
		return stegoC2SMarkerLabel
	}
	return stegoS2CMarkerLabel
}

func (sc *HTTP2StegoConn) readMarkerLabel() string {
	if sc.isClient {
		return stegoS2CMarkerLabel
	}
	return stegoC2SMarkerLabel
}

// writeViaPaddedData sends data in DATA frames with cover traffic
func (sc *HTTP2StegoConn) writeViaPaddedData(data []byte) (int, error) {
	var streamID uint32

	// Use persistent stream if available (for TUN mode bidirectional traffic)
	if sc.persistentStream != 0 {
		streamID = sc.persistentStream
	} else {
		streamID = sc.allocateStreamID()
		// Send HEADERS first for new stream
		if err := sc.sendCoverHeaders(streamID); err != nil {
			return 0, err
		}
		// Keep this stream for future writes
		sc.persistentStream = streamID
	}

	// Max chunk that fits with framing
	chunkSize := minInt(len(data), 1000)

	// XOR data with padding key for obfuscation
	obfuscated := make([]byte, chunkSize)
	for i := 0; i < chunkSize; i++ {
		obfuscated[i] = data[i] ^ sc.paddingKey[i%len(sc.paddingKey)]
	}

	// Create frame: [nonce][marker][Flags:1][Length:2][ObfuscatedData:N][NaivePadding:M]
	coverLen := sc.calculateNaivePadding(chunkSize)
	if coverLen < 10 {
		coverLen = 10 // Minimum padding
	}
	hdr, err := stegoFrameHeader(sc.secret, sc.writeMarkerLabel())
	if err != nil {
		return 0, err
	}
	h := len(hdr)
	frame := make([]byte, h+3+chunkSize+coverLen)

	copy(frame[0:h], hdr)                                         // Keyed marker
	frame[h] = 0x01                                               // Flag: obfuscated
	binary.BigEndian.PutUint16(frame[h+1:h+3], uint16(chunkSize)) // Length
	copy(frame[h+3:h+3+chunkSize], obfuscated)                    // Obfuscated data
	rand.Read(frame[h+3+chunkSize:])                              // Cover data

	if err := sc.framer.WriteData(streamID, false, frame); err != nil {
		return 0, err
	}

	return chunkSize, nil
}

// writeViaData sends data in normal DATA frames (mixed with cover traffic)
func (sc *HTTP2StegoConn) writeViaData(data []byte) (int, error) {
	var streamID uint32

	// Use persistent stream if available (for TUN mode bidirectional traffic)
	if sc.persistentStream != 0 {
		streamID = sc.persistentStream
	} else {
		streamID = sc.allocateStreamID()
		// Send HEADERS first for new stream
		if err := sc.sendCoverHeaders(streamID); err != nil {
			return 0, err
		}
		// Keep this stream for future writes
		sc.persistentStream = streamID
	}

	chunkSize := minInt(len(data), 1400)

	// Create framed data: [nonce][marker][Flags:1][Length:2][Data:N][NaivePadding:M]
	coverLen := sc.calculateNaivePadding(chunkSize)
	if coverLen < 10 {
		coverLen = 10 // Minimum padding
	}
	hdr, err := stegoFrameHeader(sc.secret, sc.writeMarkerLabel())
	if err != nil {
		return 0, err
	}
	h := len(hdr)
	frame := make([]byte, h+3+chunkSize+coverLen)
	copy(frame[0:h], hdr)                                         // Keyed marker
	frame[h] = 0x00                                               // Flag: raw
	binary.BigEndian.PutUint16(frame[h+1:h+3], uint16(chunkSize)) // Length
	copy(frame[h+3:h+3+chunkSize], data[:chunkSize])
	rand.Read(frame[h+3+chunkSize:])

	if err := sc.framer.WriteData(streamID, false, frame); err != nil {
		return 0, err
	}

	return chunkSize, nil
}

// writeViaDataFast is optimized version for TUN mode - minimal overhead
func (sc *HTTP2StegoConn) writeViaDataFast(data []byte) (int, error) {
	// Reuse persistent stream (already allocated in constructor)
	streamID := sc.persistentStream

	// Send HEADERS only once on first write
	if sc.methodCounter == 0 {
		if err := sc.sendCoverHeaders(streamID); err != nil {
			return 0, err
		}
	}
	sc.methodCounter++

	// Use actual data length - don't force larger chunks
	// This allows small responses to be sent immediately
	chunkSize := len(data)

	// Framing: [nonce][marker][Flags:1][Length:2][Data:N][cover:M]. The cover run
	// grows the DATA frame to a randomly chosen size bucket so the record length
	// stops tracking the inner packet length (the reader recovers exactly N from
	// the Length field and ignores the trailing cover). This used to be the
	// "no padding" fast path, which made every record length a fixed offset from
	// the packet it carried.
	hdr, err := stegoFrameHeader(sc.secret, sc.writeMarkerLabel())
	if err != nil {
		return 0, err
	}
	h := len(hdr)
	base := h + 3 + chunkSize
	coverLen := stegoTunCoverLen(base)
	frame := make([]byte, base+coverLen)
	copy(frame[0:h], hdr)                                         // Keyed marker
	frame[h] = 0x00                                               // Flag: raw
	binary.BigEndian.PutUint16(frame[h+1:h+3], uint16(chunkSize)) // Length
	copy(frame[h+3:base], data[:chunkSize])
	if coverLen > 0 {
		rand.Read(frame[base:]) // cover data, dropped by the reader via Length
	}

	if err := sc.framer.WriteData(streamID, false, frame); err != nil {
		return 0, err
	}

	return chunkSize, nil
}

// sendCoverHeaders sends legitimate-looking HEADERS to open a stream
func (sc *HTTP2StegoConn) sendCoverHeaders(streamID uint32) error {
	sc.hpackBuf.Reset()

	// Legitimate-looking gRPC/API headers
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: "/grpc.health.v1.Health/Check"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: sc.authority()})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "grpc-go/1.60.0"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})

	return sc.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: sc.hpackBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

// Read extracts data from incoming steganographic frames
func (sc *HTTP2StegoConn) Read(p []byte) (int, error) {
	// Use same mutex as Write for framer access
	sc.mu.Lock()

	// First, drain buffer
	if sc.readBuf.Len() > 0 {
		n, err := sc.readBuf.Read(p)
		sc.mu.Unlock()
		// Apply rate limiting to downloads to create TCP backpressure
		return n, err
	}
	sc.mu.Unlock()

	// Read frames until we get data (without holding lock during blocking read)
	for {
		frame, err := sc.framer.ReadFrame()
		if err != nil {
			return 0, err
		}

		// Accumulate flow-control credit for DATA frames outside the lock
		// so we don't block Write goroutine while counting bytes.
		if df, ok := frame.(*http2.DataFrame); ok {
			atomic.AddInt64(&sc.recvConsumed, int64(len(df.Data())))
			// Proactively return flow-control credit during downloads so the
			// peer's send window does not starve while Write is idle.
			sc.proactiveFlushWindowUpdate()
		}

		sc.mu.Lock()
		data := sc.extractCovertData(frame)
		if len(data) > 0 {
			sc.readBuf.Write(data)
			n, err := sc.readBuf.Read(p)
			sc.mu.Unlock()
			return n, err
		}
		sc.mu.Unlock()
	}
}

// extractCovertData extracts hidden data from a frame
func (sc *HTTP2StegoConn) extractCovertData(frame http2.Frame) []byte {
	switch f := frame.(type) {
	case *http2.DataFrame:
		return sc.extractFromData(f)
	case *http2.HeadersFrame:
		return sc.extractFromHeaders(f)
	case *http2.WindowUpdateFrame:
		// Peer extended our send window; no data to return but handled.
		_ = f
		return nil
	case *http2.SettingsFrame:
		if !f.IsAck() {
			sc.readPathWrite(func() { sc.framer.WriteSettingsAck() })
		}
		return nil
	default:
		return nil
	}
}

// extractFromData extracts data from DATA frames
func (sc *HTTP2StegoConn) extractFromData(f *http2.DataFrame) []byte {
	data := f.Data()

	// Check for the keyed marker at the head of the payload.
	off, ok := matchStegoFrame(sc.secret, data, sc.readMarkerLabel())
	if !ok || len(data) < off+3 {
		return nil
	}
	flags := data[off]
	length := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
	if length > len(data)-off-3 {
		return nil
	}
	payload := data[off+3 : off+3+length]

	// De-obfuscate if needed
	if flags&0x01 != 0 {
		deobfuscated := make([]byte, len(payload))
		for i := range payload {
			deobfuscated[i] = payload[i] ^ sc.paddingKey[i%len(sc.paddingKey)]
		}
		return deobfuscated
	}

	return payload
}

// extractFromHeaders extracts data from custom headers
func (sc *HTTP2StegoConn) extractFromHeaders(f *http2.HeadersFrame) []byte {
	var covertData []byte

	sc.hpackDec.SetEmitFunc(func(hf hpack.HeaderField) {
		// Look for our custom headers
		switch hf.Name {
		case "x-request-id", "x-correlation-id", "x-trace-id", "x-span-id":
			decoded := decodeFromHex(hf.Value)
			if len(decoded) > 0 {
				covertData = append(covertData, decoded...)
			}
		}
	})

	sc.hpackDec.Write(f.HeaderBlockFragment())
	return covertData
}

// allocateStreamID returns next stream ID
func (sc *HTTP2StegoConn) allocateStreamID() uint32 {
	id := sc.nextStreamID
	sc.nextStreamID += 2 // Clients use odd, servers use even
	return id
}

// Close closes the connection
func (sc *HTTP2StegoConn) Close() error {
	// GOAWAY goes through the framer like every other write, so under sc.mu:
	// the read path writes WINDOW_UPDATE under it, and a teardown during a
	// download touched the framer from two goroutines (P3-1 of the round-7
	// review). A deadline of its own: whatever deadline the last write left
	// may have passed, and a GOAWAY failing on it would spend a TLS record
	// number before close_notify.
	// The bound is set under wdMu with closing, so no write of the conn's
	// own that ends after it puts the owner's deadline back over it.
	sc.wdMu.Lock()
	sc.closing = true
	_ = sc.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	sc.wdMu.Unlock()
	sc.closeOnce.Do(func() { close(sc.closed) })
	sc.mu.Lock()
	sc.framer.WriteGoAway(sc.nextStreamID, http2.ErrCodeNo, nil)
	sc.mu.Unlock()
	// A TLS write that failed spent a record number and may have left half
	// a record on the wire; a close_notify after it reads as "bad record
	// MAC" at the peer, which then logs a broken session for a close. Shut
	// the socket under TLS instead: the peer reads the end of the stream.
	if sc.writeFailed.Load() {
		if tc, ok := sc.Conn.(interface{ NetConn() net.Conn }); ok {
			return tc.NetConn().Close()
		}
	}
	return sc.Conn.Close()
}

// Helper functions

func deriveKey(secret []byte, context string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(context))
	return h.Sum(nil)
}

// stegoAuthSkewBuckets is how many 1-minute buckets on either side of "now"
// verifyClientAuth accepts, so a client whose clock drifts by up to a minute
// still authenticates (SSH and IMAP camouflage tolerate the same +-1). The
// live server path (server.go verifyH2Auth) tolerates a wider window; this is
// the stego-as-server path used by the relay and the tests.
const stegoAuthSkewBuckets = 1

// generateAuthTokenBound derives the shared strategy auth token for the current
// 1-minute bucket, bound to the TLS session's exporter keying material (ekm).
//
// Folding ekm into the HMAC is the S22 session binding: a token lifted off one
// TLS session carries that session's exporter, so it fails verification on any
// other session even under the same secret and time bucket. The
// geneva/morph/websocket_padded/stego clients all feed it the exporter of the
// *tls.Conn they authenticate over (see sessionExporterKey).
//
// ekm==nil reproduces the pre-binding token. That path is intended only for
// transports with no TLS session of their own (the non-TLS test pipes, where
// both ends pass nil and still agree); a client that authenticates over TLS and
// passes nil here silently ships an unbound token, which is the regression this
// function exists to prevent.
func generateAuthTokenBound(secret, ekm []byte) []byte {
	return generateAuthTokenBoundAt(secret, ekm, uint64(time.Now().Unix()/60)) // 1-minute window
}

// generateAuthTokenBoundAt derives the session-bound auth token for a specific
// 1-minute bucket.
func generateAuthTokenBoundAt(secret, ekm []byte, bucket uint64) []byte {
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, bucket)

	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	h.Write(ekm) // TLS-session binding
	return h.Sum(nil)[:32]
}

// verifyAuthTokenBound reports whether receivedToken matches the session-bound
// token for any bucket within +-stegoAuthSkewBuckets of now, on the TLS session
// whose exporter is ekm. The comparison is constant-time (hmac.Equal) so it
// leaks nothing about how many leading bytes matched.
func verifyAuthTokenBound(secret, ekm, receivedToken []byte) bool {
	now := time.Now().Unix() / 60
	for offset := int64(-stegoAuthSkewBuckets); offset <= stegoAuthSkewBuckets; offset++ {
		if hmac.Equal(receivedToken, generateAuthTokenBoundAt(secret, ekm, uint64(now+offset))) {
			return true
		}
	}
	return false
}

// sessionExporterKey pulls the RFC 8446 §7.5 exporter out of a handshaked
// *tls.Conn for auth-token session binding.
//
// It must be called while the userspace TLS stack still owns the connection:
// once kTLS offloads the socket the *tls.Conn is no longer the thing on the
// wire and ConnectionState no longer reflects live keys. Every caller here
// captures the exporter right after the handshake and before ktls.Enable.
func sessionExporterKey(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	return customtls.ExportBindingKey(&state)
}

// connExporterKey is the best-effort form of sessionExporterKey for callers that
// hold a net.Conn which may or may not be a handshaked *tls.Conn (the composed
// morph path, whose base transport is another strategy). It unwraps one
// NetConn() layer and returns nil when no TLS session is reachable — a nil the
// caller and its peer must agree on, exactly as with a non-TLS test pipe.
func connExporterKey(conn net.Conn) []byte {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		if nc, hasNetConn := conn.(interface{ NetConn() net.Conn }); hasNetConn {
			tc, ok = nc.NetConn().(*tls.Conn)
		}
	}
	if !ok || tc == nil {
		return nil
	}
	ekm, err := sessionExporterKey(tc)
	if err != nil {
		return nil
	}
	return ekm
}

// stegoAckNonceLen is the per-connection nonce the server prefixes to its ack
// proof so the proof differs between connections instead of being one static
// value for the whole life of the secret.
const stegoAckNonceLen = 8

// serverAckMaterial derives the server's ack proof from the secret and a
// per-connection nonce. Binding to the nonce is what makes two connections'
// acks differ; callers take the prefix they need (16 bytes in HEADERS, 8 in
// the DATA fallback).
func serverAckMaterial(secret, nonce []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(nonce)
	h.Write([]byte("server-ack"))
	return h.Sum(nil)
}

// encodeToHex encodes bytes to a lowercase hex string.
// Wire-compatible with the previous hand-rolled encoder (lowercase alphabet).
func encodeToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// decodeFromHex decodes a hex string to bytes, returning nil on malformed
// input (odd length or invalid characters) to match the previous behaviour.
func decodeFromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// calculateNaivePadding computes padding size based on NaiveProxy-style mode.
//
// The amount is drawn from crypto/rand inside the mode's declared percentage
// band (getNaivePaddingRange, which this now actually consumes - it used to be
// dead and advertised ranges the old counter arithmetic never produced). Two
// frames of the same length no longer pad by the same amount, so a passive
// observer cannot subtract a fixed overhead to recover the plaintext length.
//
// Distribution (verification rule 3): the percentage is uniform over the band.
// There is no measured population of real HTTP/2 DATA-frame padding to match
// its shape against - servers rarely pad DATA frames at all - so "what
// distribution is this checked against" is "nothing", recorded here on purpose.
func (sc *HTTP2StegoConn) calculateNaivePadding(dataLen int) int {
	minPct, maxPct := sc.paddingMode.getNaivePaddingRange()
	pct := minPct
	if maxPct > minPct {
		pct += randIntn(maxPct - minPct + 1)
	}
	return dataLen * pct / 100
}

// stegoTunBuckets are the padded frame-payload targets for the default tun path.
// A frame is grown to a bucket drawn at random from those large enough to hold
// it, so (a) many inner packet lengths land on the same record length and (b) a
// small packet can, on any given frame, occupy the same record length as a
// full-size one. The record length therefore no longer tracks the inner IP
// packet length - the property the length-correlation detector in wiretest
// pins. The top bucket clears a full 1400-byte MTU packet plus framing.
var stegoTunBuckets = []int{128, 256, 512, 1024, 1500}

// stegoTunCoverLen returns how many cover bytes to append after a tun-path frame
// whose pre-cover length is baseLen, so the padded payload lands on a randomly
// chosen bucket >= baseLen.
//
// Distribution (verification rule 3): the bucket is chosen uniformly among the
// fitting buckets from crypto/rand, not from a counter. There is no measured
// distribution of real H2 DATA padding to match, so the target here is
// decorrelation (record length independent of packet length), recorded as
// "nothing to check against". Rule 8: quantising to a handful of sizes is itself
// a shape a passive observer could notice ("record lengths cluster near five
// values"); it is a deliberate trade - a coarse, packet-length-free size signal
// instead of a 1:1 copy of the packet-length distribution.
func stegoTunCoverLen(baseLen int) int {
	fits := make([]int, 0, len(stegoTunBuckets))
	for _, b := range stegoTunBuckets {
		if b >= baseLen {
			fits = append(fits, b)
		}
	}
	if len(fits) == 0 {
		// Larger than the top bucket (shouldn't happen under a 1400 MTU); round up
		// to the next bucket step so the length is still quantised, not a copy.
		step := stegoTunBuckets[len(stegoTunBuckets)-1]
		padded := ((baseLen / step) + 1) * step
		return padded - baseLen
	}
	return fits[randIntn(len(fits))] - baseLen
}

// randIntn returns a uniform int in [0,n) from crypto/rand, or 0 if the source
// fails (padding then degrades to the band minimum rather than panicking).
func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

// stegoCoverRotator supplies the per-connection cover host (SNI and :authority)
// when the caller left it unset. StrategyRandom keeps independent clients from
// all landing on the same donor at the same time (the old hour-of-day index
// moved every client in lockstep).
var stegoCoverRotator = evasion.NewSNIRotator(evasion.StrategyRandom)

// authority returns the HTTP/2 :authority for cover HEADERS. It is the cover
// host chosen for this connection, so the encrypted :authority matches the
// cleartext SNI; a mismatch is exactly what an active prober compares.
func (sc *HTTP2StegoConn) authority() string {
	if sc.coverHost != "" {
		return sc.coverHost
	}
	return "www.googleapis.com"
}

// getNaivePaddingRange returns min/max padding for a given mode
func (mode NaivePaddingMode) getNaivePaddingRange() (minPct, maxPct int) {
	switch mode {
	case NaivePaddingMinimal:
		return 5, 10
	case NaivePaddingStandard:
		return 15, 25
	case NaivePaddingParanoid:
		return 30, 50
	default:
		return 15, 25
	}
}
