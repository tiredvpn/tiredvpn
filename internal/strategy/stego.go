package strategy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// rateLimiterWrapper wraps evasion.AdaptiveRateLimiter for optional use
type rateLimiterWrapper struct {
	limiter *evasion.AdaptiveRateLimiter
}

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
	serverAddr  string   // Deprecated: use manager.GetServerAddr() instead
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
	if coverHost == "" {
		coverHost = "www.googleapis.com"
	}
	return &HTTP2StegoStrategy{
		manager:     manager,
		serverAddr:  "", // Deprecated: use manager.GetServerAddr() instead
		secret:      secret,
		coverHost:   coverHost,
		paddingMode: NaivePaddingMinimal, // Default to minimal for low latency
	}
}

// NewHTTP2StegoStrategyWithPadding creates a strategy with specific padding mode
// manager is required for IPv6/IPv4 transport layer support
func NewHTTP2StegoStrategyWithPadding(manager *Manager, secret []byte, coverHost string, mode NaivePaddingMode) *HTTP2StegoStrategy {
	if coverHost == "" {
		coverHost = "www.googleapis.com"
	}
	return &HTTP2StegoStrategy{
		manager:     manager,
		serverAddr:  "", // Deprecated: use manager.GetServerAddr() instead
		secret:      secret,
		coverHost:   coverHost,
		paddingMode: mode,
	}
}

// NewHTTP2StegoStrategyWithECH creates a strategy with ECH support
// manager is required for IPv6/IPv4 transport layer support
func NewHTTP2StegoStrategyWithECH(manager *Manager, secret []byte, coverHost string, echConfigList []byte, echPublicName string) *HTTP2StegoStrategy {
	if coverHost == "" {
		coverHost = "www.googleapis.com"
	}
	return &HTTP2StegoStrategy{
		manager:       manager,
		serverAddr:    "", // Deprecated: use manager.GetServerAddr() instead
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
	log.Debug("HTTP/2 Stego: Using server address: %s", serverAddr)

	// Establish TLS connection with ALPN for HTTP/2
	// "tired-stego" enables kTLS on server, "h2" is fallback for old servers
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.coverHost,
		NextProtos:         []string{"tired-stego", "h2"}, // kTLS-enabled ALPN with fallback
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

	// Verify HTTP/2 was negotiated (either tired-stego or h2)
	alpn := conn.ConnectionState().NegotiatedProtocol
	if alpn != "h2" && alpn != "tired-stego" {
		conn.Close()
		return nil, errors.New("HTTP/2 not negotiated")
	}

	// Try to enable kTLS for kernel TLS offload (reduces CPU usage)
	// This returns a wrapped connection that uses raw socket I/O
	var finalConn net.Conn = conn
	if ktlsConn := ktls.Enable(conn); ktlsConn != nil {
		log.Debug("kTLS enabled for HTTP/2 Stego connection")
		finalConn = ktlsConn
	}

	// Create steganographic connection with padding mode
	stegoConn := NewHTTP2StegoConn(finalConn, s.secret, true, s.paddingMode)

	// Perform initial handshake
	if err := stegoConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return stegoConn, nil
}

// HTTP2StegoConn implements net.Conn with HTTP/2 steganography
type HTTP2StegoConn struct {
	net.Conn
	secret      []byte
	isClient    bool
	paddingMode NaivePaddingMode

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
	readMu           sync.Mutex

	// Read buffer for reassembling data
	readBuf bytes.Buffer

	// Covert channel state
	methodCounter uint32
	paddingKey    []byte

	// Fast path optimization for TUN mode
	tunMode       bool          // Enable optimized TUN mode
	writeBuf      bytes.Buffer  // Buffer for batching small writes
	lastWriteTime time.Time     // Last write timestamp for batch timeout
	batchTimer    *time.Timer   // Timer for flushing batched writes

	// Rate limiting for TSPU evasion (client-side only)
	rateLimiter *rateLimiterWrapper
}

// NewHTTP2StegoConn creates a new steganographic HTTP/2 connection
func NewHTTP2StegoConn(conn net.Conn, secret []byte, isClient bool, paddingMode NaivePaddingMode) *HTTP2StegoConn {
	sc := &HTTP2StegoConn{
		Conn:        conn,
		secret:      secret,
		isClient:    isClient,
		paddingMode: paddingMode,
	}

	// Initialize HTTP/2 framer
	sc.framer = http2.NewFramer(conn, conn)
	sc.framer.AllowIllegalWrites = true
	sc.framer.AllowIllegalReads = true

	// Initialize HPACK
	sc.hpackEnc = hpack.NewEncoder(&sc.hpackBuf)
	sc.hpackDec = hpack.NewDecoder(4096, nil)

	// Client starts with odd stream IDs
	if isClient {
		sc.nextStreamID = 1
		// Rate limiter disabled - was causing 80 KB/s bottleneck
		sc.rateLimiter = nil
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
	if sc.isClient {
		// Send HTTP/2 connection preface
		_, err := sc.Conn.Write([]byte(http2.ClientPreface))
		if err != nil {
			return err
		}

		// Send SETTINGS frame
		if err := sc.framer.WriteSettings(); err != nil {
			return err
		}

		// Send initial covert handshake in HEADERS
		if err := sc.sendCovertHandshake(); err != nil {
			return err
		}

		// Wait for server response
		return sc.waitForServerAck()
	}

	// Server side handshake
	return sc.handleClientHandshake()
}

// sendCovertHandshake sends authentication via HEADERS with custom headers
func (sc *HTTP2StegoConn) sendCovertHandshake() error {
	streamID := sc.allocateStreamID()

	// Generate auth token
	authToken := generateAuthToken(sc.secret)

	// Encode in HEADERS
	sc.hpackBuf.Reset()

	// Required pseudo-headers for valid HTTP/2
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: "/grpc.health.v1.Health/Check"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.googleapis.com"})

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

// waitForServerAck waits for server acknowledgment
func (sc *HTTP2StegoConn) waitForServerAck() error {
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
			expectedAck := encodeToHex(deriveKey(sc.secret, "server-ack")[:16])
			if hf.Value == expectedAck {
				foundAck = true
			}
		}
	})

	sc.hpackDec.Write(f.HeaderBlockFragment())
	return foundAck
}

// verifyServerAckData checks DATA frame for ack magic
func (sc *HTTP2StegoConn) verifyServerAckData(f *http2.DataFrame) bool {
	data := f.Data()
	if len(data) >= 8 {
		expectedMagic := deriveKey(sc.secret, "server-ack")[:8]
		return bytes.Equal(data[:8], expectedMagic)
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

	// Send server SETTINGS
	if err := sc.framer.WriteSettings(); err != nil {
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
	expectedToken := generateAuthToken(sc.secret)

	return bytes.Equal(receivedToken, expectedToken)
}

// sendServerAck sends acknowledgment to client
func (sc *HTTP2StegoConn) sendServerAck(streamID uint32) error {
	// Send HEADERS response with ack
	sc.hpackBuf.Reset()

	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	sc.hpackEnc.WriteField(hpack.HeaderField{
		Name:  "x-goog-correlation-id",
		Value: encodeToHex(deriveKey(sc.secret, "server-ack")[:16]),
	})

	return sc.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: sc.hpackBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

// Write sends data using various steganographic channels
func (sc *HTTP2StegoConn) Write(p []byte) (int, error) {
	// Apply rate limiting to evade TSPU bulk transfer detection
	if sc.rateLimiter != nil && sc.rateLimiter.limiter != nil {
		sc.rateLimiter.limiter.Wait(len(p))
	}

	// Fast path for TUN mode - optimized for low latency
	if sc.tunMode {
		return sc.writeFast(p)
	}

	// Standard path with full steganography
	sc.mu.Lock()
	defer sc.mu.Unlock()

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

	return written, nil
}

// writeFast is optimized fast path for TUN mode (low latency)
func (sc *HTTP2StegoConn) writeFast(p []byte) (int, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Always write immediately for now - batching causes latency issues
	// TODO: implement proper async flush with goroutine
	return sc.writeViaDataFast(p)
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

// writeViaHeaders hides data in custom HTTP headers
func (sc *HTTP2StegoConn) writeViaHeaders(data []byte) (int, error) {
	streamID := sc.allocateStreamID()

	// Encode up to 100 bytes in header values
	chunkSize := minInt(len(data), 100)

	sc.hpackBuf.Reset()

	// Required pseudo-headers
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":path", Value: "/api/v1/telemetry"})
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: "telemetry.googleapis.com"})

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

	// Create frame: [Magic:4][Flags:1][Length:2][ObfuscatedData:N][NaivePadding:M]
	coverLen := sc.calculateNaivePadding(chunkSize)
	if coverLen < 10 {
		coverLen = 10 // Minimum padding
	}
	frame := make([]byte, 7+chunkSize+coverLen)

	copy(frame[0:4], []byte("TIRD"))                             // Magic
	frame[4] = 0x01                                              // Flag: obfuscated
	binary.BigEndian.PutUint16(frame[5:7], uint16(chunkSize))    // Length
	copy(frame[7:7+chunkSize], obfuscated)                       // Obfuscated data
	rand.Read(frame[7+chunkSize:])                               // Cover data

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

	// Create framed data: [Magic:4][Flags:1][Length:2][Data:N][NaivePadding:M]
	coverLen := sc.calculateNaivePadding(chunkSize)
	if coverLen < 10 {
		coverLen = 10 // Minimum padding
	}
	frame := make([]byte, 7+chunkSize+coverLen)
	copy(frame[0:4], []byte("TIRD"))                          // Magic
	frame[4] = 0x00                                           // Flag: raw
	binary.BigEndian.PutUint16(frame[5:7], uint16(chunkSize)) // Length
	copy(frame[7:7+chunkSize], data[:chunkSize])
	rand.Read(frame[7+chunkSize:])

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

	// Minimal framing: [Magic:4][Flags:1][Length:2][Data:N]
	// No padding in fast mode - prioritize latency
	frame := make([]byte, 7+chunkSize)
	copy(frame[0:4], []byte("TIRD"))                          // Magic
	frame[4] = 0x00                                           // Flag: raw
	binary.BigEndian.PutUint16(frame[5:7], uint16(chunkSize)) // Length
	copy(frame[7:], data[:chunkSize])

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
	sc.hpackEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.googleapis.com"})
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
		if sc.rateLimiter != nil && sc.rateLimiter.limiter != nil && n > 0 {
			sc.rateLimiter.limiter.Wait(n)
		}
		return n, err
	}
	sc.mu.Unlock()

	// Read frames until we get data (without holding lock during blocking read)
	for {
		frame, err := sc.framer.ReadFrame()
		if err != nil {
			return 0, err
		}

		sc.mu.Lock()
		data := sc.extractCovertData(frame)
		if len(data) > 0 {
			sc.readBuf.Write(data)
			n, err := sc.readBuf.Read(p)
			sc.mu.Unlock()
			// Apply rate limiting to downloads to create TCP backpressure
			if sc.rateLimiter != nil && sc.rateLimiter.limiter != nil && n > 0 {
				sc.rateLimiter.limiter.Wait(n)
			}
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
	default:
		return nil
	}
}

// extractFromData extracts data from DATA frames
func (sc *HTTP2StegoConn) extractFromData(f *http2.DataFrame) []byte {
	data := f.Data()

	// Check for magic header
	if len(data) >= 7 && bytes.Equal(data[0:4], []byte("TIRD")) {
		flags := data[4]
		length := binary.BigEndian.Uint16(data[5:7])

		if int(length) <= len(data)-7 {
			payload := data[7 : 7+length]

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
	}

	return nil
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
	// Send GOAWAY frame
	sc.framer.WriteGoAway(sc.nextStreamID, http2.ErrCodeNo, nil)
	return sc.Conn.Close()
}

// Helper functions

func deriveKey(secret []byte, context string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(context))
	return h.Sum(nil)
}

func generateAuthToken(secret []byte) []byte {
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60)) // 1-minute window

	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	return h.Sum(nil)[:32]
}

// encodeToHex encodes bytes to hex string
func encodeToHex(data []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hex[b>>4]
		result[i*2+1] = hex[b&0x0f]
	}
	return string(result)
}

// decodeFromHex decodes hex string to bytes
func decodeFromHex(s string) []byte {
	if len(s)%2 != 0 {
		return nil
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := hexVal(s[i])
		low := hexVal(s[i+1])
		if high < 0 || low < 0 {
			return nil
		}
		result[i/2] = byte(high<<4 | low)
	}
	return result
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// calculateNaivePadding computes padding size based on NaiveProxy-style mode
func (sc *HTTP2StegoConn) calculateNaivePadding(dataLen int) int {
	switch sc.paddingMode {
	case NaivePaddingMinimal:
		// 5-10% padding (optimized for speed)
		overhead := dataLen / 20                   // 5% base
		variability := int(sc.methodCounter%6) - 3 // ±3% variation
		return overhead + variability
	case NaivePaddingStandard:
		// 15-25% padding (balanced)
		overhead := dataLen / 6                    // ~16% base
		variability := int(sc.methodCounter%10) - 5 // ±5% variation
		return overhead + variability
	case NaivePaddingParanoid:
		// 30-50% padding (maximum security)
		overhead := dataLen * 2 / 5                 // 40% base
		variability := int(sc.methodCounter%20) - 10 // ±10% variation
		return overhead + variability
	default:
		return dataLen / 6 // Standard fallback
	}
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
