package strategy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	mathrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// TrafficMorphStrategy morphs traffic to match target application patterns
// Makes VPN traffic statistically indistinguishable from YouTube/Yandex.Video
type TrafficMorphStrategy struct {
	manager   *Manager // Reference to Manager for IPv6/IPv4 support
	profile   *TrafficProfile
	baseStrat Strategy // Underlying strategy (e.g., gRPC tunnel)
	secret    []byte   // Secret for authentication
}

// TrafficProfile defines statistical properties of traffic to mimic.
//
// Fields BurstSize, BurstInterval and DownUpRatio that previously lived here
// were declared but never read by the runtime (writeScheduler was disabled,
// fragmentToProfile was unused). They are intentionally absent so the profile
// only exposes parameters that actually drive behaviour today: packet size
// distribution (used by dummy generation) and padding ranges (used by Write).
//
// Inter-arrival parameters remain because they are part of the documented
// shape of each profile and will become inputs to the future shaper layer
// (see internal/shaper, task I2). They have no runtime effect right now.
type TrafficProfile struct {
	Name string

	// Packet size distribution (histogram buckets)
	PacketSizes     []int     // Bucket centers
	PacketSizeProbs []float64 // Probability for each bucket

	// Inter-arrival time distribution (milliseconds).
	// Currently informational; will drive timing once shaper is wired in.
	InterArrivalMean   float64
	InterArrivalStdDev float64

	// Padding behavior (applied per Write)
	MinPadding int
	MaxPadding int
}

// Predefined traffic profiles based on real application analysis
var (
	// YandexVideoProfile mimics Yandex.Video streaming (primary for Russia)
	YandexVideoProfile = &TrafficProfile{
		Name:               "Yandex Video",
		PacketSizes:        []int{200, 600, 1200, 1400},
		PacketSizeProbs:    []float64{0.10, 0.20, 0.35, 0.35},
		InterArrivalMean:   8.0,
		InterArrivalStdDev: 20.0,
		MinPadding:         50,
		MaxPadding:         200,
	}

	// VKVideoProfile mimics VK Video streaming
	// BaiduVideoProfile mimics Baidu Video streaming (primary for China)
	BaiduVideoProfile = &TrafficProfile{
		Name:               "Baidu Video",
		PacketSizes:        []int{250, 700, 1100, 1450},
		PacketSizeProbs:    []float64{0.12, 0.18, 0.30, 0.40},
		InterArrivalMean:   10.0,
		InterArrivalStdDev: 25.0,
		MinPadding:         60,
		MaxPadding:         250,
	}

	// AparatVideoProfile mimics Aparat Video streaming (primary for Iran)
	AparatVideoProfile = &TrafficProfile{
		Name:               "Aparat Video",
		PacketSizes:        []int{180, 550, 950, 1350},
		PacketSizeProbs:    []float64{0.15, 0.25, 0.30, 0.30},
		InterArrivalMean:   12.0,
		InterArrivalStdDev: 30.0,
		MinPadding:         40,
		MaxPadding:         180,
	}

	VKVideoProfile = &TrafficProfile{
		Name:               "VK Video",
		PacketSizes:        []int{150, 500, 1000, 1400},
		PacketSizeProbs:    []float64{0.08, 0.15, 0.32, 0.45},
		InterArrivalMean:   6.0,
		InterArrivalStdDev: 18.0,
		MinPadding:         20,
		MaxPadding:         150,
	}

	// WebBrowsingProfile mimics typical web browsing
	WebBrowsingProfile = &TrafficProfile{
		Name:               "Web Browsing",
		PacketSizes:        []int{100, 300, 800, 1400},
		PacketSizeProbs:    []float64{0.30, 0.25, 0.25, 0.20},
		InterArrivalMean:   50.0,
		InterArrivalStdDev: 100.0,
		MinPadding:         0,
		MaxPadding:         50,
	}

	// VoIPProfile mimics voice/video call
	VoIPProfile = &TrafficProfile{
		Name:               "VoIP Call",
		PacketSizes:        []int{60, 160, 320},
		PacketSizeProbs:    []float64{0.40, 0.40, 0.20},
		InterArrivalMean:   20.0, // Regular intervals
		InterArrivalStdDev: 5.0,  // Low variance
		MinPadding:         0,
		MaxPadding:         20,
	}
)

// PaddingPreset defines preset padding levels for performance vs stealth tradeoff
type PaddingPreset int

const (
	PaddingPresetMinimal  PaddingPreset = 10  // Low latency, minimal overhead (~5-10 bytes)
	PaddingPresetStandard PaddingPreset = 100 // Balanced (~50-100 bytes)
	PaddingPresetHeavy    PaddingPreset = 200 // Maximum stealth (~100-200 bytes)
)

// String returns human-readable preset name
func (p PaddingPreset) String() string {
	switch p {
	case PaddingPresetMinimal:
		return "minimal"
	case PaddingPresetStandard:
		return "standard"
	case PaddingPresetHeavy:
		return "heavy"
	default:
		return "unknown"
	}
}

// GetPaddingRange returns min/max padding for preset
func (p PaddingPreset) GetPaddingRange() (min, max int) {
	switch p {
	case PaddingPresetMinimal:
		return 0, 10
	case PaddingPresetStandard:
		return 20, 100
	case PaddingPresetHeavy:
		return 50, 200
	default:
		return 0, 10
	}
}

// ApplyPaddingPreset modifies profile's padding based on preset
func (prof *TrafficProfile) ApplyPaddingPreset(preset PaddingPreset) {
	prof.MinPadding, prof.MaxPadding = preset.GetPaddingRange()
}

// Global padding preset (can be set via CLI flag)
var GlobalPaddingPreset PaddingPreset = PaddingPresetMinimal

// Fast RNG for non-cryptographic padding (10× faster than crypto/rand)
var (
	fastRand   = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	fastRandMu sync.Mutex
)

func fastRandBytes(b []byte) {
	fastRandMu.Lock()
	fastRand.Read(b)
	fastRandMu.Unlock()
}

func fastRandInt(min, max int) int {
	fastRandMu.Lock()
	n := fastRand.Intn(max-min+1) + min
	fastRandMu.Unlock()
	return n
}

// Buffer pool for packet allocation (reduces GC pressure)
var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048) // Pre-allocated 2KB buffer
	},
}

// NewTrafficMorphStrategy creates a new traffic morphing strategy
// manager is required for IPv6/IPv4 transport layer support
func NewTrafficMorphStrategy(manager *Manager, profile *TrafficProfile, base Strategy, secret []byte) *TrafficMorphStrategy {
	if profile == nil {
		profile = YandexVideoProfile
	}

	// Apply global padding preset to profile
	// Make a copy so we don't modify the global profile
	profileCopy := *profile
	profileCopy.ApplyPaddingPreset(GlobalPaddingPreset)

	return &TrafficMorphStrategy{
		manager:   manager,
		profile:   &profileCopy,
		baseStrat: base,
		secret:    secret,
	}
}

func (s *TrafficMorphStrategy) Name() string {
	return "Traffic Morph (" + s.profile.Name + ")"
}

func (s *TrafficMorphStrategy) ID() string {
	return "morph_" + s.profile.Name
}

func (s *TrafficMorphStrategy) Priority() int {
	return 10 // High priority - try early
}

func (s *TrafficMorphStrategy) Description() string {
	return "Morphs traffic patterns to statistically match " + s.profile.Name +
		" making ML-based DPI classification ineffective"
}

func (s *TrafficMorphStrategy) RequiresServer() bool {
	return true // Server must also morph
}

func (s *TrafficMorphStrategy) Probe(ctx context.Context, target string) error {
	// Use base strategy's probe
	if s.baseStrat != nil {
		return s.baseStrat.Probe(ctx, target)
	}
	return nil
}

func (s *TrafficMorphStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Establish base connection
	var baseConn net.Conn
	var err error

	if s.baseStrat != nil {
		baseConn, err = s.baseStrat.Connect(ctx, target)
	} else {
		// --- TLS / handshake (do not touch in shaper migration) ---
		// Get server address (IPv6/IPv4 with automatic fallback)
		serverAddr := s.manager.GetServerAddr(ctx)
		log.Debug("Traffic Morph: Using server address: %s", serverAddr)

		// Use TLS connection (server requires TLS)
		// "tired-morph" enables kTLS on server, "http/1.1" is fallback
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"tired-morph", "http/1.1"},
		}
		// Use context-aware dialing (respects Android optimized timeouts)
		dialer := &net.Dialer{}
		tcpConn, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}

		// Wrap TCP connection with fragmentation to defeat DPI
		// This splits TLS ClientHello across multiple TCP segments
		fragConfig := &evasion.FragmentationConfig{
			FragmentSize:  2,                // Very small fragments
			SplitPosition: 1,                // Split SNI at first byte
			FragmentDelay: time.Millisecond, // Small delay between fragments
		}
		fragConn := evasion.NewFragmentedWriter(tcpConn, fragConfig)
		log.Debug("Morph: TLS ClientHello fragmentation enabled (size=%d)", fragConfig.FragmentSize)

		tlsConn := tls.Client(fragConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, err
		}

		// Try to enable kTLS for kernel TLS offload
		// This returns a wrapped connection that uses raw socket I/O
		if ktlsConn := ktls.Enable(tlsConn); ktlsConn != nil {
			log.Debug("kTLS enabled for Morph connection")
			baseConn = ktlsConn
		} else {
			baseConn = tlsConn
		}
		err = nil
	}

	if err != nil {
		return nil, err
	}

	// Wrap with morphing layer
	return NewMorphedConn(baseConn, s.profile, s.secret), nil
}

// MorphedConn wraps a connection with traffic morphing.
//
// Behavioural shaping is intentionally minimal here: per-Write padding plus
// a 6-byte length/padding framing header. Burst scheduling, dummy cover
// traffic and Gaussian inter-arrival jitter previously lived in a
// writeScheduler goroutine that conflicted with TLS framing and is removed.
// Those behaviours are planned for re-introduction via internal/shaper
// (task I2).
type MorphedConn struct {
	net.Conn
	profile *TrafficProfile

	// shaper drives sizing, delay and fragmentation. NoopShaper means
	// "use the legacy per-Write padding pipeline" — we keep wire bytes
	// byte-identical to pre-shaper builds in that mode (backward compat).
	shaper shaper.Shaper

	// Read buffer for partial reads
	readBuf []byte

	// Statistics tracking
	bytesSent   int64
	bytesRecv   int64
	packetsSent int64
	packetsRecv int64

	// Rate limiting for TSPU evasion
	rateLimiter *evasion.AdaptiveRateLimiter

	// pacer drains shaped frames asynchronously so the producer Write
	// never blocks on per-frame time.Sleep. Lazy-initialised via pacerOnce
	// on the first shaped Write; nil while the connection only sees
	// NoopShaper traffic.
	pacer     *writePacer
	pacerOnce sync.Once
}

// NetConn returns the underlying net.Conn for TCP optimization
func (mc *MorphedConn) NetConn() net.Conn {
	return mc.Conn
}

// NewMorphedConn creates a morphed connection with the legacy passthrough
// shaper. It performs the application-layer Morph handshake over the
// underlying (typically TLS) conn before returning.
func NewMorphedConn(conn net.Conn, profile *TrafficProfile, secret []byte) *MorphedConn {
	return NewMorphedConnWithShaper(conn, profile, secret, nil)
}

// NewMorphedConnWithShaper is like NewMorphedConn but lets callers inject a
// behavioral shaper. A nil sh defaults to shaper.NoopShaper, which keeps the
// wire format and Write/Read pipeline byte-identical to the pre-shaper code.
func NewMorphedConnWithShaper(conn net.Conn, profile *TrafficProfile, secret []byte, sh shaper.Shaper) *MorphedConn {
	if sh == nil {
		sh = shaper.NoopShaper{}
	}
	mc := &MorphedConn{
		Conn:    conn,
		profile: profile,
		shaper:  sh,
		// Rate limiter disabled - was causing 80 KB/s bottleneck
		rateLimiter: nil,
	}

	// --- TLS / handshake (do not touch in shaper migration) ---
	// Send magic handshake so server recognizes Morph protocol
	// Format: "MRPH" + profile name length (1 byte) + profile name + auth token (32 bytes)
	magic := []byte("MRPH")
	profileName := []byte(profile.Name)

	// Generate auth token (same as HTTP/2 Stego)
	authToken := generateAuthToken(secret)

	handshake := make([]byte, 5+len(profileName)+32)
	copy(handshake[0:4], magic)
	handshake[4] = byte(len(profileName))
	copy(handshake[5:], profileName)
	copy(handshake[5+len(profileName):], authToken)

	log.Debug("Morph: sending handshake, secret_prefix=%x..., token=%x...", secret[:min(8, len(secret))], authToken[:8])
	conn.Write(handshake)

	return mc
}

// --- Behavioral shaping (replaceable by internal/shaper) ---
//
// Everything in this section is the "shaping layer" that decides packet
// sizes, padding amounts and dummy/cover frames. Task I2 will replace this
// with a generic shaper.Shaper while keeping the wire format below stable.

// morphHeaderLen is the size of the 6-byte morph framing header
// laid out as [dataLen:4 BE][paddingLen:2 BE].
const morphHeaderLen = 6

// pickPaddingLen returns a random padding length within the profile's
// configured [MinPadding, MaxPadding] range. Non-cryptographic by design —
// padding only obscures size, it does not need to be unpredictable to an
// attacker who already sees ciphertext sizes.
func (mc *MorphedConn) pickPaddingLen() int {
	return fastRandInt(mc.profile.MinPadding, mc.profile.MaxPadding)
}

// selectPacketSize returns a packet size drawn from the profile's discrete
// size distribution (CDF lookup over PacketSizeProbs).
func (mc *MorphedConn) selectPacketSize() int {
	r := mc.randomFloat()
	cumulative := 0.0

	for i, prob := range mc.profile.PacketSizeProbs {
		cumulative += prob
		if r < cumulative {
			return mc.profile.PacketSizes[i]
		}
	}

	return mc.profile.PacketSizes[len(mc.profile.PacketSizes)-1]
}

// randomFloat returns a random float64 in [0, 1).
// Uses fast math/rand (non-cryptographic) — only feeds shaping decisions.
func (mc *MorphedConn) randomFloat() float64 {
	fastRandMu.Lock()
	f := fastRand.Float64()
	fastRandMu.Unlock()
	return f
}

// --- Wire format helpers (do not change without bumping protocol) ---
//
// These helpers encode/decode the 6-byte Morph framing header. The wire
// format is shared with already-deployed servers and must stay byte-stable
// across the shaper migration.

// writeFrameHeader serialises [dataLen:4 BE][paddingLen:2 BE] into dst[:6].
// dst must have length >= morphHeaderLen.
func writeFrameHeader(dst []byte, dataLen, paddingLen int) {
	dst[0] = byte(dataLen >> 24)
	dst[1] = byte(dataLen >> 16)
	dst[2] = byte(dataLen >> 8)
	dst[3] = byte(dataLen)
	dst[4] = byte(paddingLen >> 8)
	dst[5] = byte(paddingLen)
}

// readFrameHeader parses the 6-byte header from src[:6].
func readFrameHeader(src []byte) (dataLen, paddingLen int) {
	dataLen = int(src[0])<<24 | int(src[1])<<16 | int(src[2])<<8 | int(src[3])
	paddingLen = int(src[4])<<8 | int(src[5])
	return dataLen, paddingLen
}

// buildFrame allocates (or borrows from packetPool) a buffer holding a fully
// framed packet: [header:6][data:N][padding:M] with random padding bytes.
// fromPool indicates whether the returned slice must be released via
// packetPool.Put after use.
func buildFrame(data []byte, padLen int) (packet []byte, fromPool bool) {
	totalLen := morphHeaderLen + len(data) + padLen
	if totalLen <= 2048 {
		packet = packetPool.Get().([]byte)
		packet = packet[:totalLen]
		fromPool = true
	} else {
		packet = make([]byte, totalLen)
	}

	writeFrameHeader(packet, len(data), padLen)
	copy(packet[morphHeaderLen:morphHeaderLen+len(data)], data)
	if padLen > 0 {
		fastRandBytes(packet[morphHeaderLen+len(data):])
	}
	return packet, fromPool
}

// buildDummyFrame produces a [header:6][padding:M] frame with dataLen=0.
// Used both as a keepalive response and (historically) as cover traffic.
func (mc *MorphedConn) buildDummyFrame() []byte {
	size := mc.selectPacketSize()
	paddingLen := size - morphHeaderLen
	if paddingLen < 0 {
		paddingLen = 0
	}

	packet := make([]byte, morphHeaderLen+paddingLen)
	writeFrameHeader(packet, 0, paddingLen)
	if paddingLen > 0 {
		// Crypto-quality randomness for dummies — they go on the wire
		// without surrounding plaintext, so any bias would be observable.
		_, _ = rand.Read(packet[morphHeaderLen:])
	}
	return packet
}

// Write sends data immediately with morph framing (for TUN mode compatibility).
// Behaviour: one Write call -> one framed packet on the wire. The 4-zero-byte
// keepalive sentinel from the TUN layer is converted into a Morph dummy frame.
func (mc *MorphedConn) Write(p []byte) (int, error) {
	// Handle keepalive packet (4 zero bytes = length prefix for zero-length packet)
	// Send as Morph dummy packet which server echoes back
	if len(p) == 4 && p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 {
		dummy := mc.buildDummyFrame()
		_, err := mc.Conn.Write(dummy)
		if err != nil {
			return 0, err
		}
		return 4, nil
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Non-Noop shapers fragment + delay; Noop preserves the legacy wire layout
	// exactly (one Write -> one frame, padding from profile).
	if !isNoopShaper(mc.shaper) {
		return mc.writeShaped(p)
	}

	// Build framed packet [header:6][data:N][padding:M]
	padLen := mc.pickPaddingLen()
	packet, fromPool := buildFrame(p, padLen)

	// Apply rate limiting to evade TSPU bulk transfer detection
	// This adds jitter and micro-pauses to mimic legitimate streaming
	if mc.rateLimiter != nil {
		mc.rateLimiter.Wait(len(packet))
	}

	_, err := mc.Conn.Write(packet)

	// Return buffer to pool
	if fromPool {
		packetPool.Put(packet[:cap(packet)])
	}

	if err != nil {
		// Record failure for adaptive rate adjustment
		if mc.rateLimiter != nil {
			mc.rateLimiter.RecordFailure()
		}
		return 0, err
	}

	// Record success for adaptive rate adjustment
	if mc.rateLimiter != nil {
		mc.rateLimiter.RecordSuccess()
	}

	mc.packetsSent++
	mc.bytesSent += int64(len(packet))

	return len(p), nil
}

// Read reads and unpacks morphed data with buffering support.
// Reads header+data+padding in fewer syscalls; padding is silently dropped.
// NOTE: Rate limiting on Read creates TCP backpressure to slow down server.
func (mc *MorphedConn) Read(p []byte) (int, error) {
	// Drain anything already buffered by either path before pulling new bytes;
	// the shaper path may yield a payload larger than p in one go.
	if len(mc.readBuf) > 0 {
		n := copy(p, mc.readBuf)
		mc.readBuf = mc.readBuf[n:]
		// Apply rate limiting to downloads to create TCP backpressure
		// This slows down the server via TCP flow control
		if mc.rateLimiter != nil {
			mc.rateLimiter.Wait(n)
		}
		return n, nil
	}

	if !isNoopShaper(mc.shaper) {
		return mc.readShaped(p)
	}

	// Read packet header: [dataLen:4][paddingLen:2]
	header := make([]byte, morphHeaderLen)
	_, err := io.ReadFull(mc.Conn, header)
	if err != nil {
		return 0, err
	}
	dataLen, paddingLen := readFrameHeader(header)

	// Handle dummy packets (dataLen = 0) - these are keepalive responses
	if dataLen == 0 {
		// Discard padding
		if paddingLen > 0 {
			discard := make([]byte, paddingLen)
			io.ReadFull(mc.Conn, discard)
		}
		// Return keepalive marker (4 zero bytes) so TUN VPN knows it's a keepalive response
		if len(p) >= 4 {
			p[0], p[1], p[2], p[3] = 0, 0, 0, 0
			return 4, nil
		}
		return mc.Read(p) // Buffer too small, read next packet
	}

	// Read data+padding in single syscall to reduce latency
	totalPayload := dataLen + paddingLen
	var payload []byte
	var fromPool bool

	if totalPayload <= 2048 {
		payload = packetPool.Get().([]byte)
		payload = payload[:totalPayload]
		fromPool = true
	} else {
		payload = make([]byte, totalPayload)
	}

	n, err := io.ReadFull(mc.Conn, payload)
	if err != nil {
		if fromPool {
			packetPool.Put(payload[:cap(payload)])
		}
		return 0, err
	}

	// Extract data portion (padding is automatically discarded)
	data := payload[:dataLen]

	mc.packetsRecv++
	mc.bytesRecv += int64(n)

	// Copy what fits into p, buffer the rest
	copied := copy(p, data)
	if copied < len(data) {
		mc.readBuf = append(mc.readBuf, data[copied:]...)
	}

	// Return buffer to pool
	if fromPool {
		packetPool.Put(payload[:cap(payload)])
	}

	// Apply rate limiting to downloads to create TCP backpressure
	// This slows down the server via TCP flow control
	if mc.rateLimiter != nil {
		mc.rateLimiter.Wait(copied)
	}

	return copied, nil
}

// Close closes the underlying connection. If the async shaped-write pacer
// has been started, it is stopped first so its drain timeout has a chance
// to flush queued frames before the socket goes away.
func (mc *MorphedConn) Close() error {
	if mc.pacer != nil {
		mc.pacer.close()
	}
	return mc.Conn.Close()
}

// Stats returns traffic statistics
func (mc *MorphedConn) Stats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return mc.bytesSent, mc.bytesRecv, mc.packetsSent, mc.packetsRecv
}
