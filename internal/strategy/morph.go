package strategy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"math"
	mathrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// TrafficMorphStrategy morphs traffic to match target application patterns
// Makes VPN traffic statistically indistinguishable from YouTube/Yandex.Video
type TrafficMorphStrategy struct {
	manager   *Manager // Reference to Manager for IPv6/IPv4 support
	profile   *TrafficProfile
	baseStrat Strategy // Underlying strategy (e.g., gRPC tunnel)
	secret    []byte   // Secret for authentication
}

// TrafficProfile defines statistical properties of traffic to mimic
type TrafficProfile struct {
	Name string

	// Packet size distribution (histogram buckets)
	PacketSizes     []int     // Bucket centers
	PacketSizeProbs []float64 // Probability for each bucket

	// Inter-arrival time distribution (milliseconds)
	InterArrivalMean   float64
	InterArrivalStdDev float64

	// Burst patterns
	BurstSize     int           // Packets per burst
	BurstInterval time.Duration // Time between bursts

	// Direction ratio (download/upload)
	DownUpRatio float64

	// Padding behavior
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
		BurstSize:          30,
		BurstInterval:      150 * time.Millisecond,
		DownUpRatio:        15.0,
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
		BurstSize:          25,
		BurstInterval:      180 * time.Millisecond,
		DownUpRatio:        12.0,
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
		BurstSize:          20,
		BurstInterval:      200 * time.Millisecond,
		DownUpRatio:        10.0,
		MinPadding:         40,
		MaxPadding:         180,
	}

	VKVideoProfile = &TrafficProfile{
		Name:               "VK Video",
		PacketSizes:        []int{150, 500, 1000, 1400},
		PacketSizeProbs:    []float64{0.08, 0.15, 0.32, 0.45},
		InterArrivalMean:   6.0,
		InterArrivalStdDev: 18.0,
		BurstSize:          40,
		BurstInterval:      120 * time.Millisecond,
		DownUpRatio:        18.0,
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
		BurstSize:          10,
		BurstInterval:      500 * time.Millisecond,
		DownUpRatio:        5.0,
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
		BurstSize:          1,
		BurstInterval:      20 * time.Millisecond,
		DownUpRatio:        1.0, // Symmetric
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

// MorphedConn wraps a connection with traffic morphing
type MorphedConn struct {
	net.Conn
	profile *TrafficProfile

	// Write scheduling
	writeMu     sync.Mutex
	writeQueue  [][]byte
	writeTicker *time.Ticker
	writeStop   chan struct{}

	// Read buffer for partial reads
	readBuf []byte

	// Statistics tracking
	bytesSent   int64
	bytesRecv   int64
	packetsSent int64
	packetsRecv int64

	// Burst control
	burstCounter int
	lastBurst    time.Time

	// Rate limiting for TSPU evasion
	rateLimiter *evasion.AdaptiveRateLimiter
}

// NetConn returns the underlying net.Conn for TCP optimization
func (mc *MorphedConn) NetConn() net.Conn {
	return mc.Conn
}

// NewMorphedConn creates a morphed connection
func NewMorphedConn(conn net.Conn, profile *TrafficProfile, secret []byte) *MorphedConn {
	mc := &MorphedConn{
		Conn:       conn,
		profile:    profile,
		writeQueue: make([][]byte, 0),
		writeStop:  make(chan struct{}),
		lastBurst:  time.Now(),
		// Rate limiter disabled - was causing 80 KB/s bottleneck
		rateLimiter: nil,
	}

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

	// NOTE: writeScheduler disabled for TUN mode compatibility
	// TUN mode uses synchronous Write() directly without queue/scheduler
	// The scheduler's dummy packets interfere with TLS causing "bad record MAC" errors

	return mc
}

// writeScheduler sends packets according to profile timing
func (mc *MorphedConn) writeScheduler() {
	for {
		select {
		case <-mc.writeStop:
			return
		case <-mc.writeTicker.C:
			mc.writeMu.Lock()
			if len(mc.writeQueue) > 0 {
				// Send next packet
				packet := mc.writeQueue[0]
				mc.writeQueue = mc.writeQueue[1:]
				mc.writeMu.Unlock()

				mc.Conn.Write(packet)
				mc.packetsSent++
				mc.bytesSent += int64(len(packet))
			} else {
				mc.writeMu.Unlock()

				// Send dummy packet to maintain pattern
				if mc.shouldSendDummy() {
					dummy := mc.generateDummy()
					mc.Conn.Write(dummy)
					mc.packetsSent++
				}
			}

			// Adjust timing with jitter
			jitter := mc.gaussianRandom(0, mc.profile.InterArrivalStdDev)
			nextInterval := mc.profile.InterArrivalMean + jitter
			if nextInterval < 1 {
				nextInterval = 1
			}
			mc.writeTicker.Reset(time.Duration(nextInterval) * time.Millisecond)
		}
	}
}

// Write sends data immediately with morph framing (for TUN mode compatibility)
// Note: This bypasses the async queue for immediate delivery
// OPTIMIZED: Uses buffer pool, fast RNG, single write syscall
func (mc *MorphedConn) Write(p []byte) (int, error) {
	// Handle keepalive packet (4 zero bytes = length prefix for zero-length packet)
	// Send as Morph dummy packet which server echoes back
	if len(p) == 4 && p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 {
		dummy := mc.generateDummy()
		_, err := mc.Conn.Write(dummy)
		if err != nil {
			return 0, err
		}
		return 4, nil
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Send immediately with morph framing (don't fragment for TUN mode)
	// Format: [dataLen:4][paddingLen:2][data:N][padding:M]

	// OPTIMIZATION 1: Use fast math/rand instead of crypto/rand (10× faster)
	padLen := fastRandInt(mc.profile.MinPadding, mc.profile.MaxPadding)

	totalLen := 6 + len(p) + padLen

	// OPTIMIZATION 2: Use buffer pool to reduce GC pressure
	var packet []byte
	var fromPool bool
	if totalLen <= 2048 {
		packet = packetPool.Get().([]byte)
		packet = packet[:totalLen]
		fromPool = true
	} else {
		packet = make([]byte, totalLen)
	}

	// Data length header
	packet[0] = byte(len(p) >> 24)
	packet[1] = byte(len(p) >> 16)
	packet[2] = byte(len(p) >> 8)
	packet[3] = byte(len(p))

	// Padding length header
	packet[4] = byte(padLen >> 8)
	packet[5] = byte(padLen)

	// Data
	copy(packet[6:6+len(p)], p)

	// OPTIMIZATION 3: Fast random padding (non-cryptographic is fine for padding)
	if padLen > 0 {
		fastRandBytes(packet[6+len(p):])
	}

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

// fragmentToProfile splits data into packets matching size distribution
func (mc *MorphedConn) fragmentToProfile(data []byte) [][]byte {
	var packets [][]byte
	offset := 0

	for offset < len(data) {
		// Select packet size based on profile distribution
		targetSize := mc.selectPacketSize()

		// Add padding
		padding := mc.randomInt(mc.profile.MinPadding, mc.profile.MaxPadding)

		// Calculate actual data size
		// Header is 6 bytes: [dataLen:4][paddingLen:2]
		dataSize := targetSize - padding - 6
		if dataSize < 1 {
			dataSize = 1
		}
		if offset+dataSize > len(data) {
			dataSize = len(data) - offset
		}

		// Build packet: [dataLen:4][paddingLen:2][data:N][padding:M]
		packet := make([]byte, 6+dataSize+padding)

		// Data length header
		packet[0] = byte(dataSize >> 24)
		packet[1] = byte(dataSize >> 16)
		packet[2] = byte(dataSize >> 8)
		packet[3] = byte(dataSize)

		// Padding length header
		packet[4] = byte(padding >> 8)
		packet[5] = byte(padding)

		// Data
		copy(packet[6:6+dataSize], data[offset:offset+dataSize])

		// Random padding
		rand.Read(packet[6+dataSize:])

		packets = append(packets, packet)
		offset += dataSize
	}

	return packets
}

// selectPacketSize returns a packet size based on profile distribution
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

// Read reads and unpacks morphed data with buffering support
// OPTIMIZED: Reads header+data+padding in fewer syscalls
// NOTE: Rate limiting on Read creates TCP backpressure to slow down server
func (mc *MorphedConn) Read(p []byte) (int, error) {
	// If we have buffered data, return from buffer first
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

	// OPTIMIZATION: Read packet header: [dataLen:4][paddingLen:2]
	header := make([]byte, 6)
	_, err := io.ReadFull(mc.Conn, header)
	if err != nil {
		return 0, err
	}

	// Parse lengths
	dataLen := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	paddingLen := int(header[4])<<8 | int(header[5])

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

	// OPTIMIZATION 4: Read data+padding in single syscall to reduce latency
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

// shouldSendDummy decides if a dummy packet should be sent
func (mc *MorphedConn) shouldSendDummy() bool {
	// Maintain minimum packet rate
	return mc.randomFloat() < 0.1 // 10% chance
}

// generateDummy creates a dummy packet
func (mc *MorphedConn) generateDummy() []byte {
	size := mc.selectPacketSize()
	paddingLen := size - 6 // Header is 6 bytes
	if paddingLen < 0 {
		paddingLen = 0
	}

	packet := make([]byte, 6+paddingLen)

	// Data length = 0 (dummy)
	packet[0], packet[1], packet[2], packet[3] = 0, 0, 0, 0

	// Padding length
	packet[4] = byte(paddingLen >> 8)
	packet[5] = byte(paddingLen)

	// Random padding
	rand.Read(packet[6:])
	return packet
}

// gaussianRandom generates a random number with Gaussian distribution
func (mc *MorphedConn) gaussianRandom(mean, stddev float64) float64 {
	// Box-Muller transform
	u1 := mc.randomFloat()
	u2 := mc.randomFloat()

	if u1 == 0 {
		u1 = 0.0001
	}

	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	return mean + z*stddev
}

// randomFloat returns a random float64 in [0, 1)
// OPTIMIZED: Uses fast math/rand instead of crypto/rand
func (mc *MorphedConn) randomFloat() float64 {
	fastRandMu.Lock()
	f := fastRand.Float64()
	fastRandMu.Unlock()
	return f
}

// randomInt returns a random int in [min, max]
// OPTIMIZED: Uses fast math/rand instead of crypto/rand
func (mc *MorphedConn) randomInt(min, max int) int {
	if max <= min {
		return min
	}
	return fastRandInt(min, max)
}

// Close stops the scheduler and closes connection
func (mc *MorphedConn) Close() error {
	select {
	case <-mc.writeStop:
		// Already closed
	default:
		close(mc.writeStop)
	}
	if mc.writeTicker != nil {
		mc.writeTicker.Stop()
	}
	return mc.Conn.Close()
}

// Stats returns traffic statistics
func (mc *MorphedConn) Stats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return mc.bytesSent, mc.bytesRecv, mc.packetsSent, mc.packetsRecv
}
