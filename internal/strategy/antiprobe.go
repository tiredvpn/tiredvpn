package strategy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// AntiProbeStrategy implements resistance to active probing
// Server appears as a normal website to unknown clients
type AntiProbeStrategy struct {
	manager      *Manager // Reference to Manager for IPv6/IPv4 support
	knockSecret  []byte
	timingWindow time.Duration
	baseStrat    Strategy

	// ECH configuration (optional)
	echEnabled    bool
	echConfigList []byte
	echPublicName string
}

// KnockSequence defines the port knocking / timing sequence
type KnockSequence struct {
	Delays []time.Duration // Delays between packets
	Sizes  []int           // Packet sizes to send
}

// NewAntiProbeStrategy creates a new anti-probe strategy
// manager is required for IPv6/IPv4 transport layer support
func NewAntiProbeStrategy(manager *Manager, secret []byte) *AntiProbeStrategy {
	return &AntiProbeStrategy{
		manager:      manager,
		knockSecret:  secret,
		timingWindow: 100 * time.Millisecond,
	}
}

// SetECH enables ECH for this strategy
func (s *AntiProbeStrategy) SetECH(configList []byte, publicName string) {
	s.echEnabled = len(configList) > 0
	s.echConfigList = configList
	s.echPublicName = publicName
}

func (s *AntiProbeStrategy) Name() string {
	return "Anti-Probe Resistance"
}

func (s *AntiProbeStrategy) ID() string {
	return "antiprobe"
}

func (s *AntiProbeStrategy) Priority() int {
	return 20
}

func (s *AntiProbeStrategy) Description() string {
	return "Server masquerades as normal website; reveals tunnel only to authenticated clients"
}

func (s *AntiProbeStrategy) RequiresServer() bool {
	return true
}

func (s *AntiProbeStrategy) Probe(ctx context.Context, target string) error {
	// Lightweight reachability check: a plain TCP connect against the same
	// address Connect uses (no TLS handshake, no knock). A full TLS dial here
	// multiplied across ProbeAll's parallel strategies and periodic reprobes
	// triggers server admission control and anti-probe defenses.
	serverAddr := s.manager.GetServerAddr(ctx)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *AntiProbeStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := s.manager.GetServerAddr(ctx)
	secret := dialSecret(ctx, s.knockSecret)
	log.Debug("AntiProbe: Using server address: %s", serverAddr)

	// Phase 1: Connect with TLS first (server requires TLS)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "www.google.com", // Mimic Google
		NextProtos:         []string{"http/1.1"},
		ClientSessionCache: s.manager.TLSSessionCache(), // resume across reconnects
	}

	var tlsConn *tls.Conn
	var err error

	// Use context-aware dialing (respects Android optimized timeouts)
	dialer := &net.Dialer{}

	// Use ECH if enabled
	if s.echEnabled && len(s.echConfigList) > 0 {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.EncryptedClientHelloConfigList = s.echConfigList

		tcpConn, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}

		tlsConn = tls.Client(tcpConn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			// Fallback to non-ECH
			tlsConfig.EncryptedClientHelloConfigList = nil
			tcpConn2, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			tlsConn = tls.Client(tcpConn2, tlsConfig)
			if err = tlsConn.HandshakeContext(ctx); err != nil {
				tcpConn2.Close()
				return nil, err
			}
		}
	} else {
		tcpConn, dialErr := dialer.DialContext(ctx, "tcp", serverAddr)
		if dialErr != nil {
			return nil, dialErr
		}
		tlsConn = tls.Client(tcpConn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, err
		}
	}

	// Phase 2: Announce the protocol via the 1-byte dispatch discriminator,
	// mirroring every other TLS strategy. Without this the server's
	// protocol.ReadDispatch consumes the first knock byte (0x00) as the
	// discriminator, desyncing knock verification and hanging the auth.
	if err := protocol.WriteDispatch(tlsConn, protocol.TypeAntiProbe); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Phase 3: Perform timing-based authentication over TLS
	if err := s.timingKnock(tlsConn, secret); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Phase 4: Verify server response
	if err := s.verifyServerAuth(tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Knock v2 wire constants. The v1 knock derived five sizes, five delays and
// every body byte from HMAC(secret, "knock-sequence") alone: nothing
// per-connection entered it, so two dials of one client produced byte-identical
// packets with identical timing. Sizes and inter-packet gaps survive the TLS
// wrapper, so that was both a stable fingerprint and a replayable credential.
//
// v2 mixes a fresh 16-byte nonce and a coarse time bucket into an HKDF, so the
// whole schedule and every body byte change per connection. The nonce and
// bucket travel in the clear at the head of packet 0 (the server needs them to
// recompute the schedule), followed by a keyed tag the server matches to pick
// the secret without trying to read a secret-dependent length first. The bucket
// bounds a replay window; the server also keeps a nonce cache inside it.
//
// Distribution note (verification.md rule 3): the knock imitates no real
// protocol, so there is no measured population its sizes or delays are checked
// against — recorded here as "сверять не с чем". The sizes are drawn flat over
// [KnockSizeMin, KnockSizeMin+knockSizeSpan) from a CSPRNG-seeded HKDF; the
// delays are flat over [knockDelayMinMs, +knockDelaySpanMs) ms. The delays are
// uniform jitter on the time axis, which rule 3 warns has no natural shape; the
// server does not verify timing at all (it reads with per-packet deadlines), so
// the gaps are spacing, not a checked credential. They are kept per-connection
// only so they stop repeating; their absolute shape is not claimed to match
// anything.
const (
	KnockPackets   = 5                     // packets in a knock
	KnockNonceLen  = 16                    // per-connection nonce, carried in packet 0
	KnockTagLen    = 16                    // keyed tag after the header in packet 0
	KnockHeaderLen = 1 + 8 + KnockNonceLen // seq(1) + bucket(8) + nonce(16) = 25

	knockBucketSeconds = 30 // time-bucket granularity (seconds)
	// KnockBucketGrace is how many buckets on each side of "now" the server
	// accepts, bounding the replay window to (2*grace+1) buckets.
	KnockBucketGrace = 2

	knockSizeMin     = 48 // packet 0 must hold header(25)+tag(16)=41, so min > 41
	knockSizeSpan    = 88 // sizes flat over [48,136)
	knockDelayMinMs  = 20
	knockDelaySpanMs = 80 // delays flat over [20,100) ms

	knockScheduleLabel = "tiredvpn-knock-v2-schedule"
	knockTagLabel      = "tiredvpn-knock-v2-tag"
	knockBodyLabel     = "tiredvpn-knock-v2-body"
)

// timingKnock performs the per-connection knock sequence.
func (s *AntiProbeStrategy) timingKnock(conn net.Conn, secret []byte) error {
	nonce := make([]byte, KnockNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	bucket := KnockBucketNow()
	seq := knockSchedule(secret, nonce, bucket)
	tag := KnockTag(secret, nonce, bucket)

	for i := 0; i < KnockPackets; i++ {
		time.Sleep(seq.Delays[i])

		packet := make([]byte, seq.Sizes[i])
		packet[0] = byte(i) // sequence number

		if i == 0 {
			binary.BigEndian.PutUint64(packet[1:9], uint64(bucket))
			copy(packet[9:KnockHeaderLen], nonce)
			copy(packet[KnockHeaderLen:KnockHeaderLen+KnockTagLen], tag)
			copy(packet[KnockHeaderLen+KnockTagLen:], KnockBody(secret, nonce, bucket, 0, seq.Sizes[0]-KnockHeaderLen-KnockTagLen))
		} else {
			copy(packet[1:], KnockBody(secret, nonce, bucket, i, seq.Sizes[i]-1))
		}

		if _, err := conn.Write(packet); err != nil {
			return err
		}
	}

	// Wait for ACK
	ack := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, ack); err != nil {
		return errors.New("timing knock not acknowledged")
	}

	if ack[0] != 0x01 {
		return errors.New("invalid knock response")
	}

	conn.SetReadDeadline(time.Time{})
	return nil
}

// KnockBucketNow returns the current knock time bucket.
func KnockBucketNow() int64 { return time.Now().Unix() / knockBucketSeconds }

// KnockBucketFresh reports whether bucket is inside the accepted replay window
// around the current time. The client sends its own bucket; the server both
// derives the schedule from it and rejects it once it drifts outside the window.
func KnockBucketFresh(bucket int64) bool {
	now := time.Now().Unix() / knockBucketSeconds
	return bucket >= now-KnockBucketGrace && bucket <= now+KnockBucketGrace
}

func knockBucketBytes(bucket int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(bucket))
	return b
}

func knockInfo(label string, bucket int64) []byte {
	info := make([]byte, 0, len(label)+8)
	info = append(info, label...)
	return append(info, knockBucketBytes(bucket)...)
}

// knockSchedule derives this connection's packet sizes and inter-packet delays
// from the secret, the per-connection nonce and the time bucket.
func knockSchedule(secret, nonce []byte, bucket int64) *KnockSequence {
	r := hkdf.New(sha256.New, secret, nonce, knockInfo(knockScheduleLabel, bucket))
	raw := make([]byte, 2*KnockPackets)
	_, _ = io.ReadFull(r, raw)

	sizes := make([]int, KnockPackets)
	delays := make([]time.Duration, KnockPackets)
	for i := 0; i < KnockPackets; i++ {
		sizes[i] = knockSizeMin + int(raw[i])%knockSizeSpan
		delays[i] = time.Duration(knockDelayMinMs+int(raw[KnockPackets+i])%knockDelaySpanMs) * time.Millisecond
	}
	return &KnockSequence{Delays: delays, Sizes: sizes}
}

// KnockScheduleFor exposes the per-connection sizes and delays so the server and
// the wire tests can recompute the schedule from a captured nonce and bucket.
func KnockScheduleFor(secret, nonce []byte, bucket int64) *KnockSequence {
	return knockSchedule(secret, nonce, bucket)
}

// KnockTag derives the keyed tag that sits after the header in packet 0. The
// server matches it to pick the client's secret without first having to read a
// secret-dependent packet length.
func KnockTag(secret, nonce []byte, bucket int64) []byte {
	r := hkdf.New(sha256.New, secret, nonce, knockInfo(knockTagLabel, bucket))
	out := make([]byte, KnockTagLen)
	_, _ = io.ReadFull(r, out)
	return out
}

// KnockBody derives the body bytes for packet seqNum. Each packet uses an
// independent HKDF stream keyed by the nonce, bucket and sequence number, so the
// bodies are per-connection and per-packet.
func KnockBody(secret, nonce []byte, bucket int64, seqNum, bodyLen int) []byte {
	if bodyLen <= 0 {
		return nil
	}
	info := knockInfo(knockBodyLabel, bucket)
	info = append(info, byte(seqNum))
	r := hkdf.New(sha256.New, secret, nonce, info)
	out := make([]byte, bodyLen)
	_, _ = io.ReadFull(r, out)
	return out
}

// verifyServerAuth verifies server recognized us
// After timing knock ACK, server is ready for tunnel - just return success
func (s *AntiProbeStrategy) verifyServerAuth(conn *tls.Conn) error {
	// Server already sent 0x01 ACK in timingKnock, now ready for tunnel
	return nil
}
