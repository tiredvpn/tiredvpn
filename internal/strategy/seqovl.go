package strategy

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"net"
	"sync"
	"sync/atomic"

	"github.com/tiredvpn/tiredvpn/internal/geneva"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// seqovlPacketSalt is the HMAC domain separator for the packet-level (level A)
// overlap marker. Distinct from the app-framing decoy salt so the two layers
// never share a marker.
const seqovlPacketSalt = "tiredvpn-seqovl-packet-v1"

// seqovlPacketMarker derives the OverlapMarkerLen-byte marker embedded in the
// packet-level fake segment: HMAC-SHA256(secret, packetSalt)[:32].
func seqovlPacketMarker(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(seqovlPacketSalt))
	return mac.Sum(nil)[:geneva.OverlapMarkerLen]
}

// seqovlDecoySalt is the HMAC domain separator for the seqovl decoy marker.
// The server (internal/server/seqovl.go) must agree on this exact value.
const seqovlDecoySalt = "tiredvpn-seqovl-decoy-v1"

const (
	seqovlNonceLen  = 16
	seqovlMarkerLen = 32
	seqovlMinJunk   = 32
	seqovlMaxJunk   = 224
)

// seqovlMarker computes the per-connection decoy marker
// HMAC-SHA256(secret, salt||nonce)[:32]. The secret is the pre-shared VPN
// password, so a DPI box cannot forge or recognise the marker without it.
func seqovlMarker(secret, nonce []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(seqovlDecoySalt))
	mac.Write(nonce)
	return mac.Sum(nil)[:seqovlMarkerLen]
}

// buildSeqovlDecoy builds a single junk TLS handshake record (content-type
// 0x16) carrying a secret-derived marker. Wire layout of the record payload:
// [nonce:16][marker:32][junk:N]. nonce, junk bytes and junk length are
// randomized per connection so the decoy never repeats (defeats ML fingerprint
// on a static pattern). nonce[0] is forced != 0x01 so the record's first
// payload byte is never a ClientHello handshake type: this both steers a
// stateful DPI reassembler off the real ClientHello and lets the server reject
// non-decoys with an O(1) gate before doing any HMAC work.
func buildSeqovlDecoy(secret []byte) []byte {
	nonce := make([]byte, seqovlNonceLen)
	_, _ = cryptorand.Read(nonce)
	if nonce[0] == 0x01 {
		nonce[0] ^= 0xFF
	}
	marker := seqovlMarker(secret, nonce)

	var rb [1]byte
	_, _ = cryptorand.Read(rb[:])
	junkLen := seqovlMinJunk + int(rb[0])%(seqovlMaxJunk-seqovlMinJunk+1)
	junk := make([]byte, junkLen)
	_, _ = cryptorand.Read(junk)

	payloadLen := seqovlNonceLen + seqovlMarkerLen + junkLen
	rec := make([]byte, 5+payloadLen)
	rec[0] = 0x16 // handshake content type
	rec[1] = 0x03 // TLS 1.x major
	rec[2] = 0x03 // TLS 1.2 record version (typical for a ClientHello record)
	rec[3] = byte(payloadLen >> 8)
	rec[4] = byte(payloadLen)
	copy(rec[5:], nonce)
	copy(rec[5+seqovlNonceLen:], marker)
	copy(rec[5+seqovlNonceLen+seqovlMarkerLen:], junk)
	return rec
}

// seqovlConn wraps a raw TCP conn and prepends the decoy record before the very
// first write (the ClientHello first flight). After that it is a transparent
// pass-through, so all subsequent REALITY framing/mux traffic is unaffected.
type seqovlConn struct {
	net.Conn
	secret     []byte
	firstWrite bool
}

func newSeqovlConn(conn net.Conn, secret []byte) *seqovlConn {
	return &seqovlConn{Conn: conn, secret: secret, firstWrite: true}
}

func (c *seqovlConn) Write(p []byte) (int, error) {
	if c.firstWrite {
		c.firstWrite = false
		decoy := buildSeqovlDecoy(c.secret)
		// TCP_NODELAY is already set on the raw conn, so the decoy leaves as its
		// own segment ahead of the real first flight.
		if _, err := c.Conn.Write(decoy); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}

var _ net.Conn = (*seqovlConn)(nil)

// SeqovlStrategy implements the seqovl (TCP sequence overlap) strategy, level B
// app-framing variant: it rides the REALITY handshake but prepends a
// secret-marked decoy TLS record before the ClientHello. A stateful DPI
// reassembler classifies on the decoy junk (which is not a ClientHello) and
// misses the real REALITY handshake, while our cooperating server recognises the
// marker and drops the decoy before REALITY parsing. Cross-platform, including
// Android (only needs a protected kernel-TCP net.Conn).
type SeqovlStrategy struct {
	reality *REALITYStrategy
	secret  []byte

	// packetEnabled turns on the best-effort level-A packet overlap (Linux +
	// CAP_NET_ADMIN). The app-framing decoy (level B) always runs regardless, so
	// packet-level is purely additive and never a downgrade.
	packetEnabled bool

	// Packet-level (level A) injector state; only touched on Linux.
	injector     *geneva.Injector
	injectorOnce sync.Once
	injectorStop context.CancelFunc
	packetActive atomic.Bool
}

// NewSeqovlStrategy creates a seqovl strategy over its own REALITY handshake.
// packetEnabled requests the level-A packet overlap in addition to the
// always-on level-B app-framing decoy.
func NewSeqovlStrategy(manager *Manager, secret []byte, packetEnabled bool) *SeqovlStrategy {
	return &SeqovlStrategy{
		reality:       NewREALITYStrategy(manager, secret),
		secret:        secret,
		packetEnabled: packetEnabled,
	}
}

// SetFingerprint forwards the configured uTLS profile to the REALITY handshake
// seqovl rides on, so both strategies present the same ClientHello. Two
// strategies from one client showing different fingerprints to the same donor
// SNI would be a signal in itself.
func (s *SeqovlStrategy) SetFingerprint(name string) { s.reality.SetFingerprint(name) }

// Name returns the human-readable strategy name.
func (s *SeqovlStrategy) Name() string { return "Seqovl" }

// ID returns the strategy identifier.
func (s *SeqovlStrategy) ID() string { return "seqovl" }

// Priority ranks seqovl just below the REALITY baseline (5) and above Traffic
// Morph (10), so it never preempts REALITY as the default strategy.
func (s *SeqovlStrategy) Priority() int { return 7 }

// RequiresServer indicates seqovl needs cooperating server support (decoy drop).
func (s *SeqovlStrategy) RequiresServer() bool { return true }

// Description returns a human-readable description.
func (s *SeqovlStrategy) Description() string {
	return "Seqovl (TCP sequence overlap, app-framing): prepends a secret-marked decoy TLS record before the REALITY ClientHello to desync stateful DPI reassembly"
}

// Probe reuses the underlying REALITY reachability probe (shallow TCP connect).
func (s *SeqovlStrategy) Probe(ctx context.Context, target string) error {
	return s.reality.Probe(ctx, target)
}

// Connect dials the REALITY handshake with the decoy prefix wrapper installed on
// the first flight.
func (s *SeqovlStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Level A (packet overlap) is additive and best-effort: it needs Linux +
	// CAP_NET_ADMIN and an operator-provisioned OUTPUT NFQUEUE rule. On Android /
	// unprivileged hosts tryStartPacketOverlap is a no-op and we ride level B
	// alone. Either way the app-framing decoy below always runs.
	if s.packetEnabled {
		s.tryStartPacketOverlap()
	}
	log.Debug("Seqovl: connecting to %s (decoy prefix + REALITY, packet=%v)", target, s.packetActive.Load())
	return s.reality.connect(ctx, target, func(c net.Conn) net.Conn {
		return newSeqovlConn(c, s.secret)
	})
}

// Close releases the level-A injector if one was started. Safe to call multiple
// times and on strategies that never enabled packet mode.
func (s *SeqovlStrategy) Close() {
	if s.injectorStop != nil {
		s.injectorStop()
		s.injectorStop = nil
	}
	if s.injector != nil {
		s.injector.Stop()
		s.injector = nil
	}
}

var _ Strategy = (*SeqovlStrategy)(nil)
