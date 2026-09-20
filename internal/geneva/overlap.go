package geneva

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
)

// seqovl (TCP sequence overlap), level A packet-level primitive.
//
// The idea: right before the real first data segment (the REALITY ClientHello)
// leaves the host, emit a *fake* segment whose sequence number is backed up to
// the left by `OverlapLen` bytes and whose payload is secret-marked junk. The
// fake is put on the wire first, the real segment follows unchanged.
//
// Both tunnel endpoints are ours, so we do not need zapret's fooling arsenal
// (badsum / badttl) to keep the fake away from the server. With the default
// safe geometry (FakeLen == OverlapLen) the whole fake sits strictly below the
// server's rcv_nxt (the ClientHello's seq), so the cooperating server's own
// kernel treats it as already-acknowledged/duplicate data and discards it -
// the application only ever sees the clean real stream. A stateful DPI
// reassembler, however, ingests the fake from its lower sequence number and
// desyncs its TLS-record framing off the real ClientHello.
//
// The larger, "overlap-into-ClientHello" geometry (FakeLen > OverlapLen) is
// stronger against first-seen-wins reassemblers but delivers junk into the
// server's real stream, so it additionally requires the server-side NFQUEUE
// drop (see OverlapServerDropper). FakeLen is therefore configurable but
// defaults to the safe value.
const (
	overlapMinLen = 48
	overlapMaxLen = 200
	// OverlapMarkerLen is the length of the secret-derived marker embedded at
	// the start of the fake payload so a cooperating server can positively
	// identify (and drop) the fake segment.
	OverlapMarkerLen = 32
	// overlapFiredCap bounds the per-connection fired-set so a long-lived client
	// with connection churn cannot grow it without limit. Clearing it only lets a
	// later connection on a reused 4-tuple emit one more (harmless) fake segment.
	overlapFiredCap = 8192
)

// OverlapPrimitive builds and prepends a fake overlapping TCP segment before the
// first data-bearing segment it sees.
type OverlapPrimitive struct {
	// OverlapLen is how many bytes the fake segment's sequence number is backed
	// up (to the left) relative to the real segment.
	OverlapLen int
	// FakeLen is the fake segment's TCP payload length. Defaults to OverlapLen
	// (safe geometry: the fake stays entirely below the server's rcv_nxt).
	FakeLen int
	// Marker is the secret-derived tag written at the start of the fake payload.
	// Used only when MintMarker is nil (static marker, e.g. in tests). Production
	// clients set MintMarker so every connection carries a fresh nonce.
	Marker []byte
	// MintMarker, when set, produces a fresh OverlapMarkerLen-byte marker for each
	// fake segment emitted. This is how the packet-level overlap gets a
	// per-connection nonce: one NFQUEUE hook serves the whole process, but the
	// primitive mints a new [nonce||HMAC(secret,salt||nonce)] marker every time it
	// fires on a new connection, so the fake segments are not a single fixed value
	// a censor can fingerprint. Returning an empty slice suppresses the fake for
	// that segment (e.g. on an RNG failure) and the real segment passes untouched.
	MintMarker func() []byte
	// JunkByte fills the fake payload after the marker.
	JunkByte byte
	// Once, when true, emits at most one fake segment per connection (keyed by the
	// TCP 4-tuple): the first data-bearing segment of each connection is
	// transformed, later segments of the same connection pass through untouched.
	// This targets each connection's ClientHello and leaves the rest alone, while
	// still covering every connection the process opens.
	Once bool

	firedConns sync.Map // 4-tuple key -> struct{}; connections already given a fake
	firedCount atomic.Int64
}

// NewOverlapPrimitive creates a per-connection-randomized OverlapPrimitive with
// the safe geometry (FakeLen == OverlapLen). marker is the secret-derived tag
// (OverlapMarkerLen bytes) that lets the server recognise the fake.
func NewOverlapPrimitive(marker []byte) *OverlapPrimitive {
	var rb [2]byte
	_, _ = cryptorand.Read(rb[:])
	overlap := overlapMinLen + int(rb[0])%(overlapMaxLen-overlapMinLen+1)
	overlap = max(overlap, len(marker))
	return &OverlapPrimitive{
		OverlapLen: overlap,
		FakeLen:    overlap,
		Marker:     marker,
		JunkByte:   rb[1],
		Once:       true,
	}
}

// NewOverlapPrimitiveMinted creates a per-connection-randomized OverlapPrimitive
// with the safe geometry (FakeLen == OverlapLen) that mints a fresh marker for
// every connection via mint. mint must return an OverlapMarkerLen-byte marker (or
// an empty slice to suppress the fake for that segment). Unlike the static-marker
// NewOverlapPrimitive, this gives each connection's fake segment its own nonce.
func NewOverlapPrimitiveMinted(mint func() []byte) *OverlapPrimitive {
	var rb [2]byte
	_, _ = cryptorand.Read(rb[:])
	overlap := overlapMinLen + int(rb[0])%(overlapMaxLen-overlapMinLen+1)
	overlap = max(overlap, OverlapMarkerLen)
	return &OverlapPrimitive{
		OverlapLen: overlap,
		FakeLen:    overlap,
		MintMarker: mint,
		JunkByte:   rb[1],
		Once:       true,
	}
}

// Apply emits [fake, real] for the first data-bearing segment (fake first so it
// precedes the real segment on the wire). Segments with no TCP payload, or any
// segment after the first when Once is set, pass through unchanged.
func (o *OverlapPrimitive) Apply(packet []byte) ([][]byte, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short for IP header")
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return nil, errors.New("packet too short for TCP header")
	}
	tcpStart := ipHeaderLen
	tcpHeaderLen := int((packet[tcpStart+12] >> 4) * 4)
	payloadStart := tcpStart + tcpHeaderLen

	// No payload (pure ACK, SYN, etc.): nothing to overlap.
	if len(packet) <= payloadStart {
		return [][]byte{packet}, nil
	}

	// Fire at most once per connection (keyed by the TCP 4-tuple), not once per
	// process: every connection's first data segment gets its own fake, so the
	// per-connection nonce below is actually reached for each connection.
	if o.Once {
		key := overlapConnKey(packet, tcpStart)
		if _, loaded := o.firedConns.LoadOrStore(key, struct{}{}); loaded {
			return [][]byte{packet}, nil
		}
		if o.firedCount.Add(1) > overlapFiredCap {
			o.firedConns.Range(func(k, _ any) bool { o.firedConns.Delete(k); return true })
			o.firedCount.Store(0)
		}
	}

	// Mint a fresh marker per fake segment when a minter is set; this is what
	// gives each connection its own nonce. An empty marker means "suppress" (e.g.
	// RNG failure): send the real segment through untouched rather than a fake
	// with a stale or empty marker.
	marker := o.Marker
	if o.MintMarker != nil {
		marker = o.MintMarker()
		if len(marker) == 0 {
			return [][]byte{packet}, nil
		}
	}

	overlapLen := o.OverlapLen
	if overlapLen <= 0 {
		overlapLen = overlapMinLen
	}
	fakeLen := o.FakeLen
	if fakeLen <= 0 {
		fakeLen = overlapLen
	}
	if fakeLen < len(marker) {
		fakeLen = len(marker)
	}

	// Build the fake segment: copy the real IP+TCP headers, then a marked junk
	// payload, then fix seq / IP length / checksums.
	fake := make([]byte, payloadStart+fakeLen)
	copy(fake, packet[:payloadStart])
	copy(fake[payloadStart:], marker)
	for i := payloadStart + len(marker); i < len(fake); i++ {
		fake[i] = o.JunkByte
	}

	seq := binary.BigEndian.Uint32(fake[tcpStart+4:])
	seq -= uint32(overlapLen) // seq space wraps mod 2^32 - intended
	binary.BigEndian.PutUint32(fake[tcpStart+4:], seq)

	binary.BigEndian.PutUint16(fake[2:4], uint16(len(fake)))
	recalculateIPChecksum(fake)
	recalculateTCPChecksum(fake)

	// The real segment goes out unchanged, after the fake.
	realSeg := make([]byte, len(packet))
	copy(realSeg, packet)

	return [][]byte{fake, realSeg}, nil
}

// String returns a human-readable description.
func (o *OverlapPrimitive) String() string {
	return "overlap{len=" + strconv.Itoa(o.OverlapLen) + "}"
}

// NewOverlapStrategy wraps an OverlapPrimitive in a Geneva Strategy triggered by
// an outbound TCP segment whose payload begins a TLS handshake record (the
// ClientHello). Only the outbound tree is set; inbound traffic is untouched.
func NewOverlapStrategy(prim *OverlapPrimitive) *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "payload",
		Operator: "contains",
		Value:    []byte{0x16, 0x03}, // TLS record: handshake, version 3.x
	}
	return NewStrategy(trigger, NewActionTree(prim), nil)
}

// OverlapPayloadHasMarker reports whether a TCP payload starts with marker.
// Used by the (cooperating) server side to positively identify a seqovl fake
// segment before dropping it.
func OverlapPayloadHasMarker(payload, marker []byte) bool {
	if len(marker) == 0 || len(payload) < len(marker) {
		return false
	}
	// Constant-time-ish equality on a fixed-length prefix; the marker is secret.
	var diff byte
	for i := range marker {
		diff |= payload[i] ^ marker[i]
	}
	return diff == 0
}

// overlapConnKey builds a stable per-connection key from the TCP 4-tuple
// (src IP, dst IP, src port, dst port) of an IPv4 packet. Used by Apply to fire
// the overlap at most once per connection.
func overlapConnKey(packet []byte, tcpStart int) string {
	var k [12]byte
	copy(k[0:4], packet[12:16])                   // src IP
	copy(k[4:8], packet[16:20])                   // dst IP
	copy(k[8:10], packet[tcpStart:tcpStart+2])    // src port
	copy(k[10:12], packet[tcpStart+2:tcpStart+4]) // dst port
	return string(k[:])
}
