package tun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Auto-MTU active probe.
//
// The probe rides inside the ordinary tunnel data channel ([len:4][payload:N]).
// A control frame is distinguished from a real IP packet (version nibble 0x4/0x6)
// and from a keepalive (len==0) by a strict marker: byte0 0x10 (version nibble
// 0x1 -> never a valid IPv4/IPv6 header) plus magic "MT" plus a type byte.
//
// Client sends PROBE_REQUEST of a given size; the exit reflects a PROBE_REPLY of
// the identical size (echoing seq/nonce). A reply that returns proves the path
// (including relay stego reframing) carries a frame of that size end-to-end, so
// the inner MTU candidate is exactly that size. See
// research/auto-mtu-design-2026-06-28.md.
const (
	probeMarker      = 0x10
	probeTypeRequest = 0x01
	probeTypeReply   = 0x02
	probeHeaderLen   = 16

	// MTUFloor is the IPv6 minimum MTU. It is assumed always reachable and is
	// never probed below.
	MTUFloor = 1280

	defaultProbeStep    = 8
	defaultProbeRetries = 2
	minProbeTimeout     = 500 * time.Millisecond

	// fastProbeDeadline bounds the synchronous connect-time probe of cap so a
	// blackhole path never adds more than this to connect latency.
	fastProbeDeadline = 500 * time.Millisecond
)

var probeMagic = [2]byte{'M', 'T'}

// ProbeCapFlag is the handshake-response flag bit (resp[9]) by which an exit
// advertises auto-MTU echo support.
const ProbeCapFlag = 0x02

// IsProbeFrame reports whether a tunnel data payload is an auto-MTU control frame
// (marker 0x10 + magic "MT"). Exported for the server data path.
func IsProbeFrame(p []byte) bool { return isProbeFramePayload(p) }

// MakeProbeReply turns a received PROBE_REQUEST payload into a same-size
// PROBE_REPLY (echoing seq/size/nonce), or nil if p is not a valid request.
// Exported for the exit echo hooks.
func MakeProbeReply(p []byte) []byte { return makeProbeReply(p) }

// isProbeFramePayload reports whether a tunnel data payload is an MTU control
// frame. Cheap marker-only check used on the server data path before any IP
// handling. It deliberately does not validate type/size so the caller can decide.
func isProbeFramePayload(p []byte) bool {
	return len(p) >= probeHeaderLen &&
		p[0] == probeMarker && p[1] == probeMagic[0] && p[2] == probeMagic[1]
}

type probeFrame struct {
	typ   byte
	seq   uint16
	size  uint16
	nonce [8]byte
}

// encodeProbeFrame builds a control-frame payload whose total length is size.
// size is clamped to [probeHeaderLen, 65535]. Bytes after the 16-byte header are
// left zero (padding). The caller frames it with the [len:4] length prefix, so on
// the wire the probe is byte-for-byte a data frame carrying a size-byte packet.
func encodeProbeFrame(typ byte, seq uint16, size int, nonce [8]byte) []byte {
	if size < probeHeaderLen {
		size = probeHeaderLen
	}
	if size > 65535 {
		size = 65535
	}
	p := make([]byte, size)
	p[0] = probeMarker
	p[1] = probeMagic[0]
	p[2] = probeMagic[1]
	p[3] = typ
	binary.BigEndian.PutUint16(p[4:6], seq)
	binary.BigEndian.PutUint16(p[6:8], uint16(size))
	copy(p[8:16], nonce[:])
	return p
}

// decodeProbeFrame parses a control frame. ok is false unless the payload has the
// marker+magic, a known type, and a declared size matching the actual payload
// length (cross-check that the frame arrived whole).
func decodeProbeFrame(p []byte) (probeFrame, bool) {
	if !isProbeFramePayload(p) {
		return probeFrame{}, false
	}
	typ := p[3]
	if typ != probeTypeRequest && typ != probeTypeReply {
		return probeFrame{}, false
	}
	size := binary.BigEndian.Uint16(p[6:8])
	if int(size) != len(p) {
		return probeFrame{}, false
	}
	f := probeFrame{
		typ:  typ,
		seq:  binary.BigEndian.Uint16(p[4:6]),
		size: size,
	}
	copy(f.nonce[:], p[8:16])
	return f, true
}

// makeProbeReply turns a received PROBE_REQUEST payload into a PROBE_REPLY of the
// identical size (echoing seq/size/nonce/padding). Returns nil if req is not a
// valid request. Anti-amplification: the reply is exactly the request size.
func makeProbeReply(req []byte) []byte {
	f, ok := decodeProbeFrame(req)
	if !ok || f.typ != probeTypeRequest {
		return nil
	}
	reply := make([]byte, len(req))
	copy(reply, req)
	reply[3] = probeTypeReply
	return reply
}

// ProbeConfig tunes the active MTU search.
type ProbeConfig struct {
	Floor   int           // never probe below this (IPv6 min)
	Cap     int           // upper bound from configured -tun-mtu / negotiation
	Step    int           // binary-search granularity in bytes
	Timeout time.Duration // per-probe timeout
	Retries int           // retransmits of one size before a "too-big" verdict
}

// ProbeResult summarizes a completed probe for logging and metrics.
type ProbeResult struct {
	AppliedMTU     int    // min(probed, cap)
	Source         string // "cap" | "probed" | "floor"
	FallbackReason string // "" | "no-capability" | "floor-timeout"
	Probes         int    // number of probe frames sent
	DurationMs     int64
}

type replyInfo struct {
	size  uint16
	nonce [8]byte
}

// Prober runs the active MTU search over an established tunnel. It sends frames
// through send and is fed inbound PROBE_REPLY payloads via HandleReply (the data
// read loop routes replies here instead of the TUN device).
type Prober struct {
	cfg  ProbeConfig
	send func(payload []byte) error

	mu      sync.Mutex
	seq     uint16
	pending map[uint16]chan replyInfo
	probes  int
}

// NewProber builds a Prober. Zero/empty config fields fall back to sane defaults.
func NewProber(cfg ProbeConfig, send func([]byte) error) *Prober {
	if cfg.Floor <= 0 {
		cfg.Floor = MTUFloor
	}
	if cfg.Step <= 0 {
		cfg.Step = defaultProbeStep
	}
	if cfg.Retries <= 0 {
		cfg.Retries = defaultProbeRetries
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = minProbeTimeout
	}
	if cfg.Cap < cfg.Floor {
		cfg.Cap = cfg.Floor
	}
	if cfg.Cap > 65535 {
		cfg.Cap = 65535
	}
	return &Prober{cfg: cfg, send: send, pending: make(map[uint16]chan replyInfo)}
}

// HandleReply feeds an inbound payload to the prober. Non-reply or unmatched
// frames are ignored. Safe to call from the data read loop.
func (p *Prober) HandleReply(payload []byte) {
	f, ok := decodeProbeFrame(payload)
	if !ok || f.typ != probeTypeReply {
		return
	}
	p.mu.Lock()
	ch := p.pending[f.seq]
	p.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- replyInfo{size: f.size, nonce: f.nonce}:
	default:
	}
}

// probeOnce sends one PROBE_REQUEST of the given size and waits up to the
// per-probe timeout (or ctx) for a matching reply (same seq+size+nonce).
func (p *Prober) probeOnce(ctx context.Context, size int) bool {
	p.mu.Lock()
	p.seq++
	seq := p.seq
	ch := make(chan replyInfo, 1)
	p.pending[seq] = ch
	p.probes++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.pending, seq)
		p.mu.Unlock()
	}()

	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	frame := encodeProbeFrame(probeTypeRequest, seq, size, nonce)
	if err := p.send(frame); err != nil {
		log.Debug("MTU probe: send failed (size=%d): %v", size, err)
		return false
	}

	timer := time.NewTimer(p.cfg.Timeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case r := <-ch:
			if int(r.size) == size && r.nonce == nonce {
				return true
			}
			// Stale/mismatched reply: keep waiting until the timeout fires.
		}
	}
}

// probeSize retries a size up to Retries+1 times. Success on any attempt proves
// the size passes; a "too-big" verdict requires every attempt to fail (this is
// what tells an MTU drop apart from ordinary packet loss).
func (p *Prober) probeSize(ctx context.Context, size int) bool {
	for i := 0; i <= p.cfg.Retries; i++ {
		if ctx.Err() != nil {
			return false
		}
		if p.probeOnce(ctx, size) {
			return true
		}
	}
	return false
}

// FastProbe runs a single capped-deadline probe of cap (no retries). Returns true
// if cap echoes within the deadline - the common 1500-path case where the tunnel
// can come up at full MTU immediately.
func (p *Prober) FastProbe(ctx context.Context, deadline time.Duration) bool {
	fctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	return p.probeOnce(fctx, p.cfg.Cap)
}

// Probes returns the number of probe frames sent so far.
func (p *Prober) Probes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.probes
}

// Run executes the full search: anchor floor -> optimistic jump to cap -> binary
// search in (floor, cap). Returns the applied MTU = min(probed, cap). Biased to
// false-low: an inconclusive search keeps the largest known-good size.
func (p *Prober) Run(ctx context.Context) ProbeResult {
	start := time.Now()
	floor, capMTU, step := p.cfg.Floor, p.cfg.Cap, p.cfg.Step

	finish := func(r ProbeResult) ProbeResult {
		r.Probes = p.Probes()
		r.DurationMs = time.Since(start).Milliseconds()
		return r
	}

	// Anchor: floor must be reachable. If it is not, the channel is bad or the
	// exit does not echo -> fall back to static negotiation.
	if !p.probeSize(ctx, floor) {
		return finish(ProbeResult{AppliedMTU: floor, Source: "floor", FallbackReason: "floor-timeout"})
	}
	if capMTU <= floor {
		return finish(ProbeResult{AppliedMTU: floor, Source: "cap"})
	}

	// Optimistic jump: typical good path answers cap in one round.
	if p.probeSize(ctx, capMTU) {
		return finish(ProbeResult{AppliedMTU: capMTU, Source: "cap"})
	}

	// Binary search: lo known-good (floor), hi known-bad (cap).
	lo, hi := floor, capMTU
	for hi-lo > step {
		if ctx.Err() != nil {
			break
		}
		mid := alignDown((lo+hi)/2, step)
		if mid <= lo {
			mid = lo + step
		}
		if mid >= hi {
			break
		}
		if p.probeSize(ctx, mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return finish(ProbeResult{AppliedMTU: lo, Source: "probed"})
}

func alignDown(v, step int) int {
	if step <= 0 {
		return v
	}
	return v - v%step
}
