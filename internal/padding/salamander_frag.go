package padding

import (
	"sync"
	"time"
)

// Splitting a payload that does not fit one datagram.
//
// The inner frame already carried a two-byte length, and a single datagram can
// never hold more than ~1.4 KB of payload, so the length's top two bits were
// free. Bit 6 now marks a fragment and six further bytes - group id, index,
// count - follow the length. Both live inside the keystream-masked region and
// behind the keyed tag, so an observer sees neither a magic number nor a
// fragment counter; compare internal/evasion/quic_fragment.go, which prefixes
// every fragment with the cleartext bytes 0x54 0x46.
//
// Unfragmented datagrams keep the exact layout and therefore the exact bucket
// boundaries they had before this change.
const (
	// fragFlag is bit 6 of the high length byte: this datagram is one chunk.
	fragFlag = 0x40
	// fragLenMask is the part of the high length byte that is still length.
	fragLenMask = 0x3F
	// fragHeaderLen is the inner header of a fragment:
	// [tag:udpTagLen][lenHi][lenLo][id:4][index:1][count:1].
	fragHeaderLen = udpHeaderLen + 6
	// maxFrameChunk is what a 14-bit length can express.
	maxFrameChunk = 0x3FFF
	// maxFragmentsPerPayload bounds both the wire encoding (index and count are
	// one byte each) and the work one payload can ask the receiver to hold.
	maxFragmentsPerPayload = 64
	// maxUDPPayload is the largest payload the UDP framing accepts, split or
	// not. It is the limit the two-byte length carried before fragmentation
	// existed, kept so callers see no change.
	maxUDPPayload = 65535
)

// fragMeta identifies one chunk within a split payload.
type fragMeta struct {
	id    uint32
	index int
	count int
}

// udpFrame is one decrypted datagram: either a whole payload (frag false) or
// one chunk of a split one.
type udpFrame struct {
	data  []byte
	frag  bool
	id    uint32
	index int
	count int
}

const (
	// fragGroupTTL is how long an incomplete group is held. A datagram lost in
	// flight strands its siblings; QUIC treats the whole payload as lost and
	// retransmits, so holding the remains longer buys nothing.
	fragGroupTTL = 5 * time.Second
	// maxFragGroups caps concurrent incomplete groups across all peers. Only
	// datagrams whose keyed tag already matched reach the reassembler, so this
	// is a bound on damage from a legitimate peer behaving badly, not a
	// defence against arbitrary senders.
	maxFragGroups = 1024
)

// fragReassembler collects chunks into payloads, keyed by sender address and
// group id. It is safe for concurrent use.
type fragReassembler struct {
	mu      sync.Mutex
	pending map[fragKey]*fragGroup
}

type fragKey struct {
	addr string
	id   uint32
}

type fragGroup struct {
	chunks [][]byte
	have   int
	size   int
	seen   time.Time
}

func newFragReassembler() *fragReassembler {
	return &fragReassembler{pending: make(map[fragKey]*fragGroup)}
}

// add files one chunk and returns the payload once the group is complete.
// Duplicate indexes are ignored rather than counted twice, so a retransmitted
// chunk cannot complete a group that is still missing a different one.
func (r *fragReassembler) add(addr string, frame udpFrame) ([]byte, bool) {
	if !frame.frag || frame.count <= 0 || frame.index < 0 || frame.index >= frame.count {
		return nil, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	key := fragKey{addr: addr, id: frame.id}

	group, ok := r.pending[key]
	if ok && (group.count() != frame.count || now.Sub(group.seen) > fragGroupTTL) {
		// Either the id was reused with a different shape, or what is left of
		// the old group has expired. Start over rather than mix the two.
		delete(r.pending, key)
		ok = false
	}
	if !ok {
		r.evictLocked(now)
		group = &fragGroup{chunks: make([][]byte, frame.count)}
		r.pending[key] = group
	}

	if group.chunks[frame.index] != nil {
		group.seen = now
		return nil, false
	}
	group.chunks[frame.index] = frame.data
	group.have++
	group.size += len(frame.data)
	group.seen = now

	if group.have < group.count() {
		return nil, false
	}

	payload := make([]byte, 0, group.size)
	for _, c := range group.chunks {
		payload = append(payload, c...)
	}
	delete(r.pending, key)
	return payload, true
}

func (g *fragGroup) count() int { return len(g.chunks) }

// evictLocked drops expired groups, and then the single oldest one if the map
// is still at its cap. r.mu must be held.
func (r *fragReassembler) evictLocked(now time.Time) {
	for k, g := range r.pending {
		if now.Sub(g.seen) > fragGroupTTL {
			delete(r.pending, k)
		}
	}
	if len(r.pending) < maxFragGroups {
		return
	}
	var oldestKey fragKey
	var oldest time.Time
	first := true
	for k, g := range r.pending {
		if first || g.seen.Before(oldest) {
			oldestKey, oldest, first = k, g.seen, false
		}
	}
	if !first {
		delete(r.pending, oldestKey)
	}
}

// drop forgets every group held for an address, used when a peer's secret
// stops matching and its half-assembled payloads can no longer be trusted.
func (r *fragReassembler) drop(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.pending {
		if k.addr == addr {
			delete(r.pending, k)
		}
	}
}
