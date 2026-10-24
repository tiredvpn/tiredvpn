package server

import (
	"encoding/binary"
	"io"
	"sync/atomic"
	"time"
)

// clientTraffic holds the live counters of one registry client. Every data
// path that carries the client's traffic adds to it directly, so the hot path
// costs one atomic add per packet or per write and nothing touches Redis;
// FlushStats copies the totals out every flush interval.
//
// The three counters are distinct fields of one struct on purpose. Up to
// 1.11.8 they were three map entries pointing at one shared int64, so every new
// connection moved bytes_up and bytes_down by one and every byte moved all
// three, and Redis reported the connection count as the byte count.
//
// A nil *clientTraffic is valid and counts nothing: it is what a session gets
// when its bytes cannot be attributed to a registry client.
type clientTraffic struct {
	conns     atomic.Int64
	bytesUp   atomic.Int64 // client -> server: what the client sent
	bytesDown atomic.Int64 // server -> client: what the client received

	// lastSeen is the unix-nano time the client was last seen: a connection
	// opened or closed, a finished stream, or traffic that moved between two
	// flushes. Zero means never.
	lastSeen atomic.Int64

	// Owned by FlushStats (under ClientRegistry.flushMu).
	seeded      bool  // the lifetime totals stored in Redis have been folded in
	flushedUp   int64 // bytesUp at the last successful flush
	flushedDown int64 // bytesDown at the last successful flush
}

// addUp accounts n payload bytes the client sent.
func (t *clientTraffic) addUp(n int) {
	if t != nil && n > 0 {
		t.bytesUp.Add(int64(n))
	}
}

// addDown accounts n payload bytes delivered to the client.
func (t *clientTraffic) addDown(n int) {
	if t != nil && n > 0 {
		t.bytesDown.Add(int64(n))
	}
}

// addStream accounts a finished stream, for paths that only learn its byte
// counts when it ends.
func (t *clientTraffic) addStream(up, down int64) {
	if t == nil {
		return
	}
	t.addUp(int(up))
	t.addDown(int(down))
	t.touch(time.Now())
}

func (t *clientTraffic) touch(now time.Time) {
	if t != nil {
		t.lastSeen.Store(now.UnixNano())
	}
}

// trafficOf returns the counters a session's bytes are accounted to, or nil
// when they cannot be attributed: there is no registry, or the identity does
// not name exactly one registry client (the global secret, a REALITY hmac of
// it, an unauthenticated peer). Called once per session, never per packet.
//
// id must be the identity as the registry knows it, not a transport-prefixed
// relabelling of it ("polling:<id>" names no client).
func (s *serverContext) trafficOf(id clientIdentity) *clientTraffic {
	if s == nil || s.registry == nil || !id.perClient {
		return nil
	}
	return s.registry.traffic(id.id)
}

// tunFrameMeter passes a [len:4][pkt:N] TUN stream through to w and accounts
// the packet bytes it carries, without the length prefixes and zero-length
// keepalives, so a bridged session is counted the same way as one terminated
// on this node's TUN device. It keeps its parse state across writes because a
// frame can be split over any number of them.
type tunFrameMeter struct {
	w   io.Writer
	add func(int)

	hdr    [4]byte
	hdrN   int // bytes of the current length prefix seen so far
	remain int // packet bytes of the current frame still to come
}

func newTUNFrameMeter(w io.Writer, add func(int)) *tunFrameMeter {
	return &tunFrameMeter{w: w, add: add}
}

func (m *tunFrameMeter) Write(p []byte) (int, error) {
	n, err := m.w.Write(p)
	m.observe(p[:n])
	return n, err
}

func (m *tunFrameMeter) observe(p []byte) {
	payload := 0
	for len(p) > 0 {
		if m.remain > 0 {
			k := min(m.remain, len(p))
			m.remain -= k
			payload += k
			p = p[k:]
			continue
		}
		k := copy(m.hdr[m.hdrN:], p)
		m.hdrN += k
		p = p[k:]
		if m.hdrN == len(m.hdr) {
			m.remain = int(binary.BigEndian.Uint32(m.hdr[:]))
			m.hdrN = 0
		}
	}
	if payload > 0 {
		m.add(payload)
	}
}
