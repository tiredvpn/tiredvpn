package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// clientTraffic holds the live counters of one registry client on this server,
// since it started. Every data path that carries the client's traffic adds to
// it directly, so the hot path costs one atomic add per packet or per write
// and nothing touches Redis; FlushStats adds what moved to the store every
// flush interval.
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
	// opened or closed, a finished stream, or a packet (to the second, from
	// coarseClock). Zero means never.
	lastSeen atomic.Int64

	// The values the last successful flush wrote out. Owned by FlushStats
	// (under ClientRegistry.flushSem).
	flushedConns, flushedUp, flushedDown, flushedSeen int64
}

func newClientTraffic() *clientTraffic {
	coarseClockOnce.Do(startCoarseClock)
	return &clientTraffic{}
}

// coarseClock is the current time in unix nanos, truncated to the second and
// advanced once a second, so stamping lastSeen on every packet costs a load
// and, once a second, a store - not a clock read.
var (
	coarseClock     atomic.Int64
	coarseClockOnce sync.Once
)

func startCoarseClock() {
	coarseClock.Store(time.Now().Truncate(time.Second).UnixNano())
	go func() {
		for now := range time.Tick(time.Second) {
			coarseClock.Store(now.Truncate(time.Second).UnixNano())
		}
	}()
}

// seen stamps lastSeen from coarseClock.
func (t *clientTraffic) seen() {
	if now := coarseClock.Load(); t.lastSeen.Load() < now {
		t.lastSeen.Store(now)
	}
}

// addUp accounts n payload bytes the client sent.
func (t *clientTraffic) addUp(n int) {
	if t != nil && n > 0 {
		t.bytesUp.Add(int64(n))
		t.seen()
	}
}

// addDown accounts n payload bytes delivered to the client.
func (t *clientTraffic) addDown(n int) {
	if t != nil && n > 0 {
		t.bytesDown.Add(int64(n))
		t.seen()
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
// it, an unauthenticated peer - none of these are perClient). Called once per
// session, never per packet.
//
// A perClient identity is counted under its lease (leaseID), the registry
// client's ID, not under id: REALITY spells id "reality:<hmac>" for a registry
// client too, while its lease is the client the bytes belong to.
func (s *serverContext) trafficOf(id clientIdentity) *clientTraffic {
	if s == nil || s.registry == nil || !id.perClient {
		return nil
	}
	return s.registry.traffic(id.leaseID())
}

// relayCountChunk is how much a spliced relay copies between two additions to
// the counters: the most a spliced stream can be behind in the stats, and the
// most a shutdown mid-stream loses of it.
const relayCountChunk = 1 << 20

// relayCounted copies src to dst until EOF like optimizedRelay, adding to add
// as the bytes move rather than once when the stream ends, so a long download
// shows up in the stats while it runs.
//
// Where the kernel can splice (a kTLS or TCP source into a TCP or kTLS
// destination) the copy goes in chunks of relayCountChunk, each through the
// same fast path io.Copy would take: a kTLS source copies through WriteToN, a
// TCP source is limited with an io.LimitedReader, which net.TCPConn.ReadFrom
// (and the kTLS ReadFrom on top of it) still splices from. A splice returns
// only when its chunk is full or the stream ends, so such a stream is counted
// to within a chunk. Everything else - a QUIC stream, a TLS conn without
// kTLS - goes through a buffer anyway and is counted on every write.
func relayCounted(dst, src net.Conn, add func(int)) (int64, error) {
	buf := GetRelayBuffer()
	defer PutRelayBuffer(buf)
	if !spliceable(dst, src) {
		return copyCounting(dst, src, buf, add)
	}
	var total int64
	for {
		var n int64
		var err error
		if kc, ok := src.(*ktls.Conn); ok {
			n, err = kc.WriteToN(dst, relayCountChunk)
		} else {
			n, err = io.CopyBuffer(dst, &io.LimitedReader{R: src, N: relayCountChunk}, buf)
		}
		total += n
		add(int(n))
		if err != nil || n < relayCountChunk {
			return total, err
		}
	}
}

// spliceable reports whether copying src to dst can take the kernel's splice
// path.
func spliceable(dst, src net.Conn) bool {
	switch dst.(type) {
	case *net.TCPConn, *ktls.Conn:
	default:
		return false
	}
	switch src.(type) {
	case *net.TCPConn, *ktls.Conn:
		return true
	}
	return false
}

// copyCounting is the buffered copy loop, adding every write to add.
func copyCounting(dst io.Writer, src io.Reader, buf []byte, add func(int)) (int64, error) {
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			total += int64(nw)
			add(nw)
			if werr != nil {
				return total, werr
			}
			if nw < nr {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}

// tunFrameMeter passes a [len:4][pkt:N] TUN stream through to w and accounts
// the packets it carries the way an exit terminating the stream would: packet
// bytes only, no length prefixes, no keepalives, no auto-MTU probe frames, and
// a length outside 20..65535 is a bare 4-byte header that the exit skips. It
// keeps its parse state across writes because a frame can be split over any
// number of them, and accounts a packet once its last byte has passed.
type tunFrameMeter struct {
	w   io.Writer
	add func(int)

	hdr    [4]byte
	hdrN   int // bytes of the current length prefix seen so far
	frame  int // length of the packet in flight, 0 between packets
	remain int // bytes of it still to come

	// peek holds the start of the packet in flight, enough to tell an
	// auto-MTU probe frame from an IP packet.
	peek  [tunMeterPeek]byte
	peekN int
}

// tunMeterPeek covers the probe header, which tun.IsProbeFrame needs whole.
const tunMeterPeek = 16

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
			m.peekN += copy(m.peek[m.peekN:], p[:k])
			m.remain -= k
			p = p[k:]
			if m.remain == 0 {
				if !tun.IsProbeFrame(m.peek[:min(m.peekN, m.frame)]) {
					payload += m.frame
				}
				m.frame = 0
			}
			continue
		}
		k := copy(m.hdr[m.hdrN:], p)
		m.hdrN += k
		p = p[k:]
		if m.hdrN == len(m.hdr) {
			m.hdrN = 0
			if n := int(binary.BigEndian.Uint32(m.hdr[:])); n >= 20 && n <= 65535 {
				m.frame, m.remain, m.peekN = n, n, 0
			}
		}
	}
	if payload > 0 {
		m.add(payload)
	}
}
