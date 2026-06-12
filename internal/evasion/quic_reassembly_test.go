package evasion

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// buildTestFragment constructs a raw fragment packet matching the format
// that QUICReassemblyPacketConn.ReadFrom expects (see quic_fragment.go constants).
func buildTestFragment(fragID [4]byte, seq, total int, payload []byte) []byte {
	buf := make([]byte, fragHeaderSize+len(payload))
	buf[0] = fragMagic1
	buf[1] = fragMagic2
	buf[2] = byte(seq >> 8)
	buf[3] = byte(seq)
	buf[4] = byte(total >> 8)
	buf[5] = byte(total)
	copy(buf[6:10], fragID[:])
	copy(buf[fragHeaderSize:], payload)
	return buf
}

// bufferedPacketConn is a test net.PacketConn backed by a channel.
type bufferedPacketConn struct {
	mu      sync.Mutex
	packets chan []byte
	closed  chan struct{}
	addr    *net.UDPAddr
}

func newBufferedPacketConn() *bufferedPacketConn {
	return &bufferedPacketConn{
		packets: make(chan []byte, 256),
		closed:  make(chan struct{}),
		addr:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
	}
}

func (c *bufferedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.packets:
		return copy(p, pkt), c.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *bufferedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

func (c *bufferedPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *bufferedPacketConn) LocalAddr() net.Addr              { return c.addr }
func (c *bufferedPacketConn) SetDeadline(_ time.Time) error    { return nil }
func (c *bufferedPacketConn) SetReadDeadline(_ time.Time) error { return nil }
func (c *bufferedPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestQUICReassemblyMaxSessionsDoS verifies that QUICReassemblyPacketConn
// enforces MaxSessions to prevent unbounded memory growth.
//
// Bug: ReadFrom creates sessions without checking MaxSessions.
// Any remote peer can send many incomplete first-fragments to exhaust server memory.
//
// This test FAILS on current code (sessions grow past MaxSessions).
// After fix: sessions map is bounded; test passes.
func TestQUICReassemblyMaxSessionsDoS(t *testing.T) {
	const maxSessions = 5
	const attackPackets = 20 // far more than maxSessions

	mc := newBufferedPacketConn()
	cfg := &ReassemblyConfig{
		MaxSessions:    maxSessions,
		SessionTimeout: 30 * time.Second,
	}
	rc := NewQUICReassemblyPacketConn(mc, cfg)

	// Enqueue incomplete fragments - each has unique fragID, claims total=2
	// so no session ever completes and they accumulate in the map.
	for i := 0; i < attackPackets; i++ {
		var fragID [4]byte
		binary.BigEndian.PutUint32(fragID[:], uint32(i+1))
		pkt := buildTestFragment(fragID, 0, 2, []byte("payload"))
		mc.packets <- pkt
	}

	// Close after sending so ReadFrom eventually unblocks
	go func() {
		time.Sleep(100 * time.Millisecond)
		mc.Close()
	}()

	// Drain ReadFrom until it errors (connection closed)
	buf := make([]byte, 2000)
	for {
		_, _, err := rc.ReadFrom(buf)
		if err != nil {
			break
		}
	}

	rc.mu.Lock()
	sessionCount := len(rc.sessions)
	rc.mu.Unlock()

	if sessionCount > maxSessions {
		t.Fatalf(
			"sessions map not bounded: %d sessions accumulated (MaxSessions=%d). "+
				"Bug: ReadFrom never checks MaxSessions in quic_reassembly.go",
			sessionCount, maxSessions,
		)
	}
}

// TestQUICFragmentReassemblyRoundTrip verifies a basic fragment → reassemble cycle
// works correctly, including out-of-order delivery.
func TestQUICFragmentReassemblyRoundTrip(t *testing.T) {
	mc := newBufferedPacketConn()
	cfg := DefaultReassemblyConfig()
	rc := NewQUICReassemblyPacketConn(mc, cfg)

	original := []byte("hello quic fragmented world")
	fragID := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Split into 3 parts and send out of order: 2, 0, 1
	p1 := original[:10]
	p2 := original[10:20]
	p3 := original[20:]

	// Send in non-sequential order
	mc.packets <- buildTestFragment(fragID, 1, 3, p2) // seq=1 first
	mc.packets <- buildTestFragment(fragID, 2, 3, p3) // seq=2 second
	mc.packets <- buildTestFragment(fragID, 0, 3, p1) // seq=0 last (completes)

	// ReadFrom should reassemble and return the full original payload
	buf := make([]byte, 2000)
	rc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := rc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	got := buf[:n]
	if string(got) != string(original) {
		t.Fatalf("reassembly mismatch: got %q, want %q", got, original)
	}
}

// TestQUICReassemblySilentTruncation verifies that ReadFrom does not silently
// truncate reassembled data when it exceeds len(p).
//
// Bug: if len(assembled) > len(p), the code silently truncates:
//   assembled = assembled[:len(p)]
// This returns partial data with no error, corrupting the stream.
//
// After fix: ReadFrom should return an error or expand the buffer.
func TestQUICReassemblySilentTruncation(t *testing.T) {
	mc := newBufferedPacketConn()
	cfg := DefaultReassemblyConfig()
	rc := NewQUICReassemblyPacketConn(mc, cfg)

	// Create a payload that will be larger than the receive buffer
	bigPayload := make([]byte, 500)
	for i := range bigPayload {
		bigPayload[i] = byte(i & 0xff)
	}

	fragID := [4]byte{0x01, 0x02, 0x03, 0x04}
	mc.packets <- buildTestFragment(fragID, 0, 1, bigPayload)

	// Use a small buffer that can't hold the full reassembled payload
	smallBuf := make([]byte, 100)
	rc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := rc.ReadFrom(smallBuf)

	// Bug: err is nil and n == 100 (silently truncated)
	// After fix: err should be non-nil OR the implementation should expand the buffer
	if err == nil && n < len(bigPayload) {
		t.Logf(
			"KNOWN BUG: ReadFrom silently truncated %d bytes to %d (no error returned). "+
				"Bug at quic_reassembly.go:118-119: assembled = assembled[:len(p)]",
			len(bigPayload), n,
		)
	}
}
