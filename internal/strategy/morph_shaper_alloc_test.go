package strategy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
)

// scriptedConn replays a fixed byte stream for Read; Write is a sink. Unlike
// fakeConn it implements net.Conn and never returns io.EOF until the entire
// scripted buffer has been drained, which is what readShaped needs across
// repeated Read calls.
type scriptedConn struct {
	mu      sync.Mutex
	rd      *bytes.Reader
	written bytes.Buffer
}

func newScriptedConn(in []byte) *scriptedConn {
	return &scriptedConn{rd: bytes.NewReader(in)}
}

func (s *scriptedConn) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rd.Read(b)
}
func (s *scriptedConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written.Write(b)
}
func (s *scriptedConn) Close() error                       { return nil }
func (s *scriptedConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (s *scriptedConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (s *scriptedConn) SetDeadline(t time.Time) error      { return nil }
func (s *scriptedConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *scriptedConn) SetWriteDeadline(t time.Time) error { return nil }

// buildShapedFrames produces N back-to-back wire frames suitable for feeding
// into MorphedConn.Read with a chrome-style preset. Each frame carries a 4-byte
// distShaper header + payload; the morph framing wrapper is added on top.
func buildShapedFrames(t *testing.T, payloads [][]byte, padding int) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, p := range payloads {
		// distShaper-style inner frame: [len:4][payload:N]
		inner := make([]byte, 4+len(p))
		binary.LittleEndian.PutUint32(inner[:4], uint32(len(p)))
		copy(inner[4:], p)

		// Morph framing: [dataLen:4 BE][paddingLen:2 BE]
		var hdr [morphHeaderLen]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(inner)))
		binary.BigEndian.PutUint16(hdr[4:6], uint16(padding))
		buf.Write(hdr[:])
		buf.Write(inner)
		if padding > 0 {
			buf.Write(make([]byte, padding))
		}
	}
	return buf.Bytes()
}

// TestReadShaped_HeaderStackAlloc verifies the per-frame header buffer no
// longer escapes to the heap. With pooled payload + UnwrapInto we expect a
// constant-bounded allocs/op across many reads.
func TestReadShaped_HeaderStackAlloc(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 64)
	frame := buildShapedFrames(t, [][]byte{payload}, 0)

	// Concatenate many frames so AllocsPerRun has plenty of iterations.
	const reps = 64
	stream := bytes.Repeat(frame, reps)

	sc := newScriptedConn(stream)
	d, err := presets.ByName(presets.PresetChromeBrowsing, 1)
	if err != nil {
		t.Fatalf("preset: %v", err)
	}
	mc := &MorphedConn{Conn: sc, shaper: d}

	dst := make([]byte, 1500)
	// Warm up the pools.
	for range 4 {
		if _, err := mc.readShaped(dst); err != nil {
			t.Fatalf("warmup readShaped: %v", err)
		}
	}

	// Now measure across the remaining frames.
	allocs := testing.AllocsPerRun(20, func() {
		_, _ = mc.readShaped(dst)
	})
	// Pooled payload + UnwrapInto + scratch buf reuse should keep allocs/op
	// bounded by sync.Pool's internal bookkeeping under -race. 4 is generous.
	if allocs > 4 {
		t.Fatalf("readShaped allocs/op = %.1f, want ≤ 4", allocs)
	}
}

// TestReadShaped_DiscardBufferReused: reading two consecutive dummy frames
// (dataLen=0) should reuse the per-conn discard scratch buffer rather than
// allocate a fresh `make([]byte, paddingLen)` each time.
func TestReadShaped_DiscardBufferReused(t *testing.T) {
	// Dummy frame: dataLen=0, paddingLen=200. Followed by a real keepalive
	// payload would yield 4 zero-bytes; for this test we just measure the
	// padding read path's allocation profile.
	var frame bytes.Buffer
	var hdr [morphHeaderLen]byte
	binary.BigEndian.PutUint32(hdr[0:4], 0)   // dataLen=0
	binary.BigEndian.PutUint16(hdr[4:6], 200) // paddingLen=200
	frame.Write(hdr[:])
	frame.Write(make([]byte, 200))

	const reps = 32
	stream := bytes.Repeat(frame.Bytes(), reps)

	sc := newScriptedConn(stream)
	d, err := presets.ByName(presets.PresetChromeBrowsing, 1)
	if err != nil {
		t.Fatalf("preset: %v", err)
	}
	mc := &MorphedConn{Conn: sc, shaper: d}

	dst := make([]byte, 64)
	// Warm scratch buf.
	if _, err := mc.readShaped(dst); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	prevPtr := &mc.readScratchBuf[0]
	for range reps - 1 {
		if _, err := mc.readShaped(dst); err != nil && err != io.EOF {
			t.Fatalf("readShaped: %v", err)
		}
		if &mc.readScratchBuf[0] != prevPtr {
			t.Fatalf("readScratchBuf reallocated between reads (data race or growth?)")
		}
	}
}

