package strategy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// fakeConn captures writes and serves canned reads so tests can inspect
// the exact bytes Morph emits without going through a real socket.
type fakeConn struct {
	mu        sync.Mutex
	writeBuf  bytes.Buffer
	readBuf   bytes.Buffer
	closed    bool
}

func (f *fakeConn) Read(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return f.readBuf.Read(b)
}
func (f *fakeConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writeBuf.Write(b)
}
func (f *fakeConn) Close() error                       { f.closed = true; return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (f *fakeConn) writtenAfterHandshake(handshakeLen int) []byte {
	b := f.writeBuf.Bytes()
	if len(b) < handshakeLen {
		return nil
	}
	return b[handshakeLen:]
}

// newTestMorphedConn skips the real handshake's randomness and just
// computes the handshake length so tests can read post-handshake bytes.
func handshakeLen(profile *TrafficProfile) int {
	return 5 + len(profile.Name) + 32
}

// TestMorphedConn_NoopShaper_BackwardCompat: with default (nil) shaper the
// Write pipeline emits exactly one [header:6][data:N][padding:M] frame per
// Write whose layout matches readFrameHeader's view of the bytes.
func TestMorphedConn_NoopShaper_BackwardCompat(t *testing.T) {
	profile := &TrafficProfile{
		Name:            "Test",
		PacketSizes:     []int{100},
		PacketSizeProbs: []float64{1.0},
		MinPadding:      0,
		MaxPadding:      0,
	}
	fc := &fakeConn{}
	mc := NewMorphedConn(fc, profile, []byte("secretsecretsecretsecretsecretse"))

	payload := []byte("hello world")
	n, err := mc.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}

	wire := fc.writtenAfterHandshake(handshakeLen(profile))
	if len(wire) != morphHeaderLen+len(payload) {
		t.Fatalf("noop frame size = %d, want %d", len(wire), morphHeaderLen+len(payload))
	}
	dataLen, padLen := readFrameHeader(wire)
	if dataLen != len(payload) || padLen != 0 {
		t.Fatalf("noop header dataLen=%d padLen=%d", dataLen, padLen)
	}
	if !bytes.Equal(wire[morphHeaderLen:morphHeaderLen+dataLen], payload) {
		t.Fatalf("noop payload mismatch: %q", wire[morphHeaderLen:])
	}
}

// mockShaper records calls and produces deterministic Wrap/Unwrap behaviour
// so tests can assert the new Write path uses shaper output exclusively.
type mockShaper struct {
	wrapCalls    [][]byte
	unwrapCalls  [][][]byte
	nextSize     int
	nextDelay    time.Duration
	fragmentInto int // split payload into N equal-ish chunks; 0 => single frame
}

func (m *mockShaper) NextPacketSize(_ shaper.Direction) int    { return m.nextSize }
func (m *mockShaper) NextDelay(_ shaper.Direction) time.Duration { return m.nextDelay }
func (m *mockShaper) Wrap(p []byte) [][]byte {
	m.wrapCalls = append(m.wrapCalls, append([]byte(nil), p...))
	if m.fragmentInto <= 1 {
		return [][]byte{p}
	}
	chunk := (len(p) + m.fragmentInto - 1) / m.fragmentInto
	if chunk == 0 {
		return [][]byte{p}
	}
	out := make([][]byte, 0, m.fragmentInto)
	for i := 0; i < len(p); i += chunk {
		end := min(i+chunk, len(p))
		out = append(out, p[i:end])
	}
	return out
}
func (m *mockShaper) Unwrap(frames [][]byte) []byte {
	m.unwrapCalls = append(m.unwrapCalls, frames)
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	out := make([]byte, 0, total)
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

func TestMorphedConn_WithShaper_Wrap(t *testing.T) {
	profile := &TrafficProfile{Name: "T", PacketSizes: []int{100}, PacketSizeProbs: []float64{1}}
	fc := &fakeConn{}
	ms := &mockShaper{nextSize: 64, fragmentInto: 3}
	mc := NewMorphedConnWithShaper(fc, profile, []byte("secretsecretsecretsecretsecretse"), ms)

	payload := bytes.Repeat([]byte("A"), 30)
	if _, err := mc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Close drains the async pacer so the captured write buffer is stable.
	if err := mc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(ms.wrapCalls) != 1 {
		t.Fatalf("Wrap called %d times, want 1", len(ms.wrapCalls))
	}
	if !bytes.Equal(ms.wrapCalls[0], payload) {
		t.Fatalf("Wrap got %q, want %q", ms.wrapCalls[0], payload)
	}

	// Three fragments produced by mockShaper -> three frames on the wire,
	// each [header:6][data:chunk][padding:64-chunk-6].
	wire := fc.writtenAfterHandshake(handshakeLen(profile))
	off := 0
	frameCount := 0
	for off < len(wire) {
		dataLen, padLen := readFrameHeader(wire[off:])
		total := morphHeaderLen + dataLen + padLen
		if morphHeaderLen+dataLen+padLen != 64 {
			t.Errorf("frame %d total=%d, want 64 (NextPacketSize)", frameCount, morphHeaderLen+dataLen+padLen)
		}
		off += total
		frameCount++
	}
	if frameCount != 3 {
		t.Fatalf("on wire frame count = %d, want 3", frameCount)
	}
}

func TestMorphedConn_WithShaper_Roundtrip(t *testing.T) {
	profile := &TrafficProfile{Name: "T", PacketSizes: []int{100}, PacketSizeProbs: []float64{1}}
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()
	defer srvConn.Close()

	clientShaper := &mockShaper{nextSize: 0, fragmentInto: 2}
	serverShaper := &mockShaper{nextSize: 0, fragmentInto: 1}

	// Build manually to skip the handshake byte exchange that net.Pipe would
	// stall on (synchronous unbuffered Write blocks until Read on the peer).
	client := &MorphedConn{Conn: cliConn, profile: profile, shaper: clientShaper}
	server := &MorphedConn{Conn: srvConn, profile: profile, shaper: serverShaper}

	want := bytes.Repeat([]byte("XY"), 50)
	done := make(chan error, 1)
	go func() {
		_, err := client.Write(want)
		done <- err
	}()

	got := make([]byte, 0, len(want))
	for len(got) < len(want) {
		buf := make([]byte, 256)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("server.Read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if err := <-done; err != nil {
		t.Fatalf("client.Write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestShaperFromConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		sh, err := ShaperFromConfig(nil)
		if err != nil || sh == nil {
			t.Fatalf("nil cfg -> sh=%v err=%v", sh, err)
		}
		if !isNoopShaper(sh) {
			t.Fatalf("nil cfg should give NoopShaper, got %T", sh)
		}
	})
	t.Run("empty", func(t *testing.T) {
		sh, err := ShaperFromConfig(&toml.ShaperConfig{})
		if err != nil || !isNoopShaper(sh) {
			t.Fatalf("empty cfg -> sh=%T err=%v", sh, err)
		}
	})
	t.Run("preset", func(t *testing.T) {
		sh, err := ShaperFromConfig(&toml.ShaperConfig{Preset: "chrome_browsing"})
		if err != nil {
			t.Fatalf("preset cfg err: %v", err)
		}
		if sh == nil {
			t.Fatalf("preset cfg returned nil shaper")
		}
	})
}

// TestShaperFromConfig_PresetReturnsNonNoop locks in that wiring the preset
// registry actually produces a behavioral shaper, not the legacy passthrough.
func TestShaperFromConfig_PresetReturnsNonNoop(t *testing.T) {
	seed := int64(42)
	sh, err := ShaperFromConfig(&toml.ShaperConfig{
		Preset: "chrome_browsing",
		Seed:   &seed,
	})
	if err != nil {
		t.Fatalf("ShaperFromConfig: %v", err)
	}
	if isNoopShaper(sh) {
		t.Fatalf("expected non-noop shaper for preset, got %T", sh)
	}
}

func TestShaperFromConfig_UnknownPreset(t *testing.T) {
	if _, err := ShaperFromConfig(&toml.ShaperConfig{Preset: "no_such_preset"}); err == nil {
		t.Fatal("expected error for unknown preset")
	}
}
