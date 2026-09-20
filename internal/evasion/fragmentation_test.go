package evasion

import (
	"net"
	"sync"
	"testing"
	"time"
)

// capturingConn is a net.Conn whose writes are recorded as discrete segments,
// so a test can see how a FragmentedWriter split a payload.
type capturingConn struct {
	mu       sync.Mutex
	segments [][]byte
}

func (c *capturingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seg := make([]byte, len(p))
	copy(seg, p)
	c.segments = append(c.segments, seg)
	return len(p), nil
}

func (c *capturingConn) segCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.segments)
}

// joined concatenates all captured segments in write order.
func (c *capturingConn) joined() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, s := range c.segments {
		out = append(out, s...)
	}
	return out
}

func (c *capturingConn) Read(_ []byte) (int, error)         { return 0, net.ErrClosed }
func (c *capturingConn) Close() error                       { return nil }
func (c *capturingConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *capturingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *capturingConn) SetDeadline(_ time.Time) error      { return nil }
func (c *capturingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *capturingConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ net.Conn = (*capturingConn)(nil)

// clientHello builds a minimal byte slice that isTLSClientHello accepts, padded
// to n bytes so it can be fragmented.
func clientHello(n int) []byte {
	if n < 6 {
		n = 6
	}
	p := make([]byte, n)
	p[0] = 0x16 // Handshake
	p[1] = 0x03 // TLS major
	p[2] = 0x01
	p[3] = 0x00
	p[4] = 0x00
	p[5] = 0x01 // ClientHello
	for i := 6; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

func TestIsTLSClientHello(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"too short", []byte{0x16, 0x03, 0x01}, false},
		{"valid clienthello", clientHello(16), true},
		{"wrong content type", func() []byte { p := clientHello(16); p[0] = 0x17; return p }(), false},
		{"wrong version", func() []byte { p := clientHello(16); p[1] = 0x02; return p }(), false},
		{"not clienthello handshake", func() []byte { p := clientHello(16); p[5] = 0x02; return p }(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTLSClientHello(tc.in); got != tc.want {
				t.Fatalf("isTLSClientHello = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFragmentedWriterFragmentsClientHello(t *testing.T) {
	cc := &capturingConn{}
	fw := NewFragmentedWriter(cc, &FragmentationConfig{FragmentSize: 2})

	hello := clientHello(20)
	n, err := fw.Write(hello)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(hello) {
		t.Fatalf("Write returned %d, want %d", n, len(hello))
	}
	// 20 bytes at fragSize 2 => 10 segments.
	if got := cc.segCount(); got != 10 {
		t.Fatalf("segment count = %d, want 10", got)
	}
	// The bytes on the wire must equal the input, just chopped up.
	if string(cc.joined()) != string(hello) {
		t.Fatal("reassembled fragments differ from input")
	}
}

func TestFragmentedWriterPassthroughNonClientHello(t *testing.T) {
	cc := &capturingConn{}
	fw := NewFragmentedWriter(cc, &FragmentationConfig{FragmentSize: 2})

	payload := []byte("this is not a tls clienthello record at all")
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	// Non-ClientHello first write must go out as a single segment.
	if got := cc.segCount(); got != 1 {
		t.Fatalf("non-CH first write produced %d segments, want 1", got)
	}
}

func TestFragmentedWriterOnlyFirstWriteFragments(t *testing.T) {
	cc := &capturingConn{}
	fw := NewFragmentedWriter(cc, &FragmentationConfig{FragmentSize: 2})

	if _, err := fw.Write(clientHello(20)); err != nil {
		t.Fatalf("first Write error: %v", err)
	}
	first := cc.segCount()

	// A second ClientHello-shaped write must pass through whole.
	if _, err := fw.Write(clientHello(20)); err != nil {
		t.Fatalf("second Write error: %v", err)
	}
	if got := cc.segCount() - first; got != 1 {
		t.Fatalf("second write produced %d segments, want 1 (passthrough)", got)
	}
}

func TestNilConfigUsesDefault(t *testing.T) {
	cc := &capturingConn{}
	fw := NewFragmentedWriter(cc, nil)
	if fw.config.FragmentSize != DefaultFragmentationConfig().FragmentSize {
		t.Fatalf("nil config not replaced with default: FragmentSize=%d", fw.config.FragmentSize)
	}
}

// TestWriteFragmentedGuardsBadFragmentSize is the regression guard for the fix
// in writeFragmented. With FragmentSize == 0 the old loop never advances offset
// (infinite hang); with a negative size, data[offset:end] panics. The test runs
// the write in a goroutine with a hard timeout, so on the UNFIXED code case 0
// reports a timeout failure instead of hanging the whole binary, and case -1
// reports the panic (rule 1: verified failing on the pre-fix code).
func TestWriteFragmentedGuardsBadFragmentSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		size := size
		t.Run(map[bool]string{true: "zero", false: "negative"}[size == 0], func(t *testing.T) {
			cc := &capturingConn{}
			fw := NewFragmentedWriter(cc, &FragmentationConfig{FragmentSize: size})
			hello := clientHello(8)

			done := make(chan struct{})
			var (
				n        int
				writeErr error
				panicked interface{}
			)
			go func() {
				defer func() {
					panicked = recover()
					close(done)
				}()
				n, writeErr = fw.Write(hello)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("FragmentSize=%d: Write did not return within 2s (infinite loop)", size)
			}

			if panicked != nil {
				t.Fatalf("FragmentSize=%d: Write panicked: %v", size, panicked)
			}
			if writeErr != nil {
				t.Fatalf("FragmentSize=%d: Write error: %v", size, writeErr)
			}
			if n != len(hello) {
				t.Fatalf("FragmentSize=%d: Write returned %d, want %d", size, n, len(hello))
			}
			// Clamped to 1 => one segment per byte.
			if got := cc.segCount(); got != len(hello) {
				t.Fatalf("FragmentSize=%d: segment count = %d, want %d (fragSize clamped to 1)", size, got, len(hello))
			}
			if string(cc.joined()) != string(hello) {
				t.Fatalf("FragmentSize=%d: fragments differ from input", size)
			}
		})
	}
}

func TestFragmentedWriterPassthroughMethods(t *testing.T) {
	cc := &capturingConn{}
	fw := NewFragmentedWriter(cc, nil)
	if fw.NetConn() != cc {
		t.Fatal("NetConn did not return underlying conn")
	}
	if _, err := fw.Read(make([]byte, 4)); err != net.ErrClosed {
		t.Fatal("Read did not pass through to underlying conn")
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = fw.LocalAddr()
	_ = fw.RemoteAddr()
	if err := fw.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := fw.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := fw.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}
