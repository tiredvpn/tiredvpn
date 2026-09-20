package evasion

import (
	"net"
	"sync"
	"testing"
	"time"
)

// capturingPacketConn records each datagram written to it.
type capturingPacketConn struct {
	mu      sync.Mutex
	written [][]byte
	addr    *net.UDPAddr
}

func newCapturingPacketConn() *capturingPacketConn {
	return &capturingPacketConn{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4433}}
}

func (c *capturingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := make([]byte, len(p))
	copy(d, p)
	c.written = append(c.written, d)
	return len(p), nil
}

func (c *capturingPacketConn) datagrams() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.written))
	copy(out, c.written)
	return out
}

func (c *capturingPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *capturingPacketConn) Close() error                       { return nil }
func (c *capturingPacketConn) LocalAddr() net.Addr                { return c.addr }
func (c *capturingPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *capturingPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *capturingPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ net.PacketConn = (*capturingPacketConn)(nil)

// quicInitial builds an n-byte packet whose first byte marks a QUIC long-header
// Initial packet (isQUICInitialPacket returns true).
func quicInitial(n int) []byte {
	p := make([]byte, n)
	p[0] = 0xC0 // long header (0x80) + Initial type (0x00 in bits 4-5)
	for i := 1; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

func TestIsQUICInitialPacket(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"too short", []byte{0xC0, 0x00}, false},
		{"initial long header", quicInitial(10), true},
		{"short header", func() []byte { p := quicInitial(10); p[0] = 0x40; return p }(), false},
		{"long header non-initial", func() []byte { p := quicInitial(10); p[0] = 0xD0; return p }(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isQUICInitialPacket(tc.in); got != tc.want {
				t.Fatalf("isQUICInitialPacket = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQUICFragmentDisabledPassthrough(t *testing.T) {
	cc := newCapturingPacketConn()
	fc := NewQUICFragmentPacketConn(cc, &QUICFragmentConfig{Enabled: false})
	pkt := quicInitial(200)
	if _, err := fc.WriteTo(pkt, cc.addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	dg := cc.datagrams()
	if len(dg) != 1 || string(dg[0]) != string(pkt) {
		t.Fatalf("disabled fragmenter must pass through unchanged, got %d datagrams", len(dg))
	}
}

func TestQUICFragmentNonInitialPassthrough(t *testing.T) {
	cc := newCapturingPacketConn()
	fc := NewQUICFragmentPacketConn(cc, DefaultQUICFragmentConfig())
	// Short-header packet, large enough to pass the len<10 guard.
	pkt := quicInitial(200)
	pkt[0] = 0x40 // short header -> not Initial
	if _, err := fc.WriteTo(pkt, cc.addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if dg := cc.datagrams(); len(dg) != 1 {
		t.Fatalf("non-Initial packet must pass through as 1 datagram, got %d", len(dg))
	}
}

func TestQUICFragmentSmallPacketPassthrough(t *testing.T) {
	cc := newCapturingPacketConn()
	fc := NewQUICFragmentPacketConn(cc, DefaultQUICFragmentConfig())
	small := []byte{0xC0, 0x01, 0x02} // len < 10
	if _, err := fc.WriteTo(small, cc.addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if dg := cc.datagrams(); len(dg) != 1 || string(dg[0]) != string(small) {
		t.Fatalf("small packet must pass through unchanged, got %d datagrams", len(dg))
	}
}

func TestQUICFragmentInitialSplitsIntoMultiple(t *testing.T) {
	cc := newCapturingPacketConn()
	// FragmentSize is floored to 50 internally; a 200-byte packet => 4 fragments.
	fc := NewQUICFragmentPacketConn(cc, &QUICFragmentConfig{Enabled: true, FragmentSize: 50})
	pkt := quicInitial(200)
	n, err := fc.WriteTo(pkt, cc.addr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("WriteTo returned %d, want %d", n, len(pkt))
	}
	dg := cc.datagrams()
	if len(dg) < 2 {
		t.Fatalf("Initial packet was not fragmented: %d datagrams", len(dg))
	}
	// Every datagram must carry the fragment header magic.
	for i, d := range dg {
		if len(d) < fragHeaderSize || d[0] != fragMagic1 || d[1] != fragMagic2 {
			t.Fatalf("datagram %d missing fragment header magic", i)
		}
		if total := int(d[4])<<8 | int(d[5]); total != len(dg) {
			t.Fatalf("datagram %d declares total=%d, want %d", i, total, len(dg))
		}
	}
}

// TestQUICFragmentReassemblyE2E is the positive control (rule 2): fragmenting a
// packet and then reassembling it with the server-side counterpart must recover
// the exact original bytes. If the header layout or offsets were wrong, the
// round-trip would corrupt or drop the packet.
func TestQUICFragmentReassemblyE2E(t *testing.T) {
	cc := newCapturingPacketConn()
	fc := NewQUICFragmentPacketConn(cc, &QUICFragmentConfig{Enabled: true, FragmentSize: 50})

	original := quicInitial(237)
	if _, err := fc.WriteTo(original, cc.addr); err != nil {
		t.Fatalf("fragment WriteTo: %v", err)
	}

	// Feed the captured fragments into the reassembler through a buffered conn.
	mc := newBufferedPacketConn()
	for _, d := range cc.datagrams() {
		mc.packets <- d
	}
	rc := NewQUICReassemblyPacketConn(mc, DefaultReassemblyConfig())
	defer rc.Close()

	buf := make([]byte, 2000)
	rc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := rc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("reassembly ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(original) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", n, len(original))
	}
}
