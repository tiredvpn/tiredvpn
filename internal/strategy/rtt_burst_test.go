package strategy

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// recordingConn captures every Write the burst path issues to the wire.
type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

func (c *recordingConn) Close() error { return nil }

func (c *recordingConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.written))
	copy(out, c.written)
	return out
}

// TestWriteWithBurst_CallerMayReuseBuffer is the guard on the burst path passing
// the caller's slice through by reference when it flushes immediately. Buffered
// packets outlive the Write call and must still be copied; this test scribbles
// over the caller's buffer after every Write to catch a lost copy.
func TestWriteWithBurst_CallerMayReuseBuffer(t *testing.T) {
	sink := &recordingConn{}
	c := NewRTTMaskingConn(sink, RTTMaskingConfig{
		Enabled:       true,
		BurstMode:     true,
		BurstSize:     3,
		BurstInterval: time.Hour, // only the size condition may trigger a flush
	})
	defer c.Close()

	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 64),
		bytes.Repeat([]byte{0x02}, 65),
		bytes.Repeat([]byte{0x03}, 66),
	}

	scratch := make([]byte, 66)
	for i, want := range payloads {
		buf := scratch[:len(want)]
		copy(buf, want)
		n, err := c.Write(buf)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if n != len(want) {
			t.Fatalf("write %d returned %d, want %d", i, n, len(want))
		}
		// The caller owns buf again now.
		for j := range buf {
			buf[j] = 0xFF
		}
	}

	got := sink.snapshot()
	if len(got) != len(payloads) {
		t.Fatalf("wire saw %d writes, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if !bytes.Equal(got[i], payloads[i]) {
			t.Fatalf("write %d on the wire = %x..., want %x...", i, got[i][:8], payloads[i][:8])
		}
	}
}

// TestWriteWithBurst_FlushesPartialBurst covers Flush draining packets that are
// still buffered when the burst never reaches BurstSize.
func TestWriteWithBurst_FlushesPartialBurst(t *testing.T) {
	sink := &recordingConn{}
	c := NewRTTMaskingConn(sink, RTTMaskingConfig{
		Enabled:       true,
		BurstMode:     true,
		BurstSize:     10,
		BurstInterval: time.Hour,
	})
	defer c.Close()

	want := []byte("partial burst payload")
	buf := append([]byte(nil), want...)
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	for j := range buf {
		buf[j] = 0xFF
	}

	if n := len(sink.snapshot()); n != 0 {
		t.Fatalf("packet reached the wire before flush (%d writes)", n)
	}

	if err := c.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("wire saw %d writes after flush, want 1", len(got))
	}
	if !bytes.Equal(got[0], want) {
		t.Fatalf("flushed %q, want %q", got[0], want)
	}
}
