package strategy

import (
	"net"
	"sync"
	"testing"
	"time"
)

// unsyncConn is a net.Conn whose Write appends to a slice WITHOUT any lock. If
// the burst flush and the ticker Flush ever write concurrently, the race
// detector fires on this slice - which is exactly the bug writeMu closes.
type unsyncConn struct {
	writes [][]byte
}

func (c *unsyncConn) Read([]byte) (int, error) { return 0, nil }
func (c *unsyncConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *unsyncConn) Close() error                     { return nil }
func (c *unsyncConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *unsyncConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *unsyncConn) SetDeadline(time.Time) error      { return nil }
func (c *unsyncConn) SetReadDeadline(time.Time) error  { return nil }
func (c *unsyncConn) SetWriteDeadline(time.Time) error { return nil }

// TestRTTMaskingSerialisesWrites runs a producer of ordered records against a
// live burst-flush ticker and asserts, under -race, that writes to the wire are
// neither concurrent nor reordered, and that Write honours the io.Writer
// contract (n <= len(p)).
//
// Predicated against the broken code: move the c.Conn writes out of writeMu (or
// drop the lock) and -race reddens; the byte-order assertion catches a tick that
// overtakes a sleeping flush.
func TestRTTMaskingSerialisesWrites(t *testing.T) {
	sink := &unsyncConn{}
	c := NewRTTMaskingConn(sink, RTTMaskingConfig{
		Enabled:       true,
		BurstMode:     true,
		BurstSize:     4,
		BurstInterval: 500 * time.Microsecond, // ticker fires often, racing the flush
		BaseDelay:     200 * time.Microsecond,
		JitterRange:   200 * time.Microsecond,
	})

	const total = 256
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < total; i++ {
			n, err := c.Write([]byte{byte(i)})
			if err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			if n != 1 {
				t.Errorf("write %d returned n=%d, want 1 (n must be <= len(p))", i, n)
				return
			}
		}
	}()
	wg.Wait()

	// Close stops the ticker and flushes the tail, after which no goroutine
	// touches the sink, so reading it is race-free.
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var flat []byte
	for _, w := range sink.writes {
		flat = append(flat, w...)
	}
	if len(flat) != total {
		t.Fatalf("wire saw %d bytes, want %d", len(flat), total)
	}
	for i := 0; i < total; i++ {
		if flat[i] != byte(i) {
			t.Fatalf("byte %d on the wire = %d, want %d (records reordered)", i, flat[i], byte(i))
		}
	}
}
