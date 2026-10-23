package server

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

func newTestRelaySink(t *testing.T) (*relayTUNSink, net.Conn) {
	t.Helper()
	client, upstream := net.Pipe()
	sink := &relayTUNSink{
		up:     client,
		logger: log.WithPrefix("test"),
		done:   make(chan struct{}),
	}
	t.Cleanup(func() {
		sink.Close()
		upstream.Close()
	})
	return sink, upstream
}

func TestRelaySinkWritePacketFraming(t *testing.T) {
	sink, upstream := newTestRelaySink(t)

	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef}
	go func() { sink.WritePacket(pkt) }()

	buf := make([]byte, 4+len(pkt))
	upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFullConn(upstream, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if got := binary.BigEndian.Uint32(buf[:4]); int(got) != len(pkt) {
		t.Errorf("length prefix = %d, want %d", got, len(pkt))
	}
	if string(buf[4:]) != string(pkt) {
		t.Errorf("payload = %x, want %x", buf[4:], pkt)
	}
}

func TestRelaySinkPumpDeliversPackets(t *testing.T) {
	sink, upstream := newTestRelaySink(t)

	delivered := make(chan []byte, 4)
	go sink.pump(func(pkt []byte) error {
		delivered <- append([]byte(nil), pkt...)
		return nil
	})

	// A keepalive (zero-length frame) must not reach the client: the downstream
	// transport answers its own client's keepalives.
	go func() {
		upstream.Write([]byte{0, 0, 0, 0})
		pkt := []byte{0x45, 0x11, 0x22, 0x33}
		frame := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(pkt)))
		copy(frame[4:], pkt)
		upstream.Write(frame)
	}()

	select {
	case got := <-delivered:
		if string(got) != string([]byte{0x45, 0x11, 0x22, 0x33}) {
			t.Fatalf("delivered %x, want the data packet (keepalive must be dropped)", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet delivered")
	}
}

func TestRelaySinkPumpClosesOnUpstreamEOF(t *testing.T) {
	sink, upstream := newTestRelaySink(t)

	go sink.pump(func([]byte) error { return nil })
	upstream.Close()

	select {
	case <-sink.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("sink did not signal Done after the upstream closed; the transport read loop would hang")
	}
}

func TestRelaySinkPumpRejectsOversizedFrame(t *testing.T) {
	sink, upstream := newTestRelaySink(t)

	go sink.pump(func([]byte) error { return nil })
	go func() {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 70000) // above the IP packet ceiling
		upstream.Write(hdr)
	}()

	select {
	case <-sink.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("desynced stream did not tear the leg down")
	}
}

func TestRelaySinkCloseIsIdempotent(t *testing.T) {
	sink, _ := newTestRelaySink(t)
	sink.Close()
	sink.Close() // must not panic on a double close of done
}

// readFullConn reads len(buf) bytes, retrying short reads.
func readFullConn(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// nopTUNSink is a sink that swallows everything, for transport tests that only
// care about what goes back down to the client.
type nopTUNSink struct {
	packets [][]byte
}

func (s *nopTUNSink) WritePacket(pkt []byte) error {
	s.packets = append(s.packets, append([]byte(nil), pkt...))
	return nil
}
func (s *nopTUNSink) Done() <-chan struct{} { return nil }
func (s *nopTUNSink) UpdateActivity()       {}
func (s *nopTUNSink) Close()                {}

// TestRelaySinkKeepsTheUpstreamLegAlive is P3-13 of the round-4 review: an
// idle HTTP Polling session through a relay sent nothing up - the Polling
// client sends no keepalive and the relay answers keepalives itself - and the
// upstream leg died after relayTUNIdleTimeout. The downstream client's
// activity now sends a keepalive up once the leg has been silent for its
// drawn quiet period - and, since P2-5 of round 5, not while the leg carries
// traffic in either direction.
func TestRelaySinkKeepsTheUpstreamLegAlive(t *testing.T) {
	old := relayKeepaliveAfter
	var draws atomic.Int32
	relayKeepaliveAfter = func() time.Duration { draws.Add(1); return 300 * time.Millisecond }
	t.Cleanup(func() { relayKeepaliveAfter = old })
	sink, upstream := newTestRelaySink(t)

	frames := make(chan []byte, 16)
	go func() {
		for {
			hdr := make([]byte, 4)
			if _, err := readFullConn(upstream, hdr); err != nil {
				return
			}
			body := make([]byte, binary.BigEndian.Uint32(hdr))
			if _, err := readFullConn(upstream, body); err != nil {
				return
			}
			frames <- append(hdr, body...)
		}
	}()
	keepalive := func(want bool, what string) {
		t.Helper()
		select {
		case f := <-frames:
			if !want {
				t.Fatalf("%s: a frame went up (%x)", what, f)
			}
			if binary.BigEndian.Uint32(f) != 0 {
				t.Fatalf("%s: frame %x is not a keepalive", what, f)
			}
		case <-time.After(150 * time.Millisecond):
			if want {
				t.Fatalf("%s: no keepalive went up", what)
			}
		}
	}

	for range 5 { // a burst of polls on a silent leg: one keepalive
		sink.UpdateActivity()
	}
	keepalive(true, "silent leg")
	sink.UpdateActivity()
	keepalive(false, "right after a keepalive")

	// Traffic up resets the silence.
	time.Sleep(200 * time.Millisecond)
	go func() { _ = sink.WritePacket([]byte{0x45, 0, 0, 20}) }()
	if f := <-frames; binary.BigEndian.Uint32(f) == 0 {
		t.Fatal("the data frame came up as a keepalive")
	}
	time.Sleep(150 * time.Millisecond)
	sink.UpdateActivity()
	keepalive(false, "150 ms after a packet up")

	// So does traffic down, the exit's echo included.
	down := make(chan []byte, 4)
	go sink.pump(func(pkt []byte) error { down <- pkt; return nil })
	time.Sleep(200 * time.Millisecond)
	go func() { _, _ = upstream.Write([]byte{0, 0, 0, 0}) }()
	time.Sleep(150 * time.Millisecond)
	sink.UpdateActivity()
	keepalive(false, "150 ms after the exit's echo")

	time.Sleep(350 * time.Millisecond)
	sink.UpdateActivity()
	keepalive(true, "after the quiet period")
	// A quiet period is drawn for the first silence and after each keepalive:
	// one value for every period would be the grid the draw is there to avoid.
	if n := draws.Load(); n < 3 {
		t.Fatalf("%d quiet periods drawn for two keepalives", n)
	}
}

// TestRelayKeepalivePauseHasNoGrid checks the shape of the drawn quiet
// period (verification rule 3): inside 60-150 s, under the 3 min the leg dies
// at, spread out rather than on a grid, and not flat - half the draws sit in
// the hump at 75-95 s, where a uniform draw puts a fifth, and the lowest
// tenth of the range is no more crowded than a uniform draw would make it.
func TestRelayKeepalivePauseHasNoGrid(t *testing.T) {
	const n = 4000
	seen := map[time.Duration]bool{}
	var sum time.Duration
	low, mid := 0, 0
	for range n {
		d := relayKeepaliveAfter()
		if d < 60*time.Second || d >= 150*time.Second || d >= relayTUNIdleTimeout {
			t.Fatalf("drew %v, outside [60 s, 150 s)", d)
		}
		seen[d.Round(100*time.Millisecond)] = true
		sum += d
		if d < 69*time.Second {
			low++
		}
		if d >= 75*time.Second && d < 95*time.Second {
			mid++
		}
	}
	if len(seen) < n/10 {
		t.Fatalf("only %d distinct values in %d draws: a grid", len(seen), n)
	}
	if mean := sum / n; mean < 80*time.Second || mean > 100*time.Second {
		t.Fatalf("mean %v, want about 90 s", mean)
	}
	if mid < n*35/100 {
		t.Fatalf("%d of %d draws in 75-95 s: flat, not a hump", mid, n)
	}
	if low > n/10 {
		t.Fatalf("%d of %d draws in the lowest tenth of the range: a pile-up at the floor", low, n)
	}
}
