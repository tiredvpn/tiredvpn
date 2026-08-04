package server

import (
	"encoding/binary"
	"net"
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
