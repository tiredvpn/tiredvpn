package tun

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// firstFrame is a tunnel frame [len:4][pkt:N] the way the packet loop reads
// it. Its first byte is 0x00, as the first byte of every frame is (len is at
// most maxFrameLen), which is exactly what made it pass for a flags byte.
var firstFrame = func() []byte {
	pkt := []byte("first-packet")
	f := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(f, uint32(len(pkt)))
	copy(f[4:], pkt)
	return f
}()

// readFrameAfterHandshake reads one [len:4][pkt:N] frame from conn the way
// the packet loop does and fails the test unless it is firstFrame.
func readFrameAfterHandshake(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("frame header after handshake: %v", err)
	}
	l := binary.BigEndian.Uint32(hdr)
	if l != uint32(len(firstFrame)-4) {
		t.Fatalf("frame length after handshake = %d (header %x), want %d: stream desynced",
			l, hdr, len(firstFrame)-4)
	}
	pkt := make([]byte, l)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		t.Fatalf("frame body after handshake: %v", err)
	}
	if !bytes.Equal(pkt, firstFrame[4:]) {
		t.Fatalf("frame body = %q, want %q", pkt, firstFrame[4:])
	}
}

// handshakeCases are the responses a 1.11.x exit or relay sends, keyed by the
// version the client offered (see buildTUNHandshakeResponse).
func handshakeCases() []struct {
	name    string
	version byte
	resp    []byte
} {
	block, _, _ := dualBlock()
	with := func(tail ...byte) []byte { return append(append([]byte{}, handshakeBase...), tail...) }
	v2hop := with(tunFlagPortHopping|tunFlagMTUProbe, 0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x01, 0x02, 's', 'd')
	return []struct {
		name    string
		version byte
		resp    []byte
	}{
		{"v3 bare 9 (h2/morph/confusion/polling, raw relay)", tunHandshakeVersion, with()},
		{"v3 probe flag (raw exit)", tunHandshakeVersion, with(tunFlagMTUProbe)},
		{"v3 port-hop v2 (raw exit, -port-range)", tunHandshakeVersion, v2hop},
		{"v1 bare 9", 0x01, with()},
		{"v4 flags 0x00 (no v6 pool)", tunHandshakeVersionDualStack, with(0x00)},
		{"v4 probe flag", tunHandshakeVersionDualStack, with(tunFlagMTUProbe)},
		{"v4 dual block", tunHandshakeVersionDualStack, append(with(tunFlagMTUProbe|tunFlagDualStack), block...)},
	}
}

// TestHandshakeCoalescedWithFirstFrame is scenario 1 of issue #93: the first
// Read returns the handshake response together with the start of the first
// tunnel frame. Nothing past the response may be consumed.
func TestHandshakeCoalescedWithFirstFrame(t *testing.T) {
	for _, tc := range handshakeCases() {
		t.Run(tc.name, func(t *testing.T) {
			wire := append(append([]byte{}, tc.resp...), firstFrame...)
			conn := chunkedConn(t, wire) // one Write: response and frame together
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			resp, n, next, err := readHandshakeResponse(conn, tc.version, time.Time{})
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			if !bytes.Equal(resp[:n], tc.resp) {
				t.Fatalf("response = %x, want %x", resp[:n], tc.resp)
			}
			readFrameAfterHandshake(t, next)
		})
	}
}

// TestHandshakeFrameInsideFlagsWindow is scenario 2 of issue #93: the
// response arrives on its own and the first frame follows inside the old
// 300 ms flags window.
func TestHandshakeFrameInsideFlagsWindow(t *testing.T) {
	for _, tc := range handshakeCases() {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			t.Cleanup(func() { cli.Close(); srv.Close() })
			go func() {
				if _, err := srv.Write(tc.resp); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond) // well inside handshakeFlagsGrace
				_, _ = srv.Write(firstFrame)
			}()
			if err := cli.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			resp, n, next, err := readHandshakeResponse(cli, tc.version, time.Time{})
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			if !bytes.Equal(resp[:n], tc.resp) {
				t.Fatalf("response = %x, want %x", resp[:n], tc.resp)
			}
			readFrameAfterHandshake(t, next)
		})
	}
}
