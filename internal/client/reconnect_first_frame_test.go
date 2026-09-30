package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// Issue #93 on the control server's reconnect path: an exit answers a v0x03
// client with the bare 9-byte form and sends its first frame 50 ms later. The
// handshake reader has to look at the frame's first byte to tell it from a
// flags byte and hands it back through the conn it returns, so the conn put
// into ReconnectResult (what the relay reads) must be that one.

var (
	reconnServerIP = net.IPv4(10, 99, 0, 1)
	reconnClientIP = net.IPv4(10, 99, 0, 2)
)

func reconnFirstFrame() []byte {
	pkt := []byte("first-packet")
	f := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(f, uint32(len(pkt)))
	copy(f[4:], pkt)
	return f
}

// playReconnectExit answers one TUN handshake on srv with the bare v0x03
// response and sends the first frame 50 ms later.
func playReconnectExit(srv net.Conn) {
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		resp := append([]byte{0x00}, reconnServerIP.To4()...)
		resp = append(resp, reconnClientIP.To4()...)
		if _, err := srv.Write(resp); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = srv.Write(reconnFirstFrame())
	}()
}

func expectFirstFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	want := reconnFirstFrame()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("first frame after handshake: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("first frame = %x, want %x: stream desynced", got, want)
	}
}

func TestSendReconnectHandshakeKeepsFirstFrame(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	playReconnectExit(srv)

	conn, _, assigned, _, _, err := sendReconnectHandshake(cli, reconnClientIP, 1280, false)
	if err != nil {
		t.Fatalf("sendReconnectHandshake: %v", err)
	}
	if !assigned.Equal(reconnClientIP) {
		t.Errorf("assigned = %s, want %s", assigned, reconnClientIP)
	}
	expectFirstFrame(t, conn)
}

// pipeReconnectStrategy dials an in-memory exit played by playReconnectExit.
type pipeReconnectStrategy struct{ t *testing.T }

func (s *pipeReconnectStrategy) Name() string                        { return "pipe" }
func (s *pipeReconnectStrategy) ID() string                          { return "pipe" }
func (s *pipeReconnectStrategy) Priority() int                       { return 1 }
func (s *pipeReconnectStrategy) Probe(context.Context, string) error { return nil }
func (s *pipeReconnectStrategy) RequiresServer() bool                { return false }
func (s *pipeReconnectStrategy) Description() string                 { return "in-memory pipe" }
func (s *pipeReconnectStrategy) Connect(context.Context, string) (net.Conn, error) {
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	playReconnectExit(srv)
	return cli, nil
}

func TestReconnectTUNKeepsFirstFrame(t *testing.T) {
	mgr := strategy.NewManager()
	mgr.Register(&pipeReconnectStrategy{t: t})

	res, err := reconnectTUN(t.Context(), mgr, "203.0.113.10:443", reconnClientIP, 1280, false)
	if err != nil {
		t.Fatalf("reconnectTUN: %v", err)
	}
	expectFirstFrame(t, res.Conn)
}
