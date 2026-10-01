package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
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

// exit behaviours for playReconnectExitMode.
type exitMode int

const (
	frameLater  exitMode = iota // first frame 50 ms after the answer
	frameInRead                 // first frame in the same Write as the answer
	quietAfter                  // answer, then nothing
)

// playReconnectExit answers one TUN handshake on srv with the bare v0x03
// response and sends the first frame 50 ms later.
func playReconnectExit(srv net.Conn) { playReconnectExitMode(srv, frameLater) }

func playReconnectExitMode(srv net.Conn, mode exitMode) {
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		resp := append([]byte{0x00}, reconnServerIP.To4()...)
		resp = append(resp, reconnClientIP.To4()...)
		switch mode {
		case frameInRead:
			_, _ = srv.Write(append(resp, reconnFirstFrame()...))
			return
		case quietAfter:
			_, _ = srv.Write(resp)
			return
		}
		if _, err := srv.Write(resp); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = srv.Write(reconnFirstFrame())
	}()
}

// deadlineTrackConn records the last read deadline armed on it.
type deadlineTrackConn struct {
	net.Conn
	mu   sync.Mutex
	last time.Time
	n    int
}

func (c *deadlineTrackConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.last, c.n = t, c.n+1
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineTrackConn) assertCleared(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == 0 {
		t.Fatal("reconnect handshake armed no read deadline")
	}
	if !c.last.IsZero() {
		t.Fatalf("reconnect handshake left a read deadline %v out on the relay conn", time.Until(c.last).Round(time.Millisecond))
	}
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
	for name, mode := range map[string]exitMode{"frame 50ms later": frameLater, "coalesced": frameInRead} {
		t.Run(name, func(t *testing.T) {
			cli, srv := net.Pipe()
			t.Cleanup(func() { cli.Close(); srv.Close() })
			playReconnectExitMode(srv, mode)

			rec := &deadlineTrackConn{Conn: cli}
			conn, _, assigned, _, _, err := sendReconnectHandshake(rec, reconnClientIP, 1280, false, time.Time{})
			if err != nil {
				t.Fatalf("sendReconnectHandshake: %v", err)
			}
			if !assigned.Equal(reconnClientIP) {
				t.Errorf("assigned = %s, want %s", assigned, reconnClientIP)
			}
			rec.assertCleared(t)
			expectFirstFrame(t, conn)
		})
	}
}

// TestReconnectTUNSilentPeerFails: a dual-stack reconnect whose exit sends the
// prefix and goes quiet fails on the reconnect context's deadline instead of
// hanging the reconnect.
func TestReconnectTUNSilentPeerFails(t *testing.T) {
	mgr := strategy.NewManager()
	mgr.Register(&pipeReconnectStrategy{t: t, mode: quietAfter})

	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := reconnectTUN(ctx, mgr, "203.0.113.10:443", reconnClientIP, 1280, true)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent exit accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect hung on a silent exit")
	}
}

// pipeReconnectStrategy dials an in-memory exit played by playReconnectExit.
type pipeReconnectStrategy struct {
	t    *testing.T
	mode exitMode
}

func (s *pipeReconnectStrategy) Name() string                        { return "pipe" }
func (s *pipeReconnectStrategy) ID() string                          { return "pipe" }
func (s *pipeReconnectStrategy) Priority() int                       { return 1 }
func (s *pipeReconnectStrategy) Probe(context.Context, string) error { return nil }
func (s *pipeReconnectStrategy) RequiresServer() bool                { return false }
func (s *pipeReconnectStrategy) Description() string                 { return "in-memory pipe" }
func (s *pipeReconnectStrategy) Connect(context.Context, string) (net.Conn, error) {
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	playReconnectExitMode(srv, s.mode)
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
