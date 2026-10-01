package tun

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// The tests in this file drive each place that runs a TUN handshake and then
// keeps reading the tunnel, against an exit that answers a v0x03 client with
// the bare 9-byte form and sends its first frame 50 ms later (issue #93,
// scenario 2). The handshake reader has to look at that frame's first byte to
// know it is not a flags byte, and hands it back through the conn it returns;
// a caller that goes on reading the conn it passed in loses the byte and
// desyncs. So each test reads the first frame from whatever conn the caller
// installed for the packet loop.

var (
	callsiteServerIP = net.IPv4(10, 99, 0, 1)
	callsiteClientIP = net.IPv4(10, 99, 0, 2)
)

// bareV3Response is what an exit's h2/morph/confusion/polling path, or a
// relay on the raw path, sends a v0x03 client.
func bareV3Response() []byte {
	resp := []byte{0x00}
	resp = append(resp, callsiteServerIP.To4()...)
	return append(resp, callsiteClientIP.To4()...)
}

// coalesced as a playExit gap sends the first frame in the same Write as the
// response (issue #93 scenario 1); silent sends no frame at all.
const (
	coalesced time.Duration = -1
	silent    time.Duration = -2
)

// playExit serves one TUN handshake on srv: it reads the 8-byte request,
// answers with resp and, after gap, sends firstFrame.
func playExit(t *testing.T, srv net.Conn, resp []byte, gap time.Duration) {
	t.Helper()
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		switch gap {
		case coalesced:
			_, _ = srv.Write(append(append([]byte{}, resp...), firstFrame...))
			return
		case silent:
			_, _ = srv.Write(resp)
			return
		}
		if _, err := srv.Write(resp); err != nil {
			return
		}
		time.Sleep(gap)
		_, _ = srv.Write(firstFrame)
	}()
}

// pipeStrategy is a strategy whose every Connect returns the client end of a
// fresh pipe, with the exit side played by playExit.
type pipeStrategy struct {
	t    *testing.T
	resp []byte
	gap  time.Duration    // 0: 50 ms
	last *recDeadlineConn // the conn of the latest Connect
}

func (s *pipeStrategy) Name() string                        { return "pipe" }
func (s *pipeStrategy) ID() string                          { return "pipe" }
func (s *pipeStrategy) Priority() int                       { return 1 }
func (s *pipeStrategy) Probe(context.Context, string) error { return nil }
func (s *pipeStrategy) RequiresServer() bool                { return false }
func (s *pipeStrategy) Description() string                 { return "in-memory pipe" }
func (s *pipeStrategy) Connect(context.Context, string) (net.Conn, error) {
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	gap := s.gap
	if gap == 0 {
		gap = 50 * time.Millisecond
	}
	playExit(s.t, srv, s.resp, gap)
	s.last = &recDeadlineConn{Conn: cli}
	return s.last, nil
}

func newPipeManager(t *testing.T) *strategy.Manager {
	t.Helper()
	m, _ := newPipeManagerWith(t, bareV3Response(), 0)
	return m
}

func newPipeManagerWith(t *testing.T, resp []byte, gap time.Duration) (*strategy.Manager, *pipeStrategy) {
	t.Helper()
	m := strategy.NewManager()
	ps := &pipeStrategy{t: t, resp: resp, gap: gap}
	m.Register(ps)
	return m, ps
}

// noDeadlineLeft fails the test when the last read deadline armed on the
// dialled conn is not cleared.
func noDeadlineLeft(t *testing.T, c *recDeadlineConn) {
	t.Helper()
	if c == nil {
		t.Fatal("no conn was dialled")
	}
	last, n := c.lastDeadline()
	if n == 0 {
		t.Fatal("handshake armed no read deadline")
	}
	if !last.IsZero() {
		t.Fatalf("handshake left a read deadline %v out on the tunnel conn", time.Until(last).Round(time.Millisecond))
	}
}

// shortHandshakeTimeout shortens the default response budget for one test.
func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := handshakeReadTimeout
	handshakeReadTimeout = d
	t.Cleanup(func() { handshakeReadTimeout = old })
}

// newCallsiteClient is a v0x03 VPNClient whose TUN already carries the
// addresses the scripted exit assigns, so the connect paths have nothing to
// reconfigure on the (absent) interface.
func newCallsiteClient(m *strategy.Manager) *VPNClient {
	v := &VPNClient{
		manager:    m,
		serverAddr: "203.0.113.10:443",
		localIP:    callsiteClientIP,
		tun:        &TUNDevice{mtu: 1280, remoteIP: callsiteServerIP},
		ipv6Policy: IPv6PolicyOff,
	}
	atomic.StoreInt32(&v.running, 1)
	return v
}

// TestConnectKeepsFirstFrame covers connect(): the conn it publishes as v.conn
// is the one the packet loop reads.
func TestConnectKeepsFirstFrame(t *testing.T) {
	v := newCallsiteClient(newPipeManager(t))
	if err := v.connect(t.Context()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	readFrameAfterHandshake(t, v.conn)
}

// TestSeamlessPortHopKeepsFirstFrame covers the port-hop swap: the conn that
// replaces v.conn is the one the packet loop reads.
func TestSeamlessPortHopKeepsFirstFrame(t *testing.T) {
	v := newCallsiteClient(newPipeManager(t))
	old, oldPeer := net.Pipe()
	t.Cleanup(func() { old.Close(); oldPeer.Close() })
	v.conn = old

	v.seamlessPortHop(8443)

	if v.conn == old {
		t.Fatal("port hop did not swap the connection")
	}
	readFrameAfterHandshake(t, v.conn)
}

// TestControlHandshakeKeepsFirstFrame covers the control-socket (host-owned
// TUN) handshake, the Android path, which sends v0x03 unless IPv6 in the
// tunnel is turned on: cs.serverConn is what the relay goroutine reads
// afterwards, with the frame following the bare answer or in the same Read.
func TestControlHandshakeKeepsFirstFrame(t *testing.T) {
	for name, gap := range map[string]time.Duration{"frame 50ms later": 50 * time.Millisecond, "coalesced": coalesced} {
		t.Run(name, func(t *testing.T) {
			cli, srv := net.Pipe()
			t.Cleanup(func() { cli.Close(); srv.Close() })
			playExit(t, srv, bareV3Response(), gap)

			rec := &recDeadlineConn{Conn: cli}
			cs := &ControlServer{serverConn: rec, mtu: 1280, config: &ControlConfig{}}
			if _, _, err := cs.performTUNHandshake(); err != nil {
				t.Fatalf("performTUNHandshake: %v", err)
			}
			noDeadlineLeft(t, rec)
			readFrameAfterHandshake(t, cs.serverConn)
		})
	}
}

// TestControlHandshakeSilentPeerFails: a dual-stack control handshake whose
// peer sends the prefix and goes quiet fails on the response budget instead
// of hanging the control socket.
func TestControlHandshakeSilentPeerFails(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	playExit(t, srv, bareV3Response(), silent)

	cs := &ControlServer{serverConn: cli, mtu: 1280, config: &ControlConfig{DualStack: true}}
	done := make(chan error, 1)
	go func() { _, _, err := cs.performTUNHandshake(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent peer accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("control handshake hung on a silent peer")
	}
}

// TestConnectLeavesNoDeadline and TestSeamlessPortHopLeavesNoDeadline: the
// conn installed for the packet loop carries no read deadline from the
// handshake.
func TestConnectLeavesNoDeadline(t *testing.T) {
	m, ps := newPipeManagerWith(t, bareV3Response(), coalesced)
	v := newCallsiteClient(m)
	if err := v.connect(t.Context()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	noDeadlineLeft(t, ps.last)
	readFrameAfterHandshake(t, v.conn)
}

func TestSeamlessPortHopLeavesNoDeadline(t *testing.T) {
	m, ps := newPipeManagerWith(t, bareV3Response(), coalesced)
	v := newCallsiteClient(m)
	old, oldPeer := net.Pipe()
	t.Cleanup(func() { old.Close(); oldPeer.Close() })
	v.conn = old
	v.seamlessPortHop(8443)
	if v.conn == old {
		t.Fatal("port hop did not swap the connection")
	}
	noDeadlineLeft(t, ps.last)
	readFrameAfterHandshake(t, v.conn)
}

// TestConnectSilentPeerFails: a v0x04 connect whose exit sends the prefix and
// goes quiet fails on the response budget.
func TestConnectSilentPeerFails(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	m, _ := newPipeManagerWith(t, bareV3Response(), silent)
	v := newCallsiteClient(m)
	v.ipv6Policy = IPv6PolicyDual
	done := make(chan error, 1)
	go func() { done <- v.connect(t.Context()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent exit accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connect hung on a silent exit")
	}
}

// TestV4FlagsByteReadRegardlessOfTiming pins that a v0x04 client takes the
// flags byte from the version, not from when it arrives: a flags byte that
// shows up well after the old 300 ms window is still the flags byte, and the
// dual-stack block it announces is read with it.
func TestV4FlagsByteReadRegardlessOfTiming(t *testing.T) {
	block, server6, client6 := dualBlock()
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		if _, err := srv.Write(bareV3Response()); err != nil {
			return
		}
		time.Sleep(handshakeFlagsGrace + 200*time.Millisecond)
		if _, err := srv.Write(append([]byte{tunFlagDualStack}, block...)); err != nil {
			return
		}
		_, _ = srv.Write(firstFrame)
	}()
	if err := cli.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	resp, n, next, err := readHandshakeResponse(cli, tunHandshakeVersionDualStack, time.Time{})
	if err != nil {
		t.Fatalf("readHandshakeResponse: %v", err)
	}
	caps, _ := parseServerCapabilities(resp, n)
	if !caps.DualStackEnabled || !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
		t.Fatalf("late flags byte not taken as flags: n=%d caps=%+v", n, caps)
	}
	readFrameAfterHandshake(t, next)
}

// TestRefusalIsNotPeekedPast pins that a refusal, which every exit sends as
// the bare prefix, is returned at once for every version: nothing follows it,
// so a v0x04 reader must not wait for a flags byte that will never come.
func TestRefusalIsNotPeekedPast(t *testing.T) {
	for _, version := range []byte{tunHandshakeVersion, tunHandshakeVersionDualStack} {
		conn := &scriptedConn{chunks: [][]byte{{0x01, 0, 0, 0, 0, 0, 0, 0, 0}}}
		resp, n, _, err := readHandshakeResponse(conn, version, time.Time{})
		if err != nil {
			t.Fatalf("version 0x%02x: %v", version, err)
		}
		if n != 9 || resp[0] != 0x01 {
			t.Errorf("version 0x%02x: n=%d status=%#x, want 9 bytes with status 0x01", version, n, resp[0])
		}
		if conn.idx != 1 {
			t.Errorf("version 0x%02x: reader went past the refusal", version)
		}
	}
}

// replayConn must hand back the pending bytes before anything else and then
// read through; a short buffer takes them one read at a time.
func TestReplayConnOrder(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() { _, _ = srv.Write([]byte{3, 4}) }()
	c := &replayConn{Conn: cli, pending: []byte{1, 2}}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, got[1:]); err != nil {
		t.Fatal(err)
	}
	if string(got) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("read %v, want [1 2 3 4]", got)
	}
	if _, ok := any(c).(interface{ NetConn() net.Conn }); ok {
		t.Error("replayConn must not expose the inner conn via NetConn")
	}
	if _, ok := any(c).(interface{ Unwrap() net.Conn }); ok {
		t.Error("replayConn must not expose the inner conn via Unwrap")
	}
}
