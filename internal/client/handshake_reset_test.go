package client

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// A family whose transport connects and whose exit resets every session
// handshake after the request was never parked off the desktop: the
// connect was booked a success that cleared the failure before it, and the
// reset was booked as nothing - on the Android core's first connect and on
// the relay's reconnect (P2 of the round-14 review; the desktop was fixed
// in round 19).

// resettingStrategy connects to its target and plays an exit that reads the
// handshake request and resets, recording the targets it was pointed at.
type resettingStrategy struct {
	t       *testing.T
	mu      sync.Mutex
	targets []string
}

func (s *resettingStrategy) Name() string                        { return "polling" }
func (s *resettingStrategy) ID() string                          { return "polling" }
func (s *resettingStrategy) Priority() int                       { return 1 }
func (s *resettingStrategy) Probe(context.Context, string) error { return nil }
func (s *resettingStrategy) RequiresServer() bool                { return true }
func (s *resettingStrategy) Description() string                 { return "exit that resets after the request" }
func (s *resettingStrategy) Connect(_ context.Context, target string) (net.Conn, error) {
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		_, _ = io.ReadFull(srv, make([]byte, 8))
		srv.Close()
	}()
	return cli, nil
}

func (s *resettingStrategy) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 {
		return ""
	}
	return s.targets[len(s.targets)-1]
}

func parkedNow(m *strategy.Manager, addr string) bool {
	for _, h := range m.EndpointHealth() {
		if h.Addr == addr && h.CooldownUntil.After(time.Now()) {
			return true
		}
	}
	return false
}

// TestARelayReconnectWhoseHandshakeIsResetParksTheAddress: two relay
// reconnects to a, each reset after its request, park a; the third goes
// to b.
func TestARelayReconnectWhoseHandshakeIsResetParksTheAddress(t *testing.T) {
	a, b := acceptAll(t), acceptAll(t)
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	s := &resettingStrategy{t: t}
	m.Register(s)
	for i := 1; i <= 2; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		_, _, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
		cancel()
		if err == nil || s.last() != a {
			t.Fatalf("reconnect %d on %s: %v, want a reset handshake on a - the test proves nothing", i, s.last(), err)
		}
	}
	if !parkedNow(m, a) {
		t.Fatal("a is not parked after two handshakes reset after their request")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, _, _ = reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
	if got := s.last(); got != b {
		t.Fatalf("the third reconnect dialled %s, want b %s", got, b)
	}
}

// TestAnAndroidConnectWhoseHandshakeIsResetParksTheAddress: the Android
// core's connect, and the handshake after it reset (the control server
// reports HandshakeFailedOutcome, see tun's
// TestAnAndroidConnectResetAfterTheRequestIsAFailure): two of them park
// the first server, and the next connect goes to the second.
func TestAnAndroidConnectWhoseHandshakeIsResetParksTheAddress(t *testing.T) {
	m, s := androidPoolManager(t)
	sess := &androidSession{mgr: m, linkUp: func() bool { return true }}
	ccfg := androidControlConfig(&Config{ServerAddr: androidPool[0], TunMTU: 1280}, m, false, sess)
	for i := 1; i <= 2; i++ {
		_, _, conn, err := ccfg.ConnectFn(t.Context())
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		conn.Close()
		if got := s.last(); got != androidPool[0] {
			t.Fatalf("connect %d on %s - the test proves nothing", i, got)
		}
		_ = ccfg.HandshakeOutcomeFn(tun.HandshakeFailedOutcome, io.EOF)
	}
	if !parkedNow(m, androidPool[0]) {
		t.Fatal("the first server is not parked after two handshakes reset after their request")
	}
	_, _, conn, err := ccfg.ConnectFn(t.Context())
	if err != nil {
		t.Fatalf("third connect: %v", err)
	}
	conn.Close()
	if got := s.last(); got != androidPool[1] {
		t.Fatalf("the third connect dialled %s, want %s", got, androidPool[1])
	}
}

// failingConn fails the reconnect's request write or its response read with
// err, as the client's socket reports it.
type failingConn struct {
	net.Conn
	write, read error
}

func (c failingConn) Write(p []byte) (int, error) {
	if c.write != nil {
		return 0, c.write
	}
	return c.Conn.Write(p)
}

func (c failingConn) Read(p []byte) (int, error) {
	if c.read != nil {
		return 0, c.read
	}
	return c.Conn.Read(p)
}

// failingStrategy connects to a pipe whose request write or response read
// fails as failingConn says.
type failingStrategy struct {
	resettingStrategy
	write, read error
}

func (s *failingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	c, err := s.resettingStrategy.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return failingConn{Conn: c, write: s.write, read: s.read}, nil
}

// TestReconnectHandshakeFailuresAreBookedByWhoseSideFailed is findings 2
// and 3 of the round-15 review, through reconnectTUN: a request write the
// peer reset (EPIPE) is the server's failure and parks a after two; a
// read the host aborted (ECONNABORTED: netd destroying the sockets of a
// lost address) is the client's own and parks nothing.
func TestReconnectHandshakeFailuresAreBookedByWhoseSideFailed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		write, read error
		parked      bool
	}{
		{"request write reset by the peer", syscall.EPIPE, nil, true},
		{"read aborted by the host", nil, &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNABORTED)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := acceptAll(t), acceptAll(t)
			m := strategy.NewManager()
			if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "a", V4: a}, {Name: "b", V4: b, Order: 1}}, endpoint.V4Only); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(endpoint.ResetSharedSelectors)
			s := &failingStrategy{resettingStrategy: resettingStrategy{t: t}, write: tc.write, read: tc.read}
			m.Register(s)
			for i := 1; i <= 2; i++ {
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				_, _, err := reconnectTUN(ctx, m, a, reconnClientIP, 1280, false, false)
				cancel()
				if err == nil || s.last() != a {
					t.Fatalf("reconnect %d on %s: %v - the test proves nothing", i, s.last(), err)
				}
			}
			if got := parkedNow(m, a); got != tc.parked {
				t.Fatalf("a parked = %v after two of them, want %v", got, tc.parked)
			}
		})
	}
}

// TestAnUnsetHandshakeOutcomeBooksNothing: the outcomes are numbered from
// one, and one left unset is none of them - not "answered", which ended a
// run of silence, and not "unanswered" (nit of the round-15 review).
func TestAnUnsetHandshakeOutcomeBooksNothing(t *testing.T) {
	m, _ := androidPoolManager(t)
	sess := &androidSession{mgr: m, linkUp: func() bool { return true }}
	ccfg := androidControlConfig(&Config{ServerAddr: androidPool[0], TunMTU: 1280}, m, false, sess)
	_, _, conn, err := ccfg.ConnectFn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	var unset tun.HandshakeOutcome
	for range 3 {
		if got := ccfg.HandshakeOutcomeFn(unset, io.EOF); got != io.EOF {
			t.Fatalf("an unset outcome answered %v, want the error back as it came", got)
		}
	}
	if parkedNow(m, androidPool[0]) {
		t.Fatal("an unset outcome parked the server")
	}
}
