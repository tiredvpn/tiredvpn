package tun

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// returnFront is one address of the same exit: the v6 and v4 of one
// endpoint. What it does to a dial is its own; the session behind it is the
// exit's.
type returnFront struct {
	exit      *returnExit
	dialDelay time.Duration
	// mute reads the TUN handshake and never answers it.
	mute atomic.Bool
	// requested, when set, is called as the handshake request arrives.
	requested atomic.Pointer[func()]
	// answerAfter holds the answer back.
	answerAfter time.Duration
	dials       atomic.Int64
	handshakes  atomic.Int64
}

type frontStrategy struct {
	t      *testing.T
	fronts map[string]*returnFront
}

func (s *frontStrategy) Name() string                        { return "polling" }
func (s *frontStrategy) ID() string                          { return "polling" }
func (s *frontStrategy) Priority() int                       { return 6 }
func (s *frontStrategy) RequiresServer() bool                { return true }
func (s *frontStrategy) Description() string                 { return "pipe to one exit through a front" }
func (s *frontStrategy) Probe(context.Context, string) error { return nil }
func (s *frontStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	f := s.fronts[target]
	f.dials.Add(1)
	select {
	case <-time.After(f.dialDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		f.handshakes.Add(1)
		if h := f.requested.Load(); h != nil {
			(*h)()
		}
		if f.mute.Load() {
			_, _ = io.Copy(io.Discard, srv)
			return
		}
		time.Sleep(f.answerAfter)
		f.exit.serveAnswered(srv)
	}()
	return cli, nil
}

// serveAnswered is serve past the handshake request, which the front read.
func (e *returnExit) serveAnswered(srv net.Conn) {
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(make([]byte, 8))
		_, _ = io.Copy(pw, srv)
		pw.Close()
	}()
	e.serve(readWriteConn{Conn: srv, r: pr})
}

type readWriteConn struct {
	net.Conn
	r io.Reader
}

func (c readWriteConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// sameExitHarness is a client on the v4 family of an endpoint whose v6 -
// preferred - leads to the same exit, after a fault on v6 that is over.
type sameExitHarness struct {
	v        *VPNClient
	m        *strategy.Manager
	exit     *returnExit
	v6, v4   *returnFront
	v6At     string
	app      *os.File
	down     atomic.Int64
	upPacket func() []byte
}

func newSameExitHarness(t *testing.T) *sameExitHarness {
	t.Helper()
	oldIdle, oldEvery, oldRetry, oldProbe := returnIdleAfter, returnCheckEvery, returnRetryAfter, returnProbeWait
	returnIdleAfter, returnCheckEvery, returnProbeWait = 400*time.Millisecond, 50*time.Millisecond, 500*time.Millisecond
	returnRetryAfter = func() time.Duration { return time.Hour }
	t.Cleanup(func() {
		returnIdleAfter, returnCheckEvery, returnRetryAfter, returnProbeWait = oldIdle, oldEvery, oldRetry, oldProbe
	})

	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	t.Cleanup(func() { ln6.Close() })
	v6At, v4At := ln6.Addr().String(), newNetcheckListener(t).addr
	exit := &returnExit{serverIP: net.IPv4(10, 93, 0, 1), clientIP: net.IPv4(10, 93, 0, 2), displace: true}
	v6, v4 := &returnFront{exit: exit}, &returnFront{exit: exit}
	m := strategy.NewManager()
	if err := m.SetEndpointSelection(endpoint.Config{
		Endpoints: []endpoint.Endpoint{{Name: "exit", V6: v6At, V4: v4At}},
		Family:    endpoint.PreferV6, FailureThreshold: 2, Cooldown: time.Minute, MinDwell: 200 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	m.Register(&frontStrategy{t: t, fronts: map[string]*returnFront{v6At: v6, v4At: v4}})
	m.PinCandidate(endpoint.Candidate{Addr: v4At})

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := &TUNDevice{file: os.NewFile(uintptr(fds[0]), "tun"), mtu: 1500, atomicMTU: 1500, remoteIP: exit.serverIP}
	app := os.NewFile(uintptr(fds[1]), "app")
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, tun: dev, localIP: exit.clientIP,
		serverAddr: v4At, ownsInterface: true, ipv6Policy: IPv6PolicyOff, stall: newFlowTable()}
	logOut := &stampedLog{}
	setLog(t, logOut)
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logOut.String())
		}
	})
	if err := v.connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := m.GetServerAddr(context.Background()); got != v4At {
		t.Fatalf("the session rides %s, want v4 %s", got, v4At)
	}
	h := &sameExitHarness{v: v, m: m, exit: exit, v6: v6, v4: v4, v6At: v6At, app: app}
	h.upPacket = func() []byte {
		pkt := make([]byte, 60)
		pkt[0], pkt[9] = 0x45, 17
		pkt[3] = 60
		copy(pkt[12:16], exit.clientIP.To4())
		copy(pkt[16:20], net.IPv4(203, 0, 113, 7).To4())
		return pkt
	}
	go v.readFromTun()
	go v.readFromServer()
	watched := make(chan struct{})
	go func() { v.watchReturnToPreferred(); close(watched) }()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, err := app.Read(buf); err != nil {
				return
			}
			h.down.Add(1)
		}
	}()
	t.Cleanup(func() {
		atomic.StoreInt32(&v.running, 0)
		close(v.stopCh)
		<-watched
		v.mu.Lock()
		if v.conn != nil {
			v.conn.Close()
		}
		v.mu.Unlock()
		app.Close()
		dev.file.Close()
	})
	return h
}

// downlinkWorks sends packets down the exit's latest session until one
// reaches the TUN.
func (h *sameExitHarness) downlinkWorks(d time.Duration) bool {
	before := h.down.Load()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		h.exit.sendDown(h.upPacket())
		if h.down.Load() > before {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestAReturnThatWakesUpDuringItsDialLeavesTheTunnel is P2-3 (a) of the
// round-10 review: the v6 dial is slow, and traffic resumes while it runs.
// The return used to go on to the handshake, which displaced the session
// on the exit, then drop the new session for the traffic - and the tunnel
// was gone. It has to stop before the handshake.
func TestAReturnThatWakesUpDuringItsDialLeavesTheTunnel(t *testing.T) {
	h := newSameExitHarness(t)
	h.v6.dialDelay = 600 * time.Millisecond
	deadline := time.Now().Add(5 * time.Second)
	for h.v6.dials.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.v6.dials.Load() == 0 {
		t.Fatal("no return was tried - the test proves nothing")
	}
	for range 15 {
		if _, err := h.app.Write(h.upPacket()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := h.v6.handshakes.Load(); n != 0 {
		t.Fatalf("the return sent its handshake (%d) though the tunnel woke up during the dial", n)
	}
	if !h.downlinkWorks(2 * time.Second) {
		t.Fatal("the tunnel on v4 no longer carries the downlink")
	}
}

// TestAReturnWhoseHandshakeDisplacedTheOldSessionIsKept is P2-3 (a), the
// other half: traffic resumes after the handshake went out. The exit has
// moved the address to the new session; dropping it for the traffic left
// the address unregistered. The new session has to be the tunnel.
func TestAReturnWhoseHandshakeDisplacedTheOldSessionIsKept(t *testing.T) {
	h := newSameExitHarness(t)
	h.v6.answerAfter = 300 * time.Millisecond
	wake := func() {
		go func() {
			for range 5 {
				_, _ = h.app.Write(h.upPacket())
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	h.v6.requested.Store(&wake)
	deadline := time.Now().Add(5 * time.Second)
	for h.m.GetServerAddr(context.Background()) != h.v6At && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.v6.handshakes.Load() == 0 {
		t.Fatal("no handshake on v6 - the test proves nothing")
	}
	if got := h.m.GetServerAddr(context.Background()); got != h.v6At {
		t.Fatalf("after a handshake that displaced the old session the tunnel rides %s, want v6", got)
	}
	if !h.downlinkWorks(2 * time.Second) {
		t.Fatal("the tunnel carries no downlink after the return")
	}
	// One session on v6: a dropped return comes back as a reconnect, a
	// second handshake.
	time.Sleep(time.Second)
	if n := h.v6.handshakes.Load(); n != 1 {
		t.Fatalf("%d handshakes on v6: the return was dropped and the tunnel reconnected", n)
	}
}

// TestASilentHandshakeOnTheSameExitKeepsAHealthyTunnel is P2-3 (b): the v6
// family connects and never answers the handshake - the swallowed family
// the return exists to come back from. The healthy v4 tunnel was torn down
// for it, and the reconnect went back to the silent family. The old session
// answers its keepalive, so it stays, and the failure is booked on v6
// (P3-5: a TCP connect used to book it as a success).
func TestASilentHandshakeOnTheSameExitKeepsAHealthyTunnel(t *testing.T) {
	shortHandshakeTimeout(t, 500*time.Millisecond)
	h := newSameExitHarness(t)
	h.v6.mute.Store(true)
	h.v.mu.Lock()
	old := h.v.conn
	h.v.mu.Unlock()
	deadline := time.Now().Add(15 * time.Second)
	for h.v6.handshakes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.v6.handshakes.Load() == 0 {
		t.Fatal("no handshake on v6 - the test proves nothing")
	}
	time.Sleep(handshakeReadTimeout + returnProbeWait + time.Second)
	h.v.mu.Lock()
	cur := h.v.conn
	h.v.mu.Unlock()
	if cur != old {
		t.Fatal("the healthy tunnel was replaced after a silent handshake on the other family")
	}
	if !h.downlinkWorks(2 * time.Second) {
		t.Fatal("the tunnel on v4 no longer carries the downlink")
	}
	for _, st := range h.m.EndpointStates() {
		if st.Addr == h.v6At && st.ConsecutiveFailures == 0 {
			t.Fatal("the failed return was not booked on v6")
		}
	}
}
