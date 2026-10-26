package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// returnExit is one exit of the return tests: it answers the TUN handshake
// with its own addresses, echoes keepalives, counts the packets that come
// up and can send packets down.
type returnExit struct {
	serverIP, clientIP net.IP
	refuse             atomic.Bool // the dial fails
	// displace makes a new session close the ones before it, as a real
	// exit does when it registers the same address again, after its grace.
	displace bool
	// echoing leaves a displaced session up and echoing keepalives, with no
	// downlink, as an exit's HTTP/2 TUN loop did until round 17.
	echoing bool
	// requested, when set, is called as a handshake request arrives, and
	// answerAfter (nanoseconds) holds the answer back.
	requested   atomic.Pointer[func()]
	answerAfter atomic.Int64
	dials       atomic.Int64
	up       atomic.Int64
	mu       sync.Mutex
	conns    []net.Conn
}

func (e *returnExit) serve(srv net.Conn) {
	req := make([]byte, 8)
	if _, err := io.ReadFull(srv, req); err != nil {
		return
	}
	if h := e.requested.Load(); h != nil {
		(*h)()
	}
	time.Sleep(time.Duration(e.answerAfter.Load()))
	// With a flags byte, as an exit of this release answers: a bare 9-byte
	// answer makes the client wait handshakeFlagsGrace for one.
	resp := append([]byte{0x00}, e.serverIP.To4()...)
	resp = append(append(resp, e.clientIP.To4()...), tunFlagMTUProbe)
	if _, err := srv.Write(resp); err != nil {
		return
	}
	e.mu.Lock()
	if e.displace && !e.echoing {
		// After the 200 ms grace a real exit gives the writer it
		// replaces (registerClient).
		for _, old := range e.conns {
			time.AfterFunc(200*time.Millisecond, func() { old.Close() })
		}
		e.conns = nil
	}
	e.conns = append(e.conns, srv)
	e.mu.Unlock()
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(srv, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		if n == 0 {
			_, _ = srv.Write(hdr)
			continue
		}
		if _, err := io.CopyN(io.Discard, srv, int64(n)); err != nil {
			return
		}
		e.up.Add(1)
	}
}

// sendDown sends one packet down the exit's latest session.
func (e *returnExit) sendDown(pkt []byte) {
	e.mu.Lock()
	var c net.Conn
	if len(e.conns) > 0 {
		c = e.conns[len(e.conns)-1]
	}
	e.mu.Unlock()
	if c == nil {
		return
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(pkt)))
	_, _ = c.Write(append(frame, pkt...))
}

// returnStrategy dials the returnExit of its target over a pipe.
type returnStrategy struct {
	t     *testing.T
	exits map[string]*returnExit
}

func (s *returnStrategy) Name() string                        { return "polling" }
func (s *returnStrategy) ID() string                          { return "polling" }
func (s *returnStrategy) Priority() int                       { return 6 }
func (s *returnStrategy) RequiresServer() bool                { return true }
func (s *returnStrategy) Description() string                 { return "pipe to a scripted exit" }
func (s *returnStrategy) Probe(context.Context, string) error { return nil }
func (s *returnStrategy) Connect(_ context.Context, target string) (net.Conn, error) {
	e := s.exits[target]
	e.dials.Add(1)
	if e.refuse.Load() {
		return nil, errors.New("connection reset by peer")
	}
	cli, srv := net.Pipe()
	s.t.Cleanup(func() { cli.Close(); srv.Close() })
	go e.serve(srv)
	return cli, nil
}

// returnHarness is a client on its fallback b with a preferred a in the
// pool, over a socketpair TUN, running its own packet loops and the return
// watcher.
type returnHarness struct {
	v    *VPNClient
	m    *strategy.Manager
	a, b *returnExit
	aAt  string
	app  *os.File
	down atomic.Int64
}

func newReturnHarness(t *testing.T) *returnHarness {
	t.Helper()
	return newReturnHarnessOwning(t, true)
}

// newReturnHarnessOwning is newReturnHarness with ownsInterface as given:
// false is a host-owned interface (Android, macOS).
func newReturnHarnessOwning(t *testing.T, ownsInterface bool) *returnHarness {
	t.Helper()
	return newReturnHarnessWith(t, ownsInterface, false)
}

// newReturnHarnessWith is newReturnHarnessOwning whose two exits, when
// alike, hand out the same addresses, as two exits on the default pool do.
func newReturnHarnessWith(t *testing.T, ownsInterface, alike bool) *returnHarness {
	t.Helper()
	oldIdle, oldEvery, oldRetry := returnIdleAfter, returnCheckEvery, returnRetryAfter
	returnIdleAfter, returnCheckEvery = 400*time.Millisecond, 50*time.Millisecond
	returnRetryAfter = func() time.Duration { return 600 * time.Millisecond }
	t.Cleanup(func() { returnIdleAfter, returnCheckEvery, returnRetryAfter = oldIdle, oldEvery, oldRetry })

	aAt, bAt := newNetcheckListener(t).addr, newNetcheckListener(t).addr
	a := &returnExit{serverIP: net.IPv4(10, 91, 0, 1), clientIP: net.IPv4(10, 91, 0, 2)}
	b := &returnExit{serverIP: net.IPv4(10, 92, 0, 1), clientIP: net.IPv4(10, 92, 0, 2)}
	if alike {
		b.serverIP, b.clientIP = a.serverIP, a.clientIP
	}
	m := strategy.NewManager()
	if err := m.SetEndpointSelection(endpoint.Config{
		Endpoints: []endpoint.Endpoint{{Name: "a", V4: aAt}, {Name: "b", V4: bAt, Order: 1}},
		Family:    endpoint.V4Only, FailureThreshold: 2, Cooldown: time.Minute, MinDwell: 200 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	m.Register(&returnStrategy{t: t, exits: map[string]*returnExit{aAt: a, bAt: b}})
	// The client fell back to b during a fault on a, which is over.
	m.PinCandidate(endpoint.Candidate{Addr: bAt})

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := &TUNDevice{file: os.NewFile(uintptr(fds[0]), "tun"), mtu: 1500, atomicMTU: 1500, remoteIP: b.serverIP}
	app := os.NewFile(uintptr(fds[1]), "app")
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, tun: dev, localIP: b.clientIP,
		serverAddr: bAt, ownsInterface: ownsInterface, ipv6Policy: IPv6PolicyOff, stall: newFlowTable()}
	setLog(t, &stampedLog{})
	if err := v.connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := m.GetServerAddr(context.Background()); got != bAt {
		t.Fatalf("the session rides %s, want b %s", got, bAt)
	}
	h := &returnHarness{v: v, m: m, a: a, b: b, aAt: aAt, app: app}
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

// upPacket is an IPv4 packet from the client's tunnel address.
func (h *returnHarness) upPacket(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 60)
	pkt[0], pkt[9] = 0x45, 17
	binary.BigEndian.PutUint16(pkt[2:], 60)
	copy(pkt[12:16], h.v.LocalIP().To4())
	copy(pkt[16:20], net.IPv4(203, 0, 113, 7).To4())
	return pkt
}

func (h *returnHarness) onA() bool {
	return h.m.GetServerAddr(context.Background()) == h.aAt
}

// TestAnIdleTunnelReturnsToThePreferredServer: on b after a fault on a, past
// MinDwell, nothing in the tunnel for returnIdleAfter - the tunnel moves to
// a, takes a's addresses, and carries traffic there.
func TestAnIdleTunnelReturnsToThePreferredServer(t *testing.T) {
	h := newReturnHarness(t)
	deadline := time.Now().Add(5 * time.Second)
	for !h.onA() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !h.onA() {
		t.Fatal("the idle tunnel did not return to a")
	}
	if got := h.v.LocalIP(); !got.Equal(h.a.clientIP) {
		t.Fatalf("tunnel address %s after the return, want a's %s", got, h.a.clientIP)
	}
	if _, err := h.app.Write(h.upPacket(t)); err != nil {
		t.Fatal(err)
	}
	for h.a.up.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.a.up.Load() == 0 {
		t.Fatal("a packet up after the return never reached a")
	}
	h.a.sendDown(h.upPacket(t))
	for h.down.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.down.Load() == 0 {
		t.Fatal("a packet down from a never reached the TUN")
	}
}

// TestABusyTunnelStaysOnTheFallback: traffic every 50 ms, one direction at
// a time, for several idle periods - the tunnel stays on b, and a is not
// even dialled.
func TestABusyTunnelStaysOnTheFallback(t *testing.T) {
	for _, dir := range []string{"up", "down"} {
		t.Run(dir, func(t *testing.T) {
			h := newReturnHarness(t)
			end := time.Now().Add(5 * returnIdleAfter)
			for time.Now().Before(end) {
				if dir == "up" {
					if _, err := h.app.Write(h.upPacket(t)); err != nil {
						t.Fatal(err)
					}
				} else {
					h.b.sendDown(h.upPacket(t))
				}
				// An eighth of the idle threshold: 100 ms gaps failed once
				// at load over 30 (P3-13 of the round-10 review).
				time.Sleep(50 * time.Millisecond)
			}
			if h.onA() || h.a.dials.Load() != 0 {
				t.Fatalf("a busy tunnel (%s) was moved: on a %v, a dialled %d times", dir, h.onA(), h.a.dials.Load())
			}
			if dir == "up" && h.b.up.Load() == 0 || dir == "down" && h.down.Load() == 0 {
				t.Fatal("no traffic crossed the tunnel - the test proves nothing")
			}
		})
	}
}

// TestAFailedReturnKeepsTheTunnelAndWaits: a still refuses. The tunnel stays
// on b and carries traffic, and the next try waits returnRetryAfter instead
// of coming at the next check.
func TestAFailedReturnKeepsTheTunnelAndWaits(t *testing.T) {
	h := newReturnHarness(t)
	h.a.refuse.Store(true)
	first := time.Now().Add(returnIdleAfter + time.Second)
	for h.a.dials.Load() == 0 && time.Now().Before(first) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.a.dials.Load() != 1 {
		t.Fatalf("a dialled %d times by its first try", h.a.dials.Load())
	}
	time.Sleep(returnRetryAfter() / 2)
	if n := h.a.dials.Load(); n != 1 {
		t.Fatalf("a dialled %d times within the retry period after the first failure", n)
	}
	second := time.Now().Add(returnRetryAfter())
	for h.a.dials.Load() == 1 && time.Now().Before(second) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.a.dials.Load() != 2 {
		t.Fatal("no second try after the retry period")
	}
	if h.onA() {
		t.Fatal("the tunnel left b for a refusing a")
	}
	if _, err := h.app.Write(h.upPacket(t)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.b.up.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.b.up.Load() == 0 {
		t.Fatal("the tunnel on b no longer carries traffic after the failed return")
	}
}

// TestAHostOwnedInterfaceIsNotReturned: on Android and macOS the host
// configures the interface from the session it was told about, and the
// return hands out another exit's addresses. The idle tunnel stays on b.
func TestAHostOwnedInterfaceIsNotReturned(t *testing.T) {
	h := newReturnHarnessOwning(t, false)
	time.Sleep(returnIdleAfter + 6*returnCheckEvery)
	if h.onA() || h.a.dials.Load() != 0 {
		t.Fatalf("a host-owned interface was moved: on a %v, a dialled %d times", h.onA(), h.a.dials.Load())
	}
}

// TestAReturnToAnotherExitWithTheSameAddressLeavesABusyTunnel is P3-1 of
// the round-11 review: two exits on the default pool hand out the same
// address, and an answer on the old address was taken for the old
// session's own exit - so a tunnel that woke up during the handshake was
// moved to the other exit and its healthy session closed. Only the old
// session's own endpoint is that exit.
func TestAReturnToAnotherExitWithTheSameAddressLeavesABusyTunnel(t *testing.T) {
	h := newReturnHarnessWith(t, true, true)
	h.a.answerAfter.Store(int64(300 * time.Millisecond))
	wake := func() {
		go func() {
			for range 5 {
				_, _ = h.app.Write(h.upPacket(t))
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	h.a.requested.Store(&wake)
	deadline := time.Now().Add(5 * time.Second)
	for h.a.dials.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.a.dials.Load() == 0 {
		t.Fatal("no return was tried - the test proves nothing")
	}
	time.Sleep(time.Second)
	if h.onA() {
		t.Fatal("a tunnel that woke up during the handshake moved to the other exit for an equal address")
	}
	before := h.down.Load()
	for i := 0; i < 40 && h.down.Load() == before; i++ {
		h.b.sendDown(h.upPacket(t))
		time.Sleep(50 * time.Millisecond)
	}
	if h.down.Load() == before {
		t.Fatal("the tunnel on b no longer carries the downlink")
	}
}
