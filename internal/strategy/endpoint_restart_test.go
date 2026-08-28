package strategy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// blackholeListener accepts TCP and then says nothing, holding the connection
// open. That is the signature this whole file is about: on MTS the TSPU lets the
// handshake to a burnt VPN address complete and drops everything after it, so
// every transport in the scan dies on the connect timeout rather than on a
// refusal.
//
// It must hold the accepted connections. Closing them would send a FIN, the
// strategy's read would return EOF instead of a timeout, and the test would
// exercise the ordinary-failure path instead of the silent one.
type blackholeListener struct {
	ln      net.Listener
	addr    string
	accepts atomic.Int64

	mu   sync.Mutex
	held []net.Conn
	done chan struct{}
	once sync.Once
}

func newBlackholeListener(t *testing.T) *blackholeListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &blackholeListener{ln: ln, addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepts.Add(1)
			l.mu.Lock()
			l.held = append(l.held, conn)
			l.mu.Unlock()
		}
	}()
	t.Cleanup(l.stop)
	return l
}

func (l *blackholeListener) stop() {
	l.once.Do(func() {
		l.ln.Close()
		<-l.done
		l.mu.Lock()
		for _, c := range l.held {
			c.Close()
		}
		l.held = nil
		l.mu.Unlock()
	})
}

// helloListener answers every connection with one byte, which is what
// greetingStrategy takes as "this transport works".
type helloListener struct {
	ln      net.Listener
	addr    string
	accepts atomic.Int64
	done    chan struct{}
	once    sync.Once
}

func newHelloListener(t *testing.T) *helloListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &helloListener{ln: ln, addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepts.Add(1)
			_, _ = conn.Write([]byte{'x'})
			conn.Close()
		}
	}()
	t.Cleanup(l.stop)
	return l
}

func (l *helloListener) stop() {
	l.once.Do(func() {
		l.ln.Close()
		<-l.done
	})
}

// greetingStrategy dials the target and waits for the server to speak first, so
// a blackhole fails with a timeout and a live server succeeds. Every real
// strategy has the same shape - write a handshake, wait for the answer - which
// is why the device log shows all of them failing at exactly connectTimeout.
type greetingStrategy struct {
	id       string
	priority int

	// refuse makes the strategy fail immediately with an error that is not a
	// timeout, standing in for a reset, a refusal, or a handshake the peer
	// answered and rejected.
	refuse bool
	tries  *atomic.Int64

	// seen records every target this strategy was pointed at, which is what
	// tells "the endpoint layer moved on" from "it came straight back".
	seen *targetLog
}

// targetLog collects the addresses strategies were handed, across managers.
type targetLog struct {
	mu   sync.Mutex
	list []string
}

func (l *targetLog) add(addr string) {
	l.mu.Lock()
	l.list = append(l.list, addr)
	l.mu.Unlock()
}

func (l *targetLog) since(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.list[n:]...)
}

func (l *targetLog) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.list)
}

func (s *greetingStrategy) Name() string         { return s.id }
func (s *greetingStrategy) ID() string           { return s.id }
func (s *greetingStrategy) Priority() int        { return s.priority }
func (s *greetingStrategy) RequiresServer() bool { return true }
func (s *greetingStrategy) Description() string  { return "test strategy awaiting a server greeting" }

func (s *greetingStrategy) Probe(ctx context.Context, target string) error {
	conn, err := s.Connect(ctx, target)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *greetingStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	if s.tries != nil {
		s.tries.Add(1)
	}
	if s.seen != nil {
		s.seen.add(target)
	}
	if s.refuse {
		return nil, errors.New("connection refused by peer")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, nil
}

// restartedManagerScanTimeout is the per-strategy connect timeout these tests
// run with. The device uses 10s; the ratios below are what matters.
const restartedManagerScanTimeout = 300 * time.Millisecond

// newRestartedManager builds a manager exactly the way a fresh client does:
// through NewTunedSelector, the constructor initManagerTransport and
// SetEndpointsTuned both use. Calling it twice with the same endpoints is the
// Android lifecycle - the service throws the client away on every failed
// connect and builds a new one in the same process.
func newRestartedManager(t *testing.T, tuning endpoint.Tuning, strategies int, addrs ...string) *Manager {
	t.Helper()
	eps := make([]endpoint.Endpoint, len(addrs))
	for i, a := range addrs {
		eps[i] = endpoint.Endpoint{Name: fmt.Sprintf("ep%d", i), V4: a, Order: i}
	}
	sel, err := endpoint.NewTunedSelector(eps, tuning, endpoint.V4Only)
	if err != nil {
		t.Fatalf("NewTunedSelector: %v", err)
	}

	m := NewManager()
	m.endpoints = sel
	// The real Android tuning, from the initializer that applies it, so a
	// change to the abort threshold shows up here instead of in the field.
	initManagerAndroidMode(m, DefaultManagerConfig{AndroidMode: true})
	m.maxRetries = 1
	m.connectTimeout = restartedManagerScanTimeout
	m.probeTimeout = restartedManagerScanTimeout
	// The device has RTT masking on, which doubles the cost of every scan: the
	// whole strategy list is walked once more with masking before the endpoint
	// layer is told anything.
	m.rttMaskingEnabled = true
	m.rttProfile = MoscowToYandexProfile
	for i := range strategies {
		m.Register(&greetingStrategy{id: fmt.Sprintf("s%d", i), priority: i + 1})
	}
	return m
}

// TestAnAnsweringAddressStillGetsTheWholeScan is the case the scan exists for,
// and the one the silence rule must not eat: an address that answers, on a
// transport the DPI happens to recognise and cut. Only silence - no answer at
// all, transport after transport - is a verdict about the address.
//
// The strategies alternate so the streak is broken by an answering transport
// every other time. A rule that never resets the streak would abandon this
// address on the third strategy and leave three of the six untried.
func TestAnAnsweringAddressStillGetsTheWholeScan(t *testing.T) {
	silent := newBlackholeListener(t)
	live := newHelloListener(t)

	const strategies = 6
	var tries atomic.Int64

	m := newRestartedManager(t, endpoint.Tuning{FailureThreshold: 2, Cooldown: time.Minute}, 0, silent.addr, live.addr)
	for i := range strategies {
		m.Register(&greetingStrategy{
			id:       fmt.Sprintf("s%d", i),
			priority: i + 1,
			refuse:   i%2 == 1,
			tries:    &tries,
		})
	}

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()

	// The first pass runs every strategy against the first endpoint before the
	// loop moves on; anything less means the scan was cut short.
	if got := tries.Load(); got < strategies {
		t.Fatalf("the scan stopped after %d of %d strategies on an address that was answering", got, strategies)
	}
	if st := endpointState(t, m, silent.addr); !st.CooldownUntil.IsZero() {
		t.Fatal("an answering endpoint was parked after one failed cycle, ahead of the failure threshold")
	}
}

// cancellingStrategy fails without touching the network and cancels the connect
// context once it has been called cancelAt times.
type cancellingStrategy struct {
	id       string
	priority int
	tries    *atomic.Int64
	cancelAt int64
	cancel   context.CancelFunc
	atCancel *atomic.Int64
}

func (s *cancellingStrategy) Name() string         { return s.id }
func (s *cancellingStrategy) ID() string           { return s.id }
func (s *cancellingStrategy) Priority() int        { return s.priority }
func (s *cancellingStrategy) RequiresServer() bool { return true }
func (s *cancellingStrategy) Description() string  { return "test strategy that cancels the cycle" }

func (s *cancellingStrategy) Probe(ctx context.Context, target string) error {
	return errors.New("not probed")
}

func (s *cancellingStrategy) Connect(_ context.Context, _ string) (net.Conn, error) {
	n := s.tries.Add(1)
	if n == s.cancelAt {
		s.atCancel.Store(n)
		s.cancel()
	}
	return nil, errors.New("connection refused by peer")
}

// TestCancelledConnectDoesNotStartASecondPass: once the caller has walked away
// there is nobody left to hand a connection to, and on Android that caller is
// the VPN service tearing this very client down. The device log shows the
// opposite - "All strategies failed, retrying with RTT masking enabled" and a
// fresh 21-strategy scan starting one millisecond after "Stopping client",
// twelve times over.
func TestCancelledConnectDoesNotStartASecondPass(t *testing.T) {
	live := newHelloListener(t)

	m := newRestartedManager(t, endpoint.Tuning{}, 0, live.addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tries, atCancel atomic.Int64
	for i := range 4 {
		m.Register(&cancellingStrategy{
			id:       fmt.Sprintf("s%d", i),
			priority: i + 1,
			tries:    &tries,
			cancelAt: 2,
			cancel:   cancel,
			atCancel: &atCancel,
		})
	}

	if _, _, err := m.Connect(ctx, ""); err == nil {
		t.Fatal("Connect succeeded although every strategy refused")
	}

	if atCancel.Load() == 0 {
		t.Fatal("the context was never cancelled - the test proves nothing")
	}
	if got, want := tries.Load(), atCancel.Load(); got != want {
		t.Fatalf("%d strategy attempts ran after the context was cancelled", got-want)
	}
}

// TestSilentEndpointDoesNotEatTheWholeConnectBudget is the first half of the
// Pixel 9 report: the client had a working server configured and never dialled
// it, because one connect cycle against the silent address costs longer than
// the caller is willing to wait.
//
// The budget here stands in for the Android service's own deadline on the
// control socket: it gives up after ~26s and restarts the client, which is
// less than one scan (21 strategies x 10s, twice over with RTT masking).
func TestSilentEndpointDoesNotEatTheWholeConnectBudget(t *testing.T) {
	silent := newBlackholeListener(t)
	live := newHelloListener(t)

	const strategies = 6
	// A full scan is strategies*timeout, and the RTT pass doubles it. The
	// budget sits between "two strategies timed out" and "the whole list did",
	// so it can only be met by giving up on the silent address early.
	budget := 3 * restartedManagerScanTimeout

	m := newRestartedManager(t, endpoint.Tuning{FailureThreshold: 2}, strategies, silent.addr, live.addr)

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("Connect gave up on a pool with one live server: %v", err)
	}
	conn.Close()

	if got := m.GetServerAddr(context.Background()); got != live.addr {
		t.Fatalf("pinned %s, want the live server %s", got, live.addr)
	}
	if silent.accepts.Load() == 0 {
		t.Fatal("the silent endpoint was never dialled - the test proves nothing")
	}
}

// TestEndpointHealthSurvivesClientRecreation is the second half, and the one
// that explains why the desktop fallback works while Android stays stuck.
//
// The Android service builds a new client for every reconnect. A verdict that
// lives only in the selector instance dies with it, so the next cycle starts
// from the top of the pool and rediscovers the same dead server forever - the
// device log shows 60 dials, all to one address, and not one to the other five
// configured servers.
//
// The pool here is two silent servers and a live one. maxEndpointAttempts caps
// a single cycle at two candidates, so cycle one CANNOT reach the live server;
// only a verdict carried into cycle two can.
//
// The pre-flight gate is wired in because the phone has one, and an earlier
// version of this test did not: the gate probes the whole pool, a blackholed
// address answers its TCP port, and acting on that answer used to un-park the
// candidate this test is about. A test without the gate stayed green while the
// device stayed stuck.
func TestEndpointHealthSurvivesClientRecreation(t *testing.T) {
	silentA := newBlackholeListener(t)
	silentB := newBlackholeListener(t)
	live := newHelloListener(t)

	tuning := endpoint.Tuning{
		FailureThreshold: 2,
		// Long enough that cycle two, which runs immediately, still sees a
		// parked candidate.
		Cooldown: time.Minute,
		MinDwell: 5 * time.Minute,
	}
	const strategies = 4

	seen := &targetLog{}
	first := newGatedRestartedManager(t, tuning, seen, strategies, silentA.addr, silentB.addr, live.addr)
	if _, _, err := first.Connect(context.Background(), ""); err == nil {
		t.Fatal("cycle one reached a server it has no budget for - retune the test")
	}

	dialsBefore := silentA.accepts.Load() + silentB.accepts.Load()
	if dialsBefore == 0 {
		t.Fatal("cycle one dialled neither silent server - the test proves nothing")
	}

	// The service throws the client away and builds a new one. Same process,
	// same configuration, no state of its own carried across.
	second := newGatedRestartedManager(t, tuning, seen, strategies, silentA.addr, silentB.addr, live.addr)
	conn, _, err := second.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("cycle two: %v", err)
	}
	conn.Close()

	if got := second.GetServerAddr(context.Background()); got != live.addr {
		t.Fatalf("cycle two pinned %s, want the live server %s", got, live.addr)
	}
	if after := silentA.accepts.Load() + silentB.accepts.Load(); after != dialsBefore {
		t.Fatalf("cycle two dialled the silent servers %d more times; a fresh client "+
			"must inherit the verdict, not rediscover it", after-dialsBefore)
	}
}
