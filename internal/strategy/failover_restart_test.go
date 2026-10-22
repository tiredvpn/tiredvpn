package strategy

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// restartingListener is a server process that can be restarted: stop closes the
// port, so dials are refused, and start reopens the same port.
type restartingListener struct {
	addr string

	mu sync.Mutex
	ln net.Listener
}

func newRestartingListener(t *testing.T) *restartingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &restartingListener{addr: ln.Addr().String()}
	l.serve(ln)
	t.Cleanup(l.stop)
	return l
}

func (l *restartingListener) serve(ln net.Listener) {
	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte{'x'})
			conn.Close()
		}
	}()
}

func (l *restartingListener) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		l.ln.Close()
		l.ln = nil
	}
}

func (l *restartingListener) start(t *testing.T) {
	t.Helper()
	var ln net.Listener
	var err error
	for range 100 {
		if ln, err = net.Listen("tcp", l.addr); err == nil {
			l.serve(ln)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("restart %s: %v", l.addr, err)
}

// TestServerRestartKeepsTheStrategy is D2 of the 2026-10-21 stand report and
// the production episode of 2026-10-20: the server was restarted, and the
// client came back on HTTP Polling and stayed there.
//
// The restart closes the port for half a second. v1.11.8 met the refusal with
// REALITY on the fast path, went on to the full scan, and walked the list -
// REALITY twice, then the next transport, a hundred milliseconds apart - until
// the port reopened under whichever strategy was dialling at that moment. A
// refusal is the port, not the strategy: every TCP transport rides it.
func TestServerRestartKeepsTheStrategy(t *testing.T) {
	server := newRestartingListener(t)
	other := newHelloListener(t)

	m := newSilenceManager(t, time.Second, server.addr, other.addr)
	m.maxRetries = 2
	reality := &greetingStrategy{id: "reality", priority: 5}
	polling := &greetingStrategy{id: "polling", priority: 6}
	m.Register(reality)
	m.Register(polling)

	conn, strat, err := m.Connect(context.Background(), "")
	if err != nil || strat.ID() != "reality" {
		t.Fatalf("initial connect: strategy %v, err %v", strat, err)
	}
	conn.Close()
	before := m.GetStats()["reality"].Confidence

	server.stop()
	go func() {
		time.Sleep(500 * time.Millisecond)
		server.start(t)
	}()

	conn, strat, err = m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("reconnect across the restart: %v", err)
	}
	conn.Close()
	if strat.ID() != "reality" {
		t.Fatalf("came back from a server restart on %s, want reality", strat.ID())
	}
	if got := m.GetServerAddr(context.Background()); got != server.addr {
		t.Fatalf("a restart moved the client to %s, want it to stay on %s", got, server.addr)
	}
	if after := m.GetStats()["reality"].Confidence; after < before {
		t.Fatalf("reality was charged for a closed port: confidence %.2f -> %.2f", before, after)
	}
}

// TestStoppedServerIsLeftWithinTheCycle: a port that stays closed is an
// endpoint verdict, and the walk moves on in the same Connect, as it always
// did - only without spending a scan of every strategy on it first.
func TestStoppedServerIsLeftWithinTheCycle(t *testing.T) {
	server := newRestartingListener(t)
	other := newHelloListener(t)

	m := newSilenceManager(t, time.Second, server.addr, other.addr)
	var tries atomic.Int64
	m.Register(&greetingStrategy{id: "reality", priority: 5, tries: &tries})
	m.Register(&greetingStrategy{id: "polling", priority: 6, tries: &tries})

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("initial connect: %v", err)
	}
	conn.Close()
	tries.Store(0)

	server.stop()
	start := time.Now()
	conn, _, err = m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect with the first server stopped: %v", err)
	}
	conn.Close()
	if got := m.GetServerAddr(context.Background()); got != other.addr {
		t.Fatalf("pinned %s, want %s", got, other.addr)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("leaving a stopped server took %v", took)
	}
	// 1 + len(refusalRetries) dials of one strategy at the closed port, one at
	// the live one. A second strategy dialled at the closed port means the
	// scan walked a refusal.
	if got, want := tries.Load(), int64(len(refusalRetries)+2); got != want {
		t.Fatalf("%d strategy dials, want %d", got, want)
	}
}

// TestOneFailureDoesNotReorderNeighbours: one failed attempt must not put HTTP
// Polling (6) ahead of REALITY (5); two in a row may. With the old weight of 10
// a single failure moved REALITY behind four fallbacks.
func TestOneFailureDoesNotReorderNeighbours(t *testing.T) {
	m := NewManager()
	reality := &greetingStrategy{id: "reality", priority: 5}
	polling := &greetingStrategy{id: "polling", priority: 6}
	m.Register(polling)
	m.Register(reality)

	m.mu.Lock()
	for _, id := range []string{"reality", "polling"} {
		m.results[id].Confidence = 0.95
		m.results[id].LastSuccess = time.Now()
	}
	m.mu.Unlock()

	first := func() string {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.strategies[0].ID()
	}

	m.UpdateStrategyConfidence("reality", false)
	if got := first(); got != "reality" {
		t.Fatalf("one failure put %s first, want reality to keep its place", got)
	}
	m.UpdateStrategyConfidence("reality", false)
	if got := first(); got != "polling" {
		t.Fatalf("two failures in a row left %s first, want polling", got)
	}
}

// TestUsefulSessionEndKeepsTheFastPath: the fast path's five minutes used to run
// from the moment the session connected, so a session of fifteen minutes ended
// with the fast path expired and the reconnect went to a full scan in
// confidence order. A session that carried traffic until it ended is as fresh
// as it gets.
func TestUsefulSessionEndKeepsTheFastPath(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)

	var aTries atomic.Int64
	a := &greetingStrategy{id: "a", priority: 1, refuse: true, tries: &aTries}
	b := &greetingStrategy{id: "b", priority: 2}
	m.Register(a)
	m.Register(b)

	m.mu.Lock()
	m.lastSuccessfulStrategy = b
	m.lastSuccessfulTime = time.Now().Add(-15 * time.Minute)
	m.mu.Unlock()
	m.RecordSessionStart("b")

	m.SessionEnded(SessionEnd{Strategy: "b", Useful: true})

	conn, strat, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()
	if strat.ID() != "b" || aTries.Load() != 0 {
		t.Fatalf("after a long useful session the reconnect ran a full scan (got %s, %d dials of a)", strat.ID(), aTries.Load())
	}
}

// TestShortSessionStillCostsConfidence keeps the other half of SessionEnded: a
// session that died before carrying anything is what a DPI teardown looks
// like, and the strategy pays for it.
func TestShortSessionStillCostsConfidence(t *testing.T) {
	m := NewManager()
	m.Register(&greetingStrategy{id: "a", priority: 1})
	before := m.GetStats()["a"].Confidence
	m.SessionEnded(SessionEnd{Strategy: "a"})
	if after := m.GetStats()["a"].Confidence; after >= before {
		t.Fatalf("a dead session left confidence at %.2f (was %.2f)", after, before)
	}
}

// TestRefusalIsMatchedToTheAddress: a refusal from somewhere else - a relay, a
// side port - says nothing about the server and must not stop the scan.
func TestRefusalIsMatchedToTheAddress(t *testing.T) {
	refused := func(addr string) error {
		a, _ := net.ResolveTCPAddr("tcp", addr)
		return &net.OpError{Op: "dial", Net: "tcp", Addr: a, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	cases := []struct {
		err   error
		addrs []string
		want  bool
	}{
		{refused("192.0.2.1:995"), []string{"192.0.2.1:995"}, true},
		{refused("[2001:db8::1]:995"), []string{"[2001:db8::1]:995"}, true},
		{refused("192.0.2.1:443"), []string{"192.0.2.1:995"}, false},
		{refused("192.0.2.9:995"), []string{"192.0.2.1:995"}, false},
		{refused("192.0.2.9:995"), []string{"vpn.example.com:995"}, true},
		{errors.New("connection refused by peer"), []string{"192.0.2.1:995"}, false},
	}
	for _, tc := range cases {
		if got := refusedByAddr(tc.err, tc.addrs...); got != tc.want {
			t.Errorf("refusedByAddr(%v, %v) = %v, want %v", tc.err, tc.addrs, got, tc.want)
		}
	}
}
