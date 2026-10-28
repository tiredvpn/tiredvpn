package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// stampedLog records every log line with the moment it was written.
type stampedLog struct {
	mu    sync.Mutex
	lines []stampedLine
}

type stampedLine struct {
	at   time.Time
	text string
}

func (l *stampedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, stampedLine{at: time.Now(), text: string(bytes.TrimSpace(p))})
	return len(p), nil
}

// first returns the first line containing s, and whether there was one.
func (l *stampedLog) first(s string) (stampedLine, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range l.lines {
		if strings.Contains(ln.text, s) {
			return ln, true
		}
	}
	return stampedLine{}, false
}

func (l *stampedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, ln := range l.lines {
		b.WriteString(ln.text)
		b.WriteByte('\n')
	}
	return b.String()
}

// setPoolWaitKnobs shortens the reconnect loop's clocks and fakes the gateway's
// verdict for the duration of a test.
func setPoolWaitKnobs(t *testing.T, gatewayUp bool) {
	t.Helper()
	oldConnect, oldPoll, oldFast, oldMax, oldDialTO, oldDial, oldProbe := reconnectConnectTimeout, poolPollInterval, poolFastPhase, poolPollMax, poolDialTimeout, poolDial, probeInternet
	reconnectConnectTimeout = 300 * time.Millisecond
	poolPollInterval = 50 * time.Millisecond
	poolFastPhase = time.Hour
	poolPollMax = time.Second
	poolDialTimeout = 200 * time.Millisecond
	probeInternet = func() bool { return gatewayUp }
	t.Cleanup(func() {
		reconnectConnectTimeout, poolPollInterval, poolFastPhase, poolPollMax, poolDialTimeout, poolDial, probeInternet = oldConnect, oldPoll, oldFast, oldMax, oldDialTO, oldDial, oldProbe
	})
}

// deadThenAliveAddr hands out a loopback address that refuses connections
// until revive is called.
func deadThenAliveAddr(t *testing.T) (addr string, revive func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()
	ln.Close()
	return addr, func() {
		var ln net.Listener
		var err error
		for range 50 {
			if ln, err = net.Listen("tcp", addr); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Errorf("relisten on %s: %v", addr, err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
}

// runReconnectLoop starts handleDisconnect against a manager whose only
// server is addr and returns the client and its log. The caller stops it.
func runReconnectLoop(t *testing.T, addr string) (*VPNClient, *stampedLog, chan struct{}) {
	t.Helper()
	m := strategy.NewManager()
	checker := strategy.NewConnectivityChecker(addr, 200*time.Millisecond, true)
	m.SetConnectivityChecker(checker)

	out := &stampedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, serverAddr: addr}
	done := make(chan struct{})
	go func() {
		v.handleDisconnect("server read", io.EOF)
		close(done)
	}()
	return v, out, done
}

func stopReconnectLoop(t *testing.T, v *VPNClient, done chan struct{}, out *stampedLog) {
	t.Helper()
	atomic.StoreInt32(&v.running, 0)
	close(v.stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("reconnect loop did not stop; log:\n%s", out)
	}
}

// TestSilentPoolDoesNotGrowTheBackoff is D4 of the 2026-10-21 stand report. The
// provider's line went down behind a router that kept answering: the gate found
// no server in the pool, the gateway said the network was fine, and every
// failed attempt doubled the pause up to two minutes. After the line came back
// the client slept through up to 156 s of it.
//
// Here the pool comes back after a few failed rounds. The client has to notice
// within one poll interval and must not have backed off at all in between.
func TestSilentPoolDoesNotGrowTheBackoff(t *testing.T) {
	setPoolWaitKnobs(t, true)
	addr, revive := deadThenAliveAddr(t)
	v, out, done := runReconnectLoop(t, addr)

	time.Sleep(1200 * time.Millisecond)
	revivedAt := time.Now()
	revive()

	deadline := time.Now().Add(3 * time.Second)
	var back stampedLine
	var ok bool
	for time.Now().Before(deadline) {
		if back, ok = out.first("answers again"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stopReconnectLoop(t, v, done, out)

	if !ok {
		t.Fatalf("the client never noticed the pool answering again; log:\n%s", out)
	}
	if lag := back.at.Sub(revivedAt); lag > 500*time.Millisecond {
		t.Fatalf("noticed the pool %v after it came back, want within a poll interval; log:\n%s", lag, out)
	}
	if ln, backedOff := out.first("next attempt in"); backedOff && ln.at.Before(revivedAt) {
		t.Fatalf("the client backed off while nobody in the pool answered:\n%s\nlog:\n%s", ln.text, out)
	}
}

// TestSilentPoolWithNoGatewayIsANetworkOutage: when the gateway does not answer
// either, the pool's silence says nothing about the servers. That is the
// ordinary network wait, which also forgets the old network's verdicts.
//
// The gateway answers the loop's first network check and is gone by the time
// the attempt fails, so the verdict has to come from the branch that handles
// the failed attempt, not from the periodic check that runs before it.
func TestSilentPoolWithNoGatewayIsANetworkOutage(t *testing.T) {
	setPoolWaitKnobs(t, false)
	var probes atomic.Int64
	probeInternet = func() bool { return probes.Add(1) == 1 }
	addr, _ := deadThenAliveAddr(t)
	v, out, done := runReconnectLoop(t, addr)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := out.first("No network connectivity"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stopReconnectLoop(t, v, done, out)

	if _, ok := out.first("No network connectivity"); !ok {
		t.Fatalf("pool and gateway both silent, and the client did not take the network wait; log:\n%s", out)
	}
	if _, ok := out.first("polling the pool"); ok {
		t.Fatalf("pool and gateway both silent, and the client blamed the pool; log:\n%s", out)
	}
}

// silentTCPAddr is a loopback address whose SYNs go unanswered: a listener
// with a zero backlog, its one queue slot taken and never accepted. That is
// what a blackholed server looks like to a dialler - a timeout, not a refusal.
func silentTCPAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatalf("listen: %v", err)
	}
	sa, _ := syscall.Getsockname(fd)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))
	filler, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("filling the backlog: %v", err)
	}
	t.Cleanup(func() { filler.Close(); syscall.Close(fd) })
	return addr
}

// TestSilentAddressesAheadOfTheLiveOneStillReconnect is P1-1 of the PR #126
// review, the case the 4-address stand could not show. The pool poll walked
// the whole pool, found the live server, and only logged it. The reconnect's
// gate then walked from the pin - five silent addresses at its per-address
// timeout - and ran out of budget before the live one, so it reported the pool
// silent again, and the loop went round forever with a live server in reach.
// The test asks for the tunnel, not for a log line.
func TestSilentAddressesAheadOfTheLiveOneStillReconnect(t *testing.T) {
	setPoolWaitKnobs(t, true)
	reconnectConnectTimeout = time.Second

	var eps []endpoint.Endpoint
	for i := range 5 {
		eps = append(eps, endpoint.Endpoint{Name: fmt.Sprintf("dead%d", i), V4: silentTCPAddr(t), Order: i})
	}
	live := newNetcheckListener(t).addr
	eps = append(eps, endpoint.Endpoint{Name: "live", V4: live, Order: 5})

	m := strategy.NewManager()
	if err := m.SetEndpointSelection(endpoint.Config{Endpoints: eps, Family: endpoint.V4Only}); err != nil {
		t.Fatal(err)
	}
	m.Register(&pipeStrategy{t: t, resp: bareV3Response(), gap: silent})
	m.SetConnectivityChecker(strategy.NewConnectivityChecker(eps[0].V4, 300*time.Millisecond, true))

	out := &stampedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	v := newCallsiteClient(m)
	v.running = 1
	v.stopCh = make(chan struct{})
	done := make(chan struct{})
	go func() {
		v.handleDisconnect("server read", io.EOF)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		atomic.StoreInt32(&v.running, 0)
		close(v.stopCh)
		<-done
		t.Fatalf("no reconnect with a live server behind five silent ones; log:\n%s", out)
	}
	if _, ok := out.first("VPN reconnected successfully"); !ok {
		t.Fatalf("reconnect loop ended without a tunnel; log:\n%s", out)
	}
	if got := m.GetServerAddr(context.Background()); got != live {
		t.Fatalf("pinned %s, want the live server %s", got, live)
	}
}

// TestPoolPollIsOneRotatingAddressWithGrowingPauses covers P1-2 of the round-1
// review and P2-1 of round 2. The poll was a sequential SYN sweep of the whole
// pool on a strict period (17.0 s on the stand), then a strict 8 s / 63 s grid.
// Now each round is one address, the next one in the pool each time; pauses
// are drawn, not fixed, and grow past the fast phase.
func TestPoolPollIsOneRotatingAddressWithGrowingPauses(t *testing.T) {
	setPoolWaitKnobs(t, true)
	poolPollInterval = 20 * time.Millisecond
	poolFastPhase = 200 * time.Millisecond
	poolPollMax = 100 * time.Millisecond

	var mu sync.Mutex
	type dial struct {
		at   time.Time
		addr string
	}
	var dials []dial
	poolDial = func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, dial{time.Now(), addr})
		mu.Unlock()
		return nil, errors.New("silent")
	}

	m, addrs, _ := poolManager(t, 3)
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m}
	go func() {
		time.Sleep(2500 * time.Millisecond)
		atomic.StoreInt32(&v.running, 0)
		close(v.stopCh)
	}()
	start := time.Now()
	if v.waitForPool(start) {
		t.Fatal("waitForPool reported an answer from a silent pool")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dials) < 12 {
		t.Fatalf("only %d rounds - the test proves nothing", len(dials))
	}
	for i, d := range dials {
		if want := addrs[i%len(addrs)]; d.addr != want {
			t.Fatalf("round %d dialled %s, want %s: one address per round, in rotation", i, d.addr, want)
		}
	}
	var fast, slow []time.Duration
	for i := 1; i < len(dials); i++ {
		gap := dials[i].at.Sub(dials[i-1].at)
		if dials[i-1].at.Sub(start) < poolFastPhase {
			fast = append(fast, gap)
		} else {
			slow = append(slow, gap)
		}
		if gap > poolPollMax+poolDialTimeout+50*time.Millisecond {
			t.Fatalf("pause %v past the %v ceiling", gap, poolPollMax)
		}
	}
	mean := func(ds []time.Duration) time.Duration {
		var sum time.Duration
		for _, d := range ds {
			sum += d
		}
		return sum / time.Duration(max(len(ds), 1))
	}
	if len(slow) < 4 || mean(slow) <= mean(fast) {
		t.Fatalf("pauses did not grow past the fast phase: fast mean %v, later mean %v", mean(fast), mean(slow))
	}
	distinct := map[time.Duration]bool{}
	for _, g := range slow {
		distinct[g.Round(time.Millisecond)] = true
	}
	if len(distinct) < len(slow)/2 {
		t.Fatalf("later pauses %v repeat: a grid, not drawn pauses", slow)
	}
}

// TestSilentCycleCapsTheBackoffLower is the P2 "D4 only freezes the backoff
// when no TCP answers" item: a cycle where the pool answered TCP and every
// transport then went silent still doubled to 2 minutes.
func TestSilentCycleCapsTheBackoffLower(t *testing.T) {
	silentCycle := fmt.Errorf("%w: all strategies failed", strategy.ErrAddrSilent)
	if got := nextReconnectDelay(time.Minute, silentCycle); got != silentCycleMaxDelay {
		t.Fatalf("after a silent cycle the backoff is %v, want the %v cap", got, silentCycleMaxDelay)
	}
	if got := nextReconnectDelay(time.Minute, errors.New("tls: handshake failure")); got != reconnectMaxDelay {
		t.Fatalf("after an ordinary failure the backoff is %v, want %v", got, reconnectMaxDelay)
	}
	if got := nextReconnectDelay(time.Second, silentCycle); got != 2*time.Second {
		t.Fatalf("below the cap the backoff doubles: got %v", got)
	}
}

// TestPoolPauseStaysUnderItsBase is N8 of the second acceptance of PR #126:
// the drawn pause reached twice its base, so the long-run poll gap went from
// 63 s to up to 123 s, and the client whose uplink came back could wait two
// minutes for the next dial. The pause stays under base, and it is still
// drawn: neither stuck on a bound nor flat.
//
// And, P3-18 of the round-3 review, without a hard lower edge: RandomDelay's
// exponential over base/2 put 40% of the pauses in the lowest fifth and made
// base/2 a minimum an observer reads off at once.
func TestPoolPauseStaysUnderItsBase(t *testing.T) {
	const base = time.Minute
	draws := make([]time.Duration, 0, 10000)
	seen := map[time.Duration]bool{}
	var sum time.Duration
	for range 10000 {
		d := poolPause(base)
		if d < base/4 || d >= base {
			t.Fatalf("pause %v outside [%v, %v)", d, base/4, base)
		}
		seen[d.Round(time.Millisecond)] = true
		draws = append(draws, d)
		sum += d
	}
	if len(seen) < 5000 {
		t.Fatalf("only %d distinct pauses in 10000 draws: a grid", len(seen))
	}
	if mean := sum / time.Duration(len(draws)); mean < 33*time.Second || mean > 48*time.Second {
		t.Fatalf("mean pause %v, want about 3/4 of the base as before", mean)
	}
	slices.Sort(draws)
	lowFifth := base/4 + (base-base/4)/5
	n, _ := slices.BinarySearch(draws, lowFifth)
	if share := float64(n) / float64(len(draws)); share > 0.15 {
		t.Fatalf("%.0f%% of the pauses in the lowest fifth of the range: piled at the floor", 100*share)
	}
	// A hard minimum piles draws on it and leaves this span near zero. The
	// hump's own lowest 5% span 6.0-7.6 s of a minute (400 trials of 10000
	// draws), so base/10 sat on its tail and failed about one run in 300;
	// base/20 keeps the margin both ways.
	if edge := draws[len(draws)/20] - draws[0]; edge < base/20 {
		t.Fatalf("the lowest 5%% of pauses span only %v: a hard minimum", edge)
	}
}

// TestPoolPollWaitsOutADeadSessionPark: the call site of P3-9 of the round-3
// review. The only server answering TCP is parked for dead sessions; the poll
// keeps polling instead of ending the wait on it.
func TestPoolPollWaitsOutADeadSessionPark(t *testing.T) {
	setPoolWaitKnobs(t, true)
	poolPollInterval = 20 * time.Millisecond
	m, addrs, _ := poolManager(t, 1)
	for _, st := range m.EndpointStates() {
		if st.Addr == addrs[0] {
			m.SessionEnded(strategy.SessionEnd{Strategy: "x", Endpoint: st.Candidate, HasEndpoint: true, Dead: true})
		}
	}
	var dials atomic.Int64
	poolDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m}
	go func() {
		time.Sleep(400 * time.Millisecond)
		atomic.StoreInt32(&v.running, 0)
		close(v.stopCh)
	}()
	if v.waitForPool(time.Now()) {
		t.Fatal("the wait ended on a server parked for dead sessions")
	}
	if n := dials.Load(); n < 3 {
		t.Fatalf("only %d polls - the test proves nothing", n)
	}
}

// TestPoolPollDoesNotWaitOutAWholeDeadPark is P3-3 of the round-4 review: a
// server parked for dead sessions was passed over by the pool poll for as
// long as its park lasted, up to MaxCooldown (30 min), and with nothing else
// in the pool the client waited all of it. After poolDeadParkWait of hearing
// only that server, it is pinned and dialled.
func TestPoolPollDoesNotWaitOutAWholeDeadPark(t *testing.T) {
	setPoolWaitKnobs(t, true)
	poolPollInterval = 20 * time.Millisecond
	old := poolDeadParkWait
	poolDeadParkWait = 300 * time.Millisecond
	t.Cleanup(func() { poolDeadParkWait = old })
	m, addrs, _ := poolManager(t, 1)
	for _, st := range m.EndpointStates() {
		if st.Addr == addrs[0] {
			m.SessionEnded(strategy.SessionEnd{Strategy: "x", Endpoint: st.Candidate, HasEndpoint: true, Dead: true})
		}
	}
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m}
	done := make(chan bool, 1)
	go func() { done <- v.waitForPool(time.Now()) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("the wait ended without a server")
		}
	case <-time.After(3 * time.Second):
		atomic.StoreInt32(&v.running, 0)
		close(v.stopCh)
		t.Fatal("the pool poll waited out the whole dead-session park")
	}
	if cooldownLeft(t, m, addrs[0]) > 0 {
		t.Fatal("pinned but still parked")
	}
}
