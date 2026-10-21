package tun

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	oldConnect, oldPoll, oldSlow, oldAfter, oldProbe := reconnectConnectTimeout, poolPollInterval, poolPollSlowInterval, poolPollSlowAfter, probeInternet
	reconnectConnectTimeout = 300 * time.Millisecond
	poolPollInterval = 50 * time.Millisecond
	poolPollSlowInterval = 50 * time.Millisecond
	poolPollSlowAfter = time.Hour
	probeInternet = func() bool { return gatewayUp }
	t.Cleanup(func() {
		reconnectConnectTimeout, poolPollInterval, poolPollSlowInterval, poolPollSlowAfter, probeInternet = oldConnect, oldPoll, oldSlow, oldAfter, oldProbe
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

// TestPoolPollSlowsDownAfterLongSilence pins the second interval: past
// poolPollSlowAfter the poll spaces out. SYNs to a blocked pool every few
// seconds for hours are a pattern of their own.
func TestPoolPollSlowsDownAfterLongSilence(t *testing.T) {
	setPoolWaitKnobs(t, true)
	poolPollInterval = 10 * time.Millisecond
	poolPollSlowInterval = 400 * time.Millisecond
	poolPollSlowAfter = time.Minute

	addr, revive := deadThenAliveAddr(t)
	revive()
	m := strategy.NewManager()
	m.SetConnectivityChecker(strategy.NewConnectivityChecker(addr, 200*time.Millisecond, true))
	v := &VPNClient{running: 1, stopCh: make(chan struct{}), manager: m, serverAddr: addr}

	start := time.Now()
	if !v.waitForPool(time.Now().Add(-2 * time.Minute)) {
		t.Fatal("waitForPool returned false on a running client")
	}
	if took := time.Since(start); took < 350*time.Millisecond {
		t.Fatalf("after long silence the first poll came %v in, want the slow interval", took)
	}

	start = time.Now()
	if !v.waitForPool(time.Now()) {
		t.Fatal("waitForPool returned false on a running client")
	}
	if took := time.Since(start); took > 300*time.Millisecond {
		t.Fatalf("fresh silence: first poll came %v in, want the fast interval", took)
	}
}
