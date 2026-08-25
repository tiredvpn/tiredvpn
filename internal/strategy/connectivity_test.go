package strategy

import (
	"context"
	"net"
	"testing"
	"time"
)

// freeLoopbackAddr binds a loopback port, then releases it so callers get an
// address that is currently refusing connections but can be re-listened on.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestWaitForConnectivityFastRecovery verifies the backoff loop recovers within
// well under the old flat-5s tick once the server's TCP port comes back.
func TestWaitForConnectivityFastRecovery(t *testing.T) {
	addr := freeLoopbackAddr(t)
	c := NewConnectivityChecker(addr, 2*time.Second, false)

	// Server is down for ~400ms, then starts accepting.
	const downFor = 400 * time.Millisecond
	go func() {
		time.Sleep(downFor)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	res := c.WaitForConnectivity(ctx, defaultProbeInterval)
	elapsed := time.Since(start)

	if !res.TCP {
		t.Fatalf("expected TCP connectivity to be restored, got %+v", res)
	}
	if elapsed < downFor {
		t.Fatalf("recovered before server came up (%v < %v)", elapsed, downFor)
	}
	// Old behaviour quantised recovery to ~5s; with backoff it must be far less.
	if elapsed > 2*time.Second {
		t.Fatalf("recovery too slow: %v (expected <2s)", elapsed)
	}
}

// TestWaitForConnectivityImmediate returns at once when the port is already up.
func TestWaitForConnectivityImmediate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := NewConnectivityChecker(ln.Addr().String(), 2*time.Second, false)
	start := time.Now()
	res := c.WaitForConnectivity(context.Background(), defaultProbeInterval)
	if !res.TCP {
		t.Fatalf("expected TCP up, got %+v", res)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("immediate path too slow: %v", d)
	}
}

// TestWaitForConnectivityCtxCancel returns on context cancellation without hanging.
func TestWaitForConnectivityCtxCancel(t *testing.T) {
	addr := freeLoopbackAddr(t) // stays down
	c := NewConnectivityChecker(addr, 200*time.Millisecond, false)

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	done := make(chan ConnectivityResult, 1)
	go func() { done <- c.WaitForConnectivity(ctx, defaultProbeInterval) }()

	select {
	case res := <-done:
		if res.TCP {
			t.Fatalf("expected no connectivity, got TCP up")
		}
		if res.Error == nil {
			t.Fatalf("expected ctx error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForConnectivity did not return after ctx cancel")
	}
}

// TestCheckGatedOnTCP proves Check returns on the TCP verdict and does not block
// for the full UDP/ICMP probe budget on the hot path.
func TestCheckGatedOnTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := NewConnectivityChecker(ln.Addr().String(), 2*time.Second, false)
	// UDP/ICMP probes would take ~auxTimeout (700ms); the grace is 300ms.
	c.auxTimeout = time.Second
	c.auxGrace = 250 * time.Millisecond

	start := time.Now()
	res := c.Check(context.Background())
	elapsed := time.Since(start)

	if !res.TCP {
		t.Fatalf("expected TCP up, got %+v", res)
	}
	// Must return roughly within the aux grace, not the full aux timeout.
	if elapsed > c.auxTimeout {
		t.Fatalf("Check blocked on UDP/ICMP: %v (auxTimeout=%v)", elapsed, c.auxTimeout)
	}
}

// TestCheckTCPOnlyCarriesUDP confirms the fast path preserves the cached UDP
// verdict instead of resetting it to false on every retry.
func TestCheckTCPOnlyCarriesUDP(t *testing.T) {
	addr := freeLoopbackAddr(t)
	c := NewConnectivityChecker(addr, 200*time.Millisecond, false)

	// Seed the cache as if UDP had been observed working.
	c.mu.Lock()
	c.lastResult = ConnectivityResult{UDP: true, CheckedAt: time.Now()}
	c.mu.Unlock()

	res := c.checkTCPOnly(context.Background())
	if res.TCP {
		t.Fatalf("expected TCP down on a free port")
	}
	if !res.UDP {
		t.Fatalf("checkTCPOnly dropped the cached UDP verdict")
	}
}

// TestRecordConnectResult covers the consecutive-failure streak that gates the
// pre-flight check on reconnect.
func TestRecordConnectResult(t *testing.T) {
	m := &Manager{}
	m.recordConnectResult(false)
	m.recordConnectResult(false)
	if m.consecutiveConnectFailures != 2 {
		t.Fatalf("want 2 consecutive failures, got %d", m.consecutiveConnectFailures)
	}
	if m.consecutiveConnectFailures < preflightFailThreshold {
		t.Fatalf("threshold should have been reached")
	}
	m.recordConnectResult(true)
	if m.consecutiveConnectFailures != 0 {
		t.Fatalf("success must reset the streak, got %d", m.consecutiveConnectFailures)
	}
}

// TestApplyUDPGate toggles QUIC exclusion from a UDP verdict.
func TestApplyUDPGate(t *testing.T) {
	m := &Manager{}
	m.applyUDPGate(false)
	if !m.excludeUDPStrategies {
		t.Fatal("UDP down should exclude QUIC strategies")
	}
	m.applyUDPGate(true)
	if m.excludeUDPStrategies {
		t.Fatal("UDP up should re-enable QUIC strategies")
	}
}

// TestCheckerAltAddrGate covers the dual-address gate: with one family dead and
// the other alive the checker must report connectivity, because the manager
// will dial the live one. Before this a client with both addresses configured
// and a blocked IPv4 stayed in "waiting for network" forever.
func TestCheckerAltAddrGate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	live := ln.Addr().String()

	// A port nothing listens on: closed immediately, so the dial fails fast.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	t.Run("primary dead, alt live", func(t *testing.T) {
		c := NewConnectivityChecker(deadAddr, 2*time.Second, false)
		c.SetAltAddr(live)
		if err := c.checkTCPAny(context.Background()); err != nil {
			t.Fatalf("checkTCPAny = %v, want nil (alt is reachable)", err)
		}
	})

	t.Run("both dead", func(t *testing.T) {
		c := NewConnectivityChecker(deadAddr, 500*time.Millisecond, false)
		c.SetAltAddr(deadAddr + "0")
		if err := c.checkTCPAny(context.Background()); err == nil {
			t.Fatal("checkTCPAny = nil, want an error when neither address answers")
		}
	})

	t.Run("no alt configured", func(t *testing.T) {
		c := NewConnectivityChecker(live, 2*time.Second, false)
		c.SetAltAddr("")
		c.SetAltAddr(live) // duplicate of the primary, must be ignored
		if got := c.addrsToTry(); len(got) != 1 || got[0] != live {
			t.Fatalf("addrsToTry = %v, want just the primary", got)
		}
	})
}
