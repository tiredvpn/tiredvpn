package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestADialRelayLetsItsLegGoWhenTheClientHangsUp is P3-3 of the round-9
// review: a Dial relay whose client closed kept its upstream conn, and the
// conn's keepalive fed the exit while the client's TCP still counted as
// alive, so the leg outlived the client by up to about 2 3/4 minutes (one
// minute before round 13b). A browser closing an idle keep-alive connection
// does exactly this. Each path - raw, QUIC, Morph, Confusion - now tells the
// upstream conn its owner is done: no keepalive goes after the client's
// close, and the exit's deadline ends the leg within one deadline of it.
func TestADialRelayLetsItsLegGoWhenTheClientHangsUp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		relay func(*testing.T, *Config)
		dial  func(*testing.T, *pathRelay, string) net.Conn
	}{
		{name: "anti-probe", dial: strategyStream(antiProbe)},
		{name: "REALITY", relay: withREALITY, dial: strategyStream(realityV2)},
		{name: "QUIC", relay: withQUIC, dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewQUICSalamanderStrategy(m, r.srvCtx.cfg.Secret, r.quicPort)
		})},
		{name: "Morph", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewTrafficMorphStrategy(m, nil, nil, r.srvCtx.cfg.Secret)
		})},
		{name: "Confusion", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewProtocolConfusionStrategy(m, strategy.ConfusionHTTPoverTLS, r.srvCtx.cfg.Secret)
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scaleLegClocks(t)
			var mu sync.Mutex
			var sentAt []time.Time
			f := func() {
				mu.Lock()
				sentAt = append(sentAt, time.Now())
				mu.Unlock()
			}
			upstreamKeepaliveSent.Store(&f)
			t.Cleanup(func() { upstreamKeepaliveSent.Store(nil) })

			secret := []byte("relay-leg-secret-0123456789abcdef")
			exit := newLegExit(t, secret)
			// The target sends nothing: the leg is kept only by keepalives.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { c.Close() })
				}
			}()
			relay := newPathRelay(t, secret, exit.addr, tc.relay)
			conn := tc.dial(t, relay, ln.Addr().String())
			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			// Keepalives run for a while, then the client hangs up.
			time.Sleep(h2FrameReadTimeout())
			closedAt := time.Now()
			conn.Close()

			limit := closedAt.Add(h2FrameReadTimeout() + h2FrameReadTimeout()/4)
			for exit.ended.Load() == 0 && time.Now().Before(limit.Add(3*h2FrameReadTimeout())) {
				time.Sleep(10 * time.Millisecond)
			}
			endedAt := time.Now()
			mu.Lock()
			defer mu.Unlock()
			var after int
			for _, at := range sentAt {
				if at.After(closedAt.Add(50 * time.Millisecond)) {
					after++
				}
			}
			if after != 0 {
				t.Errorf("%d keepalives went up after the client hung up", after)
			}
			if exit.ended.Load() == 0 || endedAt.After(limit) {
				t.Errorf("the leg ended %v after the client hung up, want within %v",
					endedAt.Sub(closedAt).Round(time.Millisecond), limit.Sub(closedAt))
			}
		})
	}
}

// TestAPollingSessionClosedDuringItsDialClosesTheUpstream is P3-4 of the
// round-9 review: a Polling session closed while runPollingSessionRelay
// dialled the exit never saw the conn, and nothing closed it - the upstream
// conn's keepalive goroutine held it and its socket for good. Here the
// session is closed before the relay starts, its target already asked for.
func TestAPollingSessionClosedDuringItsDialClosesTheUpstream(t *testing.T) {
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	sess := newPollingSession("closed-during-dial")
	addr := []byte(ln.Addr().String())
	sess.WriteFromClient(append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...))
	sess.Close()
	srvCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(exit.addr, secret)}
	runPollingSessionRelay(sess, srvCtx, testLogger(t))
	sess.targetLock.Lock()
	up := sess.targetConn
	sess.targetLock.Unlock()
	if up == nil {
		t.Fatal("the relay never dialled the exit - the test proves nothing")
	}
	if _, err := up.Write([]byte("x")); err == nil {
		t.Fatal("the upstream conn of a closed session is still open")
	}
}
