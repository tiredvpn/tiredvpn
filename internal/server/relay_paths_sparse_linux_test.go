package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/ktls"
	"github.com/tiredvpn/tiredvpn/internal/mux"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// The fix12-slow stand's shape - the target sends 28 B every 5 s, the client
// nothing - on a proxied stream, through every relay path that dials the
// exit with UpstreamDialer.Dial and through every conn wrapper clientLiveness
// walks to the client's TCP_INFO. Each row is a real client strategy into
// the relay's dispatcher (handleConnection, the QUIC server), the relay into
// a real exit, run for legDeadlines of the exit's read deadline at 1:25.
// That is past the relay's client window too, so a client the relay cannot
// tell is there loses its leg on the row: each row is red without Dial's
// keepalive, and without its path's liveness - the client conn the path
// hands Dial, the wrapper that names the conn under it, QUIC's PeerAlive,
// the Polling session's requests. Two are not:
//   - SSH and IMAP name their conn twice (overTransport and the camouflage
//     conn's NetConn); either alone keeps the row green, both gone turn it
//     red.
//   - The HTTP/2 Stego proxy path has two rows. Driven by its own client,
//     it is red without h2ProxyWatch: the client sends nothing, and the
//     relay's 60 s read deadline ended its session before the leg mattered
//     (proxy-f14-h2-relay on the fix14 stand). As the second relay of a
//     chain, its client the first relay's upstream conn, its own keepalive
//     does not show: every write up, the first relay's empty keepalive
//     frames included, makes the stego conn flush its WINDOW_UPDATE credit
//     up the leg.

// sparseTarget is the target of the proxied streams: it sends each one 28 B
// every sparseEvery and keeps what comes up.
type sparseTarget struct {
	addr string
	mu   sync.Mutex
	got  []byte
}

func newSparseTarget(t *testing.T) *sparseTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); ln.Close() })
	s := &sparseTarget{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				go func() {
					buf := make([]byte, 512)
					for {
						n, err := c.Read(buf)
						s.mu.Lock()
						s.got = append(s.got, buf[:n]...)
						s.mu.Unlock()
						if err != nil {
							return
						}
					}
				}()
				tick := time.NewTicker(sparseEvery)
				defer tick.Stop()
				for {
					select {
					case <-stop:
						return
					case <-tick.C:
						if _, err := c.Write(make([]byte, 28)); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	return s
}

func (s *sparseTarget) received() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.got...)
}

// pathRelay is a relay on loopback, as legRelay, with what its rows need.
type pathRelay struct {
	addr     string
	srvCtx   *serverContext
	quicPort int    // the relay's QUIC port, 0 without QUIC
	b1Pub    []byte // the relay's static REALITY key, nil without B1
}

// newPathRelay starts a relay into upstream; tweak, when set, edits its
// config before anything is served.
func newPathRelay(t *testing.T, secret []byte, upstream string, tweak func(*testing.T, *Config)) *pathRelay {
	t.Helper()
	cfg := &Config{Secret: secret}
	if tweak != nil {
		tweak(t, cfg)
	}
	srvCtx := &serverContext{cfg: cfg, tlsConfig: buildTLSProfile(cfg, selfSignedCertForTest(t)),
		upstreamDialer: NewUpstreamDialer(upstream, secret), donorDialer: testDonorFor(t, cfg)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var id uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id++
			go handleConnection(c, srvCtx, id)
		}
	}()
	r := &pathRelay{addr: ln.Addr().String(), srvCtx: srvCtx}
	if cfg.REALITYB1Enabled {
		_, pub := realityStaticKeys()
		r.b1Pub = pub[:]
	}
	if cfg.QUICEnabled {
		srv := startQUICServer(cfg, srvCtx)
		if srv == nil {
			t.Fatal("the relay's QUIC server did not start")
		}
		t.Cleanup(func() { _ = srv.Stop() })
		_, port, _ := net.SplitHostPort(cfg.QUICListenAddr)
		r.quicPort, _ = strconv.Atoi(port)
	}
	return r
}

// withREALITY turns on the legacy REALITY transport, as -reality-legacy
// does by default.
func withREALITY(t *testing.T, cfg *Config) {
	t.Helper()
	if err := InitREALITYKeys(&Config{}); err != nil {
		t.Fatal(err)
	}
	cfg.REALITYLegacyEnabled = true
}

// withB1 turns on REALITY B1 with a static key, its gate built afresh for
// this relay's secret.
func withB1(t *testing.T, cfg *Config) {
	t.Helper()
	priv, _, err := GenerateREALITYKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.REALITYB1Enabled, cfg.REALITYPrivateKey, cfg.REALITYMaxTimeDiff = true, priv, 300
	if err := InitREALITYKeys(cfg); err != nil {
		t.Fatal(err)
	}
	b1GateOnce, b1Gate = sync.Once{}, nil
	t.Cleanup(func() { b1GateOnce, b1Gate = sync.Once{}, nil })
}

// withQUIC turns on the QUIC server on a free loopback port.
func withQUIC(t *testing.T, cfg *Config) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	cert := selfSignedCertForTest(t)
	dir := t.TempDir()
	cfg.CertFile, cfg.KeyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))})
	if err := os.WriteFile(cfg.CertFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.KeyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.QUICEnabled, cfg.QUICListenAddr = true, addr
}

// strategyStream opens a proxied stream to target through the relay on the
// strategy make makes, as the client's proxy does.
func strategyStream(make func(*strategy.Manager, *pathRelay) strategy.Strategy) func(*testing.T, *pathRelay, string) net.Conn {
	return func(t *testing.T, r *pathRelay, target string) net.Conn {
		t.Helper()
		m := strategy.NewManager()
		if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "relay", V4: r.addr}}, endpoint.V4Only); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(endpoint.ResetSharedSelectors)
		s := make(m, r)
		m.Register(s)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		c, err := s.Connect(ctx, target)
		if err != nil {
			t.Fatalf("%s connect: %v", s.Name(), err)
		}
		t.Cleanup(func() { c.Close() })
		requestTarget(t, c, target)
		return c
	}
}

// requestTarget asks for target on a fresh stream, as the client's proxy
// does (pool.DialTarget), and waits for the relay's ack.
func requestTarget(t *testing.T, c net.Conn, target string) {
	t.Helper()
	addr := []byte(target)
	if _, err := c.Write(append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, ack); err != nil || ack[0] != 0 {
		t.Fatalf("relay ack %x: %v", ack, err)
	}
	_ = c.SetReadDeadline(time.Time{})
}

// muxStream is the mux path: an smux session over loopback TCP into the
// relay's MuxHandler, which no listener hands a connection to - Handle is
// its only entry.
func muxStream(t *testing.T, r *pathRelay, target string) net.Conn {
	t.Helper()
	client, relaySide := tcpPair(t)
	t.Cleanup(func() { client.Close(); relaySide.Close() })
	go func() { _ = NewMuxHandler(r.srvCtx, mux.DefaultConfig(), "sparse").Handle(t.Context(), relaySide) }()
	mc, err := mux.NewClient(client, mux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mc.Close() })
	stream, err := mc.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	requestTarget(t, stream, target)
	return stream
}

func antiProbe(m *strategy.Manager, r *pathRelay) strategy.Strategy {
	return strategy.NewAntiProbeStrategy(m, r.srvCtx.cfg.Secret)
}

func realityV2(m *strategy.Manager, r *pathRelay) strategy.Strategy {
	s := strategy.NewREALITYStrategy(m, r.srvCtx.cfg.Secret)
	s.SetRequireDataV2(true)
	if r.b1Pub != nil {
		s.SetB1(r.b1Pub)
	}
	return s
}

func TestEveryRelayPathKeepsASparseProxiedStream(t *testing.T) {
	longTest(t)
	for _, tc := range []struct {
		name  string
		relay func(*testing.T, *Config)
		// chain puts a second relay in front of the one under test, the
		// client's path through it anti-probe: the relay under test then
		// serves the first one's upstream conn on its HTTP/2 Stego path.
		chain bool
		dial  func(*testing.T, *pathRelay, string) net.Conn
		// ktls says the relay's conn must have gone over to kTLS.
		ktls bool
	}{
		{name: "anti-probe", dial: strategyStream(antiProbe)},
		{name: "REALITY", relay: withREALITY, dial: strategyStream(realityV2)},
		{name: "REALITY B1", relay: withB1, dial: strategyStream(realityV2)},
		{name: "SSH", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewSSHCamouflageStrategy(m, r.srvCtx.cfg.Secret)
		})},
		{name: "IMAP", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewIMAPCamouflageStrategy(m, r.srvCtx.cfg.Secret)
		})},
		{name: "Morph over kTLS", ktls: true, dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewTrafficMorphStrategy(m, nil, nil, r.srvCtx.cfg.Secret)
		})},
		{name: "Confusion", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewProtocolConfusionStrategy(m, strategy.ConfusionHTTPoverTLS, r.srvCtx.cfg.Secret)
		})},
		{name: "WebSocket Padded", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewWebSocketPaddedStrategy(m, r.srvCtx.cfg.Secret)
		})},
		{name: "HTTP Polling", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewHTTPPollingStrategy(m, r.srvCtx.cfg.Secret)
		})},
		{name: "QUIC", relay: withQUIC, dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewQUICSalamanderStrategy(m, r.srvCtx.cfg.Secret, r.quicPort)
		})},
		{name: "HTTP2 Stego proxy", dial: strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
			return strategy.NewHTTP2StegoStrategy(m, r.srvCtx.cfg.Secret, "")
		})},
		{name: "HTTP2 Stego proxy, relay chain", chain: true, dial: strategyStream(antiProbe)},
		{name: "mux", dial: muxStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scaleLegClocks(t)
			secret := []byte("relay-leg-secret-0123456789abcdef")
			exit := newLegExit(t, secret)
			// The exit's own watch keeps a leg whose relay acknowledges its
			// downlink, whatever the relay does: off, so each row tests the
			// relay's liveness and keepalive (P2-1 of the round-10 review).
			exit.srvCtx.noH2ProxyWatch = true
			target := newSparseTarget(t)
			relay := newPathRelay(t, secret, exit.addr, tc.relay)
			front := relay
			if tc.chain {
				front = newPathRelay(t, secret, relay.addr, nil)
			}
			ktlsBefore, _ := ktls.Stats()
			conn := tc.dial(t, front, target.addr)
			if on, _ := ktls.Stats(); tc.ktls && on == ktlsBefore {
				t.Fatal("the relay's conn never went over to kTLS - the row proves nothing")
			}
			proxiedSparseDownload(t, exit, target, conn)
		})
	}
}

// proxiedSparseDownload reads what comes down conn for legDeadlines of the
// exit's read deadline, failing if the stream or the exit's leg ends; then
// "hello" up has to reach the target, and nothing else may have.
func proxiedSparseDownload(t *testing.T, exit *legExit, target *sparseTarget, conn net.Conn) {
	t.Helper()
	var down atomic.Int64
	ended := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			down.Add(int64(n))
			if err != nil {
				ended <- err
				return
			}
		}
	}()
	span := legDeadlines * h2FrameReadTimeout()
	for end := time.Now().Add(span); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		select {
		case err := <-ended:
			t.Fatalf("the stream ended after %d bytes down: %v", down.Load(), err)
		default:
		}
		if exit.ended.Load() != 0 {
			t.Fatalf("the exit ended the leg after %d bytes down (read deadline %v)", down.Load(), h2FrameReadTimeout())
		}
	}
	if want := int64(span/sparseEvery) * 28 * 8 / 10; down.Load() < want {
		t.Fatalf("%d bytes came down, want at least %d", down.Load(), want)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(target.received()) < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := target.received(); string(got) != "hello" {
		t.Fatalf("the target got %q, want the client's hello and nothing else", got)
	}
}

// TestAnH2ProxySessionWithNothingDownStillEndsOnItsDeadline is the other
// side of h2ProxyWatch: a proxied stream whose target sends nothing gives
// the client nothing to acknowledge, so the relay must still end the
// session on its read deadline - the watch keeps a client that is there,
// not every open socket. The sparse target is the control: the same path
// keeps the stream, and the watch is what moved the deadline. Only the
// relay's session with the client counts: the exit behind it hears the
// relay's own keepalive, and moving its deadline then changes nothing.
func TestAnH2ProxySessionWithNothingDownStillEndsOnItsDeadline(t *testing.T) {
	longTest(t)
	for _, tc := range []struct {
		name   string
		target func(*testing.T) string
		ends   bool
	}{
		{"quiet target", newQuietTarget, true},
		{"sparse target", func(t *testing.T) string { return newSparseTarget(t).addr }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scaleLegClocks(t)
			secret := []byte("relay-leg-secret-0123456789abcdef")
			exit := newLegExit(t, secret)
			relay := newPathRelay(t, secret, exit.addr, nil)
			var extended atomic.Int64
			hook := func(c net.Conn) {
				if c.LocalAddr().String() == relay.addr {
					extended.Add(1)
				}
			}
			h2ProxyDeadlineExtended.Store(&hook)
			t.Cleanup(func() { h2ProxyDeadlineExtended.Store(nil) })
			conn := strategyStream(func(m *strategy.Manager, r *pathRelay) strategy.Strategy {
				return strategy.NewHTTP2StegoStrategy(m, r.srvCtx.cfg.Secret, "")
			})(t, relay, tc.target(t))
			start := time.Now()
			ended := make(chan error, 1)
			go func() {
				_, err := io.Copy(io.Discard, conn)
				ended <- err
			}()
			select {
			case <-ended:
				if !tc.ends {
					t.Fatalf("the stream ended after %v, %d extensions", time.Since(start).Round(time.Millisecond), extended.Load())
				}
				if el := time.Since(start); el > 2*h2FrameReadTimeout() {
					t.Fatalf("the stream ended after %v, want within two read deadlines (%v)", el.Round(time.Millisecond), h2FrameReadTimeout())
				}
				if n := extended.Load(); n != 0 {
					t.Fatalf("the watch moved the deadline %d times for a client it sends nothing to", n)
				}
			case <-time.After(3 * h2FrameReadTimeout()):
				if tc.ends {
					t.Fatalf("the stream is open after three read deadlines, %d extensions", extended.Load())
				}
				if extended.Load() == 0 {
					t.Fatal("the stream lived without the watch moving the deadline - the row proves nothing about it")
				}
			}
		})
	}
}

// newQuietTarget accepts connections, reads what comes and sends nothing.
func newQuietTarget(t *testing.T) string {
	t.Helper()
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
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	return ln.Addr().String()
}
