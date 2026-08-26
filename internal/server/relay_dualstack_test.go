package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	exitServerIP  = net.IPv4(10, 9, 0, 1)
	exitClientIP  = net.IPv4(10, 9, 0, 7)
	exitServerIP6 = net.ParseIP("fd00:10:9::1")
	exitClientIP6 = net.ParseIP("fd00:10:9::a09:7")
)

// fakeTUNExit is an in-process upstream exit for relay tests: it terminates
// TLS + HTTP/2 stego exactly like a real server (so UpstreamDialer.connectStego
// works unmodified) and answers each TUN setup with a caller-built handshake
// response payload.
type fakeTUNExit struct {
	ln      net.Listener
	secret  []byte
	respond func(handshake []byte) []byte
}

// startFakeTUNExit launches the fake exit in the background. respond receives
// the client's TUN handshake payload ([localIP:4][mtu:2][version:1] plus any
// TRO1 origin trailer) and returns the response payload to send back.
func startFakeTUNExit(t *testing.T, secret []byte, respond func(handshake []byte) []byte) *fakeTUNExit {
	t.Helper()

	cert := selfSignedCertForTest(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("fake exit listen: %v", err)
	}
	f := &fakeTUNExit{ln: ln, secret: secret, respond: respond}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

// serve mirrors the real server's stego path: dispatch byte, h2 preface,
// framer, then a frame loop that acks the auth headers and answers TUN setups.
func (f *fakeTUNExit) serve(conn net.Conn) {
	defer conn.Close()
	logger := log.WithPrefix("fake-exit")

	if _, err := protocol.ReadDispatch(conn); err != nil {
		return
	}
	if err := readH2Preface(conn, logger); err != nil {
		return
	}
	framer, err := newH2Framer(conn, logger)
	if err != nil {
		return
	}

	paddingKey := deriveKey(f.secret, "padding-key")
	acked := false
	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		switch fr := frame.(type) {
		case *http2.SettingsFrame:
			if !fr.IsAck() {
				framer.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			// The client's first headers frame is the stego auth; later ones are
			// cover headers for data streams and need no answer.
			if !acked {
				acked = true
				sendH2AuthAck(framer, fr.StreamID, f.secret)
			}
		case *http2.DataFrame:
			data := fr.Data()
			if len(data) < 7 || !bytes.Equal(data[0:4], []byte("TIRD")) {
				continue
			}
			length := binary.BigEndian.Uint16(data[5:7])
			if int(length) > len(data)-7 {
				continue
			}
			payload := data[7 : 7+length]
			if data[4]&0x01 != 0 {
				for i := range payload {
					payload[i] ^= paddingKey[i%len(paddingKey)]
				}
			}
			if len(payload) == 0 || payload[0] != 0x02 {
				continue
			}
			resp := f.respond(payload[1:])
			sendStegoResponse(framer, fr.StreamID, resp, &Config{})
		}
	}
}

// dialTUNHandshake builds a v0x04 client handshake payload.
func dialTUNHandshake() []byte {
	return []byte{0, 0, 0, 0, 0x05, 0xdc, 0x04}
}

// TestDialTUNReadsFullHandshakeResponse drives DialTUN against a fake exit
// answering with the three response shapes an exit can produce and verifies
// the relay reads (and returns) the full raw response in each case.
func TestDialTUNReadsFullHandshakeResponse(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	dual := &dualStackAddrs{ServerIP6: exitServerIP6, ClientIP6: exitClientIP6}

	tests := []struct {
		name     string
		respond  func(handshake []byte) []byte
		wantDual bool
	}{
		{
			name: "legacy 9-byte exit response",
			respond: func([]byte) []byte {
				// A pre-dual-stack exit answers any client version with the
				// legacy layout.
				return buildTUNHandshakeResponse(0x00, exitServerIP, exitClientIP, tunHandshakeCaps{}, nil)
			},
		},
		{
			name: "extended base without dual flag",
			respond: func([]byte) []byte {
				return buildTUNHandshakeResponse(0x04, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, nil)
			},
		},
		{
			name: "extended base with dual flag and v6 block",
			respond: func([]byte) []byte {
				return buildTUNHandshakeResponse(0x04, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, dual)
			},
			wantDual: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.respond(nil)
			exit := startFakeTUNExit(t, secret, tt.respond)

			dialer := NewUpstreamDialer(exit.ln.Addr().String(), secret)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, resp, err := dialer.DialTUN(ctx, dialTUNHandshake(), "test-origin")
			if err != nil {
				t.Fatalf("DialTUN: %v", err)
			}
			defer conn.Close()

			if !bytes.Equal(resp, want) {
				t.Fatalf("resp = %x, want full exit response %x", resp, want)
			}

			caps, _ := tun.ParseTUNHandshakeCapabilities(resp)
			if caps.DualStackEnabled != tt.wantDual {
				t.Errorf("DualStackEnabled = %v, want %v", caps.DualStackEnabled, tt.wantDual)
			}
			if tt.wantDual {
				if !caps.ServerIP6.Equal(exitServerIP6) || !caps.ClientIP6.Equal(exitClientIP6) {
					t.Errorf("v6 addrs = %s/%s, want %s/%s",
						caps.ServerIP6, caps.ClientIP6, exitServerIP6, exitClientIP6)
				}
			}
		})
	}
}

// TestDialRelayTUNCarriesDualStackAddrs runs dialRelayTUN against the fake
// exit and verifies the sink carries the exit-assigned v6 addresses when (and
// only when) the exit negotiated dual-stack.
func TestDialRelayTUNCarriesDualStackAddrs(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	dual := &dualStackAddrs{ServerIP6: exitServerIP6, ClientIP6: exitClientIP6}

	t.Run("dual-stack exit", func(t *testing.T) {
		exit := startFakeTUNExit(t, secret, func([]byte) []byte {
			return buildTUNHandshakeResponse(0x04, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, dual)
		})
		srvCtx := newTestServerContext(t)
		srvCtx.upstreamDialer = NewUpstreamDialer(exit.ln.Addr().String(), secret)

		sink, serverIP, clientIP, err := dialRelayTUN(srvCtx, testLogger(t), dialTUNHandshake(), "origin", func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("dialRelayTUN: %v", err)
		}
		defer sink.Close()

		if !serverIP.Equal(exitServerIP) || !clientIP.Equal(exitClientIP) {
			t.Errorf("v4 addrs = %s/%s, want %s/%s", serverIP, clientIP, exitServerIP, exitClientIP)
		}
		d := sink.dualAddrs()
		if d == nil {
			t.Fatal("sink carries no dual-stack addrs after a dual-stack exit response")
		}
		if !d.ServerIP6.Equal(exitServerIP6) || !d.ClientIP6.Equal(exitClientIP6) {
			t.Errorf("sink v6 addrs = %s/%s, want %s/%s", d.ServerIP6, d.ClientIP6, exitServerIP6, exitClientIP6)
		}
	})

	t.Run("legacy exit degrades to v4-only", func(t *testing.T) {
		exit := startFakeTUNExit(t, secret, func([]byte) []byte {
			return buildTUNHandshakeResponse(0x00, exitServerIP, exitClientIP, tunHandshakeCaps{}, nil)
		})
		srvCtx := newTestServerContext(t)
		srvCtx.upstreamDialer = NewUpstreamDialer(exit.ln.Addr().String(), secret)

		sink, _, _, err := dialRelayTUN(srvCtx, testLogger(t), dialTUNHandshake(), "origin", func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("dialRelayTUN: %v", err)
		}
		defer sink.Close()

		if d := sink.dualAddrs(); d != nil {
			t.Errorf("legacy exit: sink.dualAddrs() = %+v, want nil", d)
		}
	})
}

// TestRelayChainForwardsDualStack is the in-process end-to-end: a downstream
// h2-stego TUN client -> relay (runH2FrameLoop + setupH2TUNTunnel +
// dialRelayTUN) -> fake exit. The client must receive the exit-assigned v4
// AND v6 addresses.
func TestRelayChainForwardsDualStack(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	dual := &dualStackAddrs{ServerIP6: exitServerIP6, ClientIP6: exitClientIP6}

	exit := startFakeTUNExit(t, secret, func(handshake []byte) []byte {
		hs, _ := splitTUNOrigin(handshake)
		version := byte(0)
		if len(hs) >= 7 {
			version = hs[6]
		}
		return buildTUNHandshakeResponse(version, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, dual)
	})

	// Relay: real server frame loop with an upstream dialer pointed at the exit.
	relayCtx := newTestServerContext(t)
	relayCtx.cfg.Secret = secret
	relayCtx.upstreamDialer = NewUpstreamDialer(exit.ln.Addr().String(), secret)

	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer relayLn.Close()

	go func() {
		conn, err := relayLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		logger := testLogger(t)
		if err := readH2Preface(conn, logger); err != nil {
			return
		}
		framer, err := newH2Framer(conn, logger)
		if err != nil {
			return
		}
		hpackDec := hpack.NewDecoder(4096, nil)
		authenticated := false
		var authClientID clientIdentity
		var tunnel *h2TunnelState
		var connTracked bool
		runH2FrameLoop(&conn, &framer, hpackDec, relayCtx, logger, &authenticated, &authClientID, &connTracked, &tunnel, nil)
	}()

	// Downstream client.
	clientConn, err := net.Dial("tcp", relayLn.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer clientConn.Close()

	stegoConn := strategy.NewHTTP2StegoConn(clientConn, secret, true, strategy.NaivePaddingMinimal)
	if err := stegoConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	setup := append([]byte{0x02}, dialTUNHandshake()...)
	if _, err := stegoConn.Write(setup); err != nil {
		t.Fatalf("write TUN setup: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := tun.ReadTUNHandshakeResponse(stegoConn)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if len(resp) < 9 || resp[0] != 0x00 {
		t.Fatalf("bad response: %x", resp)
	}
	if got := net.IP(resp[1:5]); !got.Equal(exitServerIP) {
		t.Errorf("serverIP = %s, want exit-assigned %s", got, exitServerIP)
	}
	if got := net.IP(resp[5:9]); !got.Equal(exitClientIP) {
		t.Errorf("clientIP = %s, want exit-assigned %s", got, exitClientIP)
	}

	caps, _ := tun.ParseTUNHandshakeCapabilities(resp)
	if !caps.DualStackEnabled {
		t.Fatalf("downstream response carries no dual-stack block: %x", resp)
	}
	if !caps.ServerIP6.Equal(exitServerIP6) || !caps.ClientIP6.Equal(exitClientIP6) {
		t.Errorf("v6 addrs = %s/%s, want exit-assigned %s/%s",
			caps.ServerIP6, caps.ClientIP6, exitServerIP6, exitClientIP6)
	}
}

// TestDownstreamDualStackAddrs covers the sourcing helper: relay sinks answer
// with the exit's addrs (nil when the exit did not negotiate), local sinks
// with pool-derived addrs.
func TestDownstreamDualStackAddrs(t *testing.T) {
	relaySink := &relayTUNSink{serverIP6: exitServerIP6, clientIP6: exitClientIP6}
	if d := downstreamDualStackAddrs(relaySink, "fd00:10:8::/64", hsClientIP); d == nil ||
		!d.ServerIP6.Equal(exitServerIP6) || !d.ClientIP6.Equal(exitClientIP6) {
		t.Errorf("relay sink: got %+v, want exit addrs", d)
	}

	// Relay whose exit did not negotiate dual-stack: downstream gets no block
	// even if the relay itself has a v6 pool configured.
	plainRelaySink := &relayTUNSink{}
	if d := downstreamDualStackAddrs(plainRelaySink, "fd00:10:8::/64", hsClientIP); d != nil {
		t.Errorf("relay without upstream dual: got %+v, want nil", d)
	}

	localSink := &localTUNSink{}
	d := downstreamDualStackAddrs(localSink, "fd00:10:8::/64", hsClientIP)
	if d == nil || d.ServerIP6.String() != "fd00:10:8::1" {
		t.Errorf("local sink: got %+v, want pool-derived addrs", d)
	}
}

// dualStackSessionCount reads the negotiated-session counter.
func dualStackSessionCount(srvCtx *serverContext) uint64 {
	return atomic.LoadUint64(&srvCtx.metrics.ipv6Metrics.tunnelDualStackSessions)
}

// TestRecordRelayedDualStackSession covers the plain relay path's accounting,
// which has to read the negotiated addresses back out of the exit's response
// because that path never builds one itself.
func TestRecordRelayedDualStackSession(t *testing.T) {
	dual := &dualStackAddrs{ServerIP6: exitServerIP6, ClientIP6: exitClientIP6}
	dualResp := buildTUNHandshakeResponse(0x04, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, dual)
	plainResp := buildTUNHandshakeResponse(0x04, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, nil)
	legacyResp := buildTUNHandshakeResponse(0x00, exitServerIP, exitClientIP, tunHandshakeCaps{}, nil)

	tests := []struct {
		name    string
		version byte
		resp    []byte
		want    uint64
	}{
		{"exit negotiated dual-stack", 0x04, dualResp, 1},
		{"exit answered without the block", 0x04, plainResp, 0},
		{"legacy exit", 0x04, legacyResp, 0},
		{"pre-dual client", 0x03, dualResp, 0},
		{"truncated response", 0x04, dualResp[:5], 0},
		{"empty response", 0x04, nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvCtx := newTestServerContext(t)
			srvCtx.metrics = NewMetrics(nil)
			recordRelayedDualStackSession(srvCtx, tt.version, tt.resp)
			if got := dualStackSessionCount(srvCtx); got != tt.want {
				t.Errorf("sessions = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestRelayTUNToUpstreamRecordsDualStack is the wiring check: the plain
// hop-to-hop relay path (relayTUNToUpstream, used by raw TLS/QUIC downstream
// clients) forwards the exit's response verbatim AND counts the session.
func TestRelayTUNToUpstreamRecordsDualStack(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	dual := &dualStackAddrs{ServerIP6: exitServerIP6, ClientIP6: exitClientIP6}

	exit := startFakeTUNExit(t, secret, func(handshake []byte) []byte {
		hs, _ := splitTUNOrigin(handshake)
		version := byte(0)
		if len(hs) >= 7 {
			version = hs[6]
		}
		return buildTUNHandshakeResponse(version, exitServerIP, exitClientIP, tunHandshakeCaps{mtuProbe: true}, dual)
	})

	srvCtx := newTestServerContext(t)
	srvCtx.metrics = NewMetrics(nil)
	srvCtx.upstreamDialer = NewUpstreamDialer(exit.ln.Addr().String(), secret)

	relaySide, clientSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTUNToUpstream(relaySide, srvCtx, testLogger(t), dialTUNHandshake())
	}()

	clientSide.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := tun.ReadTUNHandshakeResponse(clientSide)
	if err != nil {
		t.Fatalf("read relayed handshake response: %v", err)
	}
	caps, ok := tun.ParseTUNHandshakeCapabilities(resp)
	if !ok || !caps.DualStackEnabled {
		t.Fatalf("relayed response carries no dual-stack block: %x", resp)
	}
	if !caps.ServerIP6.Equal(exitServerIP6) || !caps.ClientIP6.Equal(exitClientIP6) {
		t.Errorf("v6 addrs = %s/%s, want exit-assigned %s/%s",
			caps.ServerIP6, caps.ClientIP6, exitServerIP6, exitClientIP6)
	}

	// The counter is bumped right after the response reaches the client, so
	// poll briefly instead of racing the relay goroutine.
	deadline := time.Now().Add(5 * time.Second)
	for dualStackSessionCount(srvCtx) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := dualStackSessionCount(srvCtx); got != 1 {
		t.Errorf("dualstack sessions = %d, want 1 (plain relay path must count too)", got)
	}

	clientSide.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("relayTUNToUpstream did not return after the client went away")
	}
}

// TestRecordDualStackSession verifies the session counter increments exactly
// when a response with the dual-stack block is built for a v0x04+ client.
func TestRecordDualStackSession(t *testing.T) {
	srvCtx := newTestServerContext(t)
	srvCtx.metrics = NewMetrics(nil)
	dual := dualTestAddrs()

	recordDualStackSession(srvCtx, 0x03, dual) // pre-dual client: no count
	recordDualStackSession(srvCtx, 0x04, nil)  // no addrs: no count
	recordDualStackSession(nil, 0x04, dual)    // no ctx: must not panic
	recordDualStackSession(srvCtx, 0x04, dual) // negotiated: count
	recordDualStackSession(srvCtx, 0x05, dual) // future version: count

	rec := httptest.NewRecorder()
	srvCtx.metrics.ipv6Metrics.ExportPrometheus(rec)
	if !strings.Contains(rec.Body.String(), "tiredvpn_tunnel_dualstack_sessions_total 2\n") {
		t.Errorf("counter export wrong, want 2 sessions:\n%s", rec.Body.String())
	}
}
