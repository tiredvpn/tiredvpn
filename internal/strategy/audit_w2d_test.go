package strategy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// ---- S11: http_polling idle backoff + connection reuse ----

// TestPollingIdleBackoff pins that the poll interval grows while the tunnel is
// idle instead of holding the old fixed 50ms metronome (the numWorkers==1 turn
// condition polled every 50ms round the clock). If idleInterval is reverted to
// return pollInterval, every assertion below fails.
func TestPollingIdleBackoff(t *testing.T) {
	c := &HTTPPollingConn{pollInterval: 50 * time.Millisecond}

	if got := c.idleInterval(0); got != c.pollInterval {
		t.Fatalf("idleInterval(0)=%v, want the fast pollInterval %v", got, c.pollInterval)
	}
	if got := c.idleInterval(1); got <= c.pollInterval {
		t.Fatalf("interval did not grow after one idle round: %v (fast is %v)", got, c.pollInterval)
	}
	if got := c.idleInterval(5); got <= 50*time.Millisecond {
		t.Fatalf("interval still at the 50ms metronome after five idle rounds: %v", got)
	}
	if got := c.idleInterval(100); got != pollIdleMax {
		t.Fatalf("idleInterval did not cap at pollIdleMax: %v (want %v)", got, pollIdleMax)
	}

	prev := c.idleInterval(0)
	for r := 1; r <= 12; r++ {
		cur := c.idleInterval(r)
		if cur < prev {
			t.Fatalf("idleInterval not monotonic at round %d: %v < %v", r, cur, prev)
		}
		prev = cur
	}
}

// serveFakePolling reads the one-shot protocol dispatch byte, then answers every
// HTTP request on the connection with 200 keep-alive, looping for as long as the
// client keeps the connection open. It is the minimum a keep-alive polling
// server has to do for the reuse test.
func serveFakePolling(c net.Conn) {
	defer c.Close()
	if _, err := protocol.ReadDispatch(c); err != nil {
		return
	}
	r := bufio.NewReader(c)
	for {
		cl := 0
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "Content-Length:") {
				fmt.Sscanf(line, "Content-Length: %d", &cl)
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		if cl > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(cl)); err != nil {
				return
			}
		}
		if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")); err != nil {
			return
		}
	}
}

// TestPollingReusesConnection pins that a burst of polls rides one TLS
// connection instead of dialling a fresh TCP+TLS handshake per request.
//
// Before: doRequest opened a new connection with Connection: close every time,
// so N polls meant N handshakes - ~20/second on an active tunnel. This drives 8
// polls and asserts the server accepted exactly one connection. On the 1.10.x
// close-per-request code this test would see 8.
func TestPollingReusesConnection(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var conns int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&conns, 1)
			go serveFakePolling(c)
		}
	}()

	mgr := NewManager()
	setTestEndpoint(mgr, ln.Addr().String())
	conn := &HTTPPollingConn{
		manager:         mgr,
		secret:          []byte("reuse-secret"),
		host:            "localhost",
		path:            "/x",
		sessionID:       "sess-reuse",
		sendBuf:         bytes.NewBuffer(nil),
		recvBuf:         bytes.NewBuffer(nil),
		closed:          make(chan struct{}),
		tlsSessionCache: tls.NewLRUClientSessionCache(4),
	}

	ctx := context.Background()
	const n = 8
	for i := 0; i < n; i++ {
		if _, err := conn.doRequest(ctx, nil, 0); err != nil {
			t.Fatalf("doRequest %d: %v", i, err)
		}
	}

	if got := atomic.LoadInt64(&conns); got != 1 {
		t.Fatalf("%d polls opened %d TCP connections; keep-alive reuse is not happening (want 1). "+
			"The 1.10.x path dialled a fresh TCP+TLS handshake per request.", n, got)
	}
}

// ---- S13: cover SNI / :authority from the shared pool ----

func evasionPoolSet() map[string]bool {
	m := map[string]bool{}
	for _, e := range evasion.WhitelistedSNIs {
		m[e.SNI] = true
	}
	return m
}

// TestQUICSelectSNIFromSharedPoolNotHourly pins that the QUIC SNI comes from the
// shared evasion whitelist and varies per call. The old selectSNI indexed five
// hardcoded Google domains by hour-of-day: within any hour every client used the
// same SNI (a synchronised signal), and two of those domains are not even in the
// vetted pool. Both properties fail on the old code.
func TestQUICSelectSNIFromSharedPoolNotHourly(t *testing.T) {
	s := NewQUICStrategy(NewManager(), []byte("x"), 443)
	pool := evasionPoolSet()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		sni := s.selectSNI()
		if !pool[sni] {
			t.Fatalf("QUIC SNI %q is not from the shared evasion pool", sni)
		}
		seen[sni] = true
	}
	if len(seen) < 2 {
		t.Fatalf("selectSNI produced %d distinct SNIs over 200 calls; the old hour-of-day index "+
			"pinned every client to one value per hour", len(seen))
	}
}

// TestStegoCoverHostFromSharedPool pins that the default stego cover host is
// drawn per connection from the shared pool rather than the build-time constant
// "www.googleapis.com".
func TestStegoCoverHostFromSharedPool(t *testing.T) {
	pool := evasionPoolSet()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		h := stegoCoverRotator.Next()
		if !pool[h] {
			t.Fatalf("stego cover host %q is not from the shared evasion pool", h)
		}
		seen[h] = true
	}
	if len(seen) < 2 {
		t.Fatalf("cover host produced %d distinct values over 200 calls; selection is not per-connection", len(seen))
	}
}

// TestStegoAuthorityTracksCoverHost pins that the HTTP/2 :authority follows the
// cover host chosen for the connection, so the encrypted :authority matches the
// cleartext SNI. The 1.10.x path hardcoded :authority to api.googleapis.com
// regardless of the SNI - the mismatch an active prober compares.
func TestStegoAuthorityTracksCoverHost(t *testing.T) {
	c, srv := net.Pipe()
	defer c.Close()
	defer srv.Close()

	conn := NewHTTP2StegoConn(c, []byte("auth-secret"), true, NaivePaddingMinimal, nil)
	conn.coverHost = "vk.com"
	if got := conn.authority(); got != "vk.com" {
		t.Fatalf("authority()=%q, want it to track coverHost vk.com", got)
	}
	conn.coverHost = "sberbank.ru"
	if got := conn.authority(); got != "sberbank.ru" {
		t.Fatalf("authority()=%q did not follow coverHost", got)
	}
}

// ---- S14: QUIC probe validity ----

// TestQUICProbeIsValidV1Initial pins that the reachability probe is a well-formed
// QUIC v1 long-header Initial at the RFC 9000 minimum size. The old probe was a
// 100-byte packet stamped with draft-29 (0xff00001d) while Connect speaks v1 -
// undersized, malformed, and a second version fingerprint. Every assertion here
// fails on that 100-byte draft-29 packet.
func TestQUICProbeIsValidV1Initial(t *testing.T) {
	s := NewQUICStrategy(NewManager(), []byte("probe-secret"), 443)
	pkt := s.buildProbePacket()

	if len(pkt) < 1200 {
		t.Fatalf("probe is %d bytes; RFC 9000 requires an Initial-bearing datagram >= 1200", len(pkt))
	}
	if pkt[0]&0xc0 != 0xc0 {
		t.Fatalf("first byte %#x is not a long-header form (long+fixed bits)", pkt[0])
	}
	if pkt[0]&0x30 != 0x00 {
		t.Fatalf("first byte %#x is not an Initial packet type (bits 4-5 must be 0)", pkt[0])
	}
	if ver := binary.BigEndian.Uint32(pkt[1:5]); ver != 0x00000001 {
		t.Fatalf("probe version %#08x is not QUIC v1 (Connect speaks v1)", ver)
	}
}
