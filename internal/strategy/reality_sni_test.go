package strategy

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/evasion"
)

// sniCatcher is a TLS listener that records the SNI of every ClientHello it
// gets and then drops the connection: what an observer on the path reads.
type sniCatcher struct {
	addr string
	mu   sync.Mutex
	seen []string
}

func newSNICatcher(t *testing.T) *sniCatcher {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &sniCatcher{addr: ln.Addr().String()}
	cfg := &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		c.mu.Lock()
		c.seen = append(c.seen, chi.ServerName)
		c.mu.Unlock()
		return nil, net.ErrClosed // stop here; the name is all we want
	}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = tls.Server(conn, cfg).Handshake()
				conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *sniCatcher) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.seen)
}

// sniTestManager is a manager over two endpoints on catchers: the first with
// its own SNI pool, the second without.
func sniTestManager(t *testing.T, own []string) (*Manager, *sniCatcher, *sniCatcher) {
	t.Helper()
	a, b := newSNICatcher(t), newSNICatcher(t)
	sel, err := endpoint.NewSelector(endpoint.Config{
		Endpoints: []endpoint.Endpoint{
			{Name: "gcp", V4: a.addr, SNI: own},
			{Name: "plain", V4: b.addr, Order: 1},
		},
		Family:       endpoint.V4Only,
		ProbeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sel.Candidates() {
		sel.ReportProbe(c, true, time.Millisecond)
	}
	m := NewManager()
	m.endpoints = sel
	m.maxRetries = 1
	m.connectTimeout = 2 * time.Second
	return m, a, b
}

// dialEach dials s once at each endpoint, through the path a reconnect takes:
// the candidate's address, secret and SNI pool decided together.
func dialEach(t *testing.T, m *Manager, s Strategy, times int) {
	t.Helper()
	for _, cand := range m.selector().Candidates() {
		for range times {
			ctx, cancel := context.WithTimeout(m.withDialCandidate(context.Background(), cand), 2*time.Second)
			if conn, err := s.Connect(ctx, cand.Addr); err == nil {
				conn.Close()
			}
			cancel()
		}
	}
}

func assertNamesFrom(t *testing.T, who string, got, pool []string) {
	t.Helper()
	if len(got) == 0 {
		t.Fatalf("%s: no ClientHello reached the endpoint - the test proves nothing", who)
	}
	for _, n := range got {
		if !slices.Contains(pool, n) {
			t.Fatalf("%s: SNI %q on the wire, not from %v", who, n, pool)
		}
	}
}

// TestREALITYSendsTheEndpointsSNI is the call-site test for the per-endpoint
// SNI pool: the name read off a real ClientHello. An exit in GCP is configured
// with Google names and REALITY must use only those there; an endpoint without
// a pool keeps the built-in donors.
func TestREALITYSendsTheEndpointsSNI(t *testing.T) {
	own := []string{"www.google.com", "www.gstatic.com"}
	m, a, b := sniTestManager(t, own)
	r := NewREALITYStrategy(m, []byte("0123456789abcdef0123456789abcdef"))
	dialEach(t, m, r, 6)

	assertNamesFrom(t, "endpoint with sni", a.names(), own)
	assertNamesFrom(t, "endpoint without sni", b.names(), developerDonors())
}

// TestStegoSendsTheEndpointsSNI: HTTP/2 stego draws its cover host from the
// same pool, and the endpoint's pool wins over the process-wide -cover.
func TestStegoSendsTheEndpointsSNI(t *testing.T) {
	own := []string{"www.google.com", "www.gstatic.com"}
	m, a, b := sniTestManager(t, own)
	s := NewHTTP2StegoStrategy(m, []byte("secret"), "api.googleapis.com")
	dialEach(t, m, s, 6)

	assertNamesFrom(t, "endpoint with sni", a.names(), own)
	assertNamesFrom(t, "endpoint without sni", b.names(), []string{"api.googleapis.com"})
}

// TestQUICDrawsTheEndpointsSNI: QUIC's SNI choice follows the dial's pool.
func TestQUICDrawsTheEndpointsSNI(t *testing.T) {
	own := []string{"www.google.com", "www.gstatic.com"}
	m, _, _ := sniTestManager(t, own)
	q := &QUICStrategy{manager: m}
	cands := m.selector().Candidates()
	withPool := m.withDialCandidate(context.Background(), cands[0])
	without := m.withDialCandidate(context.Background(), cands[1])
	for range 50 {
		if n := q.selectSNI(withPool); !slices.Contains(own, n) {
			t.Fatalf("QUIC picked %q for an endpoint configured with %v", n, own)
		}
		if n := q.selectSNI(without); slices.Contains(own, n) && !isWhitelisted(n) {
			t.Fatalf("QUIC picked %q off-pool for an endpoint without one", n)
		}
	}
}

func isWhitelisted(n string) bool {
	for _, e := range evasion.WhitelistedSNIs {
		if e.SNI == n {
			return true
		}
	}
	return false
}

// TestSmallSNIPoolIsNotAMetronome is verification rule 3 on a two-name pool.
// Under a burst every name sits in its 30 s cooldown and the old fallback
// handed out the least recently used one: A, B, A, B, ... - a fixed alternation
// per client. Picks must stay spread over both names without a fixed order.
func TestSmallSNIPoolIsNotAMetronome(t *testing.T) {
	r := NewREALITYStrategy(nil, []byte("0123456789abcdef0123456789abcdef"))
	pool := []string{"www.google.com", "www.gstatic.com"}
	var seq []string
	for range 400 {
		dest, err := r.selectDestination(r.secret, pool)
		if err != nil {
			t.Fatal(err)
		}
		host, _, _ := net.SplitHostPort(dest)
		if !slices.Contains(pool, host) {
			t.Fatalf("picked %q outside %v", host, pool)
		}
		seq = append(seq, host)
	}
	counts := map[string]int{}
	repeats := 0
	for i, h := range seq {
		counts[h]++
		if i > 0 && seq[i-1] == h {
			repeats++
		}
	}
	for _, n := range pool {
		if counts[n] < 120 {
			t.Fatalf("%s picked %d of 400 times: the pool is not shared out", n, counts[n])
		}
	}
	if repeats < 100 {
		t.Fatalf("only %d back-to-back repeats in 400 picks: a near-fixed alternation", repeats)
	}
}

// TestUnlabelledDialsTakeThePinnedEndpointsSNI: dials that do not go through
// the endpoint walk (reconnect after a network change, budget recycling,
// port-hop make-before-break) pick up the pinned endpoint's address, key and
// SNI pool in one read (ensureDialSecret).
func TestUnlabelledDialsTakeThePinnedEndpointsSNI(t *testing.T) {
	own := []string{"www.google.com", "www.gstatic.com"}
	m, a, _ := sniTestManager(t, own)
	r := NewREALITYStrategy(m, []byte("0123456789abcdef0123456789abcdef"))
	for range 4 {
		ctx, cancel := context.WithTimeout(m.ensureDialSecret(context.Background()), 2*time.Second)
		if conn, err := r.Connect(ctx, a.addr); err == nil {
			conn.Close()
		}
		cancel()
	}
	assertNamesFrom(t, "pinned endpoint with sni", a.names(), own)
}

// TestSmallSNIPoolIsNotAMetronomeAcrossCycles is P2-1 of the round-3 review
// of PR #126/#127. TestSmallSNIPoolIsNotAMetronome makes its picks back to
// back, so it only exercised the fallback for a pool in cooldown. Handshakes
// 15-30 s apart - reconnect cycles, per-CONNECT handshakes in proxy mode -
// met the 30 s cooldown rotator instead, and on a two-name pool that is a
// strict A, B, A, B: the second name never repeated the first. Each pick here
// is moved 16 s into the past before the next one.
func TestSmallSNIPoolIsNotAMetronomeAcrossCycles(t *testing.T) {
	r := NewREALITYStrategy(nil, []byte("0123456789abcdef0123456789abcdef"))
	pool := []string{"www.google.com", "www.gstatic.com"}
	prev, repeats := "", 0
	const picks = 2000
	for i := range picks {
		dest, err := r.selectDestination(r.secret, pool)
		if err != nil {
			t.Fatal(err)
		}
		host, _, _ := net.SplitHostPort(dest)
		if i > 0 && host == prev {
			repeats++
		}
		prev = host
		r.destMu.Lock()
		for k, at := range r.recentDests {
			r.recentDests[k] = at.Add(-16 * time.Second)
		}
		r.destMu.Unlock()
	}
	if share := float64(repeats) / (picks - 1); share < 0.4 || share > 0.6 {
		t.Fatalf("the next pick repeated the last in %.0f%% of spaced picks, want about half", 100*share)
	}
}

// TestFixedHostStrategiesSendTheEndpointsSNI is P3-16 of the round-3 review of
// PR #127: the strategies outside the pool sent their own fixed host to the
// same exit - HTTP Polling and Geneva cdn.jsdelivr.net, WebSocket padded
// chat.openai.com, anti-probe www.google.com - so an exit configured with
// Google names still saw a ClientHello for a CDN or OpenAI from the same
// client. With a pool they draw from it; without one they keep their host.
func TestFixedHostStrategiesSendTheEndpointsSNI(t *testing.T) {
	own := []string{"www.gstatic.com", "storage.googleapis.com"}
	secret := []byte("fixed-host-secret")
	for _, tc := range []struct {
		name  string
		make  func(m *Manager) Strategy
		fixed string
	}{
		{"HTTP Polling", func(m *Manager) Strategy { return NewHTTPPollingStrategy(m, secret) }, "cdn.jsdelivr.net"},
		{"WebSocket padded", func(m *Manager) Strategy { return NewWebSocketPaddedStrategy(m, secret) }, "chat.openai.com"},
		{"Geneva", func(m *Manager) Strategy { return NewGenevaStrategy(m, secret, "ru") }, "cdn.jsdelivr.net"},
		{"anti-probe", func(m *Manager) Strategy { return NewAntiProbeStrategy(m, secret) }, "www.google.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, a, b := sniTestManager(t, own)
			dialEach(t, m, tc.make(m), 12)
			assertNamesFrom(t, "endpoint with sni", a.names(), own)
			if got := a.names(); !slices.Contains(got, own[0]) || !slices.Contains(got, own[1]) {
				t.Fatalf("endpoint with sni: %v in 12 dials, not drawn from the whole pool", got)
			}
			assertNamesFrom(t, "endpoint without sni", b.names(), []string{tc.fixed})
		})
	}
}

// TestMorphAndExhaustionSendTheEndpointsSNI is P3-7 of the round-7 review:
// one SNI pool for every strategy, Denis's decision. Traffic Morph sent no
// SNI at all and State Exhaustion the target's host, to an exit configured
// with Google names. With a pool they draw from it; without one they keep
// what they sent (none, for an address).
func TestMorphAndExhaustionSendTheEndpointsSNI(t *testing.T) {
	own := []string{"www.gstatic.com", "storage.googleapis.com"}
	secret := []byte("fixed-host-secret")
	for _, tc := range []struct {
		name string
		make func(m *Manager) Strategy
	}{
		{"Traffic Morph", func(m *Manager) Strategy { return NewTrafficMorphStrategy(m, nil, nil, secret) }},
		{"State Exhaustion", func(m *Manager) Strategy { return NewStateExhaustionStrategy(m, secret) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, a, b := sniTestManager(t, own)
			dialEach(t, m, tc.make(m), 12)
			assertNamesFrom(t, "endpoint with sni", a.names(), own)
			if got := a.names(); !slices.Contains(got, own[0]) || !slices.Contains(got, own[1]) {
				t.Fatalf("endpoint with sni: %v in 12 dials, not drawn from the whole pool", got)
			}
			assertNamesFrom(t, "endpoint without sni", b.names(), []string{""})
		})
	}
}

// TestFixedHostStrategiesKeepSNIAndHostTogether: the strategies that send an
// HTTP request inside their TLS name the same host in both places, whichever
// one the pool gave the connection.
func TestFixedHostStrategiesKeepSNIAndHostTogether(t *testing.T) {
	own := []string{"www.gstatic.com", "storage.googleapis.com"}
	secret := []byte("fixed-host-secret")
	for _, tc := range []struct {
		name string
		make func(m *Manager) Strategy
	}{
		{"HTTP Polling", func(m *Manager) Strategy { return NewHTTPPollingStrategy(m, secret) }},
		{"WebSocket padded", func(m *Manager) Strategy { return NewWebSocketPaddedStrategy(m, secret) }},
		{"Geneva", func(m *Manager) Strategy { return NewGenevaStrategy(m, secret, "ru") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*b1TestCert(t, "x")}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			type pair struct{ sni, host string }
			pairs := make(chan pair, 16)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						tlsConn := c.(*tls.Conn)
						_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
						if tlsConn.Handshake() != nil {
							return
						}
						var req []byte
						buf := make([]byte, 4096)
						for !bytes.Contains(req, []byte("\r\n\r\n")) {
							n, err := tlsConn.Read(buf)
							req = append(req, buf[:n]...)
							if err != nil {
								break
							}
						}
						host := ""
						for _, line := range strings.Split(string(req), "\r\n") {
							if v, ok := strings.CutPrefix(line, "Host: "); ok {
								host = v
							}
						}
						pairs <- pair{tlsConn.ConnectionState().ServerName, host}
					}()
				}
			}()
			sel, err := endpoint.NewSelector(endpoint.Config{
				Endpoints: []endpoint.Endpoint{{Name: "gcp", V4: ln.Addr().String(), SNI: own}},
				Family:    endpoint.V4Only,
			})
			if err != nil {
				t.Fatal(err)
			}
			m := NewManager()
			m.endpoints = sel
			s := tc.make(m)
			cand := sel.Candidates()[0]
			for range 4 {
				ctx, cancel := context.WithTimeout(m.withDialCandidate(context.Background(), cand), 500*time.Millisecond)
				if conn, err := s.Connect(ctx, cand.Addr); err == nil {
					conn.Close()
				}
				cancel()
			}
			seen := 0
			for {
				select {
				case p := <-pairs:
					seen++
					if !slices.Contains(own, p.sni) || p.host != p.sni {
						t.Fatalf("SNI %q, Host %q: want one name from %v in both", p.sni, p.host, own)
					}
					continue
				case <-time.After(time.Second):
				}
				break
			}
			if seen == 0 {
				t.Fatal("no request reached the server - the test proves nothing")
			}
		})
	}
}
