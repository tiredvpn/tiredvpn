package strategy

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
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
