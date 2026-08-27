package strategy

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/evasion"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// deadAddr returns an address on loopback that nothing is listening on: bind,
// note the port, close. Connecting to it gets a refusal straight away, which is
// what makes "the first endpoint is down" cheap and deterministic here.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// serveB1 puts srv behind a listener and returns its address. Every accepted
// connection is served; the goroutine ends when the listener closes.
func serveB1(t *testing.T, srv *b1TestServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.serve(t, conn) }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String()
}

// v4Only is the family policy for the loopback pools below: these tests dial
// 127.0.0.1 and nothing else, and a v6 leg would only add a refused connection
// per candidate.
func v4Only() *endpoint.FamilyPolicy {
	p := endpoint.V4Only
	return &p
}

// TestPerEndpointSecretAuthenticatesSecondServer is the acceptance test for the
// whole change, and it is deliberately end to end rather than a check on a
// helper.
//
// Two endpoints, two DIFFERENT secrets. The first is dead, the second is a real
// B1 server that rejects anyone whose session_id does not carry ShortIDFor(its
// own secret) and whose binding proof is not computed under it. So the tunnel
// only comes up if the client noticed the switch and authenticated with the
// second endpoint's key - the previous build could not, and refused to start at
// all rather than try.
func TestPerEndpointSecretAuthenticatesSecondServer(t *testing.T) {
	// One static key for both endpoints: the server's X25519 identity is a
	// separate axis from the client secret, and this test is about the secret.
	staticPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	live := &b1TestServer{
		staticPriv: staticPriv,
		secret:     []byte("secret-of-the-second-server"),
		srvTime:    time.Now().Truncate(time.Second),
	}
	liveAddr := serveB1(t, live)
	firstAddr := deadAddr(t)

	m := NewManager()
	m.setDefaultSecret([]byte("process-wide-default-nobody-accepts"))
	if err := m.SetEndpointsTuned([]endpoint.Endpoint{
		{Name: "first", V4: firstAddr, Order: 0, Secret: "secret-of-the-first-server"},
		{Name: "second", V4: liveAddr, Order: 1, Secret: string(live.secret)},
	}, endpoint.Tuning{Family: v4Only()}); err != nil {
		t.Fatalf("SetEndpointsTuned: %v", err)
	}

	// The strategy is constructed with the FIRST endpoint's secret, which is how
	// it is built in production: one construction, whatever the pool does later.
	r := NewREALITYStrategy(m, []byte("secret-of-the-first-server"))
	r.SetB1(staticPriv.PublicKey().Bytes())
	if !r.b1Enabled {
		t.Fatal("B1 did not enable")
	}
	m.Register(r)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	conn, _, err := m.Connect(ctx, firstAddr)
	if err != nil {
		t.Fatalf("Connect across the pool: %v", err)
	}
	defer conn.Close()

	// The server echoes, so a round trip proves the tunnel is up rather than
	// merely that a TCP connection was made.
	want := []byte("per-endpoint secret round trip")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}

	// And the switch actually happened, rather than the first endpoint quietly
	// answering.
	if addr := m.GetServerAddr(ctx); addr != liveAddr {
		t.Fatalf("pinned address = %s, want the second endpoint %s", addr, liveAddr)
	}
}

// TestPerEndpointSecretRejectedWhenWrong is the positive control for the test
// above: the same setup, but the second endpoint is configured with a secret its
// server does not know. The dial must fail.
//
// Without this, "the tunnel came up" would be consistent with a server that
// accepts anything, and the test above would prove nothing about which key was
// used.
func TestPerEndpointSecretRejectedWhenWrong(t *testing.T) {
	staticPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	live := &b1TestServer{
		staticPriv: staticPriv,
		secret:     []byte("secret-of-the-second-server"),
		srvTime:    time.Now().Truncate(time.Second),
	}
	liveAddr := serveB1(t, live)

	m := NewManager()
	m.setDefaultSecret([]byte("process-wide-default-nobody-accepts"))
	if err := m.SetEndpointsTuned([]endpoint.Endpoint{
		{Name: "second", V4: liveAddr, Order: 0, Secret: "not-the-servers-secret"},
	}, endpoint.Tuning{Family: v4Only()}); err != nil {
		t.Fatalf("SetEndpointsTuned: %v", err)
	}

	r := NewREALITYStrategy(m, live.secret) // right key, wrong place to put it
	r.SetB1(staticPriv.PublicKey().Bytes())
	m.Register(r)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	conn, _, err := m.Connect(ctx, liveAddr)
	if err == nil {
		conn.Close()
		t.Fatal("connected with the wrong per-endpoint secret: the endpoint's secret is not reaching the handshake")
	}
}

// TestDialSecretFallsBackToConstruction pins the single-server case: nothing on
// the context, so every strategy sees exactly the secret it was built with. This
// is the shape every production unit runs today (-secret, one -server), and it
// must not have moved.
func TestDialSecretFallsBackToConstruction(t *testing.T) {
	built := []byte("built-in")
	if got := dialSecret(t.Context(), built); string(got) != "built-in" {
		t.Fatalf("dialSecret = %q, want the construction secret", got)
	}
	ctx := withDialSecret(t.Context(), []byte("from-the-endpoint"))
	if got := dialSecret(ctx, built); string(got) != "from-the-endpoint" {
		t.Fatalf("dialSecret = %q, want the endpoint secret", got)
	}
	// An empty endpoint secret must not blank out the fallback: that is how an
	// endpoint with no secret of its own inherits the process-wide default. Two
	// separate guards stand between an empty value and a strategy - one refusing
	// to record it, one refusing to return it - and each is checked on its own,
	// because either alone would make this pass.
	base := t.Context()
	if withDialSecret(base, nil) != base {
		t.Fatal("withDialSecret recorded an empty secret, which would blank out a value an outer caller set")
	}
	empty := context.WithValue(base, dialSecretKey{}, []byte(nil))
	if got := dialSecret(empty, built); string(got) != "built-in" {
		t.Fatalf("dialSecret = %q, want an empty recorded secret to fall through to the fallback", got)
	}
}

// TestManagerSecretFollowsPinnedEndpoint checks the other half of the wiring:
// which secret the manager hands out when the caller did not name one. It must
// be the pinned endpoint's, and it must move when the pin moves.
func TestManagerSecretFollowsPinnedEndpoint(t *testing.T) {
	m := NewManager()
	m.setDefaultSecret([]byte("default"))
	eps := []endpoint.Endpoint{
		{Name: "a", V4: "203.0.113.10:443", Order: 0, Secret: "secret-a"},
		{Name: "b", V4: "203.0.113.20:443", Order: 1, Secret: "secret-b"},
		{Name: "c", V4: "203.0.113.30:443", Order: 2}, // no secret of its own
	}
	if err := m.SetEndpointsTuned(eps, endpoint.Tuning{Family: v4Only()}); err != nil {
		t.Fatalf("SetEndpointsTuned: %v", err)
	}
	sel := m.selector()

	if got := m.CurrentSecret(); string(got) != "secret-a" {
		t.Fatalf("CurrentSecret = %q, want secret-a", got)
	}
	for i, want := range []string{"secret-a", "secret-b", "default"} {
		cand := sel.Candidates()[i]
		sel.Pin(cand)
		if got := m.CurrentSecret(); string(got) != want {
			t.Fatalf("after pinning %s: CurrentSecret = %q, want %q", cand, got, want)
		}
		if got := m.secretForCandidate(cand); string(got) != want {
			t.Fatalf("secretForCandidate(%s) = %q, want %q", cand, got, want)
		}
	}

	// ensureDialSecret must not overwrite a secret the caller already named -
	// dialEndpoints names one per candidate, and that is the authoritative one.
	pinned := m.ensureDialSecret(t.Context())
	if got := dialSecret(pinned, nil); string(got) != "default" {
		t.Fatalf("ensureDialSecret on a bare context gave %q, want the pinned endpoint's", got)
	}
	named := m.ensureDialSecret(withDialSecret(t.Context(), []byte("named-by-caller")))
	if got := dialSecret(named, nil); string(got) != "named-by-caller" {
		t.Fatalf("ensureDialSecret overwrote the caller's secret with %q", got)
	}
}

// TestDonorPoolFollowsEndpointSecret covers the derived value that is easiest to
// get wrong, because it is computed once at construction and then reused.
//
// The REALITY donor pool is HKDF'd from the secret (derivePool): each user hides
// behind their own ordering of cover domains. A client that switched endpoint
// but kept the first endpoint's pool would present one user's donor sequence
// while authenticating as another - exactly the linkage derivePool exists to
// prevent.
func TestDonorPoolFollowsEndpointSecret(t *testing.T) {
	developer := make([]string, 0, 8)
	for _, e := range evasion.WhitelistedSNIs {
		if e.Category == "developer" {
			developer = append(developer, e.SNI)
		}
	}
	if len(developer) < 2 {
		t.Skipf("donor pool has %d entries, nothing to order", len(developer))
	}

	r := NewREALITYStrategy(nil, []byte("secret-a"))

	poolA, rotA := r.donorsFor([]byte("secret-a"))
	if !slices.Equal(poolA, derivePool(developer, []byte("secret-a"), len(developer))) {
		t.Fatalf("pool for the construction secret = %v, want the derived one", poolA)
	}
	if rotA != r.sniRotator {
		t.Fatal("construction secret got a fresh rotator instead of the strategy's own")
	}

	poolB, rotB := r.donorsFor([]byte("secret-b"))
	if !slices.Equal(poolB, derivePool(developer, []byte("secret-b"), len(developer))) {
		t.Fatalf("pool for the second secret = %v, want the pool derived from THAT secret", poolB)
	}
	if slices.Equal(poolA, poolB) {
		t.Fatal("both secrets produced the same donor ordering: the pool is not following the secret")
	}
	if rotB == rotA {
		t.Fatal("the second secret reuses the first one's rotator, so it walks the first one's pool")
	}

	// Cached, not re-derived: a second ask must hand back the same rotator, or
	// the cooldown that rotator carries restarts on every dial.
	if _, again := r.donorsFor([]byte("secret-b")); again != rotB {
		t.Fatal("donorsFor re-derived the pool instead of caching it")
	}

	// And the destination actually chosen comes from the second pool.
	dest, err := r.selectDestination([]byte("secret-b"))
	if err != nil {
		t.Fatalf("selectDestination: %v", err)
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}
	if !slices.Contains(poolB, host) {
		t.Fatalf("destination %q is not in the second secret's pool %v", host, poolB)
	}
}

// TestShortIDFollowsDialSecret pins the client identifier the server looks up.
// ShortIDFor is what the B1 session_id carries; deriving it from a stale secret
// is what produces "client not found" on a server that is working perfectly.
func TestShortIDFollowsDialSecret(t *testing.T) {
	a := customtls.ShortIDFor([]byte("secret-a"))
	b := customtls.ShortIDFor([]byte("secret-b"))
	if a == b {
		t.Fatal("two secrets share a short id; this test cannot tell them apart")
	}

	staticPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := &b1TestServer{
		staticPriv: staticPriv,
		secret:     []byte("secret-b"),
		srvTime:    time.Now().Truncate(time.Second),
	}

	// Built with secret-a, dialled under secret-b. The stand-in server checks
	// ShortIDFor(secret-b) on the session_id before it will even hand back a
	// certificate, so reaching the echo means the identifier was recomputed.
	r := NewREALITYStrategy(nil, []byte("secret-a"))
	r.SetB1(staticPriv.PublicKey().Bytes())

	addr := serveB1(t, srv)
	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	if err := tcpConn.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	conn, err := r.connectB1(t.Context(), tcpConn, "github.com:443", deadline, []byte("secret-b"))
	if err != nil {
		tcpConn.Close()
		t.Fatalf("connectB1 under the dial secret: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Positive control: the construction secret is now the wrong one, and the
	// same call with it must be refused.
	tcpConn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := tcpConn2.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	bad, err := r.connectB1(t.Context(), tcpConn2, "github.com:443", time.Now().Add(10*time.Second), r.secret)
	tcpConn2.Close()
	if err == nil {
		bad.Close()
		t.Fatal("the stale secret was accepted; the server is not checking what this test assumes")
	}
	if errors.Is(err, errB1NoAuthKey) {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
}
