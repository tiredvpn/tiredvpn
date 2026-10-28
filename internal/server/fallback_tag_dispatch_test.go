package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// P1-1 of the rejudge r4 of PR #127: with an SNI pool of donor names, the TLS
// fallback transports never reached their handlers on a B1 server - the gate
// proxied them to the donor. These run the real client strategies against the
// real dispatcher (handleConnection -> tryREALITYB1 -> handleTLSConnection),
// with a loopback stand-in for the donor.

const tagTestSecret = "fallback-tag-dispatch-secret"

// donorPool is an endpoint SNI pool of built-in donor names: the
// configuration docs/server.md recommends, and the one that broke.
var donorPool = []string{"www.google.com", "yandex.ru"}

// tagFallbackStrategies are the TLS fallbacks, as the client builds them.
var tagFallbackStrategies = []struct {
	name string
	make func(m *strategy.Manager, secret []byte) strategy.Strategy
}{
	{"HTTP Polling", func(m *strategy.Manager, s []byte) strategy.Strategy { return strategy.NewHTTPPollingStrategy(m, s) }},
	{"WebSocket padded", func(m *strategy.Manager, s []byte) strategy.Strategy {
		return strategy.NewWebSocketPaddedStrategy(m, s)
	}},
	{"Geneva", func(m *strategy.Manager, s []byte) strategy.Strategy { return strategy.NewGenevaStrategy(m, s, "ru") }},
	{"anti-probe", func(m *strategy.Manager, s []byte) strategy.Strategy { return strategy.NewAntiProbeStrategy(m, s) }},
	{"HTTP/2 Stego", func(m *strategy.Manager, s []byte) strategy.Strategy {
		return strategy.NewHTTP2StegoStrategy(m, s, "")
	}},
	// Morph and State Exhaustion send the endpoint's SNI since the pool
	// became every strategy's (P3-7 of the round-7 review), and with it
	// the tag; they had no test here (P3-7 of the round-8 review).
	{"Traffic Morph", func(m *strategy.Manager, s []byte) strategy.Strategy {
		return strategy.NewTrafficMorphStrategy(m, nil, nil, s)
	}},
	{"State Exhaustion", func(m *strategy.Manager, s []byte) strategy.Strategy {
		return strategy.NewStateExhaustionStrategy(m, s)
	}},
}

// tagServer is a B1 server on loopback with the global secret and a stand-in
// donor, every connection dispatched by handleConnection.
type tagServer struct {
	addr   string
	donor  *countingDonor
	srvCtx *serverContext
}

func newTagServer(t *testing.T, cover string) *tagServer {
	t.Helper()
	// A Polling fallback that gets through opens a real session on the
	// process-wide pollingManager, which outlived the test and filled the
	// ceiling the session-cap tests count on.
	forgetNewPollingSessions(t)
	privB64, _, err := GenerateREALITYKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Secret:             []byte(tagTestSecret),
		REALITYB1Enabled:   true,
		REALITYPrivateKey:  privB64,
		REALITYMaxTimeDiff: 300,
		REALITYCoverDomain: cover,
		REALITYFallbackTag: true,
	}
	if err := InitREALITYKeys(cfg); err != nil {
		t.Fatal(err)
	}
	gate := newREALITYB1Gate(cfg.REALITYMaxTimeDiff)
	gate.index.Rebuild(nil, cfg.Secret)

	donor := newCountingDonor(t)
	srvCtx := &serverContext{
		cfg:         cfg,
		tlsConfig:   buildTLSProfile(cfg, selfSignedCertForTest(t)),
		donorDialer: donor.dial,
		b1Gate:      gate,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var id atomic.Uint64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConnection(conn, srvCtx, id.Add(1))
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return &tagServer{addr: ln.Addr().String(), donor: donor, srvCtx: srvCtx}
}

// countingDonor stands in for every donor site: it counts the connections
// handed to it and keeps the first bytes of each.
type countingDonor struct {
	addr  string
	conns atomic.Int64
	got   chan []byte
}

func newCountingDonor(t *testing.T) *countingDonor {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	d := &countingDonor{addr: ln.Addr().String(), got: make(chan []byte, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				first, _ := readRecord(c)
				if len(first) > 0 {
					time.Sleep(400 * time.Millisecond) // EXPERIMENT: a late accept
					d.conns.Add(1)
					d.got <- first
				}
			}()
		}
	}()
	return d
}

func (d *countingDonor) dial(string) (net.Conn, error) {
	return net.DialTimeout("tcp", d.addr, time.Second)
}

// readRecord reads one TLS record, header included.
func readRecord(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	rec := make([]byte, 5+int(binary.BigEndian.Uint16(hdr[3:])))
	copy(rec, hdr)
	_, err := io.ReadFull(r, rec[5:])
	return rec, err
}

// tagClient is a manager over one endpoint at addr with the pool and secret.
func tagClient(t *testing.T, addr, secret string, pool []string) (*strategy.Manager, endpoint.Candidate) {
	t.Helper()
	m := strategy.NewManager()
	fam := endpoint.V4Only
	if err := m.SetEndpointsTuned([]endpoint.Endpoint{
		{Name: "b1", V4: addr, Secret: secret, SNI: pool},
	}, endpoint.Tuning{Family: &fam}); err != nil {
		t.Fatal(err)
	}
	cand, ok := m.CurrentCandidate()
	if !ok {
		t.Fatal("no candidate pinned")
	}
	return m, cand
}

// dialFallback runs one Connect of the strategy against the server.
func dialFallback(t *testing.T, m *strategy.Manager, cand endpoint.Candidate, s strategy.Strategy) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := m.ConnectStrategy(ctx, s, cand)
	if err == nil {
		conn.Close()
	}
	return err
}

// TestTaggedFallbacksReachTheirHandlersOnAB1Server is P1-1 itself: each TLS
// fallback, its SNI drawn from a pool of donor names, completes its own
// handshake through the dispatcher, and the donor sees none of them. With
// the cover domain set too - it used to take every TLS hello B1 turned down.
func TestTaggedFallbacksReachTheirHandlersOnAB1Server(t *testing.T) {
	for _, cover := range []string{"", "www.microsoft.com"} {
		for _, tc := range tagFallbackStrategies {
			t.Run(tc.name+" cover="+cover, func(t *testing.T) {
				srv := newTagServer(t, cover)
				m, cand := tagClient(t, srv.addr, tagTestSecret, donorPool)
				if err := dialFallback(t, m, cand, tc.make(m, []byte("not-the-endpoint-secret"))); err != nil {
					t.Fatalf("Connect: %v (donor took %d connections)", err, srv.donor.conns.Load())
				}
				if n := srv.donor.conns.Load(); n != 0 {
					t.Fatalf("the donor took %d connections of a tagged client", n)
				}
			})
		}
	}
}

// TestUntaggedAndForeignFallbacksStillGoToTheDonor is the other half, and the
// control that the test above can see a donor at all: the same transport's
// real ClientHello with its tag replaced by random bytes (a client older than
// the tag), and one tagged with a key the server does not hold, both go to the
// donor byte for byte.
func TestUntaggedAndForeignFallbacksStillGoToTheDonor(t *testing.T) {
	for _, cover := range []string{"", "www.microsoft.com"} {
		for _, tc := range tagFallbackStrategies {
			t.Run(tc.name+" cover="+cover, func(t *testing.T) {
				srv := newTagServer(t, cover)

				untagged := captureFallbackHello(t, tc.make, tagTestSecret)
				setSessionID(t, untagged, randomSessionID(t))
				expectDonor(t, srv, untagged)

				foreign := captureFallbackHello(t, tc.make, "a-secret-this-server-does-not-know")
				expectDonor(t, srv, foreign)
			})
		}
	}
}

// TestReplayedFallbackHelloGoesToTheDonor: a captured tagged hello is let
// through once; the same bytes again are a prober's and go to the donor. So
// does a tag made outside the clock-skew window.
func TestReplayedFallbackHelloGoesToTheDonor(t *testing.T) {
	for _, tc := range tagFallbackStrategies {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTagServer(t, "")
			hello := captureFallbackHello(t, tc.make, tagTestSecret)

			expectTLSPath(t, srv, hello)
			expectDonor(t, srv, hello)

			stale, err := customtls.FallbackTag(customtls.DeriveFallbackTagKey([]byte(tagTestSecret)),
				time.Now().Add(-time.Duration(srv.srvCtx.cfg.REALITYMaxTimeDiff+60)*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			setSessionID(t, hello, stale)
			expectDonor(t, srv, hello)
		})
	}
}

// TestFallbackTagMatchesRegistryClients: the tag is checked against every
// client's own secret, not just the global one - and an index built without
// keys (the zero key is public) accepts nothing.
func TestFallbackTagMatchesRegistryClients(t *testing.T) {
	srv := newTagServer(t, "")
	gate := srv.srvCtx.b1Gate
	gate.index.Rebuild([]*ClientConfig{
		{ID: "alice", Secret: "alice-own-secret", Enabled: true},
		{ID: "bob", Secret: "bob-own-secret", Enabled: true},
	}, nil)

	hello := captureFallbackHello(t, tagFallbackStrategies[0].make, "bob-own-secret")
	entry, ok := gate.fallbackTag(srv.srvCtx, hello[5:], time.Now())
	if !ok || entry.clientID != registryIdentity("bob") {
		t.Fatalf("bob's tag: ok=%v client=%v, want bob", ok, entry.clientID)
	}
	expectDonor(t, srv, captureFallbackHello(t, tagFallbackStrategies[0].make, tagTestSecret))

	// An entry built without a tag key matches nothing - not its client's
	// tag, and not one made under the zero key, which anyone can compute.
	fresh := captureFallbackHello(t, tagFallbackStrategies[0].make, "bob-own-secret")
	gate.index.mu.Lock()
	for id, e := range gate.index.entries {
		e.tag = nil
		gate.index.entries[id] = e
	}
	gate.index.mu.Unlock()
	if _, ok := gate.fallbackTag(srv.srvCtx, fresh[5:], time.Now()); ok {
		t.Fatal("an entry without a tag key accepted its client's tag")
	}
	zero, err := customtls.FallbackTag(customtls.FallbackTagKey{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	setSessionID(t, hello, zero)
	if _, ok := gate.fallbackTag(srv.srvCtx, hello[5:], time.Now()); ok {
		t.Fatal("a tag under the zero key was accepted")
	}
}

// captureFallbackHello records the first TLS record the strategy sends when
// it dials an endpoint with secret and the donor pool.
func captureFallbackHello(t *testing.T, build func(*strategy.Manager, []byte) strategy.Strategy, secret string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		rec, _ := readRecord(c)
		got <- rec
	}()
	m, cand := tagClient(t, ln.Addr().String(), secret, donorPool)
	go func() { _ = dialFallback(t, m, cand, build(m, nil)) }()
	select {
	case rec := <-got:
		if len(rec) < 6 || rec[0] != 0x16 {
			t.Fatalf("captured %d bytes, not a ClientHello", len(rec))
		}
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("the strategy sent no ClientHello")
		return nil
	}
}

func randomSessionID(t *testing.T) [customtls.AuthSessionIDLen]byte {
	t.Helper()
	var b [customtls.AuthSessionIDLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func setSessionID(t *testing.T, record []byte, sid [customtls.AuthSessionIDLen]byte) {
	t.Helper()
	off, err := customtls.SessionIDOffset(record[5:])
	if err != nil {
		t.Fatal(err)
	}
	copy(record[5+off:], sid[:])
}

// expectDonor sends record to the server and requires the donor to receive it
// byte for byte.
func expectDonor(t *testing.T, srv *tagServer, record []byte) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(record); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-srv.donor.got:
		if string(got) != string(record) {
			t.Fatal("the donor received something other than the ClientHello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hello did not reach the donor")
	}
}

// expectTLSPath sends record to the server and requires a ServerHello from
// our own TLS stack, with the donor untouched.
func expectTLSPath(t *testing.T, srv *tagServer, record []byte) {
	t.Helper()
	before := srv.donor.conns.Load()
	conn, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(record); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	rec, err := readRecord(conn)
	if err != nil || rec[0] != 0x16 || rec[5] != 0x02 {
		t.Fatalf("no ServerHello from our TLS stack (err %v)", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := srv.donor.conns.Load() - before; n != 0 {
		t.Fatalf("the donor took %d connections", n)
	}
}

// TestRelayUpstreamReachesAB1ExitWithACoverDomain: a relay's upstream leg is
// a TLS fallback too. Its fixed SNI is no donor, but an exit with a cover
// domain used to hand it to the cover all the same.
func TestRelayUpstreamReachesAB1ExitWithACoverDomain(t *testing.T) {
	srv := newTagServer(t, "www.microsoft.com")
	d := NewUpstreamDialer(srv.addr, []byte(tagTestSecret))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, tlsConn, err := d.connectStego(ctx)
	if err != nil {
		t.Fatalf("upstream handshake: %v (donor took %d connections)", err, srv.donor.conns.Load())
	}
	conn.Close()
	tlsConn.Close()
	if n := srv.donor.conns.Load(); n != 0 {
		t.Fatalf("the cover domain took %d upstream connections", n)
	}
}

// TestANewRegistryClientsTagIsSeenSoon is P3-2 of the round-5 review: a tag
// miss looks like any stranger's hello and triggered no index refresh, so a
// client just added to the registry had its TLS fallbacks sent to the donor
// until the periodic rebuild, up to 30 s later. The registry's generation now
// says the index is behind.
func TestANewRegistryClientsTagIsSeenSoon(t *testing.T) {
	srv := newTagServer(t, "")
	reg := NewClientRegistry(nil)
	srv.srvCtx.registry = reg
	gate := srv.srvCtx.b1Gate
	gate.index.rebuildFrom(srv.srvCtx)

	carol := &ClientConfig{ID: "carol", Secret: "carol-own-secret", Enabled: true}
	reg.mu.Lock()
	reg.byID[carol.ID], reg.bySecret[carol.Secret] = carol, carol
	reg.mu.Unlock()
	reg.generation.Add(1)

	hello := captureFallbackHello(t, tagFallbackStrategies[0].make, carol.Secret)
	sid, err := customtls.SessionIDFrom(hello[5:])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := gate.index.MatchFallbackTag(sid); ok {
		t.Fatal("the index knew the new client before any refresh - the test proves nothing")
	}
	// The first hello starts the refresh. The refresh runs in the
	// background, ahead of the tag check of that same hello, so the hello
	// itself may go either way: to the donor, or - when the rebuild wins the
	// race, as it can on a loaded machine - to our own TLS. The test used to
	// require the donor and failed under load.
	conn, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		// Caught up means both: the client is in, and the index knows it is
		// current - or every later hello would rebuild it again.
		if e, _, ok := gate.index.MatchFallbackTag(sid); ok && e.clientID == registryIdentity("carol") &&
			!gate.index.behind(srv.srvCtx) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("two seconds on, the index has not caught up with the registry (behind=%v)", gate.index.behind(srv.srvCtx))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// And carol's next fallback is hers. The first hello may have gone to
	// the donor, and its accept there lands whenever the machine gets round
	// to it: counted after expectTLSPath read its baseline, it looked like
	// the second hello's (P3-9 of the round-9 review). A stability window
	// only made that less likely (P3-9 of the round-10 review): the first
	// hello is finished with explicitly. Our TLS answers it with a
	// ServerHello; the donor reads it, counts it, sends it on got and hangs
	// up, so the conn ends - and then the count already holds it.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if rec, err := readRecord(conn); err != nil || len(rec) < 6 || rec[0] != 0x16 || rec[5] != 0x02 {
		select {
		case <-srv.donor.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("the first hello reached neither our TLS nor the donor (%v)", err)
		}
	}
	conn.Close()
	expectTLSPath(t, srv, captureFallbackHello(t, tagFallbackStrategies[0].make, carol.Secret))
}

// TestALegacyHelloIsNotCheckedForATag is P3-1 of the round-5 review: the tag
// was looked for before the legacy check, so every legacy-REALITY hello paid
// one HMAC per registry client for nothing - crypto/tls sends no padding
// extension, so a legacy hello is never a tagged one. Here a legacy hello
// carries a valid tag all the same: it must go to the legacy transport
// without the tag being checked.
func TestALegacyHelloIsNotCheckedForATag(t *testing.T) {
	srv := newTagServer(t, "")
	srv.srvCtx.cfg.REALITYLegacyEnabled = true
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := buildHelloWithKeyShare(t, eph.PublicKey().Bytes())
	bare := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	ext, err := customtls.NewClientREALITYExtension([]byte(tagTestSecret), [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	record, err := customtls.AddPaddingWithREALITY(bare, ext, customtls.MinPaddingSize)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := customtls.FallbackTag(customtls.DeriveFallbackTagKey([]byte(tagTestSecret)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	setSessionID(t, record, tag)
	if !DetectREALITYExtension(record) {
		t.Fatal("fixture is not a legacy hello")
	}

	before := realityFallbackTagTotal.Load()
	if tryREALITYB1(&nopConn{}, record, srv.srvCtx, log.WithPrefix("test")) {
		t.Fatal("the gate claimed a legacy hello")
	}
	if realityFallbackTagTotal.Load() != before {
		t.Fatal("the tag was checked - and accepted - on a legacy hello")
	}
}

// TestWithTheTagOffTaggedFallbacksAreMirrored is P1-1 of the round-5 review,
// as Denis decided: -reality-fallback-tag is off by default, and then a B1
// exit admits no tagged hello and mirrors it like 1.11.8 did - and pays no
// HMAC for it. Clients keep sending the tag; nothing on the wire changes.
func TestWithTheTagOffTaggedFallbacksAreMirrored(t *testing.T) {
	for _, tc := range tagFallbackStrategies {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTagServer(t, "")
			srv.srvCtx.cfg.REALITYFallbackTag = false
			hello := captureFallbackHello(t, tc.make, tagTestSecret)
			before := srv.srvCtx.b1Gate.index.tagLookups.Load()
			expectDonor(t, srv, hello)
			if n := srv.srvCtx.b1Gate.index.tagLookups.Load() - before; n != 0 {
				t.Fatalf("the tag was looked up %d times with the flag off", n)
			}
		})
	}
}

// TestACopiedTagOpensAnotherExit documents the known exposure that keeps
// -reality-fallback-tag off by default (P1-1 of the round-5 review): the tag
// binds neither the hello nor the exit. A prober copies the 32-byte
// session_id of a client's tagged hello into its own crypto/tls ClientHello -
// its own random and key share - and sends it to another exit with the same
// secret, which has not seen the tag. With the flag on, that exit's own TLS
// stack answers, not the donor; with it off, the donor does. Binding the tag
// to hello.random and the key share is planned for 1.11.10. If the first
// half of this test starts failing, the exposure is closed: update
// docs/server.md and this test.
func TestACopiedTagOpensAnotherExit(t *testing.T) {
	exitA := newTagServer(t, "")
	exitB := newTagServer(t, "")
	tagged := captureFallbackHello(t, tagFallbackStrategies[0].make, tagTestSecret)
	expectTLSPath(t, exitA, tagged)
	sid, err := customtls.SessionIDFrom(tagged[5:])
	if err != nil {
		t.Fatal(err)
	}

	probe := proberHello(t, "www.google.com")
	setSessionID(t, probe, sid)
	expectTLSPath(t, exitB, probe) // the known exposure

	exitC := newTagServer(t, "")
	exitC.srvCtx.cfg.REALITYFallbackTag = false
	probe2 := proberHello(t, "www.google.com")
	setSessionID(t, probe2, sid)
	expectDonor(t, exitC, probe2)
}

// proberHello is a plain crypto/tls ClientHello record for sni, as any
// prober would send it.
func proberHello(t *testing.T, sni string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake() //nolint:gosec // a probe
	}()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	rec, err := readRecord(server)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestStartupWarnsAboutSecrets: P2-1 of the round-5 review - a weak global
// secret, and a global secret at all once the tag is admitted, are said at
// startup; a flag that does nothing without B1 is too.
func TestStartupWarnsAboutSecrets(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want []string
		not  []string
	}{
		{"weak global secret", Config{Secret: []byte("pass-424242")}, []string{"global -secret is weak"}, []string{"Prefer per-client"}},
		{"tag on, global secret", Config{Secret: []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
			REALITYB1Enabled: true, REALITYFallbackTag: true}, []string{"Prefer per-client registry secrets"}, []string{"is weak"}},
		{"tag without b1", Config{REALITYFallbackTag: true}, []string{"no effect without -reality-b1"}, nil},
		{"strong secret, tag off", Config{Secret: []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
			REALITYB1Enabled: true}, nil, []string{"weak", "Prefer", "no effect"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			log.SetOutput(&out)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			warnREALITYSecrets(&tc.cfg)
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("no %q in %q", w, out.String())
				}
			}
			for _, w := range tc.not {
				if strings.Contains(out.String(), w) {
					t.Errorf("unexpected %q in %q", w, out.String())
				}
			}
		})
	}
}

// TestWeakRegistrySecretsAreSaidWithTheTag: with the fallback tag admitted,
// each tag of a registry client lets anyone test guesses at its secret
// offline, so a weak one is named - once per client, not on every rebuild.
// Driven through the dispatcher: the registry changes, a stranger's hello
// comes in, and the gate's own refresh rebuilds the index.
func TestWeakRegistrySecretsAreSaidWithTheTag(t *testing.T) {
	log.SetDedupWindow(0) // count each line, repeats included
	t.Cleanup(func() { log.SetDedupWindow(5 * time.Second) })
	stranger := captureFallbackHello(t, tagFallbackStrategies[0].make, "a-stranger-who-holds-no-secret-of-ours")
	for _, on := range []bool{true, false} {
		out := &lockedLog{}
		log.SetOutput(out)
		srv := newTagServer(t, "")
		srv.srvCtx.cfg.REALITYFallbackTag = on
		reg := NewClientRegistry(nil)
		srv.srvCtx.registry = reg
		gate := srv.srvCtx.b1Gate
		gate.index.rebuildFrom(srv.srvCtx) // as at startup: an empty registry

		add := func(c *ClientConfig) {
			reg.mu.Lock()
			reg.byID[c.ID], reg.bySecret[c.Secret] = c, c
			reg.mu.Unlock()
			reg.generation.Add(1)
			// The refresh after a miss runs at most once a second.
			time.Sleep(shortIDMissRefreshInterval + 100*time.Millisecond)
			expectDonor(t, srv, stranger)
			deadline := time.Now().Add(2 * time.Second)
			for gate.index.behind(srv.srvCtx) {
				if time.Now().After(deadline) {
					t.Fatal("the gate did not rebuild its index after the registry changed")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		add(&ClientConfig{ID: "weak", Secret: "changeme-changeme-changeme", Enabled: true})
		add(&ClientConfig{ID: "strong", Secret: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Enabled: true})
		log.SetOutput(os.Stderr)

		got := strings.Count(out.String(), "Registry client weak has a weak secret")
		if want := map[bool]int{true: 1, false: 0}[on]; got != want {
			t.Fatalf("flag %v: the weak client was named %d times over two rebuilds, want %d:\n%s", on, got, want, out.String())
		}
		if strings.Contains(out.String(), "Registry client strong") {
			t.Fatal("the strong client was called weak")
		}
	}
}

// TestRunWarnsAboutAWeakSecret: the startup warning is said by Run itself,
// before anything that can fail. Here the REALITY key is missing, so Run
// stops right after the warnings.
func TestRunWarnsAboutAWeakSecret(t *testing.T) {
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	err := Run(&Config{Secret: []byte("pass-424242"), REALITYB1Enabled: true})
	if !errors.Is(err, errNoREALITYKey) {
		t.Fatalf("Run: %v, want the missing-key error - the test proves nothing", err)
	}
	if !strings.Contains(out.String(), "global -secret is weak") {
		t.Fatalf("Run said nothing about the weak secret:\n%s", out.String())
	}
}

// TestHelloShapesThatReachTheExitsOwnTLS documents P3-8 of the round-6
// review: the flag off means no tag admission, not that every hello is
// mirrored. These shapes predate the tag and reach the exit's own TLS stack
// whatever the flag says - each is a probe oracle of its own, listed in
// docs/server.md:
//   - a valid hello with no X25519 key share (P-256 only): the B1 gate cannot
//     parse it as B1 and hands it on;
//   - any hello when no donor can be dialled.
func TestHelloShapesThatReachTheExitsOwnTLS(t *testing.T) {
	srv := newTagServer(t, "")
	srv.srvCtx.cfg.REALITYFallbackTag = false

	client, server := net.Pipe()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "www.google.com", InsecureSkipVerify: true, //nolint:gosec // a probe
			CurvePreferences: []tls.CurveID{tls.CurveP256}}).Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	p256, err := readRecord(server)
	client.Close()
	server.Close()
	if err != nil {
		t.Fatal(err)
	}
	expectTLSPath(t, srv, p256)

	srv.srvCtx.donorDialer = func(string) (net.Conn, error) { return nil, errors.New("donor unreachable") }
	expectTLSPath(t, srv, proberHello(t, "www.google.com"))
}
