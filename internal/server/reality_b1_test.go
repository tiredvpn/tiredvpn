package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// b1Fixture is a server with a known static key and one registered client.
type b1Fixture struct {
	gate      *realityB1Gate
	srvCtx    *serverContext
	serverPub [32]byte
	secret    []byte
	clientID  string
}

// newB1Fixture loads a static server key and builds a gate holding one client.
// It does not use t.Parallel-safe state: the server key lives in package
// globals, as it does in production, so these tests run sequentially.
func newB1Fixture(t *testing.T, extraClients int) b1Fixture {
	t.Helper()

	privB64, _, err := GenerateREALITYKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		REALITYB1Enabled:   true,
		REALITYPrivateKey:  privB64,
		REALITYMaxTimeDiff: 300,
	}
	if err := InitREALITYKeys(cfg); err != nil {
		t.Fatal(err)
	}
	_, serverPub := realityStaticKeys()

	secret := []byte("client-under-test-secret")
	clients := []*ClientConfig{{ID: "alice", Secret: string(secret), Enabled: true}}
	for i := range extraClients {
		clients = append(clients, &ClientConfig{
			ID:      fmt.Sprintf("filler-%d", i),
			Secret:  fmt.Sprintf("filler-secret-%d", i),
			Enabled: true,
		})
	}

	gate := newREALITYB1Gate(cfg.REALITYMaxTimeDiff)
	gate.index.Rebuild(clients, nil)

	return b1Fixture{
		gate:      gate,
		srvCtx:    &serverContext{cfg: cfg},
		serverPub: serverPub,
		secret:    secret,
		clientID:  "alice",
	}
}

// buildB1Hello assembles a ClientHello handshake message authenticated to the
// fixture's server key, and returns it with the ephemeral key that signed it.
func (f b1Fixture) buildB1Hello(t *testing.T, payload customtls.AuthPayload) []byte {
	t.Helper()

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := buildHelloWithKeyShare(t, eph.PublicKey().Bytes())

	random := hello[6:38]
	sealed, err := customtls.SealSessionID(eph, f.serverPub[:], hello, random, payload)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := customtls.SessionIDOffset(hello)
	if err != nil {
		t.Fatal(err)
	}
	copy(hello[offset:offset+customtls.AuthSessionIDLen], sealed[:])
	return hello
}

// buildHelloWithKeyShare builds a ClientHello handshake message (no record
// header) carrying one X25519 key share and a zeroed 32-byte session id, which
// is the state a client seals against.
func buildHelloWithKeyShare(t *testing.T, pub []byte) []byte {
	t.Helper()

	const (
		extKeyShare  = 0x0033
		groupX25519  = 0x001d
		extServerNam = 0x0000
	)

	share := binary.BigEndian.AppendUint16(nil, groupX25519)
	share = binary.BigEndian.AppendUint16(share, uint16(len(pub)))
	share = append(share, pub...)

	ksBody := binary.BigEndian.AppendUint16(nil, uint16(len(share)))
	ksBody = append(ksBody, share...)

	exts := binary.BigEndian.AppendUint16(nil, extKeyShare)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(ksBody)))
	exts = append(exts, ksBody...)

	// An SNI extension too, so the donor-destination policy has something to
	// read on the fallback paths.
	host := []byte("yandex.ru")
	sni := []byte{0x00}
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)))
	sni = append(sni, host...)
	sniBody := binary.BigEndian.AppendUint16(nil, uint16(len(sni)))
	sniBody = append(sniBody, sni...)
	exts = binary.BigEndian.AppendUint16(exts, extServerNam)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(sniBody)))
	exts = append(exts, sniBody...)

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}

	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...) // zeroed session id
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	out := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func (f b1Fixture) payload(t *testing.T, at time.Time) customtls.AuthPayload {
	t.Helper()
	return customtls.AuthPayload{
		Version: [3]byte{1, 4, 0},
		Time:    uint32(at.Unix()),
		ShortID: customtls.ShortIDFor(f.secret),
	}
}

func TestB1GateAcceptsValidHello(t *testing.T) {
	f := newB1Fixture(t, 0)
	now := time.Now()
	hello := f.buildB1Hello(t, f.payload(t, now))

	verdict, err := f.gate.evaluate(f.srvCtx, hello, now)
	if err != nil {
		t.Fatalf("valid hello was rejected as unparseable: %v", err)
	}
	if !verdict.ok {
		t.Fatalf("valid hello did not authenticate: %s", verdict.reason)
	}
	if verdict.entry.clientID != f.clientID {
		t.Fatalf("clientID = %q, want %q", verdict.entry.clientID, f.clientID)
	}
	if string(verdict.entry.secret) != string(f.secret) {
		t.Fatal("gate returned the wrong secret")
	}
}

// TestB1GateFallbackReasons walks every way a ClientHello can fail to
// authenticate. All of them must produce a verdict rather than an error: an
// error hands the connection back to the dispatcher, which for a well-formed
// ClientHello would eventually serve the fake website and tell a prober it
// found something other than the site we claim to be.
func TestB1GateFallbackReasons(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		wantReason b1Reason
		hello      func(t *testing.T, f b1Fixture) []byte
		pre        func(t *testing.T, f b1Fixture, hello []byte)
	}{
		{
			name:       "corrupted by one byte",
			wantReason: reasonNotSealed,
			hello: func(t *testing.T, f b1Fixture) []byte {
				h := f.buildB1Hello(t, f.payload(t, now))
				h[len(h)-1] ^= 0x01 // outside session_id, so the AAD no longer matches
				return h
			},
		},
		{
			name:       "clock skew",
			wantReason: reasonClockSkew,
			hello: func(t *testing.T, f b1Fixture) []byte {
				return f.buildB1Hello(t, f.payload(t, now.Add(-1000*time.Second)))
			},
		},
		{
			name:       "unknown short id",
			wantReason: reasonUnknownID,
			hello: func(t *testing.T, f b1Fixture) []byte {
				p := f.payload(t, now)
				p.ShortID = customtls.ShortIDFor([]byte("a secret the server never heard of"))
				return f.buildB1Hello(t, p)
			},
		},
		{
			name:       "replay",
			wantReason: reasonReplay,
			hello: func(t *testing.T, f b1Fixture) []byte {
				return f.buildB1Hello(t, f.payload(t, now))
			},
			pre: func(t *testing.T, f b1Fixture, hello []byte) {
				// First delivery is accepted; the test then sends it again.
				v, err := f.gate.evaluate(f.srvCtx, hello, now)
				if err != nil || !v.ok {
					t.Fatalf("priming delivery failed: %v %s", err, v.reason)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newB1Fixture(t, 0)
			hello := tt.hello(t, f)
			if tt.pre != nil {
				tt.pre(t, f, hello)
			}

			verdict, err := f.gate.evaluate(f.srvCtx, hello, now)
			if err != nil {
				t.Fatalf("well-formed hello returned a parse error: %v", err)
			}
			if verdict.ok {
				t.Fatal("hello authenticated when it should not have")
			}
			if verdict.reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", verdict.reason, tt.wantReason)
			}
		})
	}
}

// TestB1GateRejectsOldClient covers the version policy separately, since it
// needs a server configured with a minimum.
func TestB1GateRejectsOldClient(t *testing.T) {
	f := newB1Fixture(t, 0)
	f.srvCtx.cfg.REALITYMinClientVer = "1.5.0"
	now := time.Now()

	p := f.payload(t, now)
	p.Version = [3]byte{1, 4, 0}
	verdict, err := f.gate.evaluate(f.srvCtx, f.buildB1Hello(t, p), now)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.ok || verdict.reason != reasonOldClient {
		t.Fatalf("old client: ok=%v reason=%q", verdict.ok, verdict.reason)
	}

	p.Version = [3]byte{1, 5, 0}
	verdict, err = f.gate.evaluate(f.srvCtx, f.buildB1Hello(t, p), now)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.ok {
		t.Fatalf("client at exactly the minimum was rejected: %s", verdict.reason)
	}
}

// TestB1GatePassesBrowserHelloToDonor is the criterion that keeps us from
// breaking the internet: a real browser reaching our port must be handed to the
// donor, not dropped and not misparsed. Built from the shipped uTLS profiles,
// which is as close to a live dump as a unit test gets.
func TestB1GatePassesBrowserHelloToDonor(t *testing.T) {
	f := newB1Fixture(t, 0)

	for _, name := range customtls.FingerprintNames() {
		t.Run(name, func(t *testing.T) {
			fp, ok := customtls.LookupFingerprint(name)
			if !ok {
				t.Fatalf("profile %q does not resolve", name)
			}
			record, err := customtls.BuildClientHelloBytes(&customtls.Config{
				ServerName:         "yandex.ru",
				Fingerprint:        name,
				ALPN:               []string{"h2", "http/1.1"},
				InsecureSkipVerify: true,
			}, fp)
			if err != nil {
				t.Fatalf("building a %s hello: %v", name, err)
			}

			verdict, err := f.gate.evaluate(f.srvCtx, record[tlsRecordHeaderLen:], time.Now())
			if err != nil {
				// Some profiles legitimately carry no X25519 share; those are
				// structurally not ours and the dispatcher handles them. What
				// must never happen is authenticating one.
				t.Logf("%s: not parseable as a B1 hello (%v), dispatcher will handle it", name, err)
				return
			}
			if verdict.ok {
				t.Fatal("a plain browser ClientHello authenticated")
			}
			if verdict.reason != reasonNotSealed {
				t.Fatalf("reason = %q, want %q", verdict.reason, reasonNotSealed)
			}
		})
	}
}

// TestB1GateReturnsErrorOnlyForUnparseable pins the one distinction that
// decides whether other protocols keep working: the gate may hand a connection
// back only when it cannot read the ClientHello at all.
func TestB1GateReturnsErrorOnlyForUnparseable(t *testing.T) {
	f := newB1Fixture(t, 0)

	for _, tt := range []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"truncated header", []byte{0x01, 0x00}},
		{"not a clienthello", []byte{0x02, 0x00, 0x00, 0x04, 0, 0, 0, 0}},
		{"no key share", buildHelloNoKeyShare(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := f.gate.evaluate(f.srvCtx, tt.input, time.Now()); err == nil {
				t.Fatal("claimed a connection it cannot parse")
			}
		})
	}
}

func buildHelloNoKeyShare(t *testing.T) []byte {
	t.Helper()
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, 0)
	out := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// TestB1GateRejectionsAreIndistinguishableInTime is the anti-oracle criterion.
//
// If one rejection reason were cheaper than another, a censor could ask the
// server questions - is this short ID known, is this version too old - and read
// the answer off a stopwatch. The gate defends against that by doing the
// expensive key agreement before consulting any policy, so this measures the
// decision itself rather than the donor dial that follows it, which is both
// stricter and less noisy than timing the network.
func TestB1GateRejectionsAreIndistinguishableInTime(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement, skipped under -short")
	}

	const iterations = 100
	now := time.Now()

	medians := map[b1Reason]time.Duration{}
	for _, tc := range []struct {
		reason b1Reason
		build  func(f b1Fixture) []byte
	}{
		{reasonNotSealed, func(f b1Fixture) []byte {
			h := f.buildB1Hello(t, f.payload(t, now))
			h[len(h)-1] ^= 0x01
			return h
		}},
		{reasonClockSkew, func(f b1Fixture) []byte {
			return f.buildB1Hello(t, f.payload(t, now.Add(-1000*time.Second)))
		}},
		{reasonUnknownID, func(f b1Fixture) []byte {
			p := f.payload(t, now)
			p.ShortID = customtls.ShortIDFor([]byte("unknown"))
			return f.buildB1Hello(t, p)
		}},
		{reasonReplay, func(f b1Fixture) []byte {
			h := f.buildB1Hello(t, f.payload(t, now))
			return h
		}},
	} {
		f := newB1Fixture(t, 100)

		// Warm up before measuring. The first group measured otherwise pays for
		// cold code paths and first-touch page faults, which shows up as a
		// difference between reasons that has nothing to do with the gate.
		for range 20 {
			hello := tc.build(f)
			if _, err := f.gate.evaluate(f.srvCtx, hello, now); err != nil {
				t.Fatal(err)
			}
		}

		samples := make([]time.Duration, 0, iterations)
		for range iterations {
			hello := tc.build(f)
			if tc.reason == reasonReplay {
				// Prime it so the measured call is the replay.
				if _, err := f.gate.evaluate(f.srvCtx, hello, now); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			v, err := f.gate.evaluate(f.srvCtx, hello, now)
			samples = append(samples, time.Since(start))
			if err != nil || v.ok || v.reason != tc.reason {
				t.Fatalf("setup wrong for %s: err=%v ok=%v reason=%q", tc.reason, err, v.ok, v.reason)
			}
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		medians[tc.reason] = samples[len(samples)/2]
	}

	var lo, hi time.Duration
	for reason, med := range medians {
		t.Logf("%-40s median %v", reason, med)
		if lo == 0 || med < lo {
			lo = med
		}
		if med > hi {
			hi = med
		}
	}
	if spread := hi - lo; spread > 5*time.Millisecond {
		t.Fatalf("rejection reasons differ by %v in median time, over the 5ms budget: "+
			"the gate leaks which check failed", spread)
	}
}

func TestDonorDestinationPolicy(t *testing.T) {
	t.Parallel()

	allowlisted := buildRecordWithSNI(t, "yandex.ru")
	foreign := buildRecordWithSNI(t, "attacker-controlled.example")

	tests := []struct {
		name  string
		hello []byte
		cover string
		want  string
	}{
		{"allowlisted sni is honoured", allowlisted, "www.microsoft.com", "yandex.ru"},
		{"foreign sni falls back to cover", foreign, "www.microsoft.com", "www.microsoft.com"},
		{"foreign sni without cover is refused", foreign, "", ""},
		{"unparseable hello without cover is refused", []byte{0x16, 0x03, 0x01, 0, 0}, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := donorDestination(tt.hello, tt.cover); got != tt.want {
				t.Fatalf("destination = %q, want %q", got, tt.want)
			}
		})
	}
}

// buildRecordWithSNI wraps a ClientHello carrying the given SNI in a TLS record.
func buildRecordWithSNI(t *testing.T, host string) []byte {
	t.Helper()

	name := []byte{0x00}
	name = binary.BigEndian.AppendUint16(name, uint16(len(host)))
	name = append(name, []byte(host)...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(name)))
	list = append(list, name...)
	exts := binary.BigEndian.AppendUint16(nil, 0x0000)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(list)))
	exts = append(exts, list...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// TestProxyBothWaysHalfCloses checks that a FIN from one side is passed on
// instead of tearing the pair down. A donor that gets a reset where a browser
// would have sent FIN answers differently, and that difference is observable.
func TestProxyBothWaysHalfCloses(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()
	donorSide, donorPeer := net.Pipe()

	done := make(chan struct{})
	go func() {
		proxyBothWays(serverSide, donorSide)
		close(done)
	}()

	go func() {
		_, _ = clientSide.Write([]byte("hello donor"))
		_ = clientSide.Close()
	}()

	buf := make([]byte, len("hello donor"))
	if err := donorPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := donorPeer.Read(buf); err != nil {
		t.Fatalf("donor did not receive the client bytes: %v", err)
	}
	if string(buf) != "hello donor" {
		t.Fatalf("donor got %q", buf)
	}

	_ = donorPeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after both sides closed")
	}
}

// TestB1AuthCountersMoveIndependently checks the two counters the epic uses to
// decide when the legacy transport can be switched off.
func TestB1AuthCountersMoveIndependently(t *testing.T) {
	b1Before := realityAuthB1Total.Load()
	legacyBefore := realityAuthLegacyTotal.Load()

	realityAuthB1Total.Add(1)
	if realityAuthLegacyTotal.Load() != legacyBefore {
		t.Fatal("the legacy counter moved when only B1 was incremented")
	}
	realityAuthLegacyTotal.Add(1)
	if got := realityAuthB1Total.Load(); got != b1Before+1 {
		t.Fatalf("b1 counter = %d, want %d", got, b1Before+1)
	}

	var sb testWriter
	writeREALITYAuthMetrics(&sb)
	for _, want := range []string{"reality_auth_b1_total", "reality_auth_legacy_total", "# TYPE"} {
		if !sb.contains(want) {
			t.Fatalf("metrics output is missing %q:\n%s", want, sb.String())
		}
	}
}

type testWriter struct{ b []byte }

func (w *testWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *testWriter) String() string              { return string(w.b) }
func (w *testWriter) contains(s string) bool {
	return len(w.b) > 0 && len(s) > 0 && stringContains(string(w.b), s)
}

func stringContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestShortIDIndexRebuildSkipsUnusableClients(t *testing.T) {
	t.Parallel()

	idx := newShortIDIndex()
	global := []byte("global-secret")
	idx.Rebuild([]*ClientConfig{
		{ID: "ok", Secret: "good-secret", Enabled: true},
		{ID: "disabled", Secret: "disabled-secret", Enabled: false},
		{ID: "expired", Secret: "expired-secret", Enabled: true, ExpiresAt: time.Now().Add(-time.Hour)},
		{ID: "nosecret", Secret: "", Enabled: true},
		nil,
	}, global)

	if e, ok := idx.Lookup(customtls.ShortIDFor([]byte("good-secret"))); !ok || e.clientID != "ok" {
		t.Fatal("an enabled client is missing from the index")
	}
	if _, ok := idx.Lookup(customtls.ShortIDFor([]byte("disabled-secret"))); ok {
		t.Fatal("a disabled client can still authenticate")
	}
	if _, ok := idx.Lookup(customtls.ShortIDFor([]byte("expired-secret"))); ok {
		t.Fatal("an expired client can still authenticate")
	}
	if e, ok := idx.Lookup(customtls.ShortIDFor(global)); !ok || e.clientID != "global" {
		t.Fatal("the global secret is missing from the index")
	}
}

func TestReplayCache(t *testing.T) {
	t.Parallel()

	var id [customtls.AuthSessionIDLen]byte
	id[0] = 0xAA
	now := time.Now()

	c := newReplayCache(600 * time.Second)
	if !c.checkAndRecord(id, now) {
		t.Fatal("first sighting was treated as a replay")
	}
	if c.checkAndRecord(id, now) {
		t.Fatal("second sighting was accepted")
	}
	// Past the TTL the id is forgettable: the timestamp inside it can no longer
	// pass the skew check, so remembering it buys nothing.
	if !c.checkAndRecord(id, now.Add(601*time.Second)) {
		t.Fatal("id was still blocked after its window elapsed")
	}
}

func TestReplayTTLFollowsClockTolerance(t *testing.T) {
	t.Parallel()

	if got := replayTTLFor(300); got != 600*time.Second {
		t.Fatalf("ttl = %v, want twice the skew", got)
	}
	if got := replayTTLFor(0); got != defaultReplayTTL {
		t.Fatalf("ttl with skew checking off = %v, want %v", got, defaultReplayTTL)
	}
}

func TestParseClientVersion(t *testing.T) {
	t.Parallel()

	if got, err := parseClientVersion("1.4.12"); err != nil || got != [3]byte{1, 4, 12} {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", "1.4", "1.4.0.1", "a.b.c", "1.4.256", "1.-4.0"} {
		if _, err := parseClientVersion(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version [3]byte
		min     string
		want    bool
	}{
		{[3]byte{1, 4, 0}, "", true},
		{[3]byte{1, 4, 0}, "1.4.0", true},
		{[3]byte{1, 4, 1}, "1.4.0", true},
		{[3]byte{1, 5, 0}, "1.4.9", true},
		{[3]byte{2, 0, 0}, "1.9.9", true},
		{[3]byte{1, 3, 9}, "1.4.0", false},
		{[3]byte{0, 9, 9}, "1.0.0", false},
		// An unparseable minimum cannot lock everyone out; it is rejected at
		// startup instead.
		{[3]byte{1, 4, 0}, "not-a-version", true},
	}
	for _, tt := range tests {
		if got := versionAtLeast(tt.version, tt.min); got != tt.want {
			t.Fatalf("versionAtLeast(%v, %q) = %v", tt.version, tt.min, got)
		}
	}
}

func TestWithinSkew(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ts := uint32(now.Unix())

	if !withinSkew(ts-1000, now, 0) {
		t.Fatal("skew checking disabled should accept anything")
	}
	if !withinSkew(ts-299, now, 300) || !withinSkew(ts+299, now, 300) {
		t.Fatal("a timestamp inside the window was rejected")
	}
	if withinSkew(ts-1000, now, 300) || withinSkew(ts+1000, now, 300) {
		t.Fatal("a timestamp outside the window was accepted")
	}
}

// TestB1GateDefersLegacyClients is the interaction the dispatcher ordering
// creates: with both transports on, a legacy ClientHello reaches the B1 gate
// first. It parses fine and fails to authenticate, because the legacy scheme
// never sealed anything to our static key - so without this the first operator
// to turn B1 on would send every existing client to a donor site.
func TestB1GateDefersLegacyClients(t *testing.T) {
	f := newB1Fixture(t, 0)
	f.srvCtx.cfg.REALITYLegacyEnabled = true

	// A legacy hello has everything a B1 one has - it is built from the same
	// uTLS profiles, so it carries a key share and a 32-byte session id - plus
	// the padding extension holding its credentials. That is precisely why it
	// reaches the B1 gate and parses there.
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := buildHelloWithKeyShare(t, eph.PublicKey().Bytes())
	bare := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

	ext, err := customtls.NewClientREALITYExtension(f.secret, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	record, err := customtls.AddPaddingWithREALITY(bare, ext, customtls.MinPaddingSize)
	if err != nil {
		t.Fatal(err)
	}
	if !DetectREALITYExtension(record) {
		t.Fatal("fixture is not recognised as a legacy hello")
	}

	logger := log.WithPrefix("test")
	claimed := tryREALITYB1(&nopConn{}, record, f.srvCtx, logger)
	if claimed {
		t.Fatal("the B1 gate swallowed a legacy client instead of passing it on")
	}

	// With the legacy transport switched off there is nothing to defer to, so
	// the same hello is treated like any other stranger.
	f.srvCtx.cfg.REALITYLegacyEnabled = false
	if !tryREALITYB1(&nopConn{}, record, f.srvCtx, logger) {
		t.Fatal("with legacy off the gate must claim the connection, not leak it to plain TLS")
	}
}

// nopConn is a net.Conn that reads EOF and discards writes, enough for the
// donor fallback to run to completion without a network.
type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
