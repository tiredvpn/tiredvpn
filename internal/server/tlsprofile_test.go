package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testCert is a throwaway leaf for standing up a TLS server in tests.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshakeAgainst runs a client against a server config and returns the
// client's view of the completed connection.
func handshakeAgainst(t *testing.T, serverCfg *tls.Config, clientCfg *tls.Config) tls.ConnectionState {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer raw.Close()
		sc := tls.Server(raw, serverCfg)
		errc <- sc.Handshake()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cc := tls.Client(raw, clientCfg)
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return cc.ConnectionState()
}

// TestTLSProfileDeclinesMLKEM is the whole of task 031. Our front was answering
// with a 1221-byte plaintext ServerHello where eleven of thirteen donors send
// 133, because the Go default puts X25519MLKEM768 first and nothing in the repo
// overrode it. Those 1088 bytes are the ML-KEM key, in the clear, under an SNI
// that claims to be someone else.
func TestTLSProfileDeclinesMLKEM(t *testing.T) {
	t.Parallel()

	cfg := buildTLSProfile(&Config{ListenAddr: ":443"}, testCert(t))

	// A client that would very much like the hybrid, as a current browser does.
	state := handshakeAgainst(t, cfg, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // throwaway leaf, this test is about group selection
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})

	if state.CurveID == tls.X25519MLKEM768 {
		t.Fatal("negotiated X25519MLKEM768: the ServerHello is then ~1088 bytes larger than every donor we imitate")
	}
	if state.CurveID != tls.X25519 {
		t.Fatalf("negotiated %v, want X25519", state.CurveID)
	}
}

// TestKeyExchangeFollowsTheDonor covers task 034: classic is the default, and
// the two donors that genuinely negotiate ML-KEM get ML-KEM.
//
// The boundary matters more than the values. Reproducing a measured difference
// is allowed; inventing one is not. We must never answer post-quantum to our
// own names and classic to donor names - no such split exists in the wild, and
// it would let anyone enumerate our domains by probing them.
func TestKeyExchangeFollowsTheDonor(t *testing.T) {
	t.Parallel()

	hybridDonors := []string{"raw.githubusercontent.com", "objects.githubusercontent.com"}
	for _, sni := range hybridDonors {
		if keyExchangeFor(sni) != kxHybrid {
			t.Errorf("%s negotiates ML-KEM but we would answer classic, which differs from the "+
				"donor on roughly one connection in seven", sni)
		}
		if !slices.Contains(curvePreferencesFor(sni), tls.X25519MLKEM768) {
			t.Errorf("%s: hybrid group missing from the offer", sni)
		}
	}

	// Everything else, measured or not, is classic.
	for sni, prof := range donorProfiles {
		if slices.Contains(hybridDonors, sni) {
			continue
		}
		if prof.KeyExchange != kxClassic {
			t.Errorf("%s is marked hybrid but was measured classic", sni)
		}
	}
	for _, sni := range []string{"", "api.googleapis.com", "www.google.com", "not-a-donor"} {
		if keyExchangeFor(sni) != kxClassic {
			t.Errorf("%s: a name with no measurement must default to classic", sni)
		}
		if slices.Contains(curvePreferencesFor(sni), tls.X25519MLKEM768) {
			t.Errorf("%s: hybrid offered to a name we never measured", sni)
		}
	}
}

// TestKeyExchangeIsTheSameInBothPaths is the invariant the team lead called
// out: one table, not two decisions. Two paths answering differently on one
// port is a signal of its own, and worse than the one we set out to remove.
func TestKeyExchangeIsTheSameInBothPaths(t *testing.T) {
	t.Parallel()

	shared := buildTLSProfile(&Config{ListenAddr: ":443"}, testCert(t))
	b1 := b1TLSConfig(newCertMinter(), "")

	for sni := range donorProfiles {
		chi := &tls.ClientHelloInfo{ServerName: sni}

		sharedCfg, err := shared.GetConfigForClient(chi)
		if err != nil {
			t.Fatal(err)
		}
		if sharedCfg == nil {
			sharedCfg = shared
		}
		b1Cfg, err := b1.GetConfigForClient(chi)
		if err != nil {
			t.Fatal(err)
		}
		if b1Cfg == nil {
			b1Cfg = b1
		}

		sharedHybrid := slices.Contains(sharedCfg.CurvePreferences, tls.X25519MLKEM768)
		b1Hybrid := slices.Contains(b1Cfg.CurvePreferences, tls.X25519MLKEM768)
		if sharedHybrid != b1Hybrid {
			t.Fatalf("%s: shared listener offers hybrid=%v but B1 offers hybrid=%v", sni, sharedHybrid, b1Hybrid)
		}
	}
}

// TestHybridDonorActuallyNegotiatesIt runs the handshake rather than trusting
// the configuration, since GetConfigForClient replaces the whole config and it
// is easy to hand back one that is missing something.
func TestHybridDonorActuallyNegotiatesIt(t *testing.T) {
	t.Parallel()

	cfg := buildTLSProfile(&Config{ListenAddr: ":443"}, testCert(t))
	client := func(sni string) *tls.Config {
		return &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, //nolint:gosec // throwaway leaf, this test is about group selection
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		}
	}

	if got := handshakeAgainst(t, cfg, client("raw.githubusercontent.com")).CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("under a hybrid donor we negotiated %v, want X25519MLKEM768", got)
	}
	if got := handshakeAgainst(t, cfg, client("yandex.ru")).CurveID; got != tls.X25519 {
		t.Fatalf("under a classic donor we negotiated %v, want X25519", got)
	}
}

// TestEveryProfileDeclinesMLKEM makes sure the per-node variation cannot
// reintroduce what 031 removed. The two features live in the same file, and a
// future variant that sets its own curve list would undo the fix on some
// fraction of the fleet - the worst kind of regression, because most nodes
// would still look right.
func TestEveryProfileDeclinesMLKEM(t *testing.T) {
	t.Parallel()

	cert := testCert(t)
	for _, p := range tlsProfiles {
		t.Run(p.name, func(t *testing.T) {
			cfg := &tls.Config{
				Certificates:     []tls.Certificate{cert},
				NextProtos:       []string{"h2", "http/1.1"},
				MinVersion:       p.minVersion,
				CipherSuites:     p.cipherSuites,
				CurvePreferences: classicCurves,
			}
			// No SNI, so no donor to imitate: the default applies and the
			// default is classic on every node variant.
			state := handshakeAgainst(t, cfg, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // throwaway leaf
				MinVersion:         tls.VersionTLS12,
				CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
			})
			if state.CurveID == tls.X25519MLKEM768 {
				t.Fatalf("profile %s negotiated the hybrid with no donor asking for it", p.name)
			}
		})
	}
}

// TestEveryProfileServesOurClients checks the variation does not cost us a
// working connection. Our strategies dial with MinVersion TLS 1.2 and no
// maximum, so every variant has to complete with such a client.
func TestEveryProfileServesOurClients(t *testing.T) {
	t.Parallel()

	cert := testCert(t)
	for _, p := range tlsProfiles {
		t.Run(p.name, func(t *testing.T) {
			cfg := &tls.Config{
				Certificates:     []tls.Certificate{cert},
				NextProtos:       []string{"h2", "http/1.1"},
				MinVersion:       p.minVersion,
				CipherSuites:     p.cipherSuites,
				CurvePreferences: classicCurves,
			}
			// The same shape our stego, websocket-padded and http-polling
			// clients use.
			state := handshakeAgainst(t, cfg, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // throwaway leaf
				MinVersion:         tls.VersionTLS12,
				NextProtos:         []string{"h2", "http/1.1"},
			})
			if state.Version != tls.VersionTLS13 {
				t.Fatalf("profile %s negotiated %x, want TLS 1.3 with a modern client", p.name, state.Version)
			}
			if state.NegotiatedProtocol != "h2" {
				t.Fatalf("profile %s: ALPN = %q", p.name, state.NegotiatedProtocol)
			}
		})
	}
}

// TestProfileSelectionIsStable is the property that keeps the variation from
// becoming a signal of its own: a host whose fingerprint changes every restart
// is more interesting than one that never changes.
func TestProfileSelectionIsStable(t *testing.T) {
	t.Parallel()

	first := selectTLSProfile("ams-exit|:995")
	for range 20 {
		if got := selectTLSProfile("ams-exit|:995"); got.name != first.name {
			t.Fatalf("the same seed produced %s then %s", first.name, got.name)
		}
	}
}

// TestProfileSelectionVaries checks the fingerprint actually stops being
// shared. Nine fronts on four servers currently give a bit-identical JARM, so
// one query links the fleet.
func TestProfileSelectionVaries(t *testing.T) {
	t.Parallel()

	// The real seeds differ by host and by listen address, which is the case we
	// have: several fronts on one machine.
	seeds := []string{
		"ams-exit|:995", "ams-exit|:994", "ams-exit|:996",
		"usa-exit|:443", "usa-exit-2|:995", "dubai|:443", "ruhop|:995",
	}
	seen := map[string]bool{}
	for _, s := range seeds {
		seen[selectTLSProfile(s).name] = true
	}
	if len(seen) < 3 {
		t.Fatalf("seven fronts landed on %d profiles: %v", len(seen), seen)
	}
}

// TestProfilesDoNotWeakenTheConfiguration is the floor. Varying a fingerprint
// is worth doing; buying variation by accepting weaker versions or ciphers is
// not, and the temptation to do exactly that is why this is asserted.
func TestProfilesDoNotWeakenTheConfiguration(t *testing.T) {
	t.Parallel()

	// Everything Go offers by default for TLS 1.2, as reported by the standard
	// library rather than copied into this test.
	allowed := map[uint16]bool{}
	for _, s := range tls.CipherSuites() {
		allowed[s.ID] = true
	}

	for _, p := range tlsProfiles {
		if p.minVersion < tls.VersionTLS12 {
			t.Errorf("profile %s allows %x, below TLS 1.2", p.name, p.minVersion)
		}
		for _, id := range p.cipherSuites {
			if !allowed[id] {
				t.Errorf("profile %s uses cipher %x, which is not in Go's default set "+
					"(insecure suites are reported separately by tls.InsecureCipherSuites)", p.name, id)
			}
		}
	}
}

func TestNodeSeedSeparatesFrontsOnOneHost(t *testing.T) {
	t.Parallel()

	a := nodeSeed(&Config{ListenAddr: ":995"})
	b := nodeSeed(&Config{ListenAddr: ":994"})
	if a == b {
		t.Fatal("two fronts on one host share a seed, so they would share a fingerprint")
	}
}

// TestClassicCurvesAreClassic states the invariant by name rather than by
// behaviour, so a future edit to the list is confronted with the reason.
func TestClassicCurvesAreClassic(t *testing.T) {
	t.Parallel()

	for _, c := range classicCurves {
		switch c {
		case tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521:
		default:
			t.Fatalf("curve %v is not classical; adding a hybrid here puts the ML-KEM key "+
				"back in the plaintext ServerHello", c)
		}
	}
	if !slices.Contains(classicCurves, tls.X25519) {
		t.Fatal("X25519 must stay: it is what every donor and every client actually uses")
	}
}

// TestGeneratedTableMatchesCSV keeps the generated file honest. It is the one
// thing a reader cannot check by eye, and the whole design rests on the table
// being a measurement rather than a set of numbers someone typed.
func TestGeneratedTableMatchesCSV(t *testing.T) {
	t.Parallel()

	rows, err := readDonorCSV("donor-profiles.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(donorProfiles) {
		t.Fatalf("csv has %d rows, generated table has %d entries: run go generate ./internal/server/",
			len(rows), len(donorProfiles))
	}
	for sni, want := range rows {
		got, ok := donorProfiles[sni]
		if !ok {
			t.Errorf("%s is in the csv but not in the generated table", sni)
			continue
		}
		if got != want {
			t.Errorf("%s: table has %+v, csv says %+v: regenerate", sni, got, want)
		}
	}
}

// readDonorCSV parses the measurement file the generator reads.
func readDonorCSV(path string) (map[string]donorProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	out := map[string]donorProfile{}
	for _, rec := range records[1:] {
		// Rows naming an address are measurements of our own fronts, kept as
		// evidence; the generator leaves them out of the donor table.
		if strings.Contains(rec[0], ":") {
			continue
		}
		limit, err := strconv.Atoi(rec[2])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rec[0], err)
		}
		timeoutMS, err := strconv.Atoi(rec[3])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rec[0], err)
		}
		var ccs ccsPolicy
		switch rec[1] {
		case "count":
			ccs = ccsPolicy{Mechanism: ccsCount, Limit: limit}
		case "timeout":
			ccs = ccsPolicy{Mechanism: ccsTimeout, Timeout: time.Duration(timeoutMS) * time.Millisecond}
		case "none":
			ccs = ccsPolicy{Mechanism: ccsNone}
		case "unmeasured":
			ccs = ccsPolicy{Mechanism: ccsUnmeasured}
		default:
			return nil, fmt.Errorf("%s: unknown mechanism %q", rec[0], rec[1])
		}

		var kx keyExchange
		switch rec[4] {
		case "classic":
			kx = kxClassic
		case "hybrid":
			kx = kxHybrid
		default:
			return nil, fmt.Errorf("%s: unknown key_exchange %q", rec[0], rec[4])
		}

		out[rec[0]] = donorProfile{CCS: ccs, KeyExchange: kx}
	}
	return out, nil
}
