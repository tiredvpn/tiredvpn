package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

const camouflageTestSecret = "camouflage-test-secret-32-bytes!"

// camouflageCtx returns a server context carrying only a global secret, which
// is the deployment shape the camouflage handlers see on a single-secret exit.
func camouflageCtx(t *testing.T) *serverContext {
	t.Helper()
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte(camouflageTestSecret)
	return srvCtx
}

// TestDetectIMAPCamouflage pins the peek-based classifier. The tunnel initiator
// sends the Dovecot greeting itself precisely so this stateless prefix match
// can class the connection; a miss sends a real client to the fake website.
func TestDetectIMAPCamouflage(t *testing.T) {
	tests := []struct {
		name string
		peek string
		want bool
	}{
		{"real greeting", strategy.IMAPGreeting, true},
		{"minimal Dovecot marker", "* OK Dovecot ready.\r\n", true},
		{"IMAP marker without Dovecot", "* OK [CAPABILITY IMAP4rev2] ready\r\n", true},
		{"status prefix but no marker", "* OK server ready\r\n", false},
		{"wrong status", "* NO [CAPABILITY IMAP4rev2] Dovecot\r\n", false},
		{"BAD status", "* BAD Dovecot\r\n", false},
		{"marker without the status prefix", "Dovecot (Ubuntu) ready.\r\n", false},
		{"SSH banner", strategy.SSHBanner, false},
		{"HTTP request", "GET / HTTP/1.1\r\n", false},
		{"TLS ClientHello", "\x16\x03\x01\x02\x00", false},
		{"empty", "", false},
		{"prefix shorter than the match", "* O", false},
		{"leading whitespace defeats the prefix", " * OK Dovecot", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectIMAPCamouflage([]byte(tt.peek)); got != tt.want {
				t.Errorf("DetectIMAPCamouflage(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

// TestDetectSSHCamouflage pins the SSH classifier, including the TIRED-marker
// carve-out: the legacy protocol-confusion transport also opens with an SSH
// banner, and routing it into the camouflage handshake would hang it.
func TestDetectSSHCamouflage(t *testing.T) {
	tests := []struct {
		name string
		peek string
		want bool
	}{
		{"real banner", strategy.SSHBanner, true},
		{"minimal banner", "SSH-2.0-x\r\n", true},
		{"confusion carrier banner", strategy.ConfusionSSHBanner + "\r\n", false},
		{"SSH 1.99", "SSH-1.99-OpenSSH_9.6\r\n", false},
		{"IMAP greeting", strategy.IMAPGreeting, false},
		{"HTTP request", "GET / HTTP/1.1\r\n", false},
		{"empty", "", false},
		{"prefix shorter than the match", "SSH-2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectSSHCamouflage([]byte(tt.peek)); got != tt.want {
				t.Errorf("DetectSSHCamouflage(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

// TestBase64DecodeToken covers both encodings the LOGIN password field can
// carry. Rejecting the unpadded form would lock out any client whose base64
// helper omits padding.
func TestBase64DecodeToken(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef") // 32 bytes, padding-free length
	odd := []byte("hello world")                      // 11 bytes, needs padding

	for _, tc := range []struct {
		name string
		enc  string
		want []byte
	}{
		{"padded, no padding needed", base64.StdEncoding.EncodeToString(raw), raw},
		{"padded", base64.StdEncoding.EncodeToString(odd), odd},
		{"unpadded", base64.RawStdEncoding.EncodeToString(odd), odd},
		{"empty", "", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := base64DecodeToken(tc.enc)
			if err != nil {
				t.Fatalf("base64DecodeToken(%q): %v", tc.enc, err)
			}
			if string(got) != string(tc.want) {
				t.Errorf("decoded %q, want %q", got, tc.want)
			}
		})
	}

	for _, bad := range []string{"!!!not base64!!!", "a", "====", "abc$"} {
		if _, err := base64DecodeToken(bad); err == nil {
			t.Errorf("base64DecodeToken(%q) = nil error, want a decode failure", bad)
		}
	}
}

// TestIMAPTag covers the tag extraction every command response is keyed on. A
// wrong tag makes a real IMAP client hang waiting for its own tag to come back.
func TestIMAPTag(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"a001 CAPABILITY\r\n", "a001"},
		{"a002 LOGIN user pass\r\n", "a002"},
		{"  a003   SELECT INBOX\r\n", "a003"},
		{"tag\r\n", "tag"},
		{"", ""},
		{"\r\n", ""},
		{"   \t  \r\n", ""},
	}
	for _, tt := range tests {
		if got := imapTag(tt.line); got != tt.want {
			t.Errorf("imapTag(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// TestBuildIMAPSelectResponse pins the shape of the SELECT answer. The counts
// are randomised on purpose (a fixed mailbox size across every connection is
// itself a fingerprint), so the assertions cover structure and internal
// consistency rather than values.
func TestBuildIMAPSelectResponse(t *testing.T) {
	resp := buildIMAPSelectResponse("a003")

	for _, want := range []string{
		" EXISTS\r\n",
		" RECENT\r\n",
		"* OK [UNSEEN ",
		"* OK [UIDVALIDITY ",
		"* OK [UIDNEXT ",
		"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
		"* OK [PERMANENTFLAGS ",
		"a003 OK [READ-WRITE] Select completed",
	} {
		if !strings.Contains(resp, want) {
			t.Errorf("SELECT response missing %q:\n%s", want, resp)
		}
	}

	if !strings.HasSuffix(resp, "\r\n") {
		t.Error("SELECT response must end with CRLF")
	}
	// The tagged completion has to be last, or the client keeps reading.
	lines := strings.Split(strings.TrimSuffix(resp, "\r\n"), "\r\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "a003 OK") {
		t.Errorf("last line = %q, want the tagged completion", last)
	}

	// Two calls must not produce identical mailbox sizes forever; a constant
	// response would be a stable fingerprint across the whole fleet.
	distinct := false
	for i := 0; i < 20; i++ {
		if buildIMAPSelectResponse("a003") != resp {
			distinct = true
			break
		}
	}
	if !distinct {
		t.Error("SELECT response is identical across calls; the mailbox size is a fingerprint")
	}

	// The tag is echoed verbatim, whatever the client chose.
	if got := buildIMAPSelectResponse("XYZZY"); !strings.Contains(got, "XYZZY OK [READ-WRITE]") {
		t.Error("SELECT response did not echo the client's tag")
	}
}

// imapTestChallenge and imapTestBinding stand in for the per-session inputs
// the real handshake derives: the server's SASL challenge and the RFC 9266 TLS
// exporter. Both have to reach the verifier, which is what the subtests below
// check one at a time.
const imapTestChallenge = "<1896.697170952@mail.icloud.com>"

func imapTestBinding() []byte { return bytes.Repeat([]byte{0x4D}, 32) }

func imapDigest(secret string) []byte {
	return strategy.IMAPAuthResponse([]byte(secret), imapTestChallenge, imapTestBinding())
}

// TestVerifyIMAPAuth covers secret matching against both the registry and the
// global secret. A digest that verifies against the wrong secret would let one
// client's credentials open another's session.
func TestVerifyIMAPAuth(t *testing.T) {
	global := []byte(camouflageTestSecret)
	perClient := "per-client-secret-also-32-bytes!"

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = global
	r := NewClientRegistry(nil)
	r.byID["c1"] = &ClientConfig{ID: "c1", Secret: perClient, Enabled: true}
	srvCtx.registry = r

	t.Run("per-client secret wins its own ID", func(t *testing.T) {
		id, secret, ok := verifyIMAPAuth(imapDigest(perClient), imapTestChallenge, imapTestBinding(), srvCtx)
		if !ok {
			t.Fatal("a digest minted from a registered client's secret was rejected")
		}
		if id.id != "c1" {
			t.Errorf("clientID = %q, want c1", id.id)
		}
		if !id.perClient {
			t.Error("a registry client must be marked per-client, or its lease gets qualified and it loses its stable IP")
		}
		if string(secret) != perClient {
			t.Errorf("returned secret = %q, want the client's own", secret)
		}
	})

	t.Run("global secret falls back to \"global\"", func(t *testing.T) {
		id, secret, ok := verifyIMAPAuth(imapDigest(camouflageTestSecret), imapTestChallenge, imapTestBinding(), srvCtx)
		if !ok {
			t.Fatal("a digest minted from the global secret was rejected")
		}
		if id.id != "global" {
			t.Errorf("clientID = %q, want global", id.id)
		}
		if id.perClient {
			t.Error("the global secret identifies nobody; marking it per-client is what lets two clients share one lease")
		}
		if string(secret) != string(global) {
			t.Errorf("returned secret = %q, want the global secret", secret)
		}
	})

	t.Run("unknown secret", func(t *testing.T) {
		if id, _, ok := verifyIMAPAuth(imapDigest("some-other-secret-entirely!!!"), imapTestChallenge, imapTestBinding(), srvCtx); ok {
			t.Errorf("a digest from an unknown secret authenticated as %q", id)
		}
	})

	t.Run("garbage and empty digests", func(t *testing.T) {
		for _, d := range [][]byte{nil, {}, []byte("short"), make([]byte, 16), make([]byte, 32)} {
			if _, _, ok := verifyIMAPAuth(d, imapTestChallenge, imapTestBinding(), srvCtx); ok {
				t.Errorf("digest %x authenticated", d)
			}
		}
	})

	t.Run("digest from another session does not travel", func(t *testing.T) {
		d := imapDigest(camouflageTestSecret)
		other := bytes.Repeat([]byte{0x9E}, 32)
		if _, _, ok := verifyIMAPAuth(d, "<1.2@mail.icloud.com>", imapTestBinding(), srvCtx); ok {
			t.Error("a digest replayed under a different challenge authenticated")
		}
		if _, _, ok := verifyIMAPAuth(d, imapTestChallenge, other, srvCtx); ok {
			t.Error("a digest replayed under a different channel binding authenticated")
		}
	})

	t.Run("missing session inputs are refused", func(t *testing.T) {
		if _, _, ok := verifyIMAPAuth(strategy.IMAPAuthResponse(global, "", imapTestBinding()), "", imapTestBinding(), srvCtx); ok {
			t.Error("an empty challenge authenticated")
		}
		if _, _, ok := verifyIMAPAuth(strategy.IMAPAuthResponse(global, imapTestChallenge, nil), imapTestChallenge, nil, srvCtx); ok {
			t.Error("a missing channel binding authenticated")
		}
	})

	t.Run("server with no secret at all rejects everything", func(t *testing.T) {
		empty := newTestServerContext(t)
		if _, _, ok := verifyIMAPAuth(imapDigest(camouflageTestSecret), imapTestChallenge, imapTestBinding(), empty); ok {
			t.Error("a server with no configured secret authenticated a client")
		}
	})
}

// camouflageTLSCtx returns a server context that can actually complete the
// STARTTLS upgrade: a global secret plus a throwaway leaf certificate.
func camouflageTLSCtx(t *testing.T) *serverContext {
	t.Helper()
	srvCtx := camouflageCtx(t)
	cert, err := mintLeafCertificate(defaultCertParams("imap.example.net"))
	if err != nil {
		t.Fatalf("minting a test certificate: %v", err)
	}
	srvCtx.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	return srvCtx
}

// imapClientToTLS drives the plaintext half of the exchange and hands back the
// secured connection, positioned right after the post-STARTTLS CAPABILITY.
func imapClientToTLS(t *testing.T, conn net.Conn) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	br := bufio.NewReader(conn)

	if _, err := conn.Write([]byte(strategy.IMAPGreeting)); err != nil {
		t.Fatalf("client greeting: %v", err)
	}
	if _, err := conn.Write([]byte("a001 CAPABILITY\r\n")); err != nil {
		t.Fatalf("client CAPABILITY: %v", err)
	}
	if resp := drainUntilTag(t, br, "a001"); !strings.Contains(resp, "OK") {
		t.Fatalf("CAPABILITY response = %q, want OK", resp)
	}
	if _, err := conn.Write([]byte("a002 STARTTLS\r\n")); err != nil {
		t.Fatalf("client STARTTLS: %v", err)
	}
	if resp := drainUntilTag(t, br, "a002"); !strings.Contains(resp, "OK") {
		t.Fatalf("STARTTLS response = %q, want OK", resp)
	}
	if br.Buffered() != 0 {
		t.Fatalf("the server sent %d bytes after the STARTTLS OK", br.Buffered())
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	br = bufio.NewReader(tlsConn)

	if _, err := tlsConn.Write([]byte("a003 CAPABILITY\r\n")); err != nil {
		t.Fatalf("client CAPABILITY over TLS: %v", err)
	}
	if resp := drainUntilTag(t, br, "a003"); !strings.Contains(resp, "OK") {
		t.Fatalf("CAPABILITY (TLS) response = %q, want OK", resp)
	}
	return tlsConn, br
}

// imapClientSASL runs the SASL leg and returns the challenge the server chose.
func imapClientSASL(t *testing.T, tlsConn *tls.Conn, br *bufio.Reader, secret []byte) string {
	t.Helper()
	if _, err := tlsConn.Write([]byte("a004 AUTHENTICATE CRAM-MD5\r\n")); err != nil {
		t.Fatalf("client AUTHENTICATE: %v", err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the SASL challenge: %v", err)
	}
	if !strings.HasPrefix(line, "+ ") {
		t.Fatalf("expected a SASL continuation, got %q", line)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[2:]))
	if err != nil {
		t.Fatalf("decoding the SASL challenge: %v", err)
	}
	challenge := string(raw)

	binding, err := strategy.IMAPChannelBinding(tlsConn.ConnectionState())
	if err != nil {
		t.Fatalf("channel binding: %v", err)
	}
	resp := strategy.FormatIMAPAuthResponse(
		"someone@icloud.com",
		strategy.IMAPAuthResponse(secret, challenge, binding),
	)
	if _, err := fmt.Fprintf(tlsConn, "%s\r\n", resp); err != nil {
		t.Fatalf("client SASL response: %v", err)
	}
	return challenge
}

// TestIMAPServerHandshakeSuccess drives the full server-side handshake against
// a scripted client. This is the path a real IMAP-camouflaged client takes, and
// any divergence from Dovecot's exchange is what a censor's active probe looks
// for.
func TestIMAPServerHandshakeSuccess(t *testing.T) {
	srvCtx := camouflageTLSCtx(t)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		clientID clientIdentity
		err      error
	}
	done := make(chan result, 1)
	go func() {
		id, tlsConn, br, err := imapServerHandshake(serverConn, srvCtx, testLogger(t))
		if err == nil && (br == nil || tlsConn == nil) {
			err = fmt.Errorf("handshake succeeded but returned a nil connection or reader")
		}
		done <- result{id, err}
	}()

	tlsConn, br := imapClientToTLS(t, clientConn)
	imapClientSASL(t, tlsConn, br, []byte(camouflageTestSecret))
	if resp := drainUntilTag(t, br, "a004"); !strings.Contains(resp, "OK") {
		t.Fatalf("AUTHENTICATE response = %q, want OK", resp)
	}
	if _, err := tlsConn.Write([]byte("a005 SELECT INBOX\r\n")); err != nil {
		t.Fatalf("client SELECT: %v", err)
	}
	if resp := drainUntilTag(t, br, "a005"); !strings.Contains(resp, "OK [READ-WRITE]") {
		t.Errorf("SELECT response = %q, want OK [READ-WRITE]", resp)
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("imapServerHandshake: %v", res.err)
		}
		if res.clientID.id != "global" {
			t.Errorf("clientID = %q, want global", res.clientID.id)
		}
		if res.clientID.perClient {
			t.Error("the global secret must not come back marked per-client")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("imapServerHandshake did not return")
	}
}

// TestIMAPServerHandshakeRejections covers each way the exchange can go wrong.
// Every one must return an error so the caller drops the connection rather than
// leaving a half-open session an attacker can probe.
func TestIMAPServerHandshakeRejections(t *testing.T) {
	tests := []struct {
		name   string
		script func(t *testing.T, conn net.Conn)
	}{
		{
			name: "client hangs up before the greeting",
			script: func(t *testing.T, conn net.Conn) {
				conn.Close()
			},
		},
		{
			name: "not an IMAP greeting",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte("HELO there\r\n"))
			},
		},
		{
			name: "second command is not CAPABILITY",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 NOOP\r\n"))
			},
		},
		{
			// A pre-1.11.0 client goes straight to LOGIN here. It must get a
			// tagged rejection at once: its own reader treats NO as a failed
			// command, so it fails instead of waiting out the deadline.
			name: "a 1.10.x client sends LOGIN instead of STARTTLS",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 CAPABILITY\r\n"))
				drainUntilTag(t, br, "a001")
				conn.Write([]byte("a002 LOGIN deadbeef@icloud.com c29tZXRva2Vu\r\n"))
				line := drainUntilTag(t, br, "a002")
				if !strings.Contains(line, "NO [PRIVACYREQUIRED]") {
					t.Errorf("rejection = %q, want a Dovecot-shaped PRIVACYREQUIRED", line)
				}
			},
		},
		{
			name: "client pipelines past the STARTTLS boundary",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 CAPABILITY\r\n"))
				drainUntilTag(t, br, "a001")
				conn.Write([]byte("a002 STARTTLS\r\na003 CAPABILITY\r\n"))
			},
		},
		{
			name: "no SASL exchange, a plain command instead",
			script: func(t *testing.T, conn net.Conn) {
				tlsConn, _ := imapClientToTLS(t, conn)
				tlsConn.Write([]byte("a004 LOGIN user pass\r\n"))
			},
		},
		{
			name: "SASL response is not base64",
			script: func(t *testing.T, conn net.Conn) {
				tlsConn, br := imapClientToTLS(t, conn)
				tlsConn.Write([]byte("a004 AUTHENTICATE CRAM-MD5\r\n"))
				if _, err := br.ReadString('\n'); err != nil {
					t.Fatalf("challenge: %v", err)
				}
				tlsConn.Write([]byte("!!!not-base64!!!\r\n"))
				if line := drainUntilTag(t, br, "a004"); !strings.Contains(line, "NO [AUTHENTICATIONFAILED]") {
					t.Errorf("rejection = %q, want a Dovecot-shaped AUTHENTICATIONFAILED", line)
				}
			},
		},
		{
			name: "SASL digest from the wrong secret",
			script: func(t *testing.T, conn net.Conn) {
				tlsConn, br := imapClientToTLS(t, conn)
				imapClientSASL(t, tlsConn, br, []byte("the-wrong-secret-entirely!!!!!!"))
				if line := drainUntilTag(t, br, "a004"); !strings.Contains(line, "NO [AUTHENTICATIONFAILED]") {
					t.Errorf("rejection = %q, want a Dovecot-shaped AUTHENTICATIONFAILED", line)
				}
			},
		},
		{
			name: "SASL digest replayed from another session",
			script: func(t *testing.T, conn net.Conn) {
				tlsConn, br := imapClientToTLS(t, conn)
				tlsConn.Write([]byte("a004 AUTHENTICATE CRAM-MD5\r\n"))
				if _, err := br.ReadString('\n'); err != nil {
					t.Fatalf("challenge: %v", err)
				}
				// A digest computed over a challenge and binding this session
				// never used: exactly what a capture from an earlier session
				// would give an attacker.
				stale := strategy.IMAPAuthResponse([]byte(camouflageTestSecret),
					imapTestChallenge, imapTestBinding())
				fmt.Fprintf(tlsConn, "%s\r\n",
					strategy.FormatIMAPAuthResponse("someone@icloud.com", stale))
				if line := drainUntilTag(t, br, "a004"); !strings.Contains(line, "NO [AUTHENTICATIONFAILED]") {
					t.Errorf("rejection = %q, want a Dovecot-shaped AUTHENTICATIONFAILED", line)
				}
			},
		},
		{
			name: "command after login is not SELECT",
			script: func(t *testing.T, conn net.Conn) {
				tlsConn, br := imapClientToTLS(t, conn)
				imapClientSASL(t, tlsConn, br, []byte(camouflageTestSecret))
				drainUntilTag(t, br, "a004")
				tlsConn.Write([]byte("a005 LOGOUT\r\n"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvCtx := camouflageTLSCtx(t)
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				_, _, _, err := imapServerHandshake(serverConn, srvCtx, testLogger(t))
				errCh <- err
			}()

			tt.script(t, clientConn)
			clientConn.Close()

			select {
			case err := <-errCh:
				if err == nil {
					t.Error("handshake succeeded, want a rejection")
				}
			case <-time.After(20 * time.Second):
				t.Fatal("imapServerHandshake did not return")
			}
		})
	}
}

// TestIMAPServerMintsAFreshChallengePerSession checks the call site, not the
// generator: NewIMAPAuthChallenge is provably fresh on its own, and a server
// that called it once and cached the result would still pass that test while
// handing every session the same input to sign.
func TestIMAPServerMintsAFreshChallengePerSession(t *testing.T) {
	run := func() string {
		t.Helper()
		srvCtx := camouflageTLSCtx(t)
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _, _ = imapServerHandshake(serverConn, srvCtx, testLogger(t))
		}()

		tlsConn, br := imapClientToTLS(t, clientConn)
		challenge := imapClientSASL(t, tlsConn, br, []byte(camouflageTestSecret))
		drainUntilTag(t, br, "a004")
		tlsConn.Write([]byte("a005 SELECT INBOX\r\n"))
		drainUntilTag(t, br, "a005")
		clientConn.Close()
		<-done
		return challenge
	}

	a, b := run(), run()
	if a == b {
		t.Fatalf("both sessions were challenged with %q: the challenge is not minted per session", a)
	}
}

// TestIMAPServerHandshakeWithoutTLSConfig pins the guard that keeps the
// upgrade from being skipped: without a certificate there is no secured
// session to authenticate in, and the handshake must fail rather than fall
// back to the cleartext exchange it replaced.
func TestIMAPServerHandshakeWithoutTLSConfig(t *testing.T) {
	srvCtx := camouflageCtx(t) // no tlsConfig
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		_, tlsConn, _, err := imapServerHandshake(serverConn, srvCtx, testLogger(t))
		if tlsConn != nil {
			t.Error("a TLS connection came back from a context with no certificate")
		}
		errCh <- err
	}()

	br := bufio.NewReader(clientConn)
	clientConn.Write([]byte(strategy.IMAPGreeting))
	clientConn.Write([]byte("a001 CAPABILITY\r\n"))
	drainUntilTag(t, br, "a001")
	clientConn.Write([]byte("a002 STARTTLS\r\n"))
	clientConn.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("the handshake succeeded without a TLS configuration")
		}
		// The message matters: without the explicit guard the failure comes
		// out of crypto/tls instead, which means the upgrade was attempted
		// and the operator is left reading a handshake error.
		if !strings.Contains(err.Error(), "no TLS configuration") {
			t.Errorf("error = %v, want the missing-configuration refusal", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("imapServerHandshake did not return")
	}
}

// drainUntilTag reads lines until the given tag's response arrives.
func drainUntilTag(t *testing.T, br *bufio.Reader, tag string) string {
	t.Helper()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read while waiting for %s: %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return line
		}
	}
}
