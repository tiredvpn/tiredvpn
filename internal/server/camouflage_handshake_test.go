package server

import (
	"bufio"
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
		{"confusion variant with TIRED marker", "SSH-2.0-OpenSSH_9.6p1\r\nTIRED\x00\x01", false},
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

// TestVerifyIMAPAuth covers secret matching against both the registry and the
// global secret. A token that verifies against the wrong secret would let one
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
		id, secret, ok := verifyIMAPAuth(strategy.GenerateIMAPAuthToken([]byte(perClient)), srvCtx)
		if !ok {
			t.Fatal("a token minted from a registered client's secret was rejected")
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
		id, secret, ok := verifyIMAPAuth(strategy.GenerateIMAPAuthToken(global), srvCtx)
		if !ok {
			t.Fatal("a token minted from the global secret was rejected")
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
		if id, _, ok := verifyIMAPAuth(strategy.GenerateIMAPAuthToken([]byte("some-other-secret-entirely!!!")), srvCtx); ok {
			t.Errorf("a token from an unknown secret authenticated as %q", id)
		}
	})

	t.Run("garbage and empty tokens", func(t *testing.T) {
		for _, tok := range [][]byte{nil, {}, []byte("short"), make([]byte, 32)} {
			if _, _, ok := verifyIMAPAuth(tok, srvCtx); ok {
				t.Errorf("token %x authenticated", tok)
			}
		}
	})

	t.Run("server with no secret at all rejects everything", func(t *testing.T) {
		empty := newTestServerContext(t)
		if _, _, ok := verifyIMAPAuth(strategy.GenerateIMAPAuthToken(global), empty); ok {
			t.Error("a server with no configured secret authenticated a client")
		}
	})
}

// TestVerifySSHAuth mirrors TestVerifyIMAPAuth for the SSH transport.
func TestVerifySSHAuth(t *testing.T) {
	global := []byte(camouflageTestSecret)
	perClient := "per-client-secret-also-32-bytes!"

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = global
	r := NewClientRegistry(nil)
	r.byID["c1"] = &ClientConfig{ID: "c1", Secret: perClient, Enabled: true}
	srvCtx.registry = r

	if id, _, ok := verifySSHAuth(strategy.GenerateSSHAuthToken([]byte(perClient)), srvCtx); !ok || id.id != "c1" || !id.perClient {
		t.Errorf("per-client token: id=%q perClient=%v ok=%v, want c1/true/true", id.id, id.perClient, ok)
	}
	if id, _, ok := verifySSHAuth(strategy.GenerateSSHAuthToken(global), srvCtx); !ok || id.id != "global" || id.perClient {
		t.Errorf("global token: id=%q perClient=%v ok=%v, want global/false/true", id.id, id.perClient, ok)
	}
	if _, _, ok := verifySSHAuth(strategy.GenerateSSHAuthToken([]byte("nope-nope-nope-nope-nope-nope!!")), srvCtx); ok {
		t.Error("an unknown secret authenticated")
	}
	// An IMAP token must not open an SSH session: the two derivations are
	// separate contexts and cross-acceptance would widen the auth surface.
	if _, _, ok := verifySSHAuth(strategy.GenerateIMAPAuthToken(global), srvCtx); ok {
		t.Error("an IMAP auth token was accepted by the SSH verifier")
	}
}

// imapClientScript drives the client half of the fake IMAP session against
// imapServerHandshake running on the other end of a pipe.
func imapClientScript(t *testing.T, conn net.Conn, token string, sendSelect bool) {
	t.Helper()
	br := bufio.NewReader(conn)

	write := func(s string) {
		t.Helper()
		if _, err := conn.Write([]byte(s)); err != nil {
			t.Errorf("client write %q: %v", s, err)
		}
	}
	// readUntilTag drains untagged "*" lines and returns the tagged response.
	readUntilTag := func(tag string) string {
		t.Helper()
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("client read while waiting for %s: %v", tag, err)
			}
			if strings.HasPrefix(line, tag+" ") {
				return line
			}
		}
	}

	write(strategy.IMAPGreeting)

	write("a001 CAPABILITY\r\n")
	if resp := readUntilTag("a001"); !strings.Contains(resp, "OK") {
		t.Errorf("CAPABILITY response = %q, want OK", resp)
	}

	write(fmt.Sprintf("a002 LOGIN user@example.com %s\r\n", token))
	if resp := readUntilTag("a002"); !strings.Contains(resp, "OK") {
		t.Errorf("LOGIN response = %q, want OK", resp)
		return
	}

	if !sendSelect {
		return
	}
	write("a003 SELECT INBOX\r\n")
	if resp := readUntilTag("a003"); !strings.Contains(resp, "OK [READ-WRITE]") {
		t.Errorf("SELECT response = %q, want OK [READ-WRITE]", resp)
	}
}

// TestIMAPServerHandshakeSuccess drives the full server-side handshake against
// a scripted client. This is the path a real IMAP-camouflaged client takes, and
// any divergence from Dovecot's exchange is what a censor's active probe looks
// for.
func TestIMAPServerHandshakeSuccess(t *testing.T) {
	srvCtx := camouflageCtx(t)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		clientID clientIdentity
		err      error
	}
	done := make(chan result, 1)
	go func() {
		id, br, err := imapServerHandshake(serverConn, srvCtx, testLogger(t))
		if err == nil && br == nil {
			err = fmt.Errorf("handshake succeeded but returned a nil reader")
		}
		done <- result{id, err}
	}()

	token := base64.StdEncoding.EncodeToString(
		strategy.GenerateIMAPAuthToken([]byte(camouflageTestSecret)))
	imapClientScript(t, clientConn, token, true)

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
// Every one must return an error so the caller falls through to the fake
// website rather than leaving a half-open session an attacker can probe.
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
			name: "malformed LOGIN command",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 CAPABILITY\r\n"))
				drainUntilTag(t, br, "a001")
				conn.Write([]byte("a002 LOGIN onlyuser\r\n"))
			},
		},
		{
			name: "LOGIN token is not base64",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 CAPABILITY\r\n"))
				drainUntilTag(t, br, "a001")
				conn.Write([]byte("a002 LOGIN user !!!not-base64!!!\r\n"))
			},
		},
		{
			name: "LOGIN token from the wrong secret",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 CAPABILITY\r\n"))
				drainUntilTag(t, br, "a001")
				bad := base64.StdEncoding.EncodeToString(
					strategy.GenerateIMAPAuthToken([]byte("the-wrong-secret-entirely!!!!!!")))
				fmt.Fprintf(conn, "a002 LOGIN user %s\r\n", bad)
				// The server answers with a realistic rejection before bailing.
				if line := drainUntilTag(t, br, "a002"); !strings.Contains(line, "NO [AUTHENTICATIONFAILED]") {
					t.Errorf("rejection = %q, want a Dovecot-shaped AUTHENTICATIONFAILED", line)
				}
			},
		},
		{
			name: "fourth command is not SELECT",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.IMAPGreeting))
				conn.Write([]byte("a001 CAPABILITY\r\n"))
				drainUntilTag(t, br, "a001")
				token := base64.StdEncoding.EncodeToString(
					strategy.GenerateIMAPAuthToken([]byte(camouflageTestSecret)))
				fmt.Fprintf(conn, "a002 LOGIN user %s\r\n", token)
				drainUntilTag(t, br, "a002")
				conn.Write([]byte("a003 LOGOUT\r\n"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvCtx := camouflageCtx(t)
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				_, _, err := imapServerHandshake(serverConn, srvCtx, testLogger(t))
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

// TestSSHServerHandshakeSuccess drives the fake SSH handshake end to end:
// banner, KEXINIT, and the ECDH round trip carrying the auth token. The reply
// token must be derived from the same secret, which is how the client confirms
// it reached a real tiredvpn exit rather than a probe.
func TestSSHServerHandshakeSuccess(t *testing.T) {
	srvCtx := camouflageCtx(t)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		clientID clientIdentity
		err      error
	}
	done := make(chan result, 1)
	go func() {
		id, err := sshServerHandshake(serverConn, srvCtx, testLogger(t))
		done <- result{id, err}
	}()

	br := bufio.NewReader(clientConn)

	if _, err := clientConn.Write([]byte(strategy.SSHBanner)); err != nil {
		t.Fatalf("write banner: %v", err)
	}
	banner, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read server banner: %v", err)
	}
	if !strings.HasPrefix(banner, "SSH-2.0") {
		t.Errorf("server banner = %q, want an SSH-2.0 identification line", banner)
	}

	if err := strategy.WriteSSHPacket(clientConn, strategy.BuildSSHKexInit()); err != nil {
		t.Fatalf("write client KEXINIT: %v", err)
	}
	if _, err := strategy.ReadSSHPacket(br); err != nil {
		t.Fatalf("read server KEXINIT: %v", err)
	}

	secret := []byte(camouflageTestSecret)
	token := strategy.GenerateSSHAuthToken(secret)
	if err := strategy.WriteSSHPacket(clientConn, strategy.BuildSSHKexECDH(30, token)); err != nil {
		t.Fatalf("write ECDH init: %v", err)
	}

	reply, err := strategy.ReadSSHPacket(br)
	if err != nil {
		t.Fatalf("read ECDH reply: %v", err)
	}
	serverToken, err := strategy.ParseSSHKexPubKey(reply, 31)
	if err != nil {
		t.Fatalf("parse ECDH reply: %v", err)
	}
	if !strategy.VerifySSHAuthToken(serverToken, secret) {
		t.Error("the server's reply token does not verify against the shared secret")
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("sshServerHandshake: %v", res.err)
		}
		if res.clientID.id != "global" {
			t.Errorf("clientID = %q, want global", res.clientID.id)
		}
		if res.clientID.perClient {
			t.Error("the global secret must not come back marked per-client")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("sshServerHandshake did not return")
	}
}

// TestSSHServerHandshakeRejections covers the failure modes; each has to error
// so the caller serves the fake website instead.
func TestSSHServerHandshakeRejections(t *testing.T) {
	tests := []struct {
		name   string
		script func(t *testing.T, conn net.Conn)
	}{
		{
			name: "client hangs up before the banner",
			script: func(t *testing.T, conn net.Conn) {
				conn.Close()
			},
		},
		{
			name: "not an SSH-2.0 banner",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte("SSH-1.5-ancient\r\n"))
			},
		},
		{
			name: "hangs up after the banner",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.SSHBanner))
				br.ReadString('\n')
				conn.Close()
			},
		},
		{
			name: "ECDH init carries the wrong message type",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.SSHBanner))
				br.ReadString('\n')
				strategy.WriteSSHPacket(conn, strategy.BuildSSHKexInit())
				strategy.ReadSSHPacket(br)
				token := strategy.GenerateSSHAuthToken([]byte(camouflageTestSecret))
				strategy.WriteSSHPacket(conn, strategy.BuildSSHKexECDH(99, token))
			},
		},
		{
			name: "auth token from the wrong secret",
			script: func(t *testing.T, conn net.Conn) {
				br := bufio.NewReader(conn)
				conn.Write([]byte(strategy.SSHBanner))
				br.ReadString('\n')
				strategy.WriteSSHPacket(conn, strategy.BuildSSHKexInit())
				strategy.ReadSSHPacket(br)
				bad := strategy.GenerateSSHAuthToken([]byte("the-wrong-secret-entirely!!!!!!"))
				strategy.WriteSSHPacket(conn, strategy.BuildSSHKexECDH(30, bad))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvCtx := camouflageCtx(t)
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				_, err := sshServerHandshake(serverConn, srvCtx, testLogger(t))
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
				t.Fatal("sshServerHandshake did not return")
			}
		})
	}
}
