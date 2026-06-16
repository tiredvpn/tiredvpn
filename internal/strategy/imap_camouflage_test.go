package strategy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestIMAPLiteralLenParse checks that data-carrying lines (APPEND, FETCH) yield
// their literal length while keepalive lines are skipped.
func TestIMAPLiteralLenParse(t *testing.T) {
	cases := []struct {
		line    string
		wantLen int
		wantOK  bool
	}{
		{"A004 APPEND INBOX (\\Seen) {12}\r\n", 12, true},
		{"* 7 FETCH (BODY[] {2048}\r\n", 2048, true},
		{"A005 NOOP\r\n", 0, false},
		{"* OK Still here\r\n", 0, false},
		{"A006 APPEND INBOX (\\Seen) {0}\r\n", 0, true},
		{"garbage line\r\n", 0, false},
	}
	for i, c := range cases {
		gotLen, gotOK := parseIMAPLiteralLen(c.line)
		if gotOK != c.wantOK || gotLen != c.wantLen {
			t.Fatalf("case %d (%q): got (len=%d ok=%v) want (len=%d ok=%v)",
				i, c.line, gotLen, gotOK, c.wantLen, c.wantOK)
		}
	}
}

// TestIMAPConnRoundTrip verifies the tunnel-phase connection frames and deframes
// a clean byte stream across an arbitrary split (large payload, small read
// buffer), with the client writing APPEND and the server writing FETCH.
func TestIMAPConnRoundTrip(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	client := NewIMAPCamouflageConn(cli, nil, false)
	server := NewIMAPCamouflageConn(srv, nil, true)

	msg := bytes.Repeat([]byte("TiredVPN-imap-payload-"), 500) // > 8KB

	// client -> server (APPEND framing)
	go func() {
		if _, err := client.Write(msg); err != nil {
			t.Errorf("client write: %v", err)
		}
	}()
	if got := readN(t, server, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("client->server mismatch (got %d bytes, want %d)", len(got), len(msg))
	}

	// server -> client (FETCH framing)
	go func() {
		if _, err := server.Write(msg); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()
	if got := readN(t, client, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("server->client mismatch (got %d bytes, want %d)", len(got), len(msg))
	}
}

// readN reads exactly n bytes via a deliberately small buffer to force the
// conn's internal read buffering path.
func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	got := make([]byte, 0, n)
	tmp := make([]byte, 100)
	for len(got) < n {
		m, err := c.Read(tmp)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, tmp[:m]...)
	}
	return got
}

// TestIMAPConnIgnoresKeepalives ensures Read skips NOOP / status keepalive lines
// interleaved before a real data frame.
func TestIMAPConnIgnoresKeepalives(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		// Two keepalive lines the reader must skip ...
		_, _ = cli.Write([]byte("A009 NOOP\r\n"))
		_, _ = cli.Write([]byte("* OK Still here\r\n"))
		// ... followed by a real APPEND data frame.
		conn := NewIMAPCamouflageConn(cli, nil, false)
		_, _ = conn.Write([]byte("real"))
	}()

	server := NewIMAPCamouflageConn(srv, nil, true)
	buf := make([]byte, 16)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "real" {
		t.Fatalf("expected 'real', got %q", string(buf[:n]))
	}
}

// TestIMAPAuthTokenVerify checks token generation and verification, including
// the ±1 time-bucket tolerance and rejection of wrong secrets / lengths.
func TestIMAPAuthTokenVerify(t *testing.T) {
	secret := []byte("super-secret-imap-key")

	token := GenerateIMAPAuthToken(secret)
	if len(token) != imapAuthLen {
		t.Fatalf("token length = %d, want %d", len(token), imapAuthLen)
	}
	if !VerifyIMAPAuthToken(token, secret) {
		t.Fatal("current-bucket token failed to verify")
	}
	if VerifyIMAPAuthToken(token, []byte("other-secret")) {
		t.Fatal("token verified against wrong secret")
	}
	if VerifyIMAPAuthToken(token[:16], secret) {
		t.Fatal("truncated token verified")
	}

	now := time.Now().Unix()
	for _, off := range []int64{-1, 1} {
		bucket := uint64((now / imapAuthBucket) + off)
		adj := imapAuthTokenForBucket(secret, bucket)
		if !VerifyIMAPAuthToken(adj, secret) {
			t.Fatalf("adjacent bucket (offset %d) failed to verify", off)
		}
	}
	farBucket := uint64((now / imapAuthBucket) + 2)
	far := imapAuthTokenForBucket(secret, farBucket)
	if VerifyIMAPAuthToken(far, secret) {
		t.Fatal("far bucket (+2) unexpectedly verified")
	}
}

// TestIMAPTokenBase64Length confirms the 32-byte token encodes to a 44-char
// base64 string usable as a LOGIN password field.
func TestIMAPTokenBase64Length(t *testing.T) {
	token := GenerateIMAPAuthToken([]byte("secret"))
	pw := base64.StdEncoding.EncodeToString(token)
	if len(pw) != 44 {
		t.Fatalf("base64 token length = %d, want 44", len(pw))
	}
	if strings.ContainsAny(pw, " \r\n") {
		t.Fatalf("base64 token contains whitespace: %q", pw)
	}
}

// TestIMAPClientServerHandshake runs the real client handshake against a minimal
// server handshake to confirm both halves interoperate end to end over net.Pipe.
func TestIMAPClientServerHandshake(t *testing.T) {
	secret := []byte("imap-handshake-secret")
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	clientErr := make(chan error, 1)
	go func() {
		_, err := performIMAPClientHandshake(cli, secret)
		clientErr <- err
	}()

	if err := fakeIMAPServerHandshake(srv, secret); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
}

// fakeIMAPServerHandshake mirrors the server-side handshake using only exported
// strategy helpers, so the test stays inside the strategy package.
func fakeIMAPServerHandshake(conn net.Conn, secret []byte) error {
	br := bufio.NewReader(conn)

	greeting, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return fmt.Errorf("not an IMAP greeting: %q", greeting)
	}

	capLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	capTag := strings.Fields(capLine)[0]
	if _, err := conn.Write([]byte(IMAPPreLoginCaps())); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(capTag + " OK Pre-login capabilities listed, post-login capabilities have more.\r\n")); err != nil {
		return err
	}

	loginLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	fields := strings.Fields(loginLine)
	if len(fields) < 4 || !strings.EqualFold(fields[1], "LOGIN") {
		return fmt.Errorf("malformed LOGIN: %q", loginLine)
	}
	token, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		return err
	}
	if !VerifyIMAPAuthToken(token, secret) {
		return io.ErrUnexpectedEOF
	}
	if _, err := conn.Write([]byte(IMAPPostLoginCaps())); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%s OK [CAPABILITY %s] Logged in\r\n", fields[0], IMAPCapsInline()); err != nil {
		return err
	}

	selectLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	selectTag := strings.Fields(selectLine)[0]
	resp := "* 1234 EXISTS\r\n* 0 RECENT\r\n" +
		"* OK [UNSEEN 1] Message 1 is first unseen\r\n" +
		"* OK [UIDVALIDITY 1234567890] UIDs valid\r\n" +
		"* OK [UIDNEXT 1235] Predicted next UID\r\n" +
		"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" +
		"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.\r\n" +
		selectTag + " OK [READ-WRITE] Select completed (0.001 + 0.000 secs).\r\n"
	_, err = conn.Write([]byte(resp))
	return err
}
