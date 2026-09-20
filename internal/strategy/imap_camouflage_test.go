package strategy

import (
	"bufio"
	"bytes"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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

// ---------------------------------------------------------------------------
// Auth derivation
// ---------------------------------------------------------------------------

// imapTestSecret is deliberately distinctive: the wire tests scan the capture
// for it, so it must not collide with anything the protocol emits on its own.
var imapTestSecret = []byte("ZzQq-imap-secret-material-9f3a17")

// TestIMAPAuthResponseIsBoundToChallengeAndChannel is the whole point of the
// 1.11.0 credential: the digest is a function of inputs the client does not
// choose, so a captured one is worth nothing anywhere else. Every assertion
// here fails if either input is dropped from the MAC.
func TestIMAPAuthResponseIsBoundToChallengeAndChannel(t *testing.T) {
	bindA := bytes.Repeat([]byte{0xA1}, imapChannelBindingLen)
	bindB := bytes.Repeat([]byte{0xB2}, imapChannelBindingLen)
	chalA := "<111.222@mail.example>"
	chalB := "<333.444@mail.example>"

	base := IMAPAuthResponse(imapTestSecret, chalA, bindA)

	if bytes.Equal(base, IMAPAuthResponse(imapTestSecret, chalB, bindA)) {
		t.Error("changing the server challenge did not change the digest: the challenge is not in the MAC")
	}
	if bytes.Equal(base, IMAPAuthResponse(imapTestSecret, chalA, bindB)) {
		t.Error("changing the channel binding did not change the digest: the binding is not in the MAC")
	}
	if bytes.Equal(base, IMAPAuthResponse([]byte("a-completely-different-secret!!!"), chalA, bindA)) {
		t.Error("changing the secret did not change the digest")
	}

	if !VerifyIMAPAuthResponse(base, imapTestSecret, chalA, bindA) {
		t.Fatal("a freshly computed digest failed to verify")
	}
	// Replay: the same digest presented under the next session's challenge or
	// binding must be refused.
	if VerifyIMAPAuthResponse(base, imapTestSecret, chalB, bindA) {
		t.Error("a digest replayed under a different challenge verified")
	}
	if VerifyIMAPAuthResponse(base, imapTestSecret, chalA, bindB) {
		t.Error("a digest replayed under a different channel binding verified")
	}
}

// TestVerifyIMAPAuthResponseRefusesDegenerateInputs pins the guards that keep a
// caller from silently restoring the predictable input of 1.10.x. A verifier
// that accepted an empty challenge or a short binding would be back to a MAC
// over a constant.
func TestVerifyIMAPAuthResponseRefusesDegenerateInputs(t *testing.T) {
	binding := bytes.Repeat([]byte{0x5C}, imapChannelBindingLen)
	chal := "<1.2@mail.example>"
	good := IMAPAuthResponse(imapTestSecret, chal, binding)

	cases := []struct {
		name      string
		digest    []byte
		secret    []byte
		challenge string
		binding   []byte
	}{
		{"empty challenge", IMAPAuthResponse(imapTestSecret, "", binding), imapTestSecret, "", binding},
		{"short binding", IMAPAuthResponse(imapTestSecret, chal, binding[:8]), imapTestSecret, chal, binding[:8]},
		{"nil binding", IMAPAuthResponse(imapTestSecret, chal, nil), imapTestSecret, chal, nil},
		{"empty secret", good, nil, chal, binding},
		{"truncated digest", good[:8], imapTestSecret, chal, binding},
		{"over-long digest", append(append([]byte{}, good...), 0), imapTestSecret, chal, binding},
	}
	for _, c := range cases {
		if VerifyIMAPAuthResponse(c.digest, c.secret, c.challenge, c.binding) {
			t.Errorf("%s: verified", c.name)
		}
	}
}

// TestIMAPAuthResponseWireForm pins the field widths RFC 2195 section 2 gives a
// CRAM-MD5 response: base64 of "<username> <digest in hex>", the digest exactly
// 32 hex characters wide.
func TestIMAPAuthResponseWireForm(t *testing.T) {
	binding := bytes.Repeat([]byte{0x33}, imapChannelBindingLen)
	chal := "<1896.697170952@postoffice.reston.mci.net>"
	user := imapUsername(imapTestSecret, chal)
	digest := IMAPAuthResponse(imapTestSecret, chal, binding)

	encoded := FormatIMAPAuthResponse(user, digest)
	if strings.ContainsAny(encoded, " \r\n") {
		t.Fatalf("the response carries whitespace and would break the line: %q", encoded)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	fields := strings.Split(string(raw), " ")
	if len(fields) != 2 {
		t.Fatalf("response = %q, want exactly two space-separated fields", raw)
	}
	if len(fields[1]) != 32 {
		t.Errorf("digest field is %d hex characters, want the 32 RFC 2195 specifies", len(fields[1]))
	}

	gotUser, gotDigest, err := ParseIMAPAuthResponse(raw)
	if err != nil {
		t.Fatalf("ParseIMAPAuthResponse: %v", err)
	}
	if gotUser != user || !bytes.Equal(gotDigest, digest) {
		t.Errorf("round trip lost data: user %q/%q digest %x/%x", gotUser, user, gotDigest, digest)
	}

	for _, bad := range [][]byte{
		[]byte("onlyonefield"),
		[]byte("user three fields here"),
		[]byte("user zzzznothex"),
		[]byte("user " + strings.Repeat("ab", 8)), // right shape, wrong width
	} {
		if _, _, err := ParseIMAPAuthResponse(bad); err == nil {
			t.Errorf("ParseIMAPAuthResponse(%q) accepted a malformed response", bad)
		}
	}
}

// TestIMAPChallengeShape checks the challenge against the msg-id form RFC 2195
// gives in its example and Dovecot emits: <digits.digits@host>. There is no
// capture of real Dovecot challenges to compare a distribution against, so this
// pins the form only, and separately pins that two challenges differ - a
// constant here would hand an observer back the offline oracle.
func TestIMAPChallengeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		c, err := NewIMAPAuthChallenge()
		if err != nil {
			t.Fatalf("NewIMAPAuthChallenge: %v", err)
		}
		if !strings.HasPrefix(c, "<") || !strings.HasSuffix(c, ">") {
			t.Fatalf("challenge %q is not a msg-id", c)
		}
		body := c[1 : len(c)-1]
		at := strings.LastIndexByte(body, '@')
		if at < 0 {
			t.Fatalf("challenge %q has no host part", c)
		}
		left, host := body[:at], body[at+1:]
		if host == "" {
			t.Fatalf("challenge %q has an empty host part", c)
		}
		nums := strings.Split(left, ".")
		if len(nums) != 2 {
			t.Fatalf("challenge %q local part = %q, want <random>.<timestamp>", c, left)
		}
		for _, n := range nums {
			if n == "" || strings.Trim(n, "0123456789") != "" {
				t.Fatalf("challenge %q has a non-numeric field %q", c, n)
			}
		}
		if len(nums[0]) > 10 {
			t.Errorf("random field %q is %d digits, wider than the 31-bit draw Dovecot prints", nums[0], len(nums[0]))
		}
		seen[c] = true
	}
	if len(seen) < 60 {
		t.Fatalf("only %d distinct challenges in 64 draws; the challenge is not fresh per session", len(seen))
	}
}

// TestIMAPUsernameIsUnlinkableAcrossSessions covers the 1.10.x defect head on:
// the login local part was hex(secret[:4]), which both leaked 32 bits of the
// key and was a stable handle tying every session of a client together.
func TestIMAPUsernameIsUnlinkableAcrossSessions(t *testing.T) {
	a := imapUsername(imapTestSecret, "<1.1@mail.example>")
	b := imapUsername(imapTestSecret, "<2.2@mail.example>")
	if a == b {
		t.Fatal("the same secret produced the same address under two challenges: sessions stay linkable")
	}
	if !strings.HasSuffix(a, "@"+imapMailDomain) || !strings.HasSuffix(b, "@"+imapMailDomain) {
		t.Fatalf("addresses lost their domain: %q %q", a, b)
	}
	local, _, _ := strings.Cut(a, "@")
	for n := 1; n <= len(imapTestSecret); n++ {
		if strings.Contains(local, hex.EncodeToString(imapTestSecret[:n])) {
			t.Fatalf("the address local part %q contains the first %d bytes of the secret in hex", local, n)
		}
	}
}

// ---------------------------------------------------------------------------
// End to end over the wire
// ---------------------------------------------------------------------------

// imapTapConn tees every byte crossing the socket into a buffer, so a test
// can ask what a tap on the link would have seen.
type imapTapConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *imapTapConn) record(b []byte) {
	c.mu.Lock()
	c.buf.Write(b)
	c.mu.Unlock()
}

func (c *imapTapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.record(p[:n])
	return n, err
}

func (c *imapTapConn) Write(p []byte) (int, error) {
	c.record(p)
	return c.Conn.Write(p)
}

func (c *imapTapConn) captured() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// imapServerObservation is what the fake server saw in the SASL exchange.
type imapServerObservation struct {
	user      string
	digest    []byte
	challenge string
	binding   []byte
}

// fakeIMAPServerHandshake mirrors the production server handshake using only
// exported strategy helpers, so the test stays inside the strategy package. It
// returns the TLS connection the tunnel runs over plus what it observed.
func fakeIMAPServerHandshake(t *testing.T, raw net.Conn, secret []byte) (net.Conn, *bufio.Reader, imapServerObservation, error) {
	t.Helper()
	var obs imapServerObservation
	br := bufio.NewReader(raw)

	readLine := func() (string, error) { return br.ReadString('\n') }

	greeting, err := readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return nil, nil, obs, fmt.Errorf("not an IMAP greeting: %q", greeting)
	}

	capLine, err := readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	if _, err := fmt.Fprintf(raw, "%s%s OK Pre-login capabilities listed.\r\n",
		IMAPPreLoginCaps(), strings.Fields(capLine)[0]); err != nil {
		return nil, nil, obs, err
	}

	tlsLine, err := readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	if !strings.Contains(strings.ToUpper(tlsLine), "STARTTLS") {
		return nil, nil, obs, fmt.Errorf("expected STARTTLS, got %q", tlsLine)
	}
	if _, err := fmt.Fprintf(raw, "%s OK Begin TLS negotiation now.\r\n", strings.Fields(tlsLine)[0]); err != nil {
		return nil, nil, obs, err
	}

	secured, err := serverTLS(t, raw)
	if err != nil {
		return nil, nil, obs, err
	}
	tlsConn, ok := secured.(*stdtls.Conn)
	if !ok {
		return nil, nil, obs, fmt.Errorf("serverTLS returned %T, want *tls.Conn", secured)
	}
	obs.binding, err = IMAPChannelBinding(tlsConn.ConnectionState())
	if err != nil {
		return nil, nil, obs, err
	}
	br = bufio.NewReader(tlsConn)

	capLine, err = readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	if _, err := fmt.Fprintf(tlsConn, "%s%s OK Pre-login capabilities listed.\r\n",
		IMAPPostSTARTTLSCaps(), strings.Fields(capLine)[0]); err != nil {
		return nil, nil, obs, err
	}

	authLine, err := readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	if !strings.Contains(strings.ToUpper(authLine), "AUTHENTICATE CRAM-MD5") {
		return nil, nil, obs, fmt.Errorf("expected AUTHENTICATE CRAM-MD5, got %q", authLine)
	}
	authTag := strings.Fields(authLine)[0]
	obs.challenge, err = NewIMAPAuthChallenge()
	if err != nil {
		return nil, nil, obs, err
	}
	if _, err := fmt.Fprintf(tlsConn, "+ %s\r\n",
		base64.StdEncoding.EncodeToString([]byte(obs.challenge))); err != nil {
		return nil, nil, obs, err
	}

	respLine, err := readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	rawResp, err := base64.StdEncoding.DecodeString(strings.TrimSpace(respLine))
	if err != nil {
		return nil, nil, obs, err
	}
	obs.user, obs.digest, err = ParseIMAPAuthResponse(rawResp)
	if err != nil {
		return nil, nil, obs, err
	}
	if secret != nil && !VerifyIMAPAuthResponse(obs.digest, secret, obs.challenge, obs.binding) {
		return nil, nil, obs, fmt.Errorf("client digest did not verify")
	}
	if _, err := fmt.Fprintf(tlsConn, "%s%s OK [CAPABILITY %s] Logged in\r\n",
		IMAPPostLoginCaps(), authTag, IMAPCapsInline()); err != nil {
		return nil, nil, obs, err
	}

	selectLine, err := readLine()
	if err != nil {
		return nil, nil, obs, err
	}
	resp := "* 1234 EXISTS\r\n* 0 RECENT\r\n" +
		"* OK [UNSEEN 1] Message 1 is first unseen\r\n" +
		"* OK [UIDVALIDITY 1234567890] UIDs valid\r\n" +
		"* OK [UIDNEXT 1235] Predicted next UID\r\n" +
		"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" +
		"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.\r\n" +
		strings.Fields(selectLine)[0] + " OK [READ-WRITE] Select completed (0.001 + 0.000 secs).\r\n"
	if _, err := tlsConn.Write([]byte(resp)); err != nil {
		return nil, nil, obs, err
	}
	return tlsConn, br, obs, nil
}

// imapClientTLSConfig is what the client half uses in tests: the fake server's
// certificate is throwaway, exactly as in production.
func imapClientTLSConfig() *stdtls.Config {
	return &stdtls.Config{InsecureSkipVerify: true, MinVersion: stdtls.VersionTLS12}
}

// TestIMAPClientServerHandshake runs the real client handshake against the fake
// server to confirm both halves interoperate end to end.
func TestIMAPClientServerHandshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	type clientResult struct {
		conn net.Conn
		err  error
	}
	done := make(chan clientResult, 1)
	go func() {
		conn, _, err := performIMAPClientHandshake(cli, imapTestSecret, imapClientTLSConfig())
		done <- clientResult{conn, err}
	}()

	_, _, obs, err := fakeIMAPServerHandshake(t, srv, imapTestSecret)
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("client handshake: %v", res.err)
	}
	if want := imapUsername(imapTestSecret, obs.challenge); obs.user != want {
		t.Errorf("login address = %q, want %q", obs.user, want)
	}
}

// TestIMAPTwoSessionsDifferOnTheWire is the replay half of the fix: two dials
// with the SAME secret must present different digests and different addresses,
// and neither digest may verify under the other session's challenge.
func TestIMAPTwoSessionsDifferOnTheWire(t *testing.T) {
	run := func() imapServerObservation {
		t.Helper()
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()
		go func() {
			conn, _, err := performIMAPClientHandshake(cli, imapTestSecret, imapClientTLSConfig())
			if err == nil {
				_ = conn
			}
		}()
		_, _, obs, err := fakeIMAPServerHandshake(t, srv, imapTestSecret)
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
		return obs
	}

	a, b := run(), run()
	if bytes.Equal(a.digest, b.digest) {
		t.Error("two sessions with one secret put the same digest on the wire: a capture replays")
	}
	if a.user == b.user {
		t.Error("two sessions with one secret used the same login address: the sessions are linkable")
	}
	if a.challenge == b.challenge {
		t.Error("the server reused its challenge across sessions")
	}
	// The captured digest from session A must not open session B.
	if VerifyIMAPAuthResponse(a.digest, imapTestSecret, b.challenge, b.binding) {
		t.Error("session A's digest authenticated session B")
	}
}

// TestIMAPWireCarriesNoSecretAndNoPayload reads the bytes a tap on the link
// would have collected across a full session - handshake plus tunnel traffic -
// and asks whether any of them is ours.
//
// Positive control first: the capture must contain the greeting and the
// STARTTLS command, which are in the clear by design. Without that, "the secret
// is absent" would be indistinguishable from "the recorder saw nothing".
func TestIMAPWireCarriesNoSecretAndNoPayload(t *testing.T) {
	const payload = "PAYLOAD-MARKER-MUST-NOT-APPEAR-IN-THE-CAPTURE"

	cliRaw, srv := net.Pipe()
	defer cliRaw.Close()
	defer srv.Close()
	rec := &imapTapConn{Conn: cliRaw}

	type clientResult struct {
		conn net.Conn
		br   *bufio.Reader
		err  error
	}
	done := make(chan clientResult, 1)
	go func() {
		conn, br, err := performIMAPClientHandshake(rec, imapTestSecret, imapClientTLSConfig())
		done <- clientResult{conn, br, err}
	}()

	srvTLS, srvBR, obs, err := fakeIMAPServerHandshake(t, srv, imapTestSecret)
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("client handshake: %v", res.err)
	}

	// Push user payload through the tunnel framing, both directions.
	clientTun := NewIMAPCamouflageConn(res.conn, res.br, false)
	serverTun := NewIMAPCamouflageConn(srvTLS, srvBR, true)
	go func() {
		_, _ = clientTun.Write([]byte(payload))
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(serverTun, got); err != nil {
		t.Fatalf("server read of tunnel payload: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("tunnel payload = %q, want %q", got, payload)
	}

	capture := rec.captured()

	// Positive control: the instrument can see plaintext where plaintext is.
	for _, want := range []string{"Dovecot (Ubuntu) ready.", "STARTTLS", "Begin TLS negotiation now."} {
		if !bytes.Contains(capture, []byte(want)) {
			t.Fatalf("the capture is missing %q, which is on the wire in the clear: the recorder is not seeing the link", want)
		}
	}

	// Nothing derived from the secret may appear.
	banned := map[string][]byte{
		"the secret itself":       imapTestSecret,
		"the secret in hex":       []byte(hex.EncodeToString(imapTestSecret)),
		"the secret in base64":    []byte(base64.StdEncoding.EncodeToString(imapTestSecret)),
		"the login address":       []byte(obs.user),
		"the auth digest":         obs.digest,
		"the auth digest in hex":  []byte(hex.EncodeToString(obs.digest)),
		"the server challenge":    []byte(obs.challenge),
		"the channel binding":     obs.binding,
		"the user payload":        []byte(payload),
		"an IMAP APPEND envelope": []byte("APPEND INBOX"),
	}
	// Any prefix of the secret in hex is the 1.10.x leak; check every width.
	for n := 2; n <= len(imapTestSecret); n++ {
		banned[fmt.Sprintf("the first %d bytes of the secret in hex", n)] =
			[]byte(hex.EncodeToString(imapTestSecret[:n]))
	}
	for what, b := range banned {
		if len(b) == 0 {
			t.Fatalf("%s is empty; this check would pass vacuously", what)
		}
		if bytes.Contains(capture, b) {
			t.Errorf("%s appears in the clear on the wire", what)
		}
	}

	// Everything after the tagged STARTTLS OK must be TLS records.
	marker := []byte("Begin TLS negotiation now.\r\n")
	idx := bytes.Index(capture, marker)
	if idx < 0 {
		t.Fatal("no STARTTLS OK in the capture")
	}
	rest := capture[idx+len(marker):]
	if len(rest) == 0 {
		t.Fatal("nothing was captured after the STARTTLS OK")
	}
	if rest[0] != 0x16 {
		t.Errorf("first byte after the STARTTLS OK is 0x%02x, want a TLS handshake record (0x16)", rest[0])
	}
}

// TestIMAPTapSeesPayloadOnABareSocket is the positive control for the scan in
// TestIMAPWireCarriesNoSecretAndNoPayload. It runs the same tunnel framing over
// a bare socket - which is what 1.10.x did - and requires the tap to find the
// payload and the APPEND envelope. Without this, "the payload is absent" would
// be indistinguishable from "the scan cannot find a payload at all".
func TestIMAPTapSeesPayloadOnABareSocket(t *testing.T) {
	const payload = "PAYLOAD-MARKER-MUST-NOT-APPEAR-IN-THE-CAPTURE"

	cliRaw, srv := net.Pipe()
	defer cliRaw.Close()
	defer srv.Close()
	rec := &imapTapConn{Conn: cliRaw}

	client := NewIMAPCamouflageConn(rec, nil, false)
	server := NewIMAPCamouflageConn(srv, nil, true)
	go func() {
		_, _ = client.Write([]byte(payload))
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}

	capture := rec.captured()
	for _, want := range []string{payload, "APPEND INBOX"} {
		if !bytes.Contains(capture, []byte(want)) {
			t.Errorf("the tap did not find %q in a capture that provably contains it", want)
		}
	}
}

// TestIMAPHandshakeRejectsPipeliningAcrossSTARTTLS covers the CVE-2011-0411
// class: bytes sent before the upgrade must not be carried into the session.
func TestIMAPHandshakeRejectsPipeliningAcrossSTARTTLS(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := performIMAPClientHandshake(cli, imapTestSecret, imapClientTLSConfig())
		errCh <- err
	}()

	br := bufio.NewReader(srv)
	if _, err := br.ReadString('\n'); err != nil { // greeting
		t.Fatalf("greeting: %v", err)
	}
	capLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CAPABILITY: %v", err)
	}
	fmt.Fprintf(srv, "%s%s OK done.\r\n", IMAPPreLoginCaps(), strings.Fields(capLine)[0])
	tlsLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("STARTTLS: %v", err)
	}
	// The OK, and then an injected line that a real server would never send.
	fmt.Fprintf(srv, "%s OK Begin TLS negotiation now.\r\n* OK injected\r\n", strings.Fields(tlsLine)[0])

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("the client carried pipelined plaintext into the TLS session")
		}
		if !strings.Contains(err.Error(), errIMAPPipelined.Error()) {
			t.Errorf("error = %v, want the pipelining refusal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client neither failed nor completed")
	}
}

// ---------------------------------------------------------------------------
// Literal framing limits
// ---------------------------------------------------------------------------

// TestIMAPReadRefusesOversizedLiteral checks the cap at the allocation site. A
// literal length is the peer's word for how many bytes to reserve; before
// 1.11.0 Read passed it straight to make, so one line named any allocation the
// peer liked.
func TestIMAPReadRefusesOversizedLiteral(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{"just over the cap", fmt.Sprintf("* 7 FETCH (BODY[] {%d}\r\n", maxIMAPLiteralLen+1), true},
		{"absurd", "* 7 FETCH (BODY[] {9000000000}\r\n", true},
		{"at the cap", fmt.Sprintf("* 7 FETCH (BODY[] {%d}\r\n", maxIMAPLiteralLen), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()
			defer srv.Close()

			go func() {
				_, _ = srv.Write([]byte(c.header))
				// Deliberately never send the body: a Read that honoured the
				// length would block here, and a Read that allocated first
				// would already have done the damage.
			}()

			conn := NewIMAPCamouflageConn(cli, nil, false)
			_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := conn.Read(make([]byte, 16))
			if c.wantErr {
				if err == nil {
					t.Fatal("an over-long literal was accepted")
				}
				if !strings.Contains(err.Error(), "exceeds the") {
					t.Fatalf("error = %v, want the literal cap refusal", err)
				}
				return
			}
			// At the cap the length is legal, so the failure must be the
			// missing body (timeout), not the cap.
			if err != nil && strings.Contains(err.Error(), "exceeds the") {
				t.Fatalf("a literal exactly at the cap was refused: %v", err)
			}
		})
	}
}

// TestIMAPWriteSplitsAtTheCap makes sure we never announce a literal the read
// side would refuse: a single large Write has to come out as several frames.
func TestIMAPWriteSplitsAtTheCap(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	payload := bytes.Repeat([]byte{0x7E}, maxIMAPLiteralLen+4096)
	writeErr := make(chan error, 1)
	go func() {
		client := NewIMAPCamouflageConn(cli, nil, false)
		n, err := client.Write(payload)
		if err == nil && n != len(payload) {
			err = fmt.Errorf("Write returned %d, want %d", n, len(payload))
		}
		writeErr <- err
	}()

	server := NewIMAPCamouflageConn(srv, nil, true)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the split changed the byte stream")
	}
}
