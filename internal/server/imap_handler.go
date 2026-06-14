package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// base64DecodeToken decodes the base64-encoded auth token from the LOGIN
// password field, tolerating both padded and unpadded encodings.
func base64DecodeToken(s string) ([]byte, error) {
	if tok, err := base64.StdEncoding.DecodeString(s); err == nil {
		return tok, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// DetectIMAPCamouflage reports whether the peeked bytes are the start of an
// IMAP camouflage session. The tunnel initiator opens with the unsolicited
// Dovecot greeting ("* OK [CAPABILITY ...] Dovecot (Ubuntu) ready."), so we
// match the "* OK" status prefix plus an IMAP/Dovecot marker. Real IMAP is
// server-speaks-first; emitting the greeting client-side is what lets this
// stateless peek classify the connection.
func DetectIMAPCamouflage(peek []byte) bool {
	if !bytes.HasPrefix(peek, []byte("* OK")) {
		return false
	}
	return bytes.Contains(peek, []byte("Dovecot")) || bytes.Contains(peek, []byte("IMAP"))
}

// handleIMAPCamouflage drives the server side of the fake IMAP handshake and
// then delegates the tunnel phase to handleRawTunnel over an IMAP-framed
// connection.
func handleIMAPCamouflage(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing IMAP camouflage connection")

	clientID, br, err := imapServerHandshake(conn, srvCtx, logger)
	if err != nil {
		logger.Debug("IMAP camouflage handshake failed: %v", err)
		serveFakeWebsite(conn, srvCtx.cfg, logger)
		return
	}

	logger.Info("IMAP camouflage authenticated (clientID=%s)", clientID)

	// Once IMAP literal framing is stripped the stream is a clean byte channel,
	// so handleRawTunnel (which already supports SOCKS proxy and TUN mode) runs
	// over it unchanged.
	imapConn := strategy.NewIMAPCamouflageConn(conn, br, true)
	handleRawTunnel(imapConn, srvCtx, logger, clientID)
}

// imapServerHandshake reads the client greeting, answers CAPABILITY, verifies
// the LOGIN auth token and answers SELECT INBOX. On success it returns the
// matched client ID (or "global") and the buffered reader for the tunnel phase.
func imapServerHandshake(conn net.Conn, srvCtx *serverContext, logger *log.Logger) (string, *bufio.Reader, error) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// 1. Read the unsolicited greeting line the client opened with.
	greeting, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("reading client greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return "", nil, fmt.Errorf("not an IMAP greeting")
	}

	// 2. CAPABILITY.
	capLine, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("reading CAPABILITY: %w", err)
	}
	capTag := imapTag(capLine)
	if capTag == "" || !strings.Contains(capLine, "CAPABILITY") {
		return "", nil, fmt.Errorf("expected CAPABILITY command")
	}
	if _, err := conn.Write([]byte(strategy.IMAPPreLoginCaps())); err != nil {
		return "", nil, err
	}
	if _, err := conn.Write([]byte(capTag + " OK Pre-login capabilities listed, post-login capabilities have more.\r\n")); err != nil {
		return "", nil, err
	}

	// 3. LOGIN <user> <base64-token>.
	loginLine, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("reading LOGIN: %w", err)
	}
	fields := strings.Fields(loginLine)
	if len(fields) < 4 || !strings.EqualFold(fields[1], "LOGIN") {
		return "", nil, fmt.Errorf("malformed LOGIN command")
	}
	loginTag := fields[0]
	token, err := base64DecodeToken(fields[3])
	if err != nil {
		return "", nil, fmt.Errorf("decoding LOGIN token: %w", err)
	}

	clientID, _, ok := verifyIMAPAuth(token, srvCtx)
	if !ok {
		// Look like a real auth rejection before bailing out.
		_, _ = conn.Write([]byte(loginTag + " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"))
		return "", nil, fmt.Errorf("auth token verification failed")
	}

	if _, err := conn.Write([]byte(strategy.IMAPPostLoginCaps())); err != nil {
		return "", nil, err
	}
	if _, err := conn.Write([]byte(fmt.Sprintf("%s OK [CAPABILITY %s] Logged in\r\n", loginTag, strategy.IMAPCapsInline()))); err != nil {
		return "", nil, err
	}

	// 4. SELECT INBOX.
	selectLine, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("reading SELECT: %w", err)
	}
	selectTag := imapTag(selectLine)
	if selectTag == "" || !strings.Contains(strings.ToUpper(selectLine), "SELECT") {
		return "", nil, fmt.Errorf("expected SELECT command")
	}
	if _, err := conn.Write([]byte(buildIMAPSelectResponse(selectTag))); err != nil {
		return "", nil, err
	}

	conn.SetDeadline(time.Time{})
	return clientID, br, nil
}

// imapTag returns the leading tag token of an IMAP command line, or "" if the
// line is empty.
func imapTag(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// buildIMAPSelectResponse builds a realistic SELECT INBOX response with a
// randomised message count, mirroring what Dovecot returns for a populated
// mailbox.
func buildIMAPSelectResponse(tag string) string {
	exists := 1000 + rand.Intn(49000) // 1000..49999 messages
	recent := rand.Intn(8)            // 0..7 recently arrived
	unseen := 1 + rand.Intn(exists)   // first unseen message number
	uidValidity := 1_000_000_000 + rand.Intn(900_000_000)
	uidNext := exists + 1

	var b strings.Builder
	fmt.Fprintf(&b, "* %d EXISTS\r\n", exists)
	fmt.Fprintf(&b, "* %d RECENT\r\n", recent)
	fmt.Fprintf(&b, "* OK [UNSEEN %d] Message %d is first unseen\r\n", unseen, unseen)
	fmt.Fprintf(&b, "* OK [UIDVALIDITY %d] UIDs valid\r\n", uidValidity)
	fmt.Fprintf(&b, "* OK [UIDNEXT %d] Predicted next UID\r\n", uidNext)
	b.WriteString("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
	b.WriteString("* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.\r\n")
	fmt.Fprintf(&b, "%s OK [READ-WRITE] Select completed (0.001 + 0.000 secs).\r\n", tag)
	return b.String()
}

// verifyIMAPAuth checks the token against per-client secrets (registry) and
// then the global secret. Returns the matched client ID, the secret used, and
// whether authentication succeeded.
func verifyIMAPAuth(token []byte, srvCtx *serverContext) (string, []byte, bool) {
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			secret := []byte(client.Secret)
			if strategy.VerifyIMAPAuthToken(token, secret) {
				return client.ID, secret, true
			}
		}
	}
	if len(srvCtx.cfg.Secret) > 0 && strategy.VerifyIMAPAuthToken(token, srvCtx.cfg.Secret) {
		return "global", srvCtx.cfg.Secret, true
	}
	return "", nil, false
}
