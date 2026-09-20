package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// imapHandshakeTimeout bounds the whole pre-tunnel exchange, TLS included.
const imapHandshakeTimeout = 15 * time.Second

// base64DecodeToken decodes the base64-encoded SASL response line, tolerating
// both padded and unpadded encodings.
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
// stateless peek classify the connection. The greeting stays in the clear
// after the 1.11.0 STARTTLS change for exactly that reason — a ClientHello as
// the first bytes would be IMAPS and would land in the REALITY dispatch.
func DetectIMAPCamouflage(peek []byte) bool {
	if !bytes.HasPrefix(peek, []byte("* OK")) {
		return false
	}
	return bytes.Contains(peek, []byte("Dovecot")) || bytes.Contains(peek, []byte("IMAP"))
}

// handleIMAPCamouflage drives the server side of the IMAP handshake and then
// delegates the tunnel phase to handleRawTunnel over an IMAP-framed connection
// running inside the STARTTLS session.
func handleIMAPCamouflage(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing IMAP camouflage connection")

	clientID, tlsConn, br, err := imapServerHandshake(conn, srvCtx, logger)
	if err != nil {
		logger.Debug("IMAP camouflage handshake failed: %v", err)
		if tlsConn != nil {
			// The upgrade already happened, so the peer is speaking TLS and a
			// plaintext HTTP page would be line noise to it. The rejection it
			// needs was already written inside the session.
			tlsConn.Close()
			return
		}
		serveFakeWebsite(conn, srvCtx.cfg, logger)
		return
	}

	logger.Info("IMAP camouflage authenticated (clientID=%s)", clientID)

	// Once IMAP literal framing is stripped the stream is a clean byte channel,
	// so handleRawTunnel (which already supports SOCKS proxy and TUN mode) runs
	// over it unchanged.
	imapConn := strategy.NewIMAPCamouflageConn(tlsConn, br, true)
	handleRawTunnel(imapConn, srvCtx, logger, clientID)
}

// imapServerHandshake reads the client greeting, answers CAPABILITY, upgrades
// the connection via STARTTLS and only then authenticates: the SASL exchange,
// the login address and every tunnel byte live inside TLS.
//
// The second return value is the TLS connection. It is nil until the upgrade
// completes, which is how the caller knows whether a failure may still be
// answered in the clear.
func imapServerHandshake(conn net.Conn, srvCtx *serverContext, logger *log.Logger) (clientIdentity, net.Conn, *bufio.Reader, error) {
	conn.SetDeadline(time.Now().Add(imapHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// 1. Read the unsolicited greeting line the client opened with.
	greeting, err := br.ReadString('\n')
	if err != nil {
		return clientIdentity{}, nil, nil, fmt.Errorf("reading client greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return clientIdentity{}, nil, nil, fmt.Errorf("not an IMAP greeting")
	}

	// 2. CAPABILITY on the bare socket. No AUTH= is offered here: plaintext
	//    auth is disabled, which is what makes the STARTTLS that follows the
	//    only way forward for a real client too.
	capLine, err := br.ReadString('\n')
	if err != nil {
		return clientIdentity{}, nil, nil, fmt.Errorf("reading CAPABILITY: %w", err)
	}
	capTag := imapTag(capLine)
	if capTag == "" || !strings.Contains(strings.ToUpper(capLine), "CAPABILITY") {
		return clientIdentity{}, nil, nil, fmt.Errorf("expected CAPABILITY command")
	}
	if _, err := conn.Write([]byte(strategy.IMAPPreLoginCaps())); err != nil {
		return clientIdentity{}, nil, nil, err
	}
	if _, err := conn.Write([]byte(capTag + " OK Pre-login capabilities listed, post-login capabilities have more.\r\n")); err != nil {
		return clientIdentity{}, nil, nil, err
	}

	// 3. STARTTLS.
	tlsConn, br, err := imapUpgradeToTLS(conn, br, srvCtx)
	if err != nil {
		return clientIdentity{}, nil, nil, err
	}

	// 4. The client re-issues CAPABILITY inside TLS (RFC 3501 6.2.1).
	capLine, err = br.ReadString('\n')
	if err != nil {
		return clientIdentity{}, tlsConn, nil, fmt.Errorf("reading CAPABILITY over TLS: %w", err)
	}
	capTag = imapTag(capLine)
	if capTag == "" || !strings.Contains(strings.ToUpper(capLine), "CAPABILITY") {
		return clientIdentity{}, tlsConn, nil, fmt.Errorf("expected CAPABILITY command over TLS")
	}
	if _, err := tlsConn.Write([]byte(strategy.IMAPPostSTARTTLSCaps())); err != nil {
		return clientIdentity{}, tlsConn, nil, err
	}
	if _, err := tlsConn.Write([]byte(capTag + " OK Pre-login capabilities listed, post-login capabilities have more.\r\n")); err != nil {
		return clientIdentity{}, tlsConn, nil, err
	}

	// 5. SASL.
	clientID, err := imapAuthenticate(tlsConn, br, srvCtx, logger)
	if err != nil {
		return clientIdentity{}, tlsConn, nil, err
	}

	// 6. SELECT INBOX.
	selectLine, err := br.ReadString('\n')
	if err != nil {
		return clientIdentity{}, tlsConn, nil, fmt.Errorf("reading SELECT: %w", err)
	}
	selectTag := imapTag(selectLine)
	if selectTag == "" || !strings.Contains(strings.ToUpper(selectLine), "SELECT") {
		return clientIdentity{}, tlsConn, nil, fmt.Errorf("expected SELECT command")
	}
	if _, err := tlsConn.Write([]byte(buildIMAPSelectResponse(selectTag))); err != nil {
		return clientIdentity{}, tlsConn, nil, err
	}

	conn.SetDeadline(time.Time{})
	return clientID, tlsConn, br, nil
}

// imapUpgradeToTLS reads the command that must be STARTTLS and performs the
// server side of the upgrade.
//
// A client speaking the pre-1.11.0 protocol sends LOGIN here. It gets the
// tagged NO a real Dovecot with disable_plaintext_auth=yes would send, which
// its own reader treats as a failed command, so it fails at once instead of
// waiting out the handshake deadline.
func imapUpgradeToTLS(conn net.Conn, br *bufio.Reader, srvCtx *serverContext) (*tls.Conn, *bufio.Reader, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, nil, fmt.Errorf("reading STARTTLS: %w", err)
	}
	tag := imapTag(line)
	if tag == "" {
		return nil, nil, fmt.Errorf("empty command where STARTTLS was expected")
	}
	if !strings.Contains(strings.ToUpper(line), "STARTTLS") {
		_, _ = conn.Write([]byte(tag + " NO [PRIVACYREQUIRED] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.\r\n"))
		return nil, nil, fmt.Errorf("expected STARTTLS command")
	}

	if srvCtx.tlsConfig == nil {
		return nil, nil, fmt.Errorf("no TLS configuration for the STARTTLS upgrade")
	}
	if _, err := conn.Write([]byte(tag + " OK Begin TLS negotiation now.\r\n")); err != nil {
		return nil, nil, err
	}
	// RFC 3501 6.2.1: the negotiation starts at the CRLF of that OK. Anything
	// already buffered was sent in the clear and must not be carried into the
	// session — that carry is the CVE-2011-0411 command injection.
	if br.Buffered() != 0 {
		return nil, nil, fmt.Errorf("client pipelined %d bytes across the STARTTLS boundary", br.Buffered())
	}

	tlsConn := tls.Server(conn, srvCtx.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("STARTTLS handshake: %w", err)
	}
	return tlsConn, bufio.NewReader(tlsConn), nil
}

// imapAuthenticate runs the SASL CRAM-MD5 exchange inside the TLS session. The
// server speaks first with a fresh challenge, and the digest the client returns
// is bound to both that challenge and the TLS exporter, so it is worthless in
// any other session and cannot be precomputed.
func imapAuthenticate(tlsConn *tls.Conn, br *bufio.Reader, srvCtx *serverContext, logger *log.Logger) (clientIdentity, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return clientIdentity{}, fmt.Errorf("reading AUTHENTICATE: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[1], "AUTHENTICATE") || !strings.EqualFold(fields[2], "CRAM-MD5") {
		return clientIdentity{}, fmt.Errorf("expected AUTHENTICATE CRAM-MD5")
	}
	authTag := fields[0]

	binding, err := strategy.IMAPChannelBinding(tlsConn.ConnectionState())
	if err != nil {
		return clientIdentity{}, fmt.Errorf("channel binding: %w", err)
	}
	challenge, err := strategy.NewIMAPAuthChallenge()
	if err != nil {
		return clientIdentity{}, fmt.Errorf("minting challenge: %w", err)
	}
	if _, err := fmt.Fprintf(tlsConn, "+ %s\r\n", base64.StdEncoding.EncodeToString([]byte(challenge))); err != nil {
		return clientIdentity{}, err
	}

	respLine, err := br.ReadString('\n')
	if err != nil {
		return clientIdentity{}, fmt.Errorf("reading SASL response: %w", err)
	}
	raw, err := base64DecodeToken(strings.TrimSpace(respLine))
	if err != nil {
		imapRejectAuth(tlsConn, authTag)
		return clientIdentity{}, fmt.Errorf("decoding SASL response: %w", err)
	}
	user, digest, err := strategy.ParseIMAPAuthResponse(raw)
	if err != nil {
		imapRejectAuth(tlsConn, authTag)
		return clientIdentity{}, err
	}

	clientID, _, ok := verifyIMAPAuth(digest, challenge, binding, srvCtx)
	if !ok {
		imapRejectAuth(tlsConn, authTag)
		return clientIdentity{}, fmt.Errorf("auth digest verification failed")
	}
	logger.Debug("IMAP camouflage SASL accepted for %s", user)

	if _, err := tlsConn.Write([]byte(strategy.IMAPPostLoginCaps())); err != nil {
		return clientIdentity{}, err
	}
	if _, err := fmt.Fprintf(tlsConn, "%s OK [CAPABILITY %s] Logged in\r\n", authTag, strategy.IMAPCapsInline()); err != nil {
		return clientIdentity{}, err
	}
	return clientID, nil
}

// imapRejectAuth answers a failed SASL exchange the way Dovecot does before the
// caller drops the connection.
func imapRejectAuth(w net.Conn, tag string) {
	_, _ = w.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"))
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

// verifyIMAPAuth checks the digest against per-client secrets (registry) and
// then the global secret, under the challenge and channel binding of this
// session. Returns the matched client ID, the secret used, and whether
// authentication succeeded.
func verifyIMAPAuth(digest []byte, challenge string, binding []byte, srvCtx *serverContext) (clientIdentity, []byte, bool) {
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			secret := []byte(client.Secret)
			if strategy.VerifyIMAPAuthResponse(digest, secret, challenge, binding) {
				return registryIdentity(client.ID), secret, true
			}
		}
	}
	if len(srvCtx.cfg.Secret) > 0 && strategy.VerifyIMAPAuthResponse(digest, srvCtx.cfg.Secret, challenge, binding) {
		return sharedIdentity(globalClientID), srvCtx.cfg.Secret, true
	}
	return clientIdentity{}, nil, false
}
