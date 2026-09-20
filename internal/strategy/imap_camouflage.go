package strategy

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Measured 2026-09-20 against imap.mail.ru:143 and imap.yandex.ru:143, one
// connection each: both advertise "IMAP4rev1 ... STARTTLS LOGINDISABLED" before
// the upgrade and offer no plaintext AUTH mechanism there, and Yandex answers
// STARTTLS with the exact string "OK Begin TLS negotiation now." The constants
// below follow that, with the banner and the capability set kept at Dovecot
// 2.3's (the version Ubuntu ships, which is what the greeting claims to be).
//
// IMAP camouflage disguises tunnel traffic as a public IMAP mail session
// (the kind a desktop client makes to a self-hosted Dovecot mailbox). To a DPI
// observer the wire looks like: a Dovecot greeting, a CAPABILITY round trip, a
// STARTTLS upgrade, and then TLS records for the rest of the connection —
// exactly the shape of IMAP on port 143 against a server configured with
// disable_plaintext_auth=yes, which is the Dovecot default.
//
// Everything that identifies or authenticates the client happens INSIDE the
// TLS session: the SASL exchange, the mailbox selection and the FETCH/APPEND
// literals that carry tunnel payload. Before 1.11.0 all of it was on the bare
// socket, which put the first four bytes of the shared secret and every byte
// the user sent in front of the observer.
//
// Dispatch note: the server classifies connections by peeking the first bytes
// the *client* sends. Real IMAP is server-speaks-first, but to fit that
// stateless dispatch the tunnel initiator emits the Dovecot greeting itself as
// its opening bytes. The bytes are byte-for-byte what a real Dovecot server
// sends; only the direction differs, which a stateless prefix matcher cannot
// see. Keeping the greeting in the clear is also what keeps the STARTTLS story
// coherent: a TLS ClientHello as the very first thing on the wire would be
// IMAPS, not IMAP.
const (
	// IMAPGreeting is the unsolicited Dovecot greeting line. The tunnel
	// initiator sends it first so the server's peek-based dispatch can class
	// the connection as IMAP camouflage. The advertised set is Dovecot's
	// pre-login set with plaintext auth disabled: STARTTLS is offered and
	// LOGINDISABLED says the client must take it before authenticating.
	IMAPGreeting = "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] Dovecot (Ubuntu) ready.\r\n"

	// imapPreLoginCaps is the untagged CAPABILITY line returned before
	// STARTTLS. No AUTH= mechanism is advertised: with LOGINDISABLED set,
	// Dovecot offers none until the connection is secured.
	imapPreLoginCaps = "* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE LITERAL+ STARTTLS LOGINDISABLED\r\n"

	// imapPostSTARTTLSCaps is the untagged CAPABILITY line returned inside the
	// TLS session. STARTTLS and LOGINDISABLED are gone and the SASL mechanisms
	// appear, which is what a client re-issuing CAPABILITY after the upgrade
	// (RFC 3501 6.2.1) expects to see change.
	imapPostSTARTTLSCaps = "* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE LITERAL+ AUTH=CRAM-MD5 AUTH=PLAIN AUTH=LOGIN\r\n"

	// imapPostLoginCaps is the untagged CAPABILITY line returned after login
	// (no AUTH= advertised once authenticated).
	imapPostLoginCaps = "* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE\r\n"

	// imapCapsInline is the bracketed capability list embedded in the tagged
	// "Logged in" OK response.
	imapCapsInline = "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE"
)

const (
	// imapAuthCtx separates the auth MAC from every other value derived from
	// the same secret. The "v2" marks the break with 1.10.x, whose token was
	// an HMAC over a constant and the wall clock — an input an observer knew
	// in full, so the token was both replayable and an offline oracle for
	// guessing the secret.
	imapAuthCtx = "imap-auth-v2"

	// imapUserCtx derives the local part of the login address. It is keyed by
	// the server's per-session challenge, so the address shown in one session
	// cannot be tied to the address shown in the next.
	imapUserCtx = "imap-user"

	// imapAuthLen is the digest width on the wire. 16 bytes is 32 hex
	// characters, which is exactly the field width RFC 2195 gives CRAM-MD5,
	// and 128 bits of MAC is far more than a forgery attempt gets to try.
	imapAuthLen = 16

	// imapMailDomain is the domain half of the login address. It is a
	// plausibility choice only: we have no measured corpus of IMAP usernames
	// to match a distribution against, and the field never leaves the TLS
	// session, so nothing on the wire depends on it.
	imapMailDomain = "icloud.com"

	// imapChannelBindingLabel and imapChannelBindingLen are the RFC 9266
	// tls-exporter parameters.
	imapChannelBindingLabel = "EXPORTER-Channel-Binding"
	imapChannelBindingLen   = 32

	// maxIMAPLiteralLen caps a literal length announced by the peer. Tunnel
	// frames are one relay buffer at most (tens of KB); a megabyte leaves that
	// an order of magnitude of headroom while keeping a hostile peer from
	// naming a length we would allocate.
	maxIMAPLiteralLen = 1 << 20

	// imapHandshakeTimeout bounds the whole pre-tunnel exchange, TLS included.
	imapHandshakeTimeout = 15 * time.Second
)

// errIMAPPipelined reports data buffered where the protocol forbids it. A peer
// that pipelines past STARTTLS is either broken or trying the command
// injection of CVE-2011-0411, where bytes sent before the upgrade are replayed
// as if they had arrived inside the TLS session.
var errIMAPPipelined = errors.New("data pipelined across the STARTTLS boundary")

// IMAPPreLoginCaps returns the untagged CAPABILITY line sent before STARTTLS.
func IMAPPreLoginCaps() string { return imapPreLoginCaps }

// IMAPPostSTARTTLSCaps returns the untagged CAPABILITY line sent inside the TLS
// session, before authentication.
func IMAPPostSTARTTLSCaps() string { return imapPostSTARTTLSCaps }

// IMAPPostLoginCaps returns the untagged CAPABILITY line sent after login.
func IMAPPostLoginCaps() string { return imapPostLoginCaps }

// IMAPCapsInline returns the capability list embedded in the tagged "Logged in"
// OK response.
func IMAPCapsInline() string { return imapCapsInline }

// IMAPCamouflageStrategy implements the Strategy interface over a fake IMAP session.
type IMAPCamouflageStrategy struct {
	manager *Manager
	secret  []byte
}

// NewIMAPCamouflageStrategy creates a new IMAP camouflage strategy.
func NewIMAPCamouflageStrategy(manager *Manager, secret []byte) *IMAPCamouflageStrategy {
	return &IMAPCamouflageStrategy{manager: manager, secret: secret}
}

func (s *IMAPCamouflageStrategy) Name() string { return "IMAP Camouflage" }

func (s *IMAPCamouflageStrategy) ID() string { return "imap_camouflage" }

func (s *IMAPCamouflageStrategy) Priority() int { return 29 }

func (s *IMAPCamouflageStrategy) Description() string {
	return "Disguises tunnel traffic as a public IMAP mail session (Dovecot greeting, STARTTLS, SASL login, FETCH/APPEND) so DPI sees email sync"
}

func (s *IMAPCamouflageStrategy) RequiresServer() bool { return true }

func (s *IMAPCamouflageStrategy) Probe(ctx context.Context, target string) error {
	conn, err := net.DialTimeout("tcp", target, imapHandshakeTimeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Connect dials the server, runs the plaintext part of the IMAP exchange,
// upgrades to TLS via STARTTLS and authenticates inside it. The connection
// handed back to the caller is the TLS one, so every tunnel byte is encrypted.
func (s *IMAPCamouflageStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	serverAddr := s.manager.GetServerAddr(ctx)
	secret := dialSecret(ctx, s.secret)
	log.Debug("IMAP Camouflage: connecting to %s (TCP, IMAP STARTTLS handshake)", serverAddr)

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	tlsConn, br, err := performIMAPClientHandshake(conn, secret, s.clientTLSConfig(serverAddr))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("imap camouflage handshake: %w", err)
	}

	return NewIMAPCamouflageConn(tlsConn, br, false), nil
}

// clientTLSConfig builds the TLS config for the STARTTLS upgrade. SNI carries
// the dialled hostname when there is one and is omitted when the endpoint is a
// bare address, which is what a mail client reaching a self-hosted server by IP
// would do. The certificate is not verified: the server presents its
// donor-shaped leaf, and what actually authenticates the peer pair is the
// channel-bound SASL exchange that follows (see IMAPChannelBinding).
func (s *IMAPCamouflageStrategy) clientTLSConfig(serverAddr string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if s.manager != nil {
		cfg.ClientSessionCache = s.manager.TLSSessionCache()
	}
	if host, _, err := net.SplitHostPort(serverAddr); err == nil && net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	return cfg
}

// performIMAPClientHandshake drives the client side of the IMAP exchange. It
// returns the TLS connection the tunnel must run over and the buffered reader
// positioned after the SELECT response, so the tunnel phase reuses any bytes
// read ahead.
func performIMAPClientHandshake(conn net.Conn, secret []byte, tlsCfg *tls.Config) (net.Conn, *bufio.Reader, error) {
	conn.SetDeadline(time.Now().Add(imapHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// 1. Emit the Dovecot greeting first so the server's peek-based dispatch
	//    classifies us as IMAP camouflage.
	if _, err := conn.Write([]byte(IMAPGreeting)); err != nil {
		return nil, nil, err
	}
	// 2. CAPABILITY on the bare socket.
	if _, err := conn.Write([]byte("A001 CAPABILITY\r\n")); err != nil {
		return nil, nil, err
	}
	if err := readIMAPUntilTagged(br, "A001"); err != nil {
		return nil, nil, fmt.Errorf("CAPABILITY: %w", err)
	}
	// 3. STARTTLS. RFC 3501 6.2.1: the negotiation starts immediately after
	//    the CRLF of the tagged OK, and nothing may follow it in the clear.
	if _, err := conn.Write([]byte("A002 STARTTLS\r\n")); err != nil {
		return nil, nil, err
	}
	if err := readIMAPUntilTagged(br, "A002"); err != nil {
		return nil, nil, fmt.Errorf("STARTTLS: %w", err)
	}
	if br.Buffered() != 0 {
		return nil, nil, fmt.Errorf("STARTTLS: %w", errIMAPPipelined)
	}

	// 4. TLS. Everything from here on is invisible to an on-path observer.
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("TLS: %w", err)
	}
	binding, err := IMAPChannelBinding(tlsConn.ConnectionState())
	if err != nil {
		return nil, nil, fmt.Errorf("channel binding: %w", err)
	}
	br = bufio.NewReader(tlsConn)

	// 5. Re-issue CAPABILITY inside TLS: the pre-STARTTLS list is void and a
	//    real client discards it.
	if _, err := tlsConn.Write([]byte("A003 CAPABILITY\r\n")); err != nil {
		return nil, nil, err
	}
	if err := readIMAPUntilTagged(br, "A003"); err != nil {
		return nil, nil, fmt.Errorf("CAPABILITY (TLS): %w", err)
	}

	// 6. SASL CRAM-MD5: the server speaks first with a challenge, so the MAC
	//    the client returns is over an input the client did not pick.
	if _, err := tlsConn.Write([]byte("A004 AUTHENTICATE CRAM-MD5\r\n")); err != nil {
		return nil, nil, err
	}
	challenge, err := readIMAPChallenge(br)
	if err != nil {
		return nil, nil, fmt.Errorf("AUTHENTICATE: %w", err)
	}
	resp := FormatIMAPAuthResponse(
		imapUsername(secret, challenge),
		IMAPAuthResponse(secret, challenge, binding),
	)
	if _, err := fmt.Fprintf(tlsConn, "%s\r\n", resp); err != nil {
		return nil, nil, err
	}
	if err := readIMAPUntilTagged(br, "A004"); err != nil {
		return nil, nil, fmt.Errorf("AUTHENTICATE: %w", err)
	}

	// 7. SELECT INBOX.
	if _, err := tlsConn.Write([]byte("A005 SELECT INBOX\r\n")); err != nil {
		return nil, nil, err
	}
	if err := readIMAPUntilTagged(br, "A005"); err != nil {
		return nil, nil, fmt.Errorf("SELECT: %w", err)
	}

	return tlsConn, br, nil
}

// readIMAPUntilTagged reads response lines until it sees the line tagged with
// tag. An "OK" status returns nil; "NO"/"BAD" (or anything else) is an error.
// Untagged ("* ...") lines are consumed and ignored.
func readIMAPUntilTagged(br *bufio.Reader, tag string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, tag+" ") {
			continue // untagged data line
		}
		rest := strings.TrimSpace(line[len(tag)+1:])
		if strings.HasPrefix(rest, "OK") {
			return nil
		}
		return fmt.Errorf("tagged response: %q", strings.TrimSpace(line))
	}
}

// readIMAPChallenge reads the server's SASL continuation ("+ <base64>") and
// returns the decoded challenge.
func readIMAPChallenge(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(line, "+ ") {
		return "", fmt.Errorf("expected a SASL continuation, got %q", strings.TrimSpace(line))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[2:]))
	if err != nil {
		return "", fmt.Errorf("decoding challenge: %w", err)
	}
	if len(raw) == 0 {
		return "", errors.New("empty challenge")
	}
	return string(raw), nil
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

// IMAPChannelBinding returns the RFC 9266 tls-exporter value for a TLS session.
// Mixing it into the auth MAC ties the credential to this exact TLS session: a
// man in the middle that terminates TLS sees a different exporter on each side,
// so the response it captures from the client does not verify at the server.
func IMAPChannelBinding(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(imapChannelBindingLabel, nil, imapChannelBindingLen)
}

// NewIMAPAuthChallenge mints the server's SASL challenge. The form is the RFC
// 2195 msg-id Dovecot emits — <random.timestamp@hostname> with the random half
// the width of a 31-bit PRNG draw. We have no capture of real Dovecot
// challenges to match a distribution against, so the width is copied from
// Dovecot's own formatting rather than measured; the unpredictability the auth
// actually rests on is the 32-byte TLS exporter mixed in beside it, not this
// string.
func NewIMAPAuthChallenge() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(b[:]) >> 1
	return fmt.Sprintf("<%d.%d@mail.%s>", n, time.Now().Unix(), imapMailDomain), nil
}

// imapAuthMAC computes HMAC-SHA256 over length-prefixed fields so no choice of
// challenge can shift bytes between them.
func imapAuthMAC(secret []byte, ctx, challenge string, binding []byte) []byte {
	h := hmac.New(sha256.New, secret)
	writeLenPrefixed(h, []byte(ctx))
	writeLenPrefixed(h, []byte(challenge))
	writeLenPrefixed(h, binding)
	return h.Sum(nil)
}

func writeLenPrefixed(w io.Writer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, _ = w.Write(l[:])
	_, _ = w.Write(b)
}

// IMAPAuthResponse computes the digest the client returns for the server's
// challenge. Both the challenge and the TLS exporter are inputs, so the value
// is useless in any other session and cannot be precomputed against a guess at
// the secret before the session exists.
func IMAPAuthResponse(secret []byte, challenge string, binding []byte) []byte {
	return imapAuthMAC(secret, imapAuthCtx, challenge, binding)[:imapAuthLen]
}

// VerifyIMAPAuthResponse checks a received digest. A missing challenge or
// binding is refused outright: accepting either empty would silently restore
// the predictable input this replaced.
func VerifyIMAPAuthResponse(digest, secret []byte, challenge string, binding []byte) bool {
	if len(digest) != imapAuthLen || len(secret) == 0 {
		return false
	}
	if challenge == "" || len(binding) != imapChannelBindingLen {
		return false
	}
	return hmac.Equal(digest, IMAPAuthResponse(secret, challenge, binding))
}

// imapUsername derives the local part of the login address from the secret and
// the server's challenge. Keying it on the challenge is what stops the address
// from being a stable handle an observer inside the TLS session could use to
// tie a client's sessions together; before 1.11.0 the local part was the first
// four bytes of the secret in hex, which was both a stable handle and 32 bits
// of the key in the clear.
func imapUsername(secret []byte, challenge string) string {
	mac := imapAuthMAC(secret, imapUserCtx, challenge, nil)
	return hex.EncodeToString(mac[:8]) + "@" + imapMailDomain
}

// FormatIMAPAuthResponse encodes the CRAM-MD5 client response exactly as RFC
// 2195 section 2 specifies it: base64 of "<username> <hex digest>".
func FormatIMAPAuthResponse(user string, digest []byte) string {
	return base64.StdEncoding.EncodeToString([]byte(user + " " + hex.EncodeToString(digest)))
}

// ParseIMAPAuthResponse splits a decoded CRAM-MD5 client response into its
// username and digest.
func ParseIMAPAuthResponse(raw []byte) (user string, digest []byte, err error) {
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		return "", nil, fmt.Errorf("malformed SASL response")
	}
	digest, err = hex.DecodeString(fields[1])
	if err != nil {
		return "", nil, fmt.Errorf("decoding SASL digest: %w", err)
	}
	if len(digest) != imapAuthLen {
		return "", nil, fmt.Errorf("SASL digest is %d bytes, want %d", len(digest), imapAuthLen)
	}
	return fields[0], digest, nil
}

// ---------------------------------------------------------------------------
// IMAP literal framing helpers
// ---------------------------------------------------------------------------

// parseIMAPLiteralLen inspects a command/response line and reports whether it
// carries a tunnel-data literal and, if so, its byte length. Data-carrying
// lines are a client APPEND ("A<seq> APPEND INBOX (\Seen) {N}") or a server
// FETCH ("* <seq> FETCH (BODY[] {N}"). Everything else (NOOP, "* OK Still
// here", etc.) is a keepalive and returns ok=false.
func parseIMAPLiteralLen(line string) (litLen int, ok bool) {
	s := strings.TrimRight(line, "\r\n")
	isAppend := strings.HasPrefix(s, "A") && strings.Contains(s, "APPEND")
	isFetch := strings.HasPrefix(s, "* ") && strings.Contains(s, "FETCH")
	if !isAppend && !isFetch {
		return 0, false
	}
	open := strings.LastIndexByte(s, '{')
	closeb := strings.LastIndexByte(s, '}')
	if open < 0 || closeb < 0 || closeb < open {
		return 0, false
	}
	n, err := strconv.Atoi(s[open+1 : closeb])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// ---------------------------------------------------------------------------
// Tunnel-phase connection
// ---------------------------------------------------------------------------

// IMAPCamouflageConn wraps a post-handshake connection and frames every
// Read/Write as an IMAP FETCH/APPEND literal. The client side writes APPEND
// commands; the server side writes untagged FETCH responses. Reads accept
// whichever framing carries data and silently skip keepalive lines. Deframing
// is transparent: the caller sees the same byte stream it wrote, so this can
// carry either the SOCKS proxy address protocol or the TUN [len:4][packet]
// framing unchanged.
//
// In production the wrapped connection is the TLS one the STARTTLS upgrade
// produced, so these frames never reach the wire in the clear.
type IMAPCamouflageConn struct {
	net.Conn
	br      *bufio.Reader
	server  bool // true on the server side (writes FETCH), false on client (writes APPEND)
	readBuf []byte
	seq     int
	writeMu sync.Mutex
}

// NewIMAPCamouflageConn wraps an already-handshaked connection for the tunnel
// phase. br may be the reader threaded out of the handshake (to preserve
// read-ahead bytes); pass nil to start a fresh one. server selects the write
// framing (FETCH vs APPEND).
//
// The data path is deliberately unshaped: every Write emits its IMAP frame
// immediately. The imap_sync shaper models multi-second idle gaps that fit
// cover traffic but would collapse VPN throughput, so it must never gate
// real tunnel data. (Idle camouflage, if ever added, belongs in a separate
// NOOP keepalive goroutine, not on this write path.)
func NewIMAPCamouflageConn(conn net.Conn, br *bufio.Reader, server bool) *IMAPCamouflageConn {
	if br == nil {
		br = bufio.NewReader(conn)
	}
	return &IMAPCamouflageConn{
		Conn:   conn,
		br:     br,
		server: server,
		seq:    5, // handshake used A001..A005; tunnel sequence starts at 6
	}
}

func (c *IMAPCamouflageConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		litLen, ok := parseIMAPLiteralLen(line)
		if !ok {
			continue // keepalive (NOOP / "* OK Still here")
		}
		// The length is the peer's word for how much to allocate. Cap it
		// before the make, and fail the connection rather than resync: a
		// literal this long means the stream is hostile or already lost.
		if litLen > maxIMAPLiteralLen {
			return 0, fmt.Errorf("imap literal of %d bytes exceeds the %d byte cap", litLen, maxIMAPLiteralLen)
		}
		data := make([]byte, litLen)
		if _, err := io.ReadFull(c.br, data); err != nil {
			return 0, err
		}
		// Consume the literal terminator line: "\r\n" for APPEND, ")\r\n" for
		// FETCH. ReadString stops at the first '\n' after the literal bytes.
		if _, err := c.br.ReadString('\n'); err != nil {
			return 0, err
		}
		if litLen == 0 {
			continue
		}
		n := copy(p, data)
		if n < len(data) {
			c.readBuf = append(c.readBuf, data[n:]...)
		}
		return n, nil
	}
}

func (c *IMAPCamouflageConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Never announce a literal the peer would refuse: split at the same cap
	// the read side enforces.
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxIMAPLiteralLen {
			chunk = chunk[:maxIMAPLiteralLen]
		}
		if err := c.writeFrame(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// writeFrame emits one literal. The caller holds writeMu.
func (c *IMAPCamouflageConn) writeFrame(p []byte) error {
	c.seq++
	var header, trailer string
	if c.server {
		header = fmt.Sprintf("* %d FETCH (BODY[] {%d}\r\n", c.seq, len(p))
		trailer = ")\r\n"
	} else {
		header = fmt.Sprintf("A%03d APPEND INBOX (\\Seen) {%d}\r\n", c.seq, len(p))
		trailer = "\r\n"
	}

	frame := make([]byte, 0, len(header)+len(p)+len(trailer))
	frame = append(frame, header...)
	frame = append(frame, p...)
	frame = append(frame, trailer...)

	_, err := c.Conn.Write(frame)
	return err
}

// NetConn exposes the underlying connection so optimizeTCPConn can reach the
// raw *net.TCPConn for TCP_NODELAY and buffer tuning. In production the next
// link in the chain is the *tls.Conn, which exposes its own NetConn().
func (c *IMAPCamouflageConn) NetConn() net.Conn { return c.Conn }
