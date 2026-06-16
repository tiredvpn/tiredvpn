package strategy

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// IMAP camouflage disguises tunnel traffic as a public IMAP mail session
// (the kind a desktop client makes to mail.ru / icloud.com / gmail). To a DPI
// observer the wire looks like: a Dovecot greeting, a CAPABILITY round trip, a
// LOGIN, a SELECT INBOX, then a long-lived stream of FETCH/APPEND commands
// carrying message bodies. None of it is real mail — the LOGIN password field
// carries our HMAC auth token and the FETCH/APPEND literals carry already
// TiredVPN-encrypted payload wrapped in IMAP literal framing.
//
// Dispatch note: the server classifies connections by peeking the first bytes
// the *client* sends. Real IMAP is server-speaks-first, but to fit that
// stateless dispatch the tunnel initiator emits the Dovecot greeting itself as
// its opening bytes. The bytes are byte-for-byte what a real Dovecot server
// sends; only the direction differs, which a stateless prefix matcher cannot
// see. Everything after the greeting follows the documented IMAP exchange.
const (
	// IMAPGreeting is the unsolicited Dovecot greeting line. The tunnel
	// initiator sends it first so the server's peek-based dispatch can class
	// the connection as IMAP camouflage.
	IMAPGreeting = "* OK [CAPABILITY IMAP4rev2 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.\r\n"

	// imapPreLoginCaps is the untagged CAPABILITY line returned before login.
	imapPreLoginCaps = "* CAPABILITY IMAP4rev2 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE LITERAL+ STARTTLS AUTH=PLAIN\r\n"

	// imapPostLoginCaps is the untagged CAPABILITY line returned after login
	// (no STARTTLS/AUTH advertised once authenticated).
	imapPostLoginCaps = "* CAPABILITY IMAP4rev2 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE\r\n"

	// imapCapsInline is the bracketed capability list embedded in the tagged
	// "Logged in" OK response.
	imapCapsInline = "IMAP4rev2 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE SAVEDATE QUOTA QUOTA=STORAGE QUOTA=MESSAGE SPECIAL-USE"

	imapAuthCtx    = "imap-auth"
	imapAuthBucket = 300 // seconds per auth time bucket
	imapAuthLen    = 32
)

// IMAPPreLoginCaps returns the untagged CAPABILITY line sent before login.
func IMAPPreLoginCaps() string { return imapPreLoginCaps }

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
	return "Disguises tunnel traffic as a public IMAP mail session (Dovecot greeting, LOGIN, SELECT, FETCH/APPEND) so DPI sees email sync"
}

func (s *IMAPCamouflageStrategy) RequiresServer() bool { return true }

func (s *IMAPCamouflageStrategy) Probe(ctx context.Context, target string) error {
	conn, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Connect dials the server over plain TCP and performs the fake IMAP handshake.
func (s *IMAPCamouflageStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("IMAP Camouflage: connecting to %s (raw TCP, fake IMAP handshake)", serverAddr)

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	br, err := performIMAPClientHandshake(conn, s.secret)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("imap camouflage handshake: %w", err)
	}

	return NewIMAPCamouflageConn(conn, br, false), nil
}

// performIMAPClientHandshake drives the client side of the fake IMAP handshake
// and returns the buffered reader so the tunnel phase can reuse any bytes the
// handshake read ahead.
func performIMAPClientHandshake(conn net.Conn, secret []byte) (*bufio.Reader, error) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// 1. Emit the Dovecot greeting first so the server's peek-based dispatch
	//    classifies us as IMAP camouflage.
	if _, err := conn.Write([]byte(IMAPGreeting)); err != nil {
		return nil, err
	}
	// 2. CAPABILITY.
	if _, err := conn.Write([]byte("A001 CAPABILITY\r\n")); err != nil {
		return nil, err
	}
	if err := readIMAPUntilTagged(br, "A001"); err != nil {
		return nil, fmt.Errorf("CAPABILITY: %w", err)
	}
	// 3. LOGIN with the auth token base64-encoded in the password field.
	user := imapUsername(secret)
	token := GenerateIMAPAuthToken(secret)
	pw := base64.StdEncoding.EncodeToString(token)
	if _, err := fmt.Fprintf(conn, "A002 LOGIN %s %s\r\n", user, pw); err != nil {
		return nil, err
	}
	if err := readIMAPUntilTagged(br, "A002"); err != nil {
		return nil, fmt.Errorf("LOGIN: %w", err)
	}
	// 4. SELECT INBOX.
	if _, err := conn.Write([]byte("A003 SELECT INBOX\r\n")); err != nil {
		return nil, err
	}
	if err := readIMAPUntilTagged(br, "A003"); err != nil {
		return nil, fmt.Errorf("SELECT: %w", err)
	}
	return br, nil
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

// imapUsername derives a plausible iCloud address from the first 4 bytes of the
// secret (8 hex chars). The server does not validate it; it only has to look
// like a real login to DPI.
func imapUsername(secret []byte) string {
	n := 4
	if len(secret) < n {
		n = len(secret)
	}
	return hex.EncodeToString(secret[:n]) + "@icloud.com"
}

// ---------------------------------------------------------------------------
// Auth token
// ---------------------------------------------------------------------------

// imapAuthTokenForBucket computes HMAC-SHA256(secret, "imap-auth" || bucket)
// where bucket is the 8-byte big-endian time bucket.
func imapAuthTokenForBucket(secret []byte, bucket uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], bucket)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(imapAuthCtx))
	h.Write(b[:])
	return h.Sum(nil)
}

// GenerateIMAPAuthToken returns the current auth token for the given secret.
func GenerateIMAPAuthToken(secret []byte) []byte {
	bucket := uint64(time.Now().Unix() / imapAuthBucket)
	return imapAuthTokenForBucket(secret, bucket)
}

// VerifyIMAPAuthToken checks a received token against the current time bucket
// and the adjacent ones (±1), tolerating clock skew the same way the SSH
// strategy does.
func VerifyIMAPAuthToken(token, secret []byte) bool {
	if len(token) != imapAuthLen {
		return false
	}
	current := time.Now().Unix() / imapAuthBucket
	for offset := int64(-1); offset <= 1; offset++ {
		expected := imapAuthTokenForBucket(secret, uint64(current+offset))
		if hmac.Equal(token, expected) {
			return true
		}
	}
	return false
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
		seq:    3, // handshake used A001..A003; tunnel sequence starts at 4
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

	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// NetConn exposes the underlying connection so optimizeTCPConn can reach the
// raw *net.TCPConn for TCP_NODELAY and buffer tuning.
func (c *IMAPCamouflageConn) NetConn() net.Conn { return c.Conn }
