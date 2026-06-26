package strategy

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// SSH camouflage disguises tunnel traffic as a real SSH-2.0 session. To a DPI
// observer the wire looks like: banner exchange, KEXINIT negotiation, an ECDH
// key-exchange round trip, then an opaque stream of SSH binary packets (the
// post-kex "encrypted" phase). None of it is real SSH crypto — the ECDH public
// keys carry our HMAC auth token and the post-kex packets carry already
// TiredVPN-encrypted payload wrapped in SSH packet framing.
const (
	// SSHBanner is the identification string both sides send first. It mirrors
	// a current OpenSSH release shipped on Ubuntu so it blends with real hosts.
	SSHBanner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"

	sshMsgKexInit      = 20   // SSH_MSG_KEXINIT
	sshMsgKexECDHInit  = 30   // SSH_MSG_KEX_ECDH_INIT
	sshMsgKexECDHReply = 31   // SSH_MSG_KEX_ECDH_REPLY
	sshMsgTunnelData   = 0xFF // private message type used for the tunnel phase

	sshBlockSize  = 8
	sshMaxPacket  = 256 * 1024 // sanity cap on packet_length
	sshMaxBanner  = 255        // RFC 4253 banner line cap (excluding CRLF we are lenient)
	sshAuthCtx    = "ssh-auth"
	sshAuthBucket = 300 // seconds per auth time bucket
	sshAuthLen    = 32
)

// SSHCamouflageStrategy implements the Strategy interface over a fake SSH session.
type SSHCamouflageStrategy struct {
	manager *Manager
	secret  []byte
}

// NewSSHCamouflageStrategy creates a new SSH camouflage strategy.
func NewSSHCamouflageStrategy(manager *Manager, secret []byte) *SSHCamouflageStrategy {
	return &SSHCamouflageStrategy{manager: manager, secret: secret}
}

func (s *SSHCamouflageStrategy) Name() string { return "SSH Camouflage" }

func (s *SSHCamouflageStrategy) ID() string { return "ssh_camouflage" }

func (s *SSHCamouflageStrategy) Priority() int { return 28 }

func (s *SSHCamouflageStrategy) Description() string {
	return "Disguises tunnel traffic as an SSH-2.0 session (banner, KEXINIT, ECDH) so DPI sees an SSH login"
}

func (s *SSHCamouflageStrategy) RequiresServer() bool { return true }

func (s *SSHCamouflageStrategy) Probe(ctx context.Context, target string) error {
	// Lightweight reachability check: a plain TCP connect against the same
	// address Connect uses (no fake SSH handshake). The full handshake is
	// expensive and, fanned out across ProbeAll plus reprobes, hammers the
	// server.
	serverAddr := s.manager.GetServerAddr(ctx)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Connect dials the server over plain TCP and performs the fake SSH handshake.
func (s *SSHCamouflageStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("SSH Camouflage: connecting to %s (raw TCP, fake SSH handshake)", serverAddr)

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	if err := performSSHClientHandshake(conn, s.secret); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh camouflage handshake: %w", err)
	}

	return NewSSHCamouflageConn(conn), nil
}

// performSSHClientHandshake drives the client side of the fake SSH handshake.
func performSSHClientHandshake(conn net.Conn, secret []byte) error {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// 1. Send our banner.
	if _, err := conn.Write([]byte(SSHBanner)); err != nil {
		return err
	}
	// 2. Read the server banner line.
	if _, err := readSSHBanner(br); err != nil {
		return fmt.Errorf("reading server banner: %w", err)
	}
	// 3. Send KEXINIT.
	if err := WriteSSHPacket(conn, BuildSSHKexInit()); err != nil {
		return err
	}
	// 4. Read (and discard) the server KEXINIT.
	if _, err := ReadSSHPacket(br); err != nil {
		return fmt.Errorf("reading server KEXINIT: %w", err)
	}
	// 5. Send ECDH init carrying our auth token as the client public key.
	token := GenerateSSHAuthToken(secret)
	if err := WriteSSHPacket(conn, BuildSSHKexECDH(sshMsgKexECDHInit, token)); err != nil {
		return err
	}
	// 6. Read ECDH reply and verify the server's token.
	payload, err := ReadSSHPacket(br)
	if err != nil {
		return fmt.Errorf("reading server ECDH reply: %w", err)
	}
	serverToken, err := ParseSSHKexPubKey(payload, sshMsgKexECDHReply)
	if err != nil {
		return err
	}
	if !VerifySSHAuthToken(serverToken, secret) {
		return fmt.Errorf("server auth token mismatch")
	}
	return nil
}

// readSSHBanner reads a single CRLF/LF-terminated identification line.
func readSSHBanner(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > sshMaxBanner+2 {
		return "", fmt.Errorf("banner too long: %d bytes", len(line))
	}
	return line, nil
}

// ---------------------------------------------------------------------------
// Auth token
// ---------------------------------------------------------------------------

// sshAuthTokenForBucket computes HMAC-SHA256(secret, "ssh-auth" || bucket) where
// bucket is the 8-byte big-endian time bucket.
func sshAuthTokenForBucket(secret []byte, bucket uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], bucket)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(sshAuthCtx))
	h.Write(b[:])
	return h.Sum(nil)
}

// GenerateSSHAuthToken returns the current auth token for the given secret.
func GenerateSSHAuthToken(secret []byte) []byte {
	bucket := uint64(time.Now().Unix() / sshAuthBucket)
	return sshAuthTokenForBucket(secret, bucket)
}

// VerifySSHAuthToken checks a received token against the current time bucket and
// the adjacent ones (±1), tolerating clock skew the same way REALITY auth does.
func VerifySSHAuthToken(token, secret []byte) bool {
	if len(token) != sshAuthLen {
		return false
	}
	current := time.Now().Unix() / sshAuthBucket
	for offset := int64(-1); offset <= 1; offset++ {
		expected := sshAuthTokenForBucket(secret, uint64(current+offset))
		if hmac.Equal(token, expected) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SSH binary packet framing
// ---------------------------------------------------------------------------

// WriteSSHPacket frames an SSH payload as an SSH binary packet and writes it.
//
//	padding_length = max(4, 8 - (5 + len(payload)) % 8)
//	packet_length  = 1 + len(payload) + padding_length
//	[packet_length:4][padding_length:1][payload][random padding]
func WriteSSHPacket(w io.Writer, payload []byte) error {
	paddingLen := sshBlockSize - ((5 + len(payload)) % sshBlockSize)
	if paddingLen < 4 {
		paddingLen += sshBlockSize
	}
	packetLen := 1 + len(payload) + paddingLen

	buf := make([]byte, 4+1+len(payload)+paddingLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(packetLen))
	buf[4] = byte(paddingLen)
	copy(buf[5:], payload)
	if _, err := rand.Read(buf[5+len(payload):]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

// ReadSSHPacket reads one SSH binary packet and returns its payload (without the
// padding-length byte or the trailing random padding).
func ReadSSHPacket(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint32(lenBuf[:])
	if packetLen < 2 || packetLen > sshMaxPacket {
		return nil, fmt.Errorf("ssh: invalid packet_length %d", packetLen)
	}
	body := make([]byte, packetLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	paddingLen := int(body[0])
	if paddingLen+1 > int(packetLen) {
		return nil, fmt.Errorf("ssh: invalid padding_length %d (packet_length %d)", paddingLen, packetLen)
	}
	return body[1 : int(packetLen)-paddingLen], nil
}

// ---------------------------------------------------------------------------
// SSH message builders
// ---------------------------------------------------------------------------

func writeSSHNameList(buf *[]byte, list string) {
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(list)))
	*buf = append(*buf, lenb[:]...)
	*buf = append(*buf, list...)
}

// BuildSSHKexInit builds a KEXINIT payload advertising realistic OpenSSH
// algorithm name-lists so the negotiation looks genuine to DPI.
func BuildSSHKexInit() []byte {
	payload := make([]byte, 0, 512)
	payload = append(payload, sshMsgKexInit)

	cookie := make([]byte, 16)
	rand.Read(cookie)
	payload = append(payload, cookie...)

	writeSSHNameList(&payload, "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256")
	writeSSHNameList(&payload, "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256")
	enc := "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	writeSSHNameList(&payload, enc) // client->server
	writeSSHNameList(&payload, enc) // server->client
	mac := "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com"
	writeSSHNameList(&payload, mac)                     // client->server
	writeSSHNameList(&payload, mac)                     // server->client
	writeSSHNameList(&payload, "none,zlib@openssh.com") // compression client->server
	writeSSHNameList(&payload, "none,zlib@openssh.com") // compression server->client
	writeSSHNameList(&payload, "")                      // languages client->server
	writeSSHNameList(&payload, "")                      // languages server->client

	payload = append(payload, 0x00)       // first_kex_packet_follows = false
	payload = append(payload, 0, 0, 0, 0) // reserved uint32 = 0
	return payload
}

// BuildSSHKexECDH builds an ECDH init/reply payload: [msgType][string pubkey],
// where pubkey carries our 32-byte auth token.
func BuildSSHKexECDH(msgType byte, pubkey []byte) []byte {
	out := make([]byte, 0, 1+4+len(pubkey))
	out = append(out, msgType)
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(pubkey)))
	out = append(out, lenb[:]...)
	out = append(out, pubkey...)
	return out
}

// ParseSSHKexPubKey parses [msgType][uint32 len][bytes] and returns the bytes,
// verifying the message type matches expectMsg.
func ParseSSHKexPubKey(payload []byte, expectMsg byte) ([]byte, error) {
	if len(payload) < 5 {
		return nil, fmt.Errorf("ssh: ECDH payload too short (%d bytes)", len(payload))
	}
	if payload[0] != expectMsg {
		return nil, fmt.Errorf("ssh: unexpected message type 0x%02x (want 0x%02x)", payload[0], expectMsg)
	}
	keyLen := binary.BigEndian.Uint32(payload[1:5])
	if int(keyLen) > len(payload)-5 {
		return nil, fmt.Errorf("ssh: ECDH key length %d exceeds payload", keyLen)
	}
	return payload[5 : 5+keyLen], nil
}

// ---------------------------------------------------------------------------
// Tunnel-phase connection
// ---------------------------------------------------------------------------

// SSHCamouflageConn wraps a post-handshake connection and frames every Read/Write
// as an SSH binary packet of message type 0xFF. The payload layout inside the
// packet is [0xFF][uint32 payload_len][payload]. Deframing is transparent: the
// caller sees the same byte stream it wrote, so this can carry either the SOCKS
// proxy address protocol or the TUN [len:4][packet] framing unchanged.
type SSHCamouflageConn struct {
	net.Conn
	br      *bufio.Reader
	readBuf []byte
	writeMu sync.Mutex
}

// NewSSHCamouflageConn wraps an already-handshaked connection for the tunnel phase.
func NewSSHCamouflageConn(conn net.Conn) *SSHCamouflageConn {
	return &SSHCamouflageConn{Conn: conn, br: bufio.NewReader(conn)}
}

func (c *SSHCamouflageConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read SSH packets until we get a tunnel-data packet with a non-empty payload.
	for {
		payload, err := ReadSSHPacket(c.br)
		if err != nil {
			return 0, err
		}
		if len(payload) < 5 || payload[0] != sshMsgTunnelData {
			// Ignore non-tunnel packets (e.g. SSH keepalive ignore messages).
			continue
		}
		dataLen := binary.BigEndian.Uint32(payload[1:5])
		if int(dataLen) > len(payload)-5 {
			return 0, fmt.Errorf("ssh: tunnel payload length %d exceeds packet", dataLen)
		}
		data := payload[5 : 5+dataLen]
		if len(data) == 0 {
			continue
		}
		n := copy(p, data)
		if n < len(data) {
			c.readBuf = append(c.readBuf, data[n:]...)
		}
		return n, nil
	}
}

func (c *SSHCamouflageConn) Write(p []byte) (int, error) {
	payload := make([]byte, 5+len(p))
	payload[0] = sshMsgTunnelData
	binary.BigEndian.PutUint32(payload[1:5], uint32(len(p)))
	copy(payload[5:], p)

	c.writeMu.Lock()
	err := WriteSSHPacket(c.Conn, payload)
	c.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// NetConn exposes the underlying connection so optimizeTCPConn can reach the
// raw *net.TCPConn for TCP_NODELAY and buffer tuning.
func (c *SSHCamouflageConn) NetConn() net.Conn { return c.Conn }
