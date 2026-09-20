package strategy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// SSH camouflage carries the tunnel inside a genuine SSH-2.0 transport. To a
// DPI observer the wire is an SSH session because it is one: banner exchange,
// KEXINIT negotiation, a real curve25519 key exchange signed by a real
// ssh-ed25519 host key, SSH_MSG_NEWKEYS from both ends, then
// chacha20-poly1305@openssh.com packets. Tunnel bytes ride in
// SSH_MSG_CHANNEL_DATA inside that encrypted channel, so nothing of the user's
// traffic is ever on the wire in clear.
//
// Authentication happens after NEWKEYS, in the userauth phase where real SSH
// puts it. The tokens are HMACs over the exchange hash H, which covers both
// KEXINIT cookies and both ephemeral public keys; a token therefore cannot be
// replayed into another connection, and the two directions use different
// context strings so reflecting the client's token back at it does not verify.
const (
	// SSHBanner is the identification string both ends send. The algorithm
	// name-lists below were captured from this exact release, so the banner and
	// the KEXINIT agree - a mismatch between them is a fingerprint on its own.
	SSHBanner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18\r\n"

	// sshAuthUser is the login name in the userauth request. It never reaches
	// the wire in clear; it only has to be an unremarkable value.
	sshAuthUser = "root"

	sshAuthCtxC2S = "tiredvpn-ssh-auth-c2s-v1"
	sshAuthCtxS2C = "tiredvpn-ssh-auth-s2c-v1"
	sshAuthLen    = sha256.Size

	// sshChannelMaxPacket is the default OpenSSH channel packet size. Chunking
	// writes at this boundary keeps our CHANNEL_DATA packets in the same size
	// range a real session produces.
	sshChannelMaxPacket = 32 * 1024
)

// SSHCamouflageStrategy implements the Strategy interface over an SSH session.
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
	return "Carries the tunnel inside a real SSH-2.0 transport (curve25519 KEX, ed25519 host key, chacha20-poly1305)"
}

func (s *SSHCamouflageStrategy) RequiresServer() bool { return true }

func (s *SSHCamouflageStrategy) Probe(ctx context.Context, target string) error {
	// Lightweight reachability check: a plain TCP connect against the same
	// address Connect uses (no SSH handshake). The full handshake is expensive
	// and, fanned out across ProbeAll plus reprobes, hammers the server.
	serverAddr := s.manager.GetServerAddr(ctx)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Connect dials the server over plain TCP and performs the SSH handshake.
func (s *SSHCamouflageStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	serverAddr := s.manager.GetServerAddr(ctx)
	secret := dialSecret(ctx, s.secret)
	log.Debug("SSH Camouflage: connecting to %s (raw TCP, SSH transport)", serverAddr)

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	transport, err := performSSHClientHandshake(conn, secret)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh camouflage handshake: %w", err)
	}

	return NewSSHCamouflageConn(transport), nil
}

// performSSHClientHandshake runs the transport handshake and then the userauth
// exchange inside the encrypted channel.
func performSSHClientHandshake(conn net.Conn, secret []byte) (*SSHTransport, error) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	transport, err := SSHClientHandshake(conn)
	if err != nil {
		return nil, err
	}
	if err := SSHClientAuth(transport, secret); err != nil {
		return nil, err
	}
	return transport, nil
}

// ---------------------------------------------------------------------------
// Auth tokens
// ---------------------------------------------------------------------------

// SSHAuthDir selects which direction an auth token belongs to. The two
// directions use different HMAC contexts, so a token captured in one direction
// never verifies in the other.
type SSHAuthDir int

const (
	// SSHAuthClientToServer is the token the client proves itself with.
	SSHAuthClientToServer SSHAuthDir = iota
	// SSHAuthServerToClient is the token the server answers with.
	SSHAuthServerToClient
)

func (d SSHAuthDir) context() string {
	if d == SSHAuthServerToClient {
		return sshAuthCtxS2C
	}
	return sshAuthCtxC2S
}

// SSHAuthToken derives the auth token for one direction of one session.
// sessionID is the exchange hash H, which binds the token to both KEXINIT
// cookies and both ephemeral public keys: it is different on every connection,
// so a captured token is worthless anywhere else.
func SSHAuthToken(secret, sessionID []byte, dir SSHAuthDir) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(dir.context()))
	h.Write(sessionID)
	return h.Sum(nil)
}

// VerifySSHAuthToken checks a token against a secret for one session and one
// direction.
func VerifySSHAuthToken(token, secret, sessionID []byte, dir SSHAuthDir) bool {
	if len(token) != sshAuthLen {
		return false
	}
	return hmac.Equal(token, SSHAuthToken(secret, sessionID, dir))
}

// ---------------------------------------------------------------------------
// Userauth exchange (inside the encrypted channel)
// ---------------------------------------------------------------------------

func buildSSHServiceRequest() []byte {
	return sshAppendString([]byte{sshMsgServiceRequest}, []byte("ssh-userauth"))
}

func buildSSHServiceAccept() []byte {
	return sshAppendString([]byte{sshMsgServiceAccept}, []byte("ssh-userauth"))
}

func checkSSHServiceMessage(payload []byte, want byte) error {
	if len(payload) == 0 || payload[0] != want {
		return fmt.Errorf("ssh: expected service message 0x%02x", want)
	}
	name, _, err := sshReadString(payload[1:])
	if err != nil {
		return err
	}
	if string(name) != "ssh-userauth" {
		return fmt.Errorf("ssh: service %q, want ssh-userauth", name)
	}
	return nil
}

// buildSSHUserAuthRequest shapes the token as an ordinary password userauth
// request, which is what the packet sizes on the wire will look like.
func buildSSHUserAuthRequest(token []byte) []byte {
	out := []byte{sshMsgUserAuthRequest}
	out = sshAppendString(out, []byte(sshAuthUser))
	out = sshAppendString(out, []byte("ssh-connection"))
	out = sshAppendString(out, []byte("password"))
	out = append(out, 0x00) // FALSE: not a password change request
	return sshAppendString(out, []byte(hex.EncodeToString(token)))
}

func parseSSHUserAuthRequest(payload []byte) ([]byte, error) {
	if len(payload) == 0 || payload[0] != sshMsgUserAuthRequest {
		return nil, errors.New("ssh: expected SSH_MSG_USERAUTH_REQUEST")
	}
	rest := payload[1:]
	for i := 0; i < 3; i++ { // user name, service name, method name
		_, r, err := sshReadString(rest)
		if err != nil {
			return nil, err
		}
		rest = r
	}
	if len(rest) < 1 {
		return nil, errors.New("ssh: truncated userauth request")
	}
	pw, _, err := sshReadString(rest[1:])
	if err != nil {
		return nil, err
	}
	return sshDecodeToken(pw)
}

// buildSSHUserAuthBanner carries the server's answering token. A banner is
// free-form text that real servers send before success, so its length does not
// stand out.
func buildSSHUserAuthBanner(token []byte) []byte {
	out := sshAppendString([]byte{sshMsgUserAuthBanner}, []byte(hex.EncodeToString(token)))
	return sshAppendString(out, nil) // language tag
}

func parseSSHUserAuthBanner(payload []byte) ([]byte, error) {
	if len(payload) == 0 || payload[0] != sshMsgUserAuthBanner {
		return nil, errors.New("ssh: expected SSH_MSG_USERAUTH_BANNER")
	}
	msg, _, err := sshReadString(payload[1:])
	if err != nil {
		return nil, err
	}
	return sshDecodeToken(msg)
}

// sshDecodeToken turns the hex form back into a token, refusing anything that
// is not exactly one token long before it decodes.
func sshDecodeToken(encoded []byte) ([]byte, error) {
	if len(encoded) != hex.EncodedLen(sshAuthLen) {
		return nil, fmt.Errorf("ssh: auth field is %d bytes, want %d", len(encoded), hex.EncodedLen(sshAuthLen))
	}
	token := make([]byte, sshAuthLen)
	if _, err := hex.Decode(token, encoded); err != nil {
		return nil, err
	}
	return token, nil
}

func buildSSHUserAuthFailure() []byte {
	out := sshAppendString([]byte{sshMsgUserAuthFailure}, []byte("publickey,password"))
	return append(out, 0x00) // partial success = FALSE
}

func buildSSHDisconnect(reason uint32, msg string) []byte {
	out := make([]byte, 5)
	out[0] = sshMsgDisconnect
	binary.BigEndian.PutUint32(out[1:5], reason)
	out = sshAppendString(out, []byte(msg))
	return sshAppendString(out, nil) // language tag
}

// SSHClientAuth runs the client side of the userauth exchange and checks the
// server's answering token. The server cannot produce it by echoing ours back:
// the two directions use different HMAC contexts.
func SSHClientAuth(t *SSHTransport, secret []byte) error {
	if err := t.WritePacket(buildSSHServiceRequest()); err != nil {
		return err
	}
	accept, err := t.ReadPacket()
	if err != nil {
		return fmt.Errorf("reading SERVICE_ACCEPT: %w", err)
	}
	if err := checkSSHServiceMessage(accept, sshMsgServiceAccept); err != nil {
		return err
	}

	token := SSHAuthToken(secret, t.SessionID(), SSHAuthClientToServer)
	if err := t.WritePacket(buildSSHUserAuthRequest(token)); err != nil {
		return err
	}

	banner, err := t.ReadPacket()
	if err != nil {
		return fmt.Errorf("reading userauth reply: %w", err)
	}
	serverToken, err := parseSSHUserAuthBanner(banner)
	if err != nil {
		return err
	}
	if !VerifySSHAuthToken(serverToken, secret, t.SessionID(), SSHAuthServerToClient) {
		return errors.New("ssh: server auth token mismatch")
	}

	success, err := t.ReadPacket()
	if err != nil {
		return fmt.Errorf("reading USERAUTH_SUCCESS: %w", err)
	}
	if len(success) == 0 || success[0] != sshMsgUserAuthSuccess {
		return errors.New("ssh: server did not accept the authentication")
	}
	return nil
}

// SSHServerReadAuth runs the server side up to the point where it has the
// client's token: it answers the service request and returns the token from the
// userauth request.
func SSHServerReadAuth(t *SSHTransport) ([]byte, error) {
	req, err := t.ReadPacket()
	if err != nil {
		return nil, fmt.Errorf("reading SERVICE_REQUEST: %w", err)
	}
	if err := checkSSHServiceMessage(req, sshMsgServiceRequest); err != nil {
		return nil, err
	}
	if err := t.WritePacket(buildSSHServiceAccept()); err != nil {
		return nil, err
	}
	auth, err := t.ReadPacket()
	if err != nil {
		return nil, fmt.Errorf("reading USERAUTH_REQUEST: %w", err)
	}
	return parseSSHUserAuthRequest(auth)
}

// SSHServerAcceptAuth sends the answering token and USERAUTH_SUCCESS.
func SSHServerAcceptAuth(t *SSHTransport, secret []byte) error {
	token := SSHAuthToken(secret, t.SessionID(), SSHAuthServerToClient)
	if err := t.WritePacket(buildSSHUserAuthBanner(token)); err != nil {
		return err
	}
	return t.WritePacket([]byte{sshMsgUserAuthSuccess})
}

// SSHServerRejectAuth turns a failed login down the way a real sshd does. The
// encrypted channel is already up at this point, so an HTTP decoy here would be
// a fingerprint rather than a disguise.
func SSHServerRejectAuth(t *SSHTransport) {
	_ = t.WritePacket(buildSSHUserAuthFailure())
	_ = t.WritePacket(buildSSHDisconnect(sshDisconnectNoMoreAuth, "Too many authentication failures"))
}

// SSHAuthRejectedError reports the sentinel the server handler uses to tell a
// post-NEWKEYS auth failure apart from a connection that never got that far.
func SSHAuthRejectedError() error { return errSSHAuthRejected }

// ---------------------------------------------------------------------------
// KEXINIT
// ---------------------------------------------------------------------------

// The name-lists below are what OpenSSH_9.6p1 Ubuntu-3ubuntu13.18 actually puts
// on the wire, captured from the stock client and the stock sshd. Two entries
// are deliberately different on our server, and both are consistent rather than
// cosmetic:
//
//   - the server kex list drops sntrup761x25519-sha512@openssh.com. We only
//     implement curve25519-sha256, and advertising a post-quantum kex we then
//     refuse to use would be visible: the negotiation rule is deterministic, so
//     an observer knows which algorithm two lists select and therefore how long
//     KEX_ECDH_INIT has to be. A server that pins KexAlgorithms is ordinary;
//     one whose message sizes contradict its own offer is not.
//   - the server host-key list is just ssh-ed25519, which is what a host with
//     only an ed25519 host key advertises. Offering rsa or ecdsa we cannot sign
//     with would fail the moment a prober asked for them.
//
// With these lists the negotiation resolves to curve25519-sha256 /
// ssh-ed25519 / chacha20-poly1305@openssh.com / compression none on both ends.
const (
	sshKexClient = "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org," +
		"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256," +
		"diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256," +
		"ext-info-c,kex-strict-c-v00@openssh.com"

	sshKexServer = "curve25519-sha256,curve25519-sha256@libssh.org," +
		"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256," +
		"diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256," +
		"ext-info-s,kex-strict-s-v00@openssh.com"

	sshHostKeysClient = "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
		"sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com," +
		"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," +
		"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256"

	sshHostKeysServer = "ssh-ed25519"

	sshCiphers = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr," +
		"aes128-gcm@openssh.com,aes256-gcm@openssh.com"

	sshMACs = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com," +
		"hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com," +
		"umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"

	sshCompressionClient = "none,zlib@openssh.com,zlib"
	sshCompressionServer = "none,zlib@openssh.com"
)

func writeSSHNameList(buf *[]byte, list string) {
	*buf = sshAppendString(*buf, []byte(list))
}

func buildSSHKexInit(kex, hostKeys, compression string) []byte {
	payload := make([]byte, 0, 1600)
	payload = append(payload, sshMsgKexInit)

	cookie := make([]byte, 16)
	sshRandRead(cookie)
	payload = append(payload, cookie...)

	writeSSHNameList(&payload, kex)
	writeSSHNameList(&payload, hostKeys)
	writeSSHNameList(&payload, sshCiphers) // client->server
	writeSSHNameList(&payload, sshCiphers) // server->client
	writeSSHNameList(&payload, sshMACs)    // client->server
	writeSSHNameList(&payload, sshMACs)    // server->client
	writeSSHNameList(&payload, compression)
	writeSSHNameList(&payload, compression)
	writeSSHNameList(&payload, "") // languages client->server
	writeSSHNameList(&payload, "") // languages server->client

	payload = append(payload, 0x00)       // first_kex_packet_follows = false
	payload = append(payload, 0, 0, 0, 0) // reserved uint32 = 0
	return payload
}

// BuildSSHClientKexInit builds the KEXINIT a stock OpenSSH 9.6p1 client sends.
func BuildSSHClientKexInit() []byte {
	return buildSSHKexInit(sshKexClient, sshHostKeysClient, sshCompressionClient)
}

// BuildSSHServerKexInit builds our server KEXINIT.
func BuildSSHServerKexInit() []byte {
	return buildSSHKexInit(sshKexServer, sshHostKeysServer, sshCompressionServer)
}

// ---------------------------------------------------------------------------
// Tunnel-phase connection
// ---------------------------------------------------------------------------

// SSHCamouflageConn presents the authenticated SSH transport as a net.Conn.
// Every Write becomes one or more SSH_MSG_CHANNEL_DATA packets inside the
// encrypted channel, chunked at the default OpenSSH channel packet size; every
// Read pulls the next channel-data payload. The caller sees the same byte
// stream it wrote, so this carries either the SOCKS proxy address protocol or
// the TUN [len:4][packet] framing unchanged.
type SSHCamouflageConn struct {
	net.Conn
	transport *SSHTransport
	readBuf   []byte
	writeMu   sync.Mutex
}

// NewSSHCamouflageConn wraps an authenticated transport for the tunnel phase.
func NewSSHCamouflageConn(t *SSHTransport) *SSHCamouflageConn {
	return &SSHCamouflageConn{Conn: t.Conn(), transport: t}
}

func (c *SSHCamouflageConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		payload, err := c.transport.ReadPacket()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		if payload[0] == sshMsgDisconnect {
			return 0, errors.New("ssh: peer disconnected")
		}
		if payload[0] != sshMsgChannelData || len(payload) < 5 {
			// Ignore anything that is not channel data (keepalives, requests).
			continue
		}
		data, _, err := sshReadString(payload[5:])
		if err != nil {
			return 0, err
		}
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for written < len(p) {
		chunk := p[written:]
		if len(chunk) > sshChannelMaxPacket {
			chunk = chunk[:sshChannelMaxPacket]
		}
		payload := make([]byte, 5, 5+4+len(chunk))
		payload[0] = sshMsgChannelData
		binary.BigEndian.PutUint32(payload[1:5], 0) // recipient channel
		payload = sshAppendString(payload, chunk)
		if err := c.transport.WritePacket(payload); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

// NetConn exposes the underlying connection so optimizeTCPConn can reach the
// raw *net.TCPConn for TCP_NODELAY and buffer tuning.
func (c *SSHCamouflageConn) NetConn() net.Conn { return c.Conn }

// sshRandRead fills b with cryptographic randomness, panicking on the failure
// that crypto/rand documents as impossible.
func sshRandRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("ssh: crypto/rand failed: " + err.Error())
	}
}
