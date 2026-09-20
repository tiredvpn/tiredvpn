package strategy

// SSH transport layer. This is a real RFC 4253 transport, not a costume over
// one: curve25519-sha256 key exchange with a fresh ephemeral pair per
// connection, an ssh-ed25519 host key that actually signs the exchange hash,
// SSH_MSG_NEWKEYS from both ends, and chacha20-poly1305@openssh.com
// authenticated encryption afterwards. User traffic rides inside the encrypted
// channel, so a DPI box sees the same opaque packet stream it sees on any SSH
// session and never sees an IP header.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

// SSH transport message numbers (RFC 4253 §12, RFC 4252 §6, RFC 5656 §7.1).
const (
	sshMsgDisconnect      = 1
	sshMsgIgnore          = 2
	sshMsgUnimplemented   = 3
	sshMsgDebug           = 4
	sshMsgServiceRequest  = 5
	sshMsgServiceAccept   = 6
	sshMsgExtInfo         = 7
	sshMsgKexInit         = 20
	sshMsgNewKeys         = 21
	sshMsgKexECDHInit     = 30
	sshMsgKexECDHReply    = 31
	sshMsgUserAuthRequest = 50
	sshMsgUserAuthFailure = 51
	sshMsgUserAuthSuccess = 52
	sshMsgUserAuthBanner  = 53
	sshMsgChannelData     = 94
)

// sshDisconnectNoMoreAuth is SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE.
const sshDisconnectNoMoreAuth = 14

const (
	// sshBlockSize is the cipher block size used for the padding calculation.
	// OpenSSH uses 8 both for the plaintext phase and for chacha20-poly1305.
	sshBlockSize = 8

	// sshMaxPacket mirrors OpenSSH's PACKET_MAX_SIZE. Every packet_length that
	// comes off the wire is checked against a cap before a single byte is
	// allocated for it, so a peer cannot make us reserve memory by lying.
	sshMaxPacket = 256 * 1024

	// sshMaxHandshakePacket caps the pre-authentication packets. A real KEXINIT
	// is about 1.5 KB and nothing legitimate before NEWKEYS is larger, so an
	// unauthenticated peer can never make us allocate more than this.
	sshMaxHandshakePacket = 64 * 1024

	// sshMaxBanner is the RFC 4253 §4.2 identification-line cap.
	sshMaxBanner = 255

	sshTagSize = poly1305.TagSize
	// sshCipherKeyLen is the key material chacha20-poly1305@openssh.com needs
	// per direction: two 256-bit chacha20 keys.
	sshCipherKeyLen = 64
)

// errSSHAuthRejected marks a failure that happened after the encrypted channel
// was already up. The caller must not fall back to the fake website there: an
// HTTP response in the middle of an SSH stream is itself a fingerprint.
var errSSHAuthRejected = errors.New("ssh: authentication rejected")

// ---------------------------------------------------------------------------
// Wire primitives
// ---------------------------------------------------------------------------

// sshAppendString appends an SSH "string": uint32 length followed by the bytes.
func sshAppendString(b []byte, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	b = append(b, l[:]...)
	return append(b, s...)
}

// sshReadString peels one length-prefixed string off buf. The length is checked
// against what is actually left in the buffer before anything is sliced, so a
// forged length cannot walk us off the end or make us reserve memory.
func sshReadString(buf []byte) (val, rest []byte, err error) {
	if len(buf) < 4 {
		return nil, nil, errors.New("ssh: truncated string header")
	}
	n := binary.BigEndian.Uint32(buf[0:4])
	if uint64(n) > uint64(len(buf)-4) {
		return nil, nil, fmt.Errorf("ssh: string length %d exceeds %d remaining bytes", n, len(buf)-4)
	}
	return buf[4 : 4+n], buf[4+n:], nil
}

// sshAppendMPInt appends an SSH "mpint": the value as a big-endian unsigned
// integer with leading zero bytes removed and a 0x00 prepended when the top bit
// would otherwise read as a sign bit.
func sshAppendMPInt(b, v []byte) []byte {
	i := 0
	for i < len(v) && v[i] == 0 {
		i++
	}
	v = v[i:]
	if len(v) == 0 {
		return append(b, 0, 0, 0, 0)
	}
	if v[0]&0x80 != 0 {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(v)+1))
		b = append(b, l[:]...)
		b = append(b, 0x00)
		return append(b, v...)
	}
	return sshAppendString(b, v)
}

// sshPaddingLen returns the padding_length for a payload of the given size.
// OpenSSH computes it over padding_length+payload+padding for AEAD ciphers
// (where the length field is authenticated separately) and over the length
// field too in the plaintext phase; aadLen selects between the two.
func sshPaddingLen(payloadLen, aadLen int) int {
	n := 4 + 1 + payloadLen - aadLen
	pad := sshBlockSize - (n % sshBlockSize)
	if pad < 4 {
		pad += sshBlockSize
	}
	return pad
}

// sshFramePacket builds padding_length || payload || padding. OpenSSH fills the
// padding with zeros while the connection is still plaintext and with random
// bytes once a cipher is in place; we do the same, because the padding of a
// real KEXINIT is observably all zeros and ours must be too.
func sshFramePacket(payload []byte, aadLen int, randomPad bool) ([]byte, error) {
	padLen := sshPaddingLen(len(payload), aadLen)
	packet := make([]byte, 1+len(payload)+padLen)
	packet[0] = byte(padLen)
	copy(packet[1:], payload)
	if randomPad {
		if _, err := rand.Read(packet[1+len(payload):]); err != nil {
			return nil, err
		}
	}
	return packet, nil
}

// WriteSSHPacket frames a payload as a plaintext SSH binary packet and writes
// it. Only the pre-NEWKEYS phase uses this; everything after is encrypted.
func WriteSSHPacket(w io.Writer, payload []byte) error {
	packet, err := sshFramePacket(payload, 0, false)
	if err != nil {
		return err
	}
	buf := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(packet)))
	copy(buf[4:], packet)
	_, err = w.Write(buf)
	return err
}

// ReadSSHPacket reads one plaintext SSH binary packet and returns its payload.
// packet_length is bounded before the body buffer is allocated.
func ReadSSHPacket(r io.Reader) ([]byte, error) {
	return readSSHPacketLimit(r, sshMaxHandshakePacket)
}

func readSSHPacketLimit(r io.Reader, max uint32) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint32(lenBuf[:])
	if packetLen < 2 || packetLen > max {
		return nil, fmt.Errorf("ssh: invalid packet_length %d (cap %d)", packetLen, max)
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

// readSSHBanner reads one identification line, refusing to buffer without
// bound: a peer that never sends a newline cannot grow our heap.
func readSSHBanner(r *bufio.Reader) (string, error) {
	line := make([]byte, 0, 64)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return string(line), nil
		}
		if len(line) >= sshMaxBanner+1 {
			return "", fmt.Errorf("ssh: banner exceeds %d bytes", sshMaxBanner)
		}
		line = append(line, b)
	}
}

// sshTrimBanner strips the CR/LF that the exchange hash must not include.
func sshTrimBanner(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// chacha20-poly1305@openssh.com
// ---------------------------------------------------------------------------

// sshChaChaCipher implements OpenSSH's chacha20-poly1305 construction, which is
// not the RFC 8439 AEAD: the 4-byte packet length gets its own chacha20
// instance under a separate key so a reader can size a packet before it can
// authenticate it, and the Poly1305 key comes from block 0 of the payload
// stream. See OpenSSH's PROTOCOL.chacha20poly1305.
type sshChaChaCipher struct {
	payloadKey [32]byte // K_2: payload and Poly1305 key generation
	lengthKey  [32]byte // K_1: the packet_length field only
}

func newSSHChaChaCipher(key []byte) (*sshChaChaCipher, error) {
	if len(key) != sshCipherKeyLen {
		return nil, fmt.Errorf("ssh: chacha20-poly1305 needs %d key bytes, got %d", sshCipherKeyLen, len(key))
	}
	c := &sshChaChaCipher{}
	copy(c.payloadKey[:], key[0:32])
	copy(c.lengthKey[:], key[32:64])
	return c, nil
}

// sshChaChaNonce builds the 12-byte nonce for a sequence number. OpenSSH uses
// the original 8-byte-nonce chacha20; prefixing four zero bytes to the sequence
// number makes the RFC 8439 layout produce the identical keystream.
func sshChaChaNonce(seq uint64) []byte {
	n := make([]byte, chacha20.NonceSize)
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

func (c *sshChaChaCipher) polyKeyAndStream(seq uint64) (*chacha20.Cipher, [32]byte, error) {
	s, err := chacha20.NewUnauthenticatedCipher(c.payloadKey[:], sshChaChaNonce(seq))
	if err != nil {
		return nil, [32]byte{}, err
	}
	var polyKey [32]byte
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1) // skip the rest of block 0; the payload starts at block 1
	return s, polyKey, nil
}

// seal encrypts one already-framed packet and returns the bytes to put on the
// wire: encrypted length, encrypted packet, Poly1305 tag.
func (c *sshChaChaCipher) seal(seq uint64, packet []byte) ([]byte, error) {
	lengthStream, err := chacha20.NewUnauthenticatedCipher(c.lengthKey[:], sshChaChaNonce(seq))
	if err != nil {
		return nil, err
	}
	payloadStream, polyKey, err := c.polyKeyAndStream(seq)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 4+len(packet)+sshTagSize)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(packet)))
	lengthStream.XORKeyStream(out[0:4], lenBuf[:])
	payloadStream.XORKeyStream(out[4:4+len(packet)], packet)

	var tag [sshTagSize]byte
	poly1305.Sum(&tag, out[:4+len(packet)], &polyKey)
	copy(out[4+len(packet):], tag[:])
	return out, nil
}

// decryptLength recovers packet_length from its own keystream. This runs before
// the tag can be checked, which is exactly why the caller must bound the result
// before allocating.
func (c *sshChaChaCipher) decryptLength(seq uint64, ct []byte) (uint32, error) {
	s, err := chacha20.NewUnauthenticatedCipher(c.lengthKey[:], sshChaChaNonce(seq))
	if err != nil {
		return 0, err
	}
	var out [4]byte
	s.XORKeyStream(out[:], ct)
	return binary.BigEndian.Uint32(out[:]), nil
}

// open authenticates and decrypts one packet body. lenCT is the still-encrypted
// length field, which is part of the authenticated data.
func (c *sshChaChaCipher) open(seq uint64, lenCT, bodyCT, tag []byte) ([]byte, error) {
	payloadStream, polyKey, err := c.polyKeyAndStream(seq)
	if err != nil {
		return nil, err
	}

	authed := make([]byte, 0, 4+len(bodyCT))
	authed = append(authed, lenCT...)
	authed = append(authed, bodyCT...)
	var want [sshTagSize]byte
	copy(want[:], tag)
	if !poly1305.Verify(&want, authed, &polyKey) {
		return nil, errors.New("ssh: packet authentication failed")
	}

	plain := make([]byte, len(bodyCT))
	payloadStream.XORKeyStream(plain, bodyCT)
	return plain, nil
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// sshDeriveKey implements RFC 4253 §7.2: K_x = HASH(K || H || X || session_id),
// extended by K_x = K_x || HASH(K || H || K_x) until it is long enough.
func sshDeriveKey(kMPInt, h []byte, label byte, sessionID []byte, n int) []byte {
	d := sha256.New()
	d.Write(kMPInt)
	d.Write(h)
	d.Write([]byte{label})
	d.Write(sessionID)
	out := d.Sum(nil)
	for len(out) < n {
		d.Reset()
		d.Write(kMPInt)
		d.Write(h)
		d.Write(out)
		out = append(out, d.Sum(nil)...)
	}
	return out[:n]
}

// sshExchangeHash computes H for curve25519-sha256 (RFC 5656 §4, RFC 8731 §3).
// Every field that identifies this connection is in here: both banners, both
// KEXINIT payloads with their random cookies, the host key, both ephemeral
// public values and the shared secret. Binding the auth tokens to H is what
// makes a replayed or relayed token useless.
func sshExchangeHash(vc, vs string, ic, is, ks, qc, qs, k []byte) []byte {
	b := make([]byte, 0, 512)
	b = sshAppendString(b, []byte(vc))
	b = sshAppendString(b, []byte(vs))
	b = sshAppendString(b, ic)
	b = sshAppendString(b, is)
	b = sshAppendString(b, ks)
	b = sshAppendString(b, qc)
	b = sshAppendString(b, qs)
	b = sshAppendMPInt(b, k)
	sum := sha256.Sum256(b)
	return sum[:]
}

// ---------------------------------------------------------------------------
// Host key
// ---------------------------------------------------------------------------

var (
	sshEphemeralHostKeyOnce sync.Once
	sshEphemeralHostKey     ed25519.PrivateKey
)

// SSHHostKey returns the ssh-ed25519 host key the camouflage server presents.
// It is derived from the server secret so it survives restarts: a host whose
// key changes on every restart is a signal in itself. Deployments that run on
// per-client secrets only get a key that lives as long as the process.
func SSHHostKey(secret []byte) ed25519.PrivateKey {
	if len(secret) == 0 {
		sshEphemeralHostKeyOnce.Do(func() {
			seed := make([]byte, ed25519.SeedSize)
			if _, err := rand.Read(seed); err != nil {
				panic("ssh: host key seed: " + err.Error())
			}
			sshEphemeralHostKey = ed25519.NewKeyFromSeed(seed)
		})
		return sshEphemeralHostKey
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("tiredvpn-ssh-hostkey-v1"))
	return ed25519.NewKeyFromSeed(h.Sum(nil)[:ed25519.SeedSize])
}

// sshHostKeyBlob encodes a public host key as string("ssh-ed25519") ||
// string(key), the K_S that goes into the exchange hash.
func sshHostKeyBlob(pub ed25519.PublicKey) []byte {
	b := sshAppendString(nil, []byte("ssh-ed25519"))
	return sshAppendString(b, pub)
}

func sshParseHostKeyBlob(blob []byte) (ed25519.PublicKey, error) {
	algo, rest, err := sshReadString(blob)
	if err != nil {
		return nil, err
	}
	if string(algo) != "ssh-ed25519" {
		return nil, fmt.Errorf("ssh: host key algorithm %q, want ssh-ed25519", algo)
	}
	key, _, err := sshReadString(rest)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ssh: host key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func sshSignatureBlob(sig []byte) []byte {
	b := sshAppendString(nil, []byte("ssh-ed25519"))
	return sshAppendString(b, sig)
}

func sshParseSignatureBlob(blob []byte) ([]byte, error) {
	algo, rest, err := sshReadString(blob)
	if err != nil {
		return nil, err
	}
	if string(algo) != "ssh-ed25519" {
		return nil, fmt.Errorf("ssh: signature algorithm %q, want ssh-ed25519", algo)
	}
	sig, _, err := sshReadString(rest)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("ssh: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// ---------------------------------------------------------------------------
// KEX messages
// ---------------------------------------------------------------------------

func buildSSHKexECDHInit(qc []byte) []byte {
	out := []byte{sshMsgKexECDHInit}
	return sshAppendString(out, qc)
}

func buildSSHKexECDHReply(ks, qs, sig []byte) []byte {
	out := []byte{sshMsgKexECDHReply}
	out = sshAppendString(out, ks)
	out = sshAppendString(out, qs)
	return sshAppendString(out, sig)
}

func parseSSHKexECDHInit(payload []byte) ([]byte, error) {
	if len(payload) == 0 || payload[0] != sshMsgKexECDHInit {
		return nil, errors.New("ssh: expected SSH_MSG_KEX_ECDH_INIT")
	}
	qc, _, err := sshReadString(payload[1:])
	if err != nil {
		return nil, err
	}
	if len(qc) != curve25519.PointSize {
		return nil, fmt.Errorf("ssh: client ephemeral key is %d bytes, want %d", len(qc), curve25519.PointSize)
	}
	return qc, nil
}

func parseSSHKexECDHReply(payload []byte) (ks, qs, sig []byte, err error) {
	if len(payload) == 0 || payload[0] != sshMsgKexECDHReply {
		return nil, nil, nil, errors.New("ssh: expected SSH_MSG_KEX_ECDH_REPLY")
	}
	rest := payload[1:]
	if ks, rest, err = sshReadString(rest); err != nil {
		return nil, nil, nil, err
	}
	if qs, rest, err = sshReadString(rest); err != nil {
		return nil, nil, nil, err
	}
	if sig, _, err = sshReadString(rest); err != nil {
		return nil, nil, nil, err
	}
	if len(qs) != curve25519.PointSize {
		return nil, nil, nil, fmt.Errorf("ssh: server ephemeral key is %d bytes, want %d", len(qs), curve25519.PointSize)
	}
	return ks, qs, sig, nil
}

// sshServerSigAlgs is the server-sig-algs value OpenSSH 9.6p1 advertises. The
// other two extensions a stock sshd sends, publickey-hostbound@openssh.com and
// ping@openssh.com, are left out on purpose: they commit the server to answer
// messages we do not implement, and advertising something we would then refuse
// is the same mistake as offering a kex we cannot run.
const sshServerSigAlgs = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384," +
	"ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
	"rsa-sha2-512,rsa-sha2-256"

// buildSSHExtInfo builds SSH_MSG_EXT_INFO (RFC 8308 §2.3).
func buildSSHExtInfo() []byte {
	out := make([]byte, 5)
	out[0] = sshMsgExtInfo
	binary.BigEndian.PutUint32(out[1:5], 1) // one extension
	out = sshAppendString(out, []byte("server-sig-algs"))
	return sshAppendString(out, []byte(sshServerSigAlgs))
}

// ReadSSHTransportPacket returns the next packet that carries meaning, skipping
// the transport housekeeping messages RFC 4253 §11 allows at any time plus the
// EXT_INFO our own KEXINIT invites the peer to send.
func ReadSSHTransportPacket(t *SSHTransport) ([]byte, error) {
	for {
		payload, err := t.ReadPacket()
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case sshMsgIgnore, sshMsgUnimplemented, sshMsgDebug, sshMsgExtInfo:
			continue
		case sshMsgDisconnect:
			return nil, errors.New("ssh: peer sent SSH_MSG_DISCONNECT")
		default:
			return payload, nil
		}
	}
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// SSHTransport is an established SSH transport: an encrypted, authenticated
// packet channel plus the session identifier both ends agreed on.
type SSHTransport struct {
	conn net.Conn
	br   *bufio.Reader

	sessionID []byte

	out    *sshChaChaCipher
	in     *sshChaChaCipher
	outSeq uint64
	inSeq  uint64

	writeMu sync.Mutex
	readMu  sync.Mutex
}

// SessionID returns H from the key exchange. It is unique per connection and
// covers both KEXINIT cookies, both ephemeral public keys and the host key.
func (t *SSHTransport) SessionID() []byte { return t.sessionID }

// Conn exposes the underlying connection.
func (t *SSHTransport) Conn() net.Conn { return t.conn }

// WritePacket encrypts and sends one SSH packet.
func (t *SSHTransport) WritePacket(payload []byte) error {
	packet, err := sshFramePacket(payload, 4, true)
	if err != nil {
		return err
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	wire, err := t.out.seal(t.outSeq, packet)
	if err != nil {
		return err
	}
	if _, err := t.conn.Write(wire); err != nil {
		return err
	}
	t.outSeq++
	return nil
}

// ReadPacket receives, authenticates and decrypts one SSH packet.
func (t *SSHTransport) ReadPacket() ([]byte, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	var lenCT [4]byte
	if _, err := io.ReadFull(t.br, lenCT[:]); err != nil {
		return nil, err
	}
	packetLen, err := t.in.decryptLength(t.inSeq, lenCT[:])
	if err != nil {
		return nil, err
	}
	// The length is not authenticated yet, so it is bounded here, before any
	// allocation. Without this a peer can name 4 GB and we would try to hold it.
	if packetLen < sshBlockSize || packetLen > sshMaxPacket || packetLen%sshBlockSize != 0 {
		return nil, fmt.Errorf("ssh: invalid encrypted packet_length %d", packetLen)
	}

	buf := make([]byte, int(packetLen)+sshTagSize)
	if _, err := io.ReadFull(t.br, buf); err != nil {
		return nil, err
	}
	plain, err := t.in.open(t.inSeq, lenCT[:], buf[:packetLen], buf[packetLen:])
	if err != nil {
		return nil, err
	}
	t.inSeq++

	padLen := int(plain[0])
	if padLen < 4 || padLen+1 > len(plain) {
		return nil, fmt.Errorf("ssh: invalid padding_length %d in a %d byte packet", padLen, len(plain))
	}
	return plain[1 : len(plain)-padLen], nil
}

// newSSHTransport wires up the ciphers once both ends have exchanged NEWKEYS.
// Both sides advertise kex-strict-*-v00@openssh.com, so the sequence numbers
// restart at zero here rather than carrying over from the plaintext phase.
func newSSHTransport(conn net.Conn, br *bufio.Reader, k, h []byte, client bool) (*SSHTransport, error) {
	kMPInt := sshAppendMPInt(nil, k)
	c2s := sshDeriveKey(kMPInt, h, 'C', h, sshCipherKeyLen)
	s2c := sshDeriveKey(kMPInt, h, 'D', h, sshCipherKeyLen)

	outKey, inKey := c2s, s2c
	if !client {
		outKey, inKey = s2c, c2s
	}
	out, err := newSSHChaChaCipher(outKey)
	if err != nil {
		return nil, err
	}
	in, err := newSSHChaChaCipher(inKey)
	if err != nil {
		return nil, err
	}
	return &SSHTransport{
		conn:      conn,
		br:        br,
		sessionID: h,
		out:       out,
		in:        in,
	}, nil
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

// SSHClientHandshake runs the client half of the SSH transport handshake and
// returns the encrypted channel. The ephemeral key pair is fresh per call, so
// the public value in KEX_ECDH_INIT differs on every connection and differs
// from the one the server puts in KEX_ECDH_REPLY.
func SSHClientHandshake(conn net.Conn) (*SSHTransport, error) {
	br := bufio.NewReader(conn)

	vc := sshTrimBanner(SSHBanner)
	if _, err := conn.Write([]byte(SSHBanner)); err != nil {
		return nil, err
	}
	rawVS, err := readSSHBanner(br)
	if err != nil {
		return nil, fmt.Errorf("reading server banner: %w", err)
	}
	vs := sshTrimBanner(rawVS)
	if len(vs) < 7 || vs[:7] != "SSH-2.0" {
		return nil, fmt.Errorf("server banner %q is not SSH-2.0", vs)
	}

	ic := BuildSSHClientKexInit()
	if err := WriteSSHPacket(conn, ic); err != nil {
		return nil, err
	}
	is, err := ReadSSHPacket(br)
	if err != nil {
		return nil, fmt.Errorf("reading server KEXINIT: %w", err)
	}
	if err := checkSSHKexInit(is); err != nil {
		return nil, err
	}

	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	qc, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	if err := WriteSSHPacket(conn, buildSSHKexECDHInit(qc)); err != nil {
		return nil, err
	}

	reply, err := ReadSSHPacket(br)
	if err != nil {
		return nil, fmt.Errorf("reading KEX_ECDH_REPLY: %w", err)
	}
	ks, qs, sigBlob, err := parseSSHKexECDHReply(reply)
	if err != nil {
		return nil, err
	}
	k, err := curve25519.X25519(priv, qs)
	if err != nil {
		return nil, fmt.Errorf("ssh: bad server ephemeral key: %w", err)
	}
	h := sshExchangeHash(vc, vs, ic, is, ks, qc, qs, k)

	hostPub, err := sshParseHostKeyBlob(ks)
	if err != nil {
		return nil, err
	}
	sig, err := sshParseSignatureBlob(sigBlob)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(hostPub, h, sig) {
		return nil, errors.New("ssh: host key signature does not verify")
	}

	if _, err := ReadSSHPacket(br); err != nil {
		return nil, fmt.Errorf("reading server NEWKEYS: %w", err)
	}
	if err := WriteSSHPacket(conn, []byte{sshMsgNewKeys}); err != nil {
		return nil, err
	}
	return newSSHTransport(conn, br, k, h, true)
}

// SSHServerHandshake runs the server half. It reads the client banner itself,
// so the peeking dispatcher hands over an untouched connection.
func SSHServerHandshake(conn net.Conn, hostKey ed25519.PrivateKey) (*SSHTransport, error) {
	br := bufio.NewReader(conn)

	rawVC, err := readSSHBanner(br)
	if err != nil {
		return nil, fmt.Errorf("reading client banner: %w", err)
	}
	vc := sshTrimBanner(rawVC)
	if len(vc) < 7 || vc[:7] != "SSH-2.0" {
		return nil, fmt.Errorf("client banner %q is not SSH-2.0", vc)
	}
	vs := sshTrimBanner(SSHBanner)

	// A real sshd puts its identification string and its KEXINIT in the same
	// flight; splitting them costs an extra round trip that shows up in timing.
	is := BuildSSHServerKexInit()
	isPacket, err := sshFramePacket(is, 0, false)
	if err != nil {
		return nil, err
	}
	first := make([]byte, 0, len(SSHBanner)+4+len(isPacket))
	first = append(first, SSHBanner...)
	var isLen [4]byte
	binary.BigEndian.PutUint32(isLen[:], uint32(len(isPacket)))
	first = append(first, isLen[:]...)
	first = append(first, isPacket...)
	if _, err := conn.Write(first); err != nil {
		return nil, err
	}

	ic, err := ReadSSHPacket(br)
	if err != nil {
		return nil, fmt.Errorf("reading client KEXINIT: %w", err)
	}
	if err := checkSSHKexInit(ic); err != nil {
		return nil, err
	}
	wantsExtInfo := sshKexInitOffers(ic, "ext-info-c")

	initPayload, err := ReadSSHPacket(br)
	if err != nil {
		return nil, fmt.Errorf("reading KEX_ECDH_INIT: %w", err)
	}
	qc, err := parseSSHKexECDHInit(initPayload)
	if err != nil {
		return nil, err
	}

	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	qs, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	k, err := curve25519.X25519(priv, qc)
	if err != nil {
		return nil, fmt.Errorf("ssh: bad client ephemeral key: %w", err)
	}

	ks := sshHostKeyBlob(hostKey.Public().(ed25519.PublicKey))
	h := sshExchangeHash(vc, vs, ic, is, ks, qc, qs, k)
	sig := ed25519.Sign(hostKey, h)

	replyPacket, err := sshFramePacket(buildSSHKexECDHReply(ks, qs, sshSignatureBlob(sig)), 0, false)
	if err != nil {
		return nil, err
	}
	newKeysPacket, err := sshFramePacket([]byte{sshMsgNewKeys}, 0, false)
	if err != nil {
		return nil, err
	}
	second := make([]byte, 0, 8+len(replyPacket)+len(newKeysPacket))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(replyPacket)))
	second = append(second, l[:]...)
	second = append(second, replyPacket...)
	binary.BigEndian.PutUint32(l[:], uint32(len(newKeysPacket)))
	second = append(second, l[:]...)
	second = append(second, newKeysPacket...)
	if _, err := conn.Write(second); err != nil {
		return nil, err
	}

	if _, err := ReadSSHPacket(br); err != nil {
		return nil, fmt.Errorf("reading client NEWKEYS: %w", err)
	}
	transport, err := newSSHTransport(conn, br, k, h, false)
	if err != nil {
		return nil, err
	}
	// A stock sshd answers a client that offered ext-info-c with EXT_INFO as
	// the first packet after NEWKEYS. Skipping it would drop a real SSH client
	// at an unusual point in the conversation.
	if wantsExtInfo {
		if err := transport.WritePacket(buildSSHExtInfo()); err != nil {
			return nil, err
		}
	}
	return transport, nil
}

// sshKexInitOffers reports whether a KEXINIT payload lists name in its kex
// algorithm list, which is where the ext-info and strict-kex markers live.
func sshKexInitOffers(payload []byte, name string) bool {
	if len(payload) < 17 || payload[0] != sshMsgKexInit {
		return false
	}
	list, _, err := sshReadString(payload[17:])
	if err != nil {
		return false
	}
	return sshNameListHas(list, name)
}

// checkSSHKexInit rejects a peer that is not offering what we will negotiate.
// A real implementation runs the RFC 4253 §7.1 guess here; ours only has one
// choice, so it verifies the peer named it.
func checkSSHKexInit(payload []byte) error {
	if len(payload) < 17 || payload[0] != sshMsgKexInit {
		return errors.New("ssh: expected SSH_MSG_KEXINIT")
	}
	rest := payload[17:]
	lists := make([][]byte, 0, 4)
	for i := 0; i < 4; i++ {
		val, r, err := sshReadString(rest)
		if err != nil {
			return fmt.Errorf("ssh: malformed KEXINIT: %w", err)
		}
		lists = append(lists, val)
		rest = r
	}
	if !sshNameListHas(lists[0], "curve25519-sha256") {
		return errors.New("ssh: peer does not offer curve25519-sha256")
	}
	if !sshNameListHas(lists[2], "chacha20-poly1305@openssh.com") ||
		!sshNameListHas(lists[3], "chacha20-poly1305@openssh.com") {
		return errors.New("ssh: peer does not offer chacha20-poly1305@openssh.com")
	}
	return nil
}

func sshNameListHas(list []byte, name string) bool {
	s := string(list)
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != ',' {
			i++
		}
		if s[:i] == name {
			return true
		}
		if i == len(s) {
			return false
		}
		s = s[i+1:]
	}
	return false
}
