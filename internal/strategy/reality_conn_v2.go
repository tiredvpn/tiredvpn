package strategy

import (
	"bufio"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// realityV2MaxPlaintext is the largest plaintext we put in one record. The
// record body is plaintext + 16-byte Poly1305 tag and must stay within the
// 16383 cap the v1 writer already used, so the plaintext cap drops by the tag.
const realityV2MaxPlaintext = 16383 - chacha20poly1305.Overhead

// realityV2MinRecordBody is the smallest body that can hold a tag plus one byte.
const realityV2MinRecordBody = chacha20poly1305.Overhead + 1

// RealityV2Params is the per-connection key material for the v2 data layer.
// Every field is unique to one connection, which is the entire point: v1 derived
// its key and nonce from (password, process-wide client key), so every
// connection of a client reused one keystream from counter zero.
type RealityV2Params struct {
	// SharedSecret is the VPN password. It authenticates the exchange; on its
	// own it no longer determines the data keys.
	SharedSecret []byte
	// ECDH is the X25519 shared secret of the two ephemeral connection keys.
	ECDH []byte
	// ClientPub / ServerPub are the ephemeral public keys of this connection,
	// bound into the key schedule so a swapped key yields a different key.
	ClientPub [32]byte
	ServerPub [32]byte
	// ClientSalt / ServerSalt are fresh CSPRNG values exchanged in the
	// handshake padding.
	ClientSalt [32]byte
	ServerSalt [32]byte
}

// RealityV2ECDH computes the X25519 shared secret for the data layer. It
// rejects low-order points (all-zero output), which is what curve25519.X25519
// reports as an error.
func RealityV2ECDH(priv, peerPub [32]byte) ([]byte, error) {
	sec, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	return sec, nil
}

// deriveRealityDataKeysV2 runs the v2 key schedule:
//
//	PRK = HKDF-Extract(SHA256, salt = clientSalt||serverSalt, IKM = ECDH||secret)
//	OKM = HKDF-Expand(PRK, "tiredvpn-reality-data-v2"||clientPub||serverPub, 88)
//
// Layout: [0:32] c2s key, [32:64] s2c key, [64:76] c2s IV, [76:88] s2c IV.
//
// Mixing the password into the IKM keeps the channel authenticated against a
// passive attacker who learns the ECDH output some other way; mixing the ECDH
// in is what gives forward secrecy, since a leaked password alone no longer
// opens recorded traffic.
func deriveRealityDataKeysV2(p RealityV2Params) ([88]byte, error) {
	var out [88]byte
	if len(p.ECDH) == 0 {
		return out, errors.New("reality v2: empty ecdh secret")
	}

	salt := make([]byte, 0, 64)
	salt = append(salt, p.ClientSalt[:]...)
	salt = append(salt, p.ServerSalt[:]...)

	ikm := make([]byte, 0, len(p.ECDH)+len(p.SharedSecret))
	ikm = append(ikm, p.ECDH...)
	ikm = append(ikm, p.SharedSecret...)

	info := make([]byte, 0, 24+64)
	info = append(info, []byte("tiredvpn-reality-data-v2")...)
	info = append(info, p.ClientPub[:]...)
	info = append(info, p.ServerPub[:]...)

	r := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

// realityDataConnV2 wraps a net.Conn and seals post-handshake data with
// ChaCha20-Poly1305, framed as TLS Application Data records (type 0x17).
//
// Differences from v1 (realityDataConn), all of them deliberate:
//   - AEAD instead of a bare keystream, so a middlebox flipping bits in the
//     tunnel breaks the connection instead of going unnoticed;
//   - an explicit per-direction record counter in the nonce, so no nonce is
//     ever reused inside a connection;
//   - the record body is 16 bytes longer than the plaintext, which is also what
//     a real TLS 1.3 record looks like — v1's exact length equality was itself
//     a distinguishing feature.
type realityDataConnV2 struct {
	net.Conn
	br *bufio.Reader

	wMu    sync.Mutex
	wAEAD  cipher.AEAD
	wIV    [12]byte
	wSeq   uint64
	wNonce [12]byte // scratch, held under wMu; a local array would escape per record

	rMu    sync.Mutex
	rAEAD  cipher.AEAD
	rIV    [12]byte
	rSeq   uint64
	rNonce [12]byte
	rErr   error  // sticky: a failed tag poisons the read side for good
	decBuf []byte // per-conn scratch for one record body
	rbuf   []byte // leftover plaintext, a slice into decBuf
}

// errRealityAuthFailed is returned once a record fails its Poly1305 tag. It is
// sticky: after tampering there is no safe way to resynchronise on a stream an
// attacker is writing into, so the connection stays broken.
var errRealityAuthFailed = errors.New("reality: record authentication failed")

// NewRealityDataConnV2 wraps conn in the v2 AEAD record layer. isClient selects
// the write direction: the client writes with the c2s key, the server with s2c.
func NewRealityDataConnV2(conn net.Conn, p RealityV2Params, isClient bool) (net.Conn, error) {
	keys, err := deriveRealityDataKeysV2(p)
	if err != nil {
		return nil, err
	}

	var wKey, rKey []byte
	var wIV, rIV [12]byte
	if isClient {
		wKey, rKey = keys[0:32], keys[32:64]
		copy(wIV[:], keys[64:76])
		copy(rIV[:], keys[76:88])
	} else {
		wKey, rKey = keys[32:64], keys[0:32]
		copy(wIV[:], keys[76:88])
		copy(rIV[:], keys[64:76])
	}

	wAEAD, err := chacha20poly1305.New(wKey)
	if err != nil {
		return nil, err
	}
	rAEAD, err := chacha20poly1305.New(rKey)
	if err != nil {
		return nil, err
	}

	return &realityDataConnV2{
		Conn:   conn,
		br:     bufio.NewReaderSize(conn, realityReadBufferSize),
		wAEAD:  wAEAD,
		wIV:    wIV,
		rAEAD:  rAEAD,
		rIV:    rIV,
		decBuf: make([]byte, realityMaxRecordBody),
	}, nil
}

// setRecordNonce fills dst with the nonce for record seq the way TLS 1.3 does:
// the static per-direction IV XOR the big-endian sequence number, right-aligned.
// dst is a field of the conn rather than a return value so the hot path does not
// allocate a fresh array per record.
func setRecordNonce(dst *[12]byte, iv [12]byte, seq uint64) {
	*dst = iv
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := range seqBytes {
		dst[4+i] ^= seqBytes[i]
	}
}

// Write seals p into one or more TLS Application Data records.
func (c *realityDataConnV2) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > realityV2MaxPlaintext {
			chunk = chunk[:realityV2MaxPlaintext]
		}

		bodyLen := len(chunk) + chacha20poly1305.Overhead

		bufp := realityFramePool.Get().(*[]byte)
		frame := (*bufp)[:5+bodyLen]

		frame[0] = 0x17 // content type: Application Data
		frame[1] = 0x03 // TLS 1.2 legacy version
		frame[2] = 0x03
		binary.BigEndian.PutUint16(frame[3:5], uint16(bodyLen))

		// The 5-byte header is the AAD, as in TLS 1.3: a truncated or retyped
		// record then fails to open instead of being silently accepted.
		setRecordNonce(&c.wNonce, c.wIV, c.wSeq)
		c.wAEAD.Seal(frame[5:5], c.wNonce[:], chunk, frame[0:5])
		c.wSeq++

		_, err := c.Conn.Write(frame)
		realityFramePool.Put(bufp)
		if err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read opens one record at a time, buffering plaintext that does not fit in b.
func (c *realityDataConnV2) Read(b []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	if c.rErr != nil {
		return 0, c.rErr
	}

	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		if len(c.rbuf) == 0 {
			c.rbuf = nil
		}
		return n, nil
	}

	var hdr [5]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x17 {
		return 0, errors.New("reality: unexpected TLS record type")
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[3:]))
	if bodyLen < realityV2MinRecordBody || bodyLen > realityMaxRecordBody {
		return 0, errors.New("reality: invalid TLS record length")
	}

	body := c.decBuf[:bodyLen]
	if _, err := io.ReadFull(c.br, body); err != nil {
		return 0, err
	}

	setRecordNonce(&c.rNonce, c.rIV, c.rSeq)
	plain, err := c.rAEAD.Open(body[:0], c.rNonce[:], body, hdr[:])
	if err != nil {
		// A failed tag is either corruption or an active tamper. Either way the
		// stream is no longer trustworthy: latch the error so the caller tears
		// the connection down instead of resynchronising on attacker-chosen bytes.
		c.rErr = errRealityAuthFailed
		return 0, c.rErr
	}
	c.rSeq++

	n := copy(b, plain)
	if n < len(plain) {
		c.rbuf = plain[n:]
	}
	return n, nil
}
