package strategy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// realityDataConn wraps a net.Conn and encrypts post-handshake data using
// ChaCha20 keystream framed as TLS Application Data records (type 0x17).
//
// This is needed because TSPU (Russian DPI) inspects post-handshake TCP data
// on REALITY connections. Since our "TLS" is a fake handshake forwarded from
// a cover domain, the actual data layer is raw smux — visible and
// distinguishable from real TLS by TSPU, which throttles it after ~600 bytes.
//
// By framing smux as TLS Application Data with a random chacha20 keystream,
// TSPU sees a valid-looking TLS stream and does not throttle.
//
// Key derivation: HKDF-SHA256(sharedSecret, salt=clientPubKey,
// info="tiredvpn-reality-data-v1") → 64 bytes:
//   - [0:32]  = write key (client→server direction)
//   - [32:64] = read key  (server→client direction)
//
// Server reverses the direction: write=[32:64], read=[0:32].
type realityDataConn struct {
	net.Conn
	wCipher *chacha20.Cipher // encrypt on write
	rCipher *chacha20.Cipher // decrypt on read
	rbuf    []byte           // leftover plaintext from last record
}

// deriveRealityDataKeys derives directional chacha20 keys for post-handshake data.
// sharedSecret is the VPN shared password, clientPubKey is the 32-byte X25519
// ephemeral public key from the REALITY extension (unique per connection).
// Returns [0:32]=c2s key, [32:64]=s2c key, [64:76]=c2s nonce, [76:88]=s2c nonce.
func deriveRealityDataKeys(sharedSecret, clientPubKey []byte) ([88]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, clientPubKey, []byte("tiredvpn-reality-data-v1"))
	var out [88]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

// NewRealityDataConn wraps conn in a TLS-record-framed ChaCha20 cipher.
// isClient controls which directional key is used for writing:
// client writes with c2s key, server writes with s2c key.
func NewRealityDataConn(conn net.Conn, sharedSecret, clientPubKey []byte, isClient bool) (net.Conn, error) {
	keys, err := deriveRealityDataKeys(sharedSecret, clientPubKey)
	if err != nil {
		return nil, err
	}

	var wKey, rKey [32]byte
	var wNonce, rNonce [12]byte
	if isClient {
		copy(wKey[:], keys[0:32])
		copy(rKey[:], keys[32:64])
		copy(wNonce[:], keys[64:76])
		copy(rNonce[:], keys[76:88])
	} else {
		// server: reverse directions
		copy(wKey[:], keys[32:64])
		copy(rKey[:], keys[0:32])
		copy(wNonce[:], keys[76:88])
		copy(rNonce[:], keys[64:76])
	}

	wCipher, err := chacha20.NewUnauthenticatedCipher(wKey[:], wNonce[:])
	if err != nil {
		return nil, err
	}
	rCipher, err := chacha20.NewUnauthenticatedCipher(rKey[:], rNonce[:])
	if err != nil {
		return nil, err
	}

	return &realityDataConn{
		Conn:    conn,
		wCipher: wCipher,
		rCipher: rCipher,
	}, nil
}

// Write encrypts p and sends it as one or more TLS Application Data records.
// Each record is at most 16383 bytes (TLS max record body).
func (c *realityDataConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 16383 {
			chunk = chunk[:16383]
		}

		// Encrypt in-place into a temporary buffer.
		enc := make([]byte, len(chunk))
		c.wCipher.XORKeyStream(enc, chunk)

		// TLS Application Data record header.
		var hdr [5]byte
		hdr[0] = 0x17         // content type: Application Data
		hdr[1] = 0x03         // TLS 1.2 legacy version
		hdr[2] = 0x03
		binary.BigEndian.PutUint16(hdr[3:], uint16(len(enc)))

		// Write header + encrypted payload as one syscall where possible.
		frame := make([]byte, 5+len(enc))
		copy(frame, hdr[:])
		copy(frame[5:], enc)
		if _, err := c.Conn.Write(frame); err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read reads and decrypts one TLS Application Data record at a time,
// buffering any leftover bytes from a record longer than b.
func (c *realityDataConn) Read(b []byte) (int, error) {
	// Drain leftover bytes from a previous record first.
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		if len(c.rbuf) == 0 {
			c.rbuf = nil
		}
		return n, nil
	}

	// Read TLS record header (5 bytes).
	var hdr [5]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x17 {
		return 0, errors.New("reality: unexpected TLS record type")
	}
	dataLen := int(binary.BigEndian.Uint16(hdr[3:]))
	if dataLen == 0 || dataLen > 16384 {
		return 0, errors.New("reality: invalid TLS record length")
	}

	// Read encrypted payload.
	enc := make([]byte, dataLen)
	if _, err := io.ReadFull(c.Conn, enc); err != nil {
		return 0, err
	}

	// Decrypt in-place.
	c.rCipher.XORKeyStream(enc, enc)

	// Copy to b, buffer remainder.
	n := copy(b, enc)
	if n < len(enc) {
		c.rbuf = enc[n:]
	}
	return n, nil
}
