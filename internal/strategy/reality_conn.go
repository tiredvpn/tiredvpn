package strategy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// realityFramePool reuses Write frame buffers (TLS 5-byte header + up to the
// max 16383-byte record body = 16388 bytes). A buffer is borrowed for the
// duration of a single c.Conn.Write call and returned immediately after, so
// no reference outlives the write. Stores *[]byte to avoid per-Get allocation
// of the slice header.
var realityFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, 5+16383)
		return &b
	},
}

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

		// Borrow a pooled frame buffer: 5-byte TLS header + encrypted payload.
		bufp := realityFramePool.Get().(*[]byte)
		frame := (*bufp)[:5+len(chunk)]

		// TLS Application Data record header, written directly into the frame.
		frame[0] = 0x17 // content type: Application Data
		frame[1] = 0x03 // TLS 1.2 legacy version
		frame[2] = 0x03
		binary.BigEndian.PutUint16(frame[3:5], uint16(len(chunk)))

		// Encrypt straight into the payload region (ChaCha20 XOR is symmetric
		// and consumes the same keystream regardless of dst/src aliasing, so
		// this is byte-identical to encrypting into a scratch buffer + copy).
		c.wCipher.XORKeyStream(frame[5:], chunk)

		_, err := c.Conn.Write(frame)
		// Return the buffer only after Write completes (Conn.Write does not
		// retain the slice past the call), then handle any error.
		realityFramePool.Put(bufp)
		if err != nil {
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
