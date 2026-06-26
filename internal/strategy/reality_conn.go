package strategy

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// realityReadBufferSize is the bufio.Reader size on the REALITY read path. The
// max TLS record body is 16383 + 5-byte header; a buffer above that lets a full
// record (and often the next header) be pulled in one syscall instead of the two
// io.ReadFull triggered per record before. Read-only sizing, no wire impact.
const realityReadBufferSize = 32 * 1024

// realityMaxRecordBody is the largest TLS Application Data body we accept on read
// (and the size of the per-conn decrypt buffer). Write caps chunks at 16383; the
// read side tolerates up to 16384 for robustness.
const realityMaxRecordBody = 16384

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
	br      *bufio.Reader    // buffered reads from c.Conn (batches header+body syscalls)
	wCipher *chacha20.Cipher // encrypt on write
	rCipher *chacha20.Cipher // decrypt on read
	decBuf  []byte           // per-conn decrypt scratch (realityMaxRecordBody bytes)
	rbuf    []byte           // leftover plaintext, a slice into decBuf
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
		br:      bufio.NewReaderSize(conn, realityReadBufferSize),
		wCipher: wCipher,
		rCipher: rCipher,
		decBuf:  make([]byte, realityMaxRecordBody),
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

	// Read TLS record header (5 bytes) through the buffered reader.
	var hdr [5]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x17 {
		return 0, errors.New("reality: unexpected TLS record type")
	}
	dataLen := int(binary.BigEndian.Uint16(hdr[3:]))
	if dataLen == 0 || dataLen > realityMaxRecordBody {
		return 0, errors.New("reality: invalid TLS record length")
	}

	// Read the encrypted payload into the per-conn scratch buffer (no per-Read
	// allocation). dataLen <= realityMaxRecordBody == len(c.decBuf).
	buf := c.decBuf[:dataLen]
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return 0, err
	}

	// Decrypt in-place. ChaCha20 keystream consumption stays byte-for-byte in
	// sync with the wire: bufio only changes how bytes are fetched, not which
	// bytes or their order, so framing is identical to the unbuffered path.
	c.rCipher.XORKeyStream(buf, buf)

	// Copy to b; any remainder stays in decBuf as a bounded leftover slice
	// (no retention of a separate full-record allocation).
	n := copy(b, buf)
	if n < dataLen {
		c.rbuf = c.decBuf[n:dataLen]
	}
	return n, nil
}
