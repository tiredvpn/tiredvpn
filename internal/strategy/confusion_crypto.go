package strategy

import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// The confusion wire, version 2.
//
// v1 put a literal "TIRED" in the first packet and relayed plaintext behind it.
// Both halves were defects: the literal identified the server in one packet to
// anyone who sent five bytes, and the plaintext framing meant every byte of a
// user's traffic crossed the wire in the clear under a protocol whose whole
// premise is that the wire is hostile.
//
// v2 replaces the literal with a marker keyed to the shared secret and a fresh
// per-connection nonce, and seals everything after it with ChaCha20-Poly1305.
// The marker is what the server authenticates on: it is computed before any
// dial, any address parse and any answer, so a peer that does not hold the
// secret gets the same fake website every other unknown peer gets.
//
// There is no transitional mode. A 1.10.x client speaks v1, its first packet
// fails the marker check, and it is served the fake website - a fast, final
// answer rather than a hang.

const (
	// ConfusionNonceLen is the per-connection nonce the marker and the data
	// keys are derived from. 16 bytes is the same order as a TLS random and
	// makes a replayed first packet the only way to repeat a key schedule.
	ConfusionNonceLen = 16

	// confusionMarkerMinLen / confusionMarkerSpan bound the marker length.
	// The length itself is derived from (secret, nonce), so it is not a field
	// on the wire and an observer cannot read it off the packet - but the
	// resulting block length IS observable, and it is flat over [16,48).
	//
	// Rule 3 of the verification rules asks what measured distribution such a
	// field is checked against. For this one the answer is "nothing": the
	// marker lives inside an opaque option of the carrier protocol (an EDNS0
	// local-use option, an HTTP body, an SSH string, a SASL initial response),
	// and we have no measurement of those lengths in the wild to match. That
	// is recorded here deliberately rather than left implied.
	confusionMarkerMinLen = 16
	confusionMarkerSpan   = 32
	confusionMarkerMaxLen = confusionMarkerMinLen + confusionMarkerSpan - 1

	// confusionMaxPlaintext is the largest plaintext in one sealed frame. The
	// frame header carries the body length in two bytes, so body (plaintext +
	// tag) must stay under 64 KiB; 16 KiB matches a TLS record and keeps the
	// receive scratch buffer small.
	confusionMaxPlaintext = 16384
	confusionMaxBody      = confusionMaxPlaintext + chacha20poly1305.Overhead

	confusionClientMarkerLabel = "tiredvpn-confusion-client-marker-v2"
	confusionServerMarkerLabel = "tiredvpn-confusion-server-marker-v2"
	confusionDataKeyLabel      = "tiredvpn-confusion-data-v2"
)

// ErrConfusionAuth is returned when a sealed frame fails its tag. It is sticky:
// once an attacker has written into the stream there is no safe resynchronisation
// point, so the connection stays broken for good.
var ErrConfusionAuth = errors.New("confusion: frame authentication failed")

// NewConfusionNonce returns a fresh per-connection nonce.
func NewConfusionNonce() ([ConfusionNonceLen]byte, error) {
	var n [ConfusionNonceLen]byte
	if _, err := rand.Read(n[:]); err != nil {
		return n, err
	}
	return n, nil
}

// confusionMarker derives the variable-length marker for one direction.
//
// The variant byte is mixed in so a marker captured from, say, the DNS carrier
// cannot be replayed inside the SMTP one: the two carriers then disagree about
// what the same secret and nonce should produce.
func confusionMarker(label string, secret []byte, nonce []byte, variant byte) []byte {
	if len(secret) == 0 {
		return nil
	}
	info := make([]byte, 0, len(label)+1)
	info = append(info, label...)
	info = append(info, variant)

	r := hkdf.New(sha256.New, secret, nonce, info)
	var lenByte [1]byte
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return nil
	}
	markerLen := confusionMarkerMinLen + int(lenByte[0]%confusionMarkerSpan)
	out := make([]byte, markerLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil
	}
	return out
}

// ConfusionClientMarker is the proof of the secret the client puts in its first
// packet. The server recomputes it per candidate secret; a match is what
// identifies the client, and it is the only thing that does.
func ConfusionClientMarker(secret []byte, nonce []byte, variant byte) []byte {
	return confusionMarker(confusionClientMarkerLabel, secret, nonce, variant)
}

// ConfusionServerMarker is the server's answering proof. It is a different
// derivation from the client's so a peer that captured one cannot echo it back
// and pass for the server.
func ConfusionServerMarker(secret []byte, nonce []byte, variant byte) []byte {
	return confusionMarker(confusionServerMarkerLabel, secret, nonce, variant)
}

// MatchConfusionClientMarker reports whether payload opens with the marker this
// secret and nonce produce, and how many bytes that marker occupied.
//
// It returns the length rather than taking it as an argument because the length
// is itself derived from the secret: a caller that does not know the secret
// cannot say where the marker ends, which is the point.
func MatchConfusionClientMarker(secret []byte, nonce []byte, variant byte, payload []byte) (int, bool) {
	want := ConfusionClientMarker(secret, nonce, variant)
	if len(want) == 0 || len(payload) < len(want) {
		return 0, false
	}
	if !hmac.Equal(payload[:len(want)], want) {
		return 0, false
	}
	return len(want), true
}

// confusionDataKeys derives the two directional keys and IVs from the secret and
// the connection's nonce.
//
// Layout: [0:32] c2s key, [32:64] s2c key, [64:76] c2s IV, [76:88] s2c IV.
//
// A fresh nonce per connection is what keeps two connections of the same client
// from sharing a key schedule - the defect the REALITY data layer had in v1 and
// the reason this one starts where that one ended up.
func confusionDataKeys(secret []byte, nonce []byte, variant byte) ([88]byte, error) {
	var out [88]byte
	if len(secret) == 0 {
		return out, errors.New("confusion: empty secret")
	}
	info := make([]byte, 0, len(confusionDataKeyLabel)+1)
	info = append(info, confusionDataKeyLabel...)
	info = append(info, variant)

	r := hkdf.New(sha256.New, secret, nonce, info)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

// confusionFramePool reuses write frames (2-byte header + max body).
var confusionFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, 2+confusionMaxBody)
		return &b
	},
}

// ConfusionConn is the sealed record layer that carries everything after the
// first packet's marker.
//
// Write seals each call as exactly one frame (chunked when it exceeds the
// plaintext cap), so a peer using ReadFrame sees the same message boundaries the
// writer used - the server's proxy relay depends on that to recognise a control
// message. Read is a plain byte stream over the same frames, which is what the
// TUN path wants, since it does its own [length:4] framing on top.
type ConfusionConn struct {
	net.Conn
	br *bufio.Reader

	wMu    sync.Mutex
	wAEAD  cipher.AEAD
	wIV    [12]byte
	wSeq   uint64
	wNonce [12]byte

	rMu    sync.Mutex
	rAEAD  cipher.AEAD
	rIV    [12]byte
	rSeq   uint64
	rNonce [12]byte
	rErr   error
	decBuf []byte
	rbuf   []byte // leftover plaintext, a slice into decBuf
}

// NewConfusionConn wraps conn in the sealed record layer. isClient picks the
// write direction: the client writes with the c2s key, the server with s2c.
func NewConfusionConn(conn net.Conn, secret []byte, nonce []byte, variant byte, isClient bool) (*ConfusionConn, error) {
	keys, err := confusionDataKeys(secret, nonce, variant)
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

	return &ConfusionConn{
		Conn:   conn,
		br:     bufio.NewReaderSize(conn, 32*1024),
		wAEAD:  wAEAD,
		wIV:    wIV,
		rAEAD:  rAEAD,
		rIV:    rIV,
		decBuf: make([]byte, confusionMaxBody),
	}, nil
}

// setConfusionNonce fills dst the way TLS 1.3 does: the static per-direction IV
// XOR the big-endian record number, right-aligned. No nonce repeats inside a
// connection, and two connections differ because their IVs do.
func setConfusionNonce(dst *[12]byte, iv [12]byte, seq uint64) {
	*dst = iv
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := range seqBytes {
		dst[4+i] ^= seqBytes[i]
	}
}

// SealFrames returns p sealed as one or more frames without writing them. The
// first packet needs the sealed bytes as a value, because they go inside the
// carrier rather than straight onto the socket.
func (c *ConfusionConn) SealFrames(p []byte) []byte {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	return c.sealLocked(p)
}

func (c *ConfusionConn) sealLocked(p []byte) []byte {
	out := make([]byte, 0, len(p)+2+chacha20poly1305.Overhead)
	for {
		chunk := p
		if len(chunk) > confusionMaxPlaintext {
			chunk = chunk[:confusionMaxPlaintext]
		}

		bodyLen := len(chunk) + chacha20poly1305.Overhead
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(bodyLen))

		frame := make([]byte, 2, 2+bodyLen)
		copy(frame, hdr[:])
		setConfusionNonce(&c.wNonce, c.wIV, c.wSeq)
		// The 2-byte header is the AAD: a truncated or retargeted frame then
		// fails to open instead of being accepted as a shorter message.
		frame = c.wAEAD.Seal(frame, c.wNonce[:], chunk, hdr[:])
		c.wSeq++
		out = append(out, frame...)

		p = p[len(chunk):]
		if len(p) == 0 {
			return out
		}
	}
}

// Write seals p and puts it on the wire. One call is one frame unless p exceeds
// the plaintext cap.
func (c *ConfusionConn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()

	total := 0
	for {
		chunk := p
		if len(chunk) > confusionMaxPlaintext {
			chunk = chunk[:confusionMaxPlaintext]
		}

		bodyLen := len(chunk) + chacha20poly1305.Overhead
		bufp := confusionFramePool.Get().(*[]byte)
		frame := (*bufp)[:2]
		binary.BigEndian.PutUint16(frame[:2], uint16(bodyLen))

		setConfusionNonce(&c.wNonce, c.wIV, c.wSeq)
		frame = c.wAEAD.Seal(frame, c.wNonce[:], chunk, frame[:2])
		c.wSeq++

		_, err := c.Conn.Write(frame)
		confusionFramePool.Put(bufp)
		if err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
		if len(p) == 0 {
			return total, nil
		}
	}
}

// readFrameLocked opens exactly one frame into c.decBuf and returns the
// plaintext as a slice of it.
func (c *ConfusionConn) readFrameLocked() ([]byte, error) {
	if c.rErr != nil {
		return nil, c.rErr
	}

	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, err
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[:]))
	if bodyLen < chacha20poly1305.Overhead || bodyLen > confusionMaxBody {
		c.rErr = ErrConfusionAuth
		return nil, c.rErr
	}

	body := c.decBuf[:bodyLen]
	if _, err := io.ReadFull(c.br, body); err != nil {
		return nil, err
	}

	setConfusionNonce(&c.rNonce, c.rIV, c.rSeq)
	plain, err := c.rAEAD.Open(body[:0], c.rNonce[:], body, hdr[:])
	if err != nil {
		c.rErr = ErrConfusionAuth
		return nil, c.rErr
	}
	c.rSeq++
	return plain, nil
}

// ReadFrame returns the plaintext of exactly one frame, preserving the message
// boundary the writer used. It refuses to run once Read has buffered a partial
// frame, because mixing the two would silently drop the buffered remainder.
func (c *ConfusionConn) ReadFrame() ([]byte, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	if len(c.rbuf) > 0 {
		return nil, errors.New("confusion: ReadFrame after a partial stream read")
	}
	return c.readFrameLocked()
}

// Read is a byte stream over the same frames.
func (c *ConfusionConn) Read(b []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		if len(c.rbuf) == 0 {
			c.rbuf = nil
		}
		return n, nil
	}

	plain, err := c.readFrameLocked()
	if err != nil {
		return 0, err
	}
	n := copy(b, plain)
	if n < len(plain) {
		c.rbuf = plain[n:]
	}
	return n, nil
}
