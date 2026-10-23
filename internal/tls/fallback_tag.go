package tls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Fallback-transport tag carried in the TLS session_id.
//
// B1 is not the only first flight a B1 server's gate sees. HTTP Polling,
// WebSocket padded, Geneva, anti-probe, HTTP/2 stego, Traffic Morph, State
// Exhaustion and a relay's upstream open with a plain crypto/tls ClientHello on
// the same port. The gate cannot open their session_id, so it treats them as
// strangers and proxies them to the donor their SNI names - and an endpoint's
// SNI pool lists donors by design. Every TLS fallback then reached a real site
// instead of its handler.
//
// The tag tells the gate that the hello is ours without telling anyone else
// anything. It is 32 bytes in the field every TLS 1.3 ClientHello already
// fills with 32 random bytes, and it is built to be as random as what it
// replaces:
//
//	nonce (12) || time XOR PRF(nonce) (4) || MAC(nonce || masked time) (16)
//
// The nonce is fresh per connection, the time is masked by a pad only the key
// holder can compute, and the MAC is a PRF output. Nothing is static and
// nothing repeats between two connections, so there is no field to link them
// by. The key comes from the client's secret through HKDF with its own info
// string, so a tag is never a B1 credential and a B1 session_id is never a tag.
//
// What the tag does not do is bind the rest of the hello. crypto/tls draws the
// session_id before it builds the key shares, and offers no hook in between.
// A captured hello replayed byte for byte is caught by the server's replay
// cache; a censor that drops the original and sends it first instead reaches
// our TLS stack with a key share it holds no private key for - B1 accepts the
// same exposure.
const (
	// FallbackTagInfo is the HKDF info string of the tag key. Distinct from
	// AuthHKDFInfo and ShortIDInfo on purpose: one secret, three keys that
	// cannot stand in for each other.
	FallbackTagInfo = "tiredvpn-fallback-tag-v1"

	fallbackTagNonceLen = 12
	fallbackTagTimeLen  = 4
	fallbackTagMACLen   = AuthSessionIDLen - fallbackTagNonceLen - fallbackTagTimeLen
)

// FallbackTagKey is the key a client's tags are made and checked with.
type FallbackTagKey [32]byte

// DeriveFallbackTagKey derives the tag key from a client secret.
func DeriveFallbackTagKey(secret []byte) FallbackTagKey {
	var k FallbackTagKey
	key, err := hkdf.Key(sha256.New, secret, nil, FallbackTagInfo, len(k))
	if err != nil {
		// Only a key length out of range fails, and 32 is in range.
		panic("fallback tag: hkdf: " + err.Error())
	}
	copy(k[:], key)
	return k
}

// FallbackTag makes a fresh tag for now.
func FallbackTag(key FallbackTagKey, now time.Time) ([AuthSessionIDLen]byte, error) {
	var nonce [fallbackTagNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [AuthSessionIDLen]byte{}, err
	}
	return key.seal(nonce, uint32(now.Unix())), nil
}

func (k FallbackTagKey) seal(nonce [fallbackTagNonceLen]byte, unix uint32) [AuthSessionIDLen]byte {
	var out [AuthSessionIDLen]byte
	copy(out[:fallbackTagNonceLen], nonce[:])
	pad := k.prf(0x01, nonce[:])
	binary.BigEndian.PutUint32(out[fallbackTagNonceLen:], unix^binary.BigEndian.Uint32(pad))
	mac := k.prf(0x02, out[:fallbackTagNonceLen+fallbackTagTimeLen])
	copy(out[fallbackTagNonceLen+fallbackTagTimeLen:], mac[:fallbackTagMACLen])
	return out
}

// Open checks sid against the key and returns the time it was made at.
//
// One HMAC for a session_id that is not this key's: the MAC covers the masked
// time, so the pad is computed only once the MAC has matched.
func (k FallbackTagKey) Open(sid [AuthSessionIDLen]byte) (unix uint32, ok bool) {
	body := sid[:fallbackTagNonceLen+fallbackTagTimeLen]
	mac := k.prf(0x02, body)
	if !hmac.Equal(mac[:fallbackTagMACLen], sid[fallbackTagNonceLen+fallbackTagTimeLen:]) {
		return 0, false
	}
	pad := k.prf(0x01, sid[:fallbackTagNonceLen])
	return binary.BigEndian.Uint32(sid[fallbackTagNonceLen:]) ^ binary.BigEndian.Uint32(pad), true
}

func (k FallbackTagKey) prf(label byte, msg []byte) []byte {
	h := hmac.New(sha256.New, k[:])
	h.Write([]byte{label})
	h.Write(msg)
	return h.Sum(nil)
}

// WithFallbackTag returns cfg for one handshake to a tiredvpn server, with the
// session_id carrying a fresh tag for secret. Call it at every tls.Client: the
// reader it installs serves exactly one ClientHello, and a dial that retries
// (the ECH fallbacks) needs a second one. An empty secret leaves cfg alone.
func WithFallbackTag(cfg *tls.Config, secret []byte) *tls.Config {
	if len(secret) == 0 {
		return cfg
	}
	c := cfg.Clone()
	c.Rand = NewFallbackTagRand(secret)
	return c
}

// NewFallbackTagRand returns a crypto/tls Config.Rand that writes a fresh tag
// for secret where crypto/tls draws the ClientHello session_id, and is
// crypto/rand everywhere else. One reader serves one handshake: give every
// tls.Client its own.
//
// crypto/tls has no API for the session_id, and this is the only way to set it
// while keeping the stdlib's ClientHello - and so its fingerprint - exactly as
// it is. The read is recognised by its caller, not by its position alone: the
// second 32-byte read made directly from makeClientHello (the first is
// ClientHello.random). Anything else, including a crypto/tls that one day
// draws its reads in another order, gets crypto/rand, so the tag can only ever
// land in the session_id or nowhere - never in a key.
func NewFallbackTagRand(secret []byte) io.Reader {
	return &fallbackTagRand{key: DeriveFallbackTagKey(secret)}
}

type fallbackTagRand struct {
	key FallbackTagKey

	mu    sync.Mutex
	reads int // 32-byte reads made from makeClientHello so far
}

// makeClientHelloFunc is the crypto/tls function that draws the session_id.
const makeClientHelloFunc = "crypto/tls.(*Conn).makeClientHello"

func (r *fallbackTagRand) Read(p []byte) (int, error) {
	if len(p) == AuthSessionIDLen && readFrom(makeClientHelloFunc) {
		r.mu.Lock()
		n := r.reads
		r.reads++
		r.mu.Unlock()
		if n == 1 {
			tag, err := FallbackTag(r.key, time.Now())
			if err != nil {
				return 0, err
			}
			return copy(p, tag[:]), nil
		}
	}
	return rand.Read(p)
}

// readFrom reports whether the Read in progress was called, through io's
// helpers, by fn.
func readFrom(fn string) bool {
	var pcs [8]uintptr
	// Skip runtime.Callers, readFrom and Read.
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs[:])])
	for {
		f, more := frames.Next()
		if !strings.HasPrefix(f.Function, "io.") {
			return f.Function == fn
		}
		if !more {
			return false
		}
	}
}
