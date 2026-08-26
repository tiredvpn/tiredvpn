package padding

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// PaddingLevel defines the aggressiveness of padding obfuscation
type PaddingLevel int

const (
	// Conservative adds 5-10% padding overhead (minimal impact, good for stable connections)
	Conservative PaddingLevel = iota
	// Balanced adds 15-25% padding overhead (default, good balance)
	Balanced
	// Aggressive adds 30-50% padding overhead (maximum obfuscation, higher latency)
	Aggressive
)

// String returns the string representation of PaddingLevel
func (p PaddingLevel) String() string {
	switch p {
	case Conservative:
		return "Conservative"
	case Balanced:
		return "Balanced"
	case Aggressive:
		return "Aggressive"
	default:
		return "Unknown"
	}
}

// SalamanderPadder implements BLAKE2b-256 based cryptographic padding (Hysteria2-style)
// Each packet: [salt:8][XOR(data, BLAKE2b(salt || secret))][random padding]
type SalamanderPadder struct {
	secret  []byte
	level   PaddingLevel
	buckets []int // Packet size buckets for normalization
}

// NewSalamanderPadder creates a new Salamander padder with specified level
func NewSalamanderPadder(secret []byte, level PaddingLevel) *SalamanderPadder {
	sp := &SalamanderPadder{
		secret: secret,
		level:  level,
	}

	// Initialize buckets based on level
	sp.buckets = getBucketsForLevel(level)

	return sp
}

// Encrypt obfuscates plaintext data with Salamander padding
func (sp *SalamanderPadder) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("salamander: empty plaintext")
	}
	if len(sp.secret) > 64 {
		return nil, errors.New("salamander: secret too long (max 64 bytes for BLAKE2b)")
	}

	// 1. Generate random salt (8 bytes)
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// 2. Derive 32-byte hash from salt + secret using BLAKE2b-256
	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, err
	}
	h.Write(salt)
	hash := h.Sum(nil) // 32 bytes

	// 3. XOR plaintext with hash (cycling through hash bytes)
	encrypted := make([]byte, len(plaintext))
	for i, b := range plaintext {
		encrypted[i] = b ^ hash[i%32]
	}

	// 4. Determine target bucket size (padding)
	plaintextLen := len(plaintext)
	targetSize := sp.normalizeToucket(plaintextLen)

	// 5. Calculate padding length (accounting for salt overhead)
	totalDataLen := 8 + len(encrypted) // salt + encrypted
	paddingLen := targetSize - totalDataLen

	if paddingLen < 0 {
		paddingLen = 0 // Data larger than largest bucket, no padding
	}

	// 6. Generate random padding
	padding := make([]byte, paddingLen)
	if paddingLen > 0 {
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	// 7. Assemble final packet: [salt:8][encrypted][padding]
	result := make([]byte, 0, 8+len(encrypted)+paddingLen)
	result = append(result, salt...)
	result = append(result, encrypted...)
	result = append(result, padding...)

	return result, nil
}

// Decrypt recovers plaintext from Salamander-encrypted data
func (sp *SalamanderPadder) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 8 {
		return nil, errors.New("salamander: ciphertext too short")
	}

	// 1. Extract salt (first 8 bytes)
	salt := ciphertext[:8]

	// 2. Derive same hash from salt + secret
	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, err
	}
	h.Write(salt)
	hash := h.Sum(nil)

	// 3. XOR encrypted data (rest of ciphertext, including padding)
	encrypted := ciphertext[8:]
	plaintext := make([]byte, len(encrypted))
	for i, b := range encrypted {
		plaintext[i] = b ^ hash[i%32]
	}

	// Note: We cannot know exact plaintext length here without additional framing
	// The caller must handle length detection (e.g., via WebSocket frame length or length prefix)
	// For now, return full decrypted data including padding

	return plaintext, nil
}

// udpTagLen is the width of the keyed authenticity tag carried by the UDP/QUIC
// framing. It sets the odds that a packet encrypted under a foreign secret
// survives the check: 2^-udpTagLen*8. The previous width of 2 bytes gave 2^-16,
// i.e. one bogus accept per ~65k trials - a server holding a few thousand
// per-client secrets trials each of them against every unmatched packet, so at
// that width false accepts are an operational event, not a theoretical one. At
// 8 bytes the same server needs on the order of 10^19 trials before the first
// one, which is out of reach of any traffic volume this code will ever see.
//
// The six extra bytes cost nothing on the wire in the common case: EncryptUDP
// pads to a fixed size bucket, so a wider tag only eats into the random padding
// and the datagram an observer measures is unchanged. The exceptions are
// payloads within six bytes below a bucket boundary, which move up one bucket,
// and payloads above the largest bucket, where no padding applies at all and
// the datagram grows by six. See TestSalamanderUDPWireSizeStable.
const udpTagLen = 8

// udpHeaderLen is the framing that precedes the payload inside the masked
// region: [tag:udpTagLen][lenHi][lenLo].
const udpHeaderLen = udpTagLen + 2

// keyTag derives a deterministic verification tag from the secret and salt. It
// is used by the UDP/QUIC framing to confirm that a packet was encrypted with
// the same secret before trusting the (XOR-only, unauthenticated) length
// prefix. A wrong secret yields a different keystream and therefore a different
// tag, so mismatches are rejected deterministically instead of being guessed at
// via header heuristics.
func (sp *SalamanderPadder) keyTag(salt []byte) ([udpTagLen]byte, error) {
	var tag [udpTagLen]byte
	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return tag, err
	}
	// Domain-separate the tag from the XOR keystream so the tag never leaks
	// keystream bytes used to mask the payload.
	h.Write([]byte("tag"))
	h.Write(salt)
	copy(tag[:], h.Sum(nil))
	return tag, nil
}

// EncryptUDP frames a single UDP/QUIC payload for transmission. The inner
// plaintext layout is [tag:udpTagLen][lenHi][lenLo][payload], which is then
// masked with the keystream and padded to a bucket. The tag lets the receiver
// verify the secret deterministically.
func (sp *SalamanderPadder) EncryptUDP(payload []byte) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, fmt.Errorf("salamander: payload too large (%d > 65535)", len(payload))
	}

	inner := make([]byte, udpHeaderLen+len(payload))
	// tag is filled after we know the salt, so encrypt manually below.
	inner[udpTagLen] = byte(len(payload) >> 8)
	inner[udpTagLen+1] = byte(len(payload))
	copy(inner[udpHeaderLen:], payload)

	// Generate salt + keystream exactly like Encrypt, but inject the tag.
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	tag, err := sp.keyTag(salt)
	if err != nil {
		return nil, err
	}
	copy(inner[:udpTagLen], tag[:])

	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, err
	}
	h.Write(salt)
	hash := h.Sum(nil)

	encrypted := make([]byte, len(inner))
	for i, b := range inner {
		encrypted[i] = b ^ hash[i%32]
	}

	targetSize := sp.normalizeToucket(len(inner))
	totalDataLen := 8 + len(encrypted)
	paddingLen := targetSize - totalDataLen
	if paddingLen < 0 {
		paddingLen = 0
	}
	padding := make([]byte, paddingLen)
	if paddingLen > 0 {
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	result := make([]byte, 0, 8+len(encrypted)+paddingLen)
	result = append(result, salt...)
	result = append(result, encrypted...)
	result = append(result, padding...)
	return result, nil
}

// DecryptUDP reverses EncryptUDP. It returns the original payload only if the
// embedded tag matches the secret; otherwise ok is false. This is the
// authoritative secret-match check for the UDP/QUIC transport.
func (sp *SalamanderPadder) DecryptUDP(ciphertext []byte) (payload []byte, ok bool) {
	if len(ciphertext) < 8+udpHeaderLen {
		return nil, false
	}
	salt := ciphertext[:8]

	wantTag, err := sp.keyTag(salt)
	if err != nil {
		return nil, false
	}

	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, false
	}
	h.Write(salt)
	hash := h.Sum(nil)

	enc := ciphertext[8:]
	// Decrypt just the header first (tag + length) to validate cheaply.
	var hdr [udpHeaderLen]byte
	for i := 0; i < udpHeaderLen; i++ {
		hdr[i] = enc[i] ^ hash[i%32]
	}
	// Constant-time so the number of leading tag bytes an attacker got right is
	// not readable from how long the reject took. MultiSecret trials this per
	// registered secret, which would otherwise be a convenient amplifier.
	if subtle.ConstantTimeCompare(hdr[:udpTagLen], wantTag[:]) != 1 {
		return nil, false
	}
	dataLen := int(hdr[udpTagLen])<<8 | int(hdr[udpTagLen+1])
	if udpHeaderLen+dataLen > len(enc) {
		return nil, false
	}

	payload = make([]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		payload[i] = enc[udpHeaderLen+i] ^ hash[(udpHeaderLen+i)%32]
	}
	return payload, true
}

// DecryptWithLength decrypts data and returns only the specified plaintext length
func (sp *SalamanderPadder) DecryptWithLength(ciphertext []byte, plaintextLen int) ([]byte, error) {
	decrypted, err := sp.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	if len(decrypted) < plaintextLen {
		return nil, errors.New("salamander: decrypted data shorter than expected length")
	}

	return decrypted[:plaintextLen], nil
}

// normalizeToucket finds the smallest bucket that fits the data
func (sp *SalamanderPadder) normalizeToucket(dataLen int) int {
	// Account for salt overhead (8 bytes)
	requiredSize := dataLen + 8

	// Find smallest bucket that fits
	for _, bucket := range sp.buckets {
		if bucket >= requiredSize {
			return bucket
		}
	}

	// If data is larger than all buckets, return data size (no padding)
	// Alternatively, could use largest bucket and split into multiple packets
	return requiredSize
}

// getBucketsForLevel returns bucket sizes for a given padding level
func getBucketsForLevel(level PaddingLevel) []int {
	switch level {
	case Conservative:
		// MTU-aligned buckets (minimal overhead)
		return []int{512, 1024, 1452} // 1452 = 1500 MTU - 48 bytes (IP+TCP headers)

	case Balanced:
		// More buckets for better distribution
		return []int{400, 800, 1200, 1400}

	case Aggressive:
		// Many small buckets for maximum obfuscation
		return []int{300, 600, 900, 1200, 1400}

	default:
		return []int{512, 1024, 1452}
	}
}

// GetOverheadPercentage returns the approximate overhead percentage for this level
func (sp *SalamanderPadder) GetOverheadPercentage() (min, max int) {
	switch sp.level {
	case Conservative:
		return 5, 10
	case Balanced:
		return 15, 25
	case Aggressive:
		return 30, 50
	default:
		return 10, 20
	}
}

// GetBuckets returns the current bucket configuration
func (sp *SalamanderPadder) GetBuckets() []int {
	return sp.buckets
}

// GetLevel returns the current padding level
func (sp *SalamanderPadder) GetLevel() PaddingLevel {
	return sp.level
}

// SetLevel updates the padding level and bucket configuration
func (sp *SalamanderPadder) SetLevel(level PaddingLevel) {
	sp.level = level
	sp.buckets = getBucketsForLevel(level)
}

// EstimatePaddedSize estimates the padded size for a given plaintext length
func (sp *SalamanderPadder) EstimatePaddedSize(plaintextLen int) int {
	return sp.normalizeToucket(plaintextLen)
}

// Obfuscate is an alias for Encrypt for clarity in some contexts
func (sp *SalamanderPadder) Obfuscate(data []byte) ([]byte, error) {
	return sp.Encrypt(data)
}

// Deobfuscate is an alias for Decrypt for clarity in some contexts
func (sp *SalamanderPadder) Deobfuscate(data []byte) ([]byte, error) {
	return sp.Decrypt(data)
}

// LevelFromString parses a padding level from string
func LevelFromString(s string) PaddingLevel {
	switch s {
	case "conservative", "low", "1":
		return Conservative
	case "balanced", "medium", "2":
		return Balanced
	case "aggressive", "high", "3":
		return Aggressive
	default:
		return Balanced // Default to balanced
	}
}

// LevelToString converts padding level to string
func LevelToString(level PaddingLevel) string {
	switch level {
	case Conservative:
		return "conservative"
	case Balanced:
		return "balanced"
	case Aggressive:
		return "aggressive"
	default:
		return "balanced"
	}
}
