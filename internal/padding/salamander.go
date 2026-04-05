package padding

import (
	"crypto/rand"
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
