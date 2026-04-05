package tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Post-Quantum Constants
const (
	// Version identifier for PQ-enhanced protocol
	REALITYVersionPQ = 0x02

	// Key sizes
	Kyber768PublicKeySize  = 1184
	Kyber768PrivateKeySize = 2400
	Kyber768CiphertextSize = 1088
	Kyber768SharedKeySize  = 32

	Dilithium3PublicKeySize  = 1952
	Dilithium3PrivateKeySize = 4000
	Dilithium3SignatureSize  = 3293
)

// HybridKeyExchange implements X25519 + ML-KEM-768 hybrid key exchange
// This provides both classical and post-quantum security
type HybridKeyExchange struct {
	// Classical (X25519)
	ClassicalPrivateKey [32]byte
	ClassicalPublicKey  [32]byte

	// Post-Quantum (ML-KEM-768 / Kyber768)
	KemPublicKey  []byte
	KemPrivateKey []byte
}

// Kyber768 key sizes
const (
	kyber768PublicKeyBytes  = 1184
	kyber768PrivateKeyBytes = 2400
	kyber768CiphertextBytes = 1088
	kyber768SharedKeyBytes  = 32
)

// NewHybridKeyExchange generates a new hybrid keypair
func NewHybridKeyExchange() (*HybridKeyExchange, error) {
	hke := &HybridKeyExchange{}

	// Generate X25519 keypair
	if _, err := rand.Read(hke.ClassicalPrivateKey[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&hke.ClassicalPublicKey, &hke.ClassicalPrivateKey)

	// Generate ML-KEM-768 (Kyber768) keypair
	pk, sk, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}

	hke.KemPublicKey = make([]byte, kyber768PublicKeyBytes)
	hke.KemPrivateKey = make([]byte, kyber768PrivateKeyBytes)
	pk.Pack(hke.KemPublicKey)
	sk.Pack(hke.KemPrivateKey)

	return hke, nil
}

// Encapsulate performs hybrid key encapsulation
// Returns: ciphertext (for peer), shared secret (for KDF)
func (h *HybridKeyExchange) Encapsulate(peerClassicalPub [32]byte, peerKemPub []byte) (kemCiphertext []byte, hybridSecret []byte, err error) {
	// 1. X25519 shared secret
	var classicalShared [32]byte
	curve25519.ScalarMult(&classicalShared, &h.ClassicalPrivateKey, &peerClassicalPub)

	// 2. ML-KEM-768 encapsulation
	var peerPk kyber768.PublicKey
	peerPk.Unpack(peerKemPub)

	// Allocate buffers for ciphertext and shared secret
	kemCiphertext = make([]byte, kyber768CiphertextBytes)
	kemShared := make([]byte, kyber768SharedKeyBytes)

	// Generate random seed for encapsulation
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	peerPk.EncapsulateTo(kemCiphertext, kemShared, seed)

	// 3. Combine secrets using HKDF
	hybridSecret, err = combineSecrets(classicalShared[:], kemShared)
	if err != nil {
		return nil, nil, err
	}

	return kemCiphertext, hybridSecret, nil
}

// Decapsulate performs hybrid key decapsulation
// Takes peer's classical public key and KEM ciphertext, returns shared secret
func (h *HybridKeyExchange) Decapsulate(peerClassicalPub [32]byte, kemCiphertext []byte) (hybridSecret []byte, err error) {
	// 1. X25519 shared secret
	var classicalShared [32]byte
	curve25519.ScalarMult(&classicalShared, &h.ClassicalPrivateKey, &peerClassicalPub)

	// 2. ML-KEM-768 decapsulation
	var sk kyber768.PrivateKey
	sk.Unpack(h.KemPrivateKey)

	// Allocate buffer for shared secret
	kemShared := make([]byte, kyber768SharedKeyBytes)
	sk.DecapsulateTo(kemShared, kemCiphertext)

	// 3. Combine secrets using HKDF
	hybridSecret, err = combineSecrets(classicalShared[:], kemShared)
	if err != nil {
		return nil, err
	}

	return hybridSecret, nil
}

// combineSecrets uses HKDF to combine classical and PQ shared secrets
func combineSecrets(classical, quantum []byte) ([]byte, error) {
	// Concatenate secrets
	combined := append(classical, quantum...)

	// Use HKDF-SHA256 to derive final key
	hkdfReader := hkdf.New(sha256.New, combined, nil, []byte("tiredvpn-hybrid-v1"))

	hybridSecret := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, hybridSecret); err != nil {
		return nil, err
	}

	return hybridSecret, nil
}

// QuantumSignature implements ML-DSA-65 (Dilithium3) signatures
type QuantumSignature struct {
	PublicKey  []byte
	PrivateKey []byte
}

// NewQuantumSignature generates a new ML-DSA-65 keypair
func NewQuantumSignature() (*QuantumSignature, error) {
	pk, sk, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	qs := &QuantumSignature{
		PublicKey:  pk.Bytes(),
		PrivateKey: sk.Bytes(),
	}

	return qs, nil
}

// Sign creates an ML-DSA-65 signature
func (q *QuantumSignature) Sign(message []byte) ([]byte, error) {
	sk := new(mode3.PrivateKey)
	if err := sk.UnmarshalBinary(q.PrivateKey); err != nil {
		return nil, err
	}

	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, message, sig)

	return sig, nil
}

// Verify validates an ML-DSA-65 signature
func (q *QuantumSignature) Verify(message, signature []byte) bool {
	pk := new(mode3.PublicKey)
	if err := pk.UnmarshalBinary(q.PublicKey); err != nil {
		return false
	}

	return mode3.Verify(pk, message, signature)
}

// VerifyWithPublicKey validates signature with provided public key
func VerifyQuantumSignature(publicKey, message, signature []byte) bool {
	pk := new(mode3.PublicKey)
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}

	return mode3.Verify(pk, message, signature)
}

// REALITYExtensionV2 is the post-quantum enhanced REALITY extension
// Extension format: [Magic:"REAL"][Version:0x02][ClassicalPubKey:32][KemCiphertext:1088][Signature:3293][AuthToken:64]
type REALITYExtensionV2 struct {
	Magic              [4]byte
	Version            uint8
	ClassicalPubKey    [32]byte
	KemCiphertext      []byte // 1088 bytes
	QuantumSignature   []byte // 3293 bytes
	AuthToken          [64]byte // SHA-512 for stronger auth
}

// REALITYExtensionV2Length is the total length of the PQ extension
const REALITYExtensionV2Length = 4 + 1 + 32 + Kyber768CiphertextSize + Dilithium3SignatureSize + 64 // ~4482 bytes

// NewClientREALITYExtensionV2 creates a PQ-enhanced client extension
func NewClientREALITYExtensionV2(secret []byte, hybrid *HybridKeyExchange, signer *QuantumSignature, serverKemPub []byte) (*REALITYExtensionV2, error) {
	// Encapsulate to server's KEM public key
	kemCT, _, err := hybrid.Encapsulate([32]byte{}, serverKemPub) // Server classical pub not needed for KEM-only
	if err != nil {
		return nil, err
	}

	// Generate enhanced auth token (SHA-512)
	authToken := generateAuthTokenV2(secret, "reality-auth-v2")

	// Sign the auth token with ML-DSA-65
	signature, err := signer.Sign(authToken[:])
	if err != nil {
		return nil, err
	}

	ext := &REALITYExtensionV2{
		Version:            REALITYVersionPQ,
		ClassicalPubKey:    hybrid.ClassicalPublicKey,
		KemCiphertext:      kemCT,
		QuantumSignature:   signature,
		AuthToken:          authToken,
	}
	copy(ext.Magic[:], REALITYMagic)

	return ext, nil
}

// MarshalV2 serializes the V2 extension to bytes
func (e *REALITYExtensionV2) MarshalV2() []byte {
	buf := make([]byte, 0, REALITYExtensionV2Length)

	buf = append(buf, e.Magic[:]...)
	buf = append(buf, e.Version)
	buf = append(buf, e.ClassicalPubKey[:]...)
	buf = append(buf, e.KemCiphertext...)
	buf = append(buf, e.QuantumSignature...)
	buf = append(buf, e.AuthToken[:]...)

	return buf
}

// UnmarshalV2 parses the V2 extension from bytes
func (e *REALITYExtensionV2) UnmarshalV2(data []byte) error {
	if len(data) < REALITYExtensionV2Length {
		return errors.New("reality v2 extension too short")
	}

	offset := 0

	copy(e.Magic[:], data[offset:offset+4])
	if string(e.Magic[:]) != REALITYMagic {
		return errors.New("invalid reality magic")
	}
	offset += 4

	e.Version = data[offset]
	if e.Version != REALITYVersionPQ {
		return errors.New("unsupported reality version (expected v2)")
	}
	offset += 1

	copy(e.ClassicalPubKey[:], data[offset:offset+32])
	offset += 32

	e.KemCiphertext = make([]byte, Kyber768CiphertextSize)
	copy(e.KemCiphertext, data[offset:offset+Kyber768CiphertextSize])
	offset += Kyber768CiphertextSize

	e.QuantumSignature = make([]byte, Dilithium3SignatureSize)
	copy(e.QuantumSignature, data[offset:offset+Dilithium3SignatureSize])
	offset += Dilithium3SignatureSize

	copy(e.AuthToken[:], data[offset:offset+64])

	return nil
}

// VerifyClientAuthV2 validates a V2 client's auth token with quantum signature
func VerifyClientAuthV2(secret []byte, authToken [64]byte, signature, signerPubKey []byte) bool {
	// Verify HMAC-based auth token
	expected := generateAuthTokenV2(secret, "reality-auth-v2")
	if !hmac.Equal(expected[:], authToken[:]) {
		return false
	}

	// Verify ML-DSA-65 signature
	return VerifyQuantumSignature(signerPubKey, authToken[:], signature)
}

// generateAuthTokenV2 creates a SHA-512 based auth token
func generateAuthTokenV2(secret []byte, context string) [64]byte {
	// Include timestamp (5-minute window)
	timestamp := time.Now().Unix() / 300

	h := hmac.New(sha512.New, secret)

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	h.Write(tsBuf[:])
	h.Write([]byte(context))

	var token [64]byte
	copy(token[:], h.Sum(nil))
	return token
}

// HybridTLSConfig holds configuration for hybrid TLS connections
type HybridTLSConfig struct {
	// ClassicalOnly disables PQ crypto (for compatibility)
	ClassicalOnly bool

	// PreferPQ prefers PQ cipher suites when available
	PreferPQ bool

	// RequirePQ fails if PQ is not negotiated
	RequirePQ bool

	// HybridKeyExchange for key exchange
	KeyExchange *HybridKeyExchange

	// QuantumSignature for authentication
	Signature *QuantumSignature
}

// DefaultHybridTLSConfig returns default hybrid TLS config
func DefaultHybridTLSConfig() *HybridTLSConfig {
	return &HybridTLSConfig{
		ClassicalOnly: false,
		PreferPQ:      true,
		RequirePQ:     false,
	}
}

// InitializeHybridCrypto initializes all PQ crypto components
func InitializeHybridCrypto() (*HybridTLSConfig, error) {
	config := DefaultHybridTLSConfig()

	// Generate hybrid key exchange
	hke, err := NewHybridKeyExchange()
	if err != nil {
		return nil, err
	}
	config.KeyExchange = hke

	// Generate quantum signature
	sig, err := NewQuantumSignature()
	if err != nil {
		return nil, err
	}
	config.Signature = sig

	return config, nil
}

// GetKyber768PublicKey returns the Kyber768 public key for sharing
func (h *HybridKeyExchange) GetKyber768PublicKey() []byte {
	return h.KemPublicKey
}

// GetDilithium3PublicKey returns the Dilithium3 public key for sharing
func (q *QuantumSignature) GetDilithium3PublicKey() []byte {
	return q.PublicKey
}

// IsPostQuantumExtension checks if extension data is V2 (PQ)
func IsPostQuantumExtension(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// Check magic and version
	if string(data[0:4]) != REALITYMagic {
		return false
	}
	return data[4] == REALITYVersionPQ
}

// Benchmark helpers for performance testing
type PQBenchmarkResult struct {
	KeyGenTime     time.Duration
	EncapsTime     time.Duration
	DecapsTime     time.Duration
	SignTime       time.Duration
	VerifyTime     time.Duration
}

// BenchmarkPQ runs performance benchmarks for PQ operations
func BenchmarkPQ() (*PQBenchmarkResult, error) {
	result := &PQBenchmarkResult{}

	// Key generation
	start := time.Now()
	hke, err := NewHybridKeyExchange()
	if err != nil {
		return nil, err
	}
	sig, err := NewQuantumSignature()
	if err != nil {
		return nil, err
	}
	result.KeyGenTime = time.Since(start)

	// Encapsulation
	start = time.Now()
	ct, _, err := hke.Encapsulate([32]byte{}, hke.KemPublicKey)
	if err != nil {
		return nil, err
	}
	result.EncapsTime = time.Since(start)

	// Decapsulation
	start = time.Now()
	_, err = hke.Decapsulate([32]byte{}, ct)
	if err != nil {
		return nil, err
	}
	result.DecapsTime = time.Since(start)

	// Signing
	message := []byte("test message for benchmarking")
	start = time.Now()
	signature, err := sig.Sign(message)
	if err != nil {
		return nil, err
	}
	result.SignTime = time.Since(start)

	// Verification
	start = time.Now()
	sig.Verify(message, signature)
	result.VerifyTime = time.Since(start)

	return result, nil
}
