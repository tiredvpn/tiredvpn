package tls

import (
	"bytes"
	"crypto/hmac"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	// Check keys are not zero
	zeroKey := [32]byte{}
	if bytes.Equal(privKey[:], zeroKey[:]) {
		t.Error("Private key is all zeros")
	}
	if bytes.Equal(pubKey[:], zeroKey[:]) {
		t.Error("Public key is all zeros")
	}

	// Verify public key derivation
	var expectedPubKey [32]byte
	curve25519.ScalarBaseMult(&expectedPubKey, &privKey)

	if !bytes.Equal(pubKey[:], expectedPubKey[:]) {
		t.Error("Public key does not match expected value")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate two key pairs
	alicePriv, alicePub, _ := GenerateX25519KeyPair()
	bobPriv, bobPub, _ := GenerateX25519KeyPair()

	// Compute shared secrets
	aliceShared, err := ComputeSharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice shared secret computation failed: %v", err)
	}

	bobShared, err := ComputeSharedSecret(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Bob shared secret computation failed: %v", err)
	}

	// Shared secrets must match
	if !bytes.Equal(aliceShared[:], bobShared[:]) {
		t.Error("Shared secrets do not match")
	}
}

func TestREALITYExtensionMarshalUnmarshal(t *testing.T) {
	secret := []byte("test-secret-key")
	clientPriv, _, _ := GenerateX25519KeyPair()

	// Create client extension
	ext, err := NewClientREALITYExtension(secret, clientPriv)
	if err != nil {
		t.Fatalf("NewClientREALITYExtension failed: %v", err)
	}

	// Marshal
	data := ext.Marshal()
	if len(data) != REALITYExtensionLength {
		t.Errorf("Marshal length = %d, want %d", len(data), REALITYExtensionLength)
	}

	// Unmarshal
	var ext2 REALITYExtension
	if err := ext2.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields
	if !bytes.Equal(ext2.PubKey[:], ext.PubKey[:]) {
		t.Error("PubKey mismatch")
	}
	if !bytes.Equal(ext2.AuthToken[:], ext.AuthToken[:]) {
		t.Error("AuthToken mismatch")
	}
}

func TestREALITYExtensionUnmarshalInvalid(t *testing.T) {
	var ext REALITYExtension
	err := ext.Unmarshal([]byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for too-short input, got nil")
	}
}

func TestVerifyClientAuth(t *testing.T) {
	secret := []byte("test-secret")
	clientPriv, _, _ := GenerateX25519KeyPair()

	ext, _ := NewClientREALITYExtension(secret, clientPriv)

	// Valid auth
	if !VerifyClientAuth(secret, ext.PubKey, ext.AuthToken) {
		t.Error("Valid auth token rejected")
	}

	// Invalid secret
	wrongSecret := []byte("wrong-secret")
	if VerifyClientAuth(wrongSecret, ext.PubKey, ext.AuthToken) {
		t.Error("Invalid secret accepted")
	}

	// Invalid token
	var wrongToken [32]byte
	copy(wrongToken[:], "totally-wrong-token-data-here")
	if VerifyClientAuth(secret, ext.PubKey, wrongToken) {
		t.Error("Invalid token accepted")
	}
}

func TestVerifyServerAuth(t *testing.T) {
	secret := []byte("test-secret")
	serverPriv, _, _ := GenerateX25519KeyPair()
	_, clientPub, _ := GenerateX25519KeyPair()

	serverExt, _ := NewServerREALITYExtension(secret, serverPriv, clientPub)

	// Valid auth
	if !VerifyServerAuth(secret, clientPub[:], serverExt.AuthToken) {
		t.Error("Valid server auth token rejected")
	}

	// Invalid secret
	wrongSecret := []byte("wrong-secret")
	if VerifyServerAuth(wrongSecret, clientPub[:], serverExt.AuthToken) {
		t.Error("Invalid secret accepted")
	}

	// Invalid client pubkey
	_, otherClientPub, _ := GenerateX25519KeyPair()
	if VerifyServerAuth(secret, otherClientPub[:], serverExt.AuthToken) {
		t.Error("Wrong client pubkey accepted")
	}
}

func TestAuthTokenTimestampWindow(t *testing.T) {
	secret := []byte("test-secret")
	var pubKey [32]byte
	copy(pubKey[:], "test-pubkey-32-bytes-fixed-value")

	token1 := generateAuthToken(secret, pubKey)

	time.Sleep(100 * time.Millisecond)

	token2 := generateAuthToken(secret, pubKey)

	if !bytes.Equal(token1[:], token2[:]) {
		t.Error("Tokens in same time window do not match")
	}
}

func TestClientServerAuthFlow(t *testing.T) {
	secret := []byte("shared-secret-key")

	// Client generates keys and extension
	clientPriv, clientPub, _ := GenerateX25519KeyPair()
	clientExt, _ := NewClientREALITYExtension(secret, clientPriv)

	// Server receives and verifies client auth
	if !VerifyClientAuth(secret, clientExt.PubKey, clientExt.AuthToken) {
		t.Fatal("Server rejected client auth")
	}

	// Server generates response
	serverPriv, serverPub, _ := GenerateX25519KeyPair()
	serverExt, _ := NewServerREALITYExtension(secret, serverPriv, clientPub)

	// Client verifies server auth
	if !VerifyServerAuth(secret, clientPub[:], serverExt.AuthToken) {
		t.Fatal("Client rejected server auth")
	}

	// Both compute shared secret
	clientShared, _ := ComputeSharedSecret(clientPriv, serverPub)
	serverShared, _ := ComputeSharedSecret(serverPriv, clientPub)

	if !bytes.Equal(clientShared[:], serverShared[:]) {
		t.Error("Shared secrets do not match")
	}
}

func TestREALITYExtensionConstants(t *testing.T) {
	if REALITYExtensionType != 0xFF01 {
		t.Errorf("REALITYExtensionType = 0x%04X, want 0xFF01", REALITYExtensionType)
	}

	if REALITYMagic != "REAL" {
		t.Errorf("REALITYMagic = %q, want %q", REALITYMagic, "REAL")
	}

	if REALITYVersion != 0x01 {
		t.Errorf("REALITYVersion = 0x%02X, want 0x01", REALITYVersion)
	}

	expectedLen := 32 + 32 // pubkey + auth token (no magic, no version)
	if REALITYExtensionLength != expectedLen {
		t.Errorf("REALITYExtensionLength = %d, want %d", REALITYExtensionLength, expectedLen)
	}
}

func TestHMACAuthTokenConsistency(t *testing.T) {
	secret := []byte("test-secret")
	var pubKey [32]byte
	copy(pubKey[:], "test-pubkey-32-bytes-fixed-value")

	tokens := make([][32]byte, 5)
	for i := range tokens {
		tokens[i] = generateAuthToken(secret, pubKey)
	}

	for i := 1; i < len(tokens); i++ {
		if !hmac.Equal(tokens[0][:], tokens[i][:]) {
			t.Errorf("Token %d differs from token 0", i)
		}
	}
}

func BenchmarkGenerateX25519KeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateX25519KeyPair()
	}
}

func BenchmarkComputeSharedSecret(b *testing.B) {
	privKey, _, _ := GenerateX25519KeyPair()
	_, pubKey, _ := GenerateX25519KeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeSharedSecret(privKey, pubKey)
	}
}

func BenchmarkREALITYExtensionMarshal(b *testing.B) {
	secret := []byte("test-secret")
	clientPriv, _, _ := GenerateX25519KeyPair()
	ext, _ := NewClientREALITYExtension(secret, clientPriv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Marshal()
	}
}

func BenchmarkREALITYExtensionUnmarshal(b *testing.B) {
	secret := []byte("test-secret")
	clientPriv, _, _ := GenerateX25519KeyPair()
	ext, _ := NewClientREALITYExtension(secret, clientPriv)
	data := ext.Marshal()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var ext2 REALITYExtension
		ext2.Unmarshal(data)
	}
}

func BenchmarkVerifyClientAuth(b *testing.B) {
	secret := []byte("test-secret")
	clientPriv, _, _ := GenerateX25519KeyPair()
	ext, _ := NewClientREALITYExtension(secret, clientPriv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyClientAuth(secret, ext.PubKey, ext.AuthToken)
	}
}
