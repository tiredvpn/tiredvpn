package tls

import (
	"bytes"
	"crypto/hmac"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// computeSharedSecret derives the X25519 shared secret. Defined here because
// the production code no longer exposes this helper (it is only needed in tests).
func computeSharedSecret(privKey, peerPubKey [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(privKey[:], peerPubKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var shared [32]byte
	copy(shared[:], out)
	return shared, nil
}

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
	aliceShared, err := computeSharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice shared secret computation failed: %v", err)
	}

	bobShared, err := computeSharedSecret(bobPriv, alicePub)
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

// testBucketStart is the first second of a 5-minute bucket. Its bucket number
// is even, so a 10-minute bucket would start here too and could not pass the
// edge check below by accident.
var testBucketStart = time.Unix(1_800_000_000, 0)

// TestAuthTokenTimestampWindow runs on a fixed clock. It used to sleep 100 ms
// between two tokens on the real one and failed whenever the sleep crossed a
// bucket edge, about once in 3000 runs.
func TestAuthTokenTimestampWindow(t *testing.T) {
	secret := []byte("test-secret")
	var pubKey [32]byte
	copy(pubKey[:], "test-pubkey-32-bytes-fixed-value")

	token := func(at time.Time) [32]byte { return generateAuthTokenAt(secret, pubKey, at, 0) }
	end := testBucketStart.Add(300*time.Second - 50*time.Millisecond)

	if a, b := token(testBucketStart), token(end); !bytes.Equal(a[:], b[:]) {
		t.Error("tokens from the first and the last moment of one bucket do not match")
	}
	if a, b := token(end), token(end.Add(100*time.Millisecond)); bytes.Equal(a[:], b[:]) {
		t.Error("tokens on both sides of a bucket edge match")
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
	clientShared, _ := computeSharedSecret(clientPriv, serverPub)
	serverShared, _ := computeSharedSecret(serverPriv, clientPub)

	if !bytes.Equal(clientShared[:], serverShared[:]) {
		t.Error("Shared secrets do not match")
	}
}

func TestREALITYExtensionConstants(t *testing.T) {
	if REALITYMagic != "REAL" {
		t.Errorf("REALITYMagic = %q, want %q", REALITYMagic, "REAL")
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
		tokens[i] = generateAuthTokenAt(secret, pubKey, testBucketStart, 0)
	}

	for i := 1; i < len(tokens); i++ {
		if !hmac.Equal(tokens[0][:], tokens[i][:]) {
			t.Errorf("Token %d differs from token 0", i)
		}
	}
}

// TestVerifyClientAuthGrace verifies the blast-radius-min T1 invariant: the
// auth-token grace window is exactly +-1 bucket. Tokens minted for the current
// bucket and for the immediately adjacent buckets (offset -1 and +1) must pass;
// tokens two buckets away (offset -2 and +2) must be rejected.
//
// generateAuthTokenAt and verifyClientAuthAt take the clock as an argument, so
// both sides see the same bucket even if the real clock crosses an edge.
func TestVerifyClientAuthGrace(t *testing.T) {
	secret := []byte("grace-window-secret")
	var pubKey [32]byte
	copy(pubKey[:], "grace-pubkey-32-bytes-fixed-val!")

	cases := []struct {
		name   string
		offset int64
		want   bool
	}{
		{"offset 0 (now)", 0, true},
		{"offset -1 (previous bucket)", -1, true},
		{"offset +1 (next bucket)", 1, true},
		{"offset -2 (too old)", -2, false},
		{"offset +2 (too new)", 2, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := generateAuthTokenAt(secret, pubKey, testBucketStart, tc.offset)
			got := verifyClientAuthAt(secret, pubKey, token, testBucketStart)
			if got != tc.want {
				t.Errorf("VerifyClientAuth with bucketOffset=%d = %v, want %v", tc.offset, got, tc.want)
			}
		})
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
		computeSharedSecret(privKey, pubKey)
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
