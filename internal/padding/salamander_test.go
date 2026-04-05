package padding

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSalamanderEncryptDecrypt(t *testing.T) {
	secret := []byte("test-secret-key-12345")
	padder := NewSalamanderPadder(secret, Balanced)

	plaintext := []byte("Hello, World! This is a test message.")

	// Encrypt
	encrypted, err := padder.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Should be padded (larger than plaintext + 8 byte salt)
	if len(encrypted) <= len(plaintext)+8 {
		t.Errorf("Encrypted length = %d, expected > %d", len(encrypted), len(plaintext)+8)
	}

	// Decrypt
	decrypted, err := padder.DecryptWithLength(encrypted, len(plaintext))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify plaintext recovered
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestSalamanderSymmetry(t *testing.T) {
	secret := []byte("shared-secret")
	level := Conservative

	// Same padder instance
	padder := NewSalamanderPadder(secret, level)

	testCases := [][]byte{
		[]byte("short"),
		[]byte("medium length message here"),
		[]byte("very long message that will definitely exceed the smallest bucket size and require a larger bucket or even the largest one available"),
		make([]byte, 1500), // Large payload
	}

	for i, plaintext := range testCases {
		// Random fill for large payload
		if len(plaintext) == 1500 {
			rand.Read(plaintext)
		}

		encrypted, err := padder.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Case %d: Encrypt failed: %v", i, err)
		}

		decrypted, err := padder.DecryptWithLength(encrypted, len(plaintext))
		if err != nil {
			t.Fatalf("Case %d: Decrypt failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Case %d: Symmetry broken", i)
		}
	}
}

func TestSalamanderDifferentSecrets(t *testing.T) {
	plaintext := []byte("secret message")

	padder1 := NewSalamanderPadder([]byte("secret1"), Balanced)
	padder2 := NewSalamanderPadder([]byte("secret2"), Balanced)

	encrypted, _ := padder1.Encrypt(plaintext)

	// Decrypt with different secret should produce garbage
	decrypted, err := padder2.DecryptWithLength(encrypted, len(plaintext))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Should NOT match plaintext
	if bytes.Equal(decrypted, plaintext) {
		t.Error("Different secrets produced same result (crypto broken!)")
	}
}

func TestSalamanderBucketNormalization(t *testing.T) {
	secret := []byte("test-secret")

	tests := []struct {
		level        PaddingLevel
		plaintextLen int
		wantBucket   int
	}{
		{Conservative, 10, 512},    // 10 + 8 = 18 → 512
		{Conservative, 500, 512},   // 500 + 8 = 508 → 512
		{Conservative, 510, 1024},  // 510 + 8 = 518 → 1024
		{Conservative, 1000, 1024}, // 1000 + 8 = 1008 → 1024
		{Conservative, 1440, 1452}, // 1440 + 8 = 1448 → 1452
		{Balanced, 10, 400},        // 10 + 8 = 18 → 400
		{Balanced, 390, 400},       // 390 + 8 = 398 → 400
		{Balanced, 790, 800},       // 790 + 8 = 798 → 800
		{Aggressive, 10, 300},      // 10 + 8 = 18 → 300
		{Aggressive, 290, 300},     // 290 + 8 = 298 → 300
		{Aggressive, 590, 600},     // 590 + 8 = 598 → 600
	}

	for _, tt := range tests {
		padder := NewSalamanderPadder(secret, tt.level)
		plaintext := make([]byte, tt.plaintextLen)

		encrypted, err := padder.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if len(encrypted) != tt.wantBucket {
			t.Errorf("Level=%v, len=%d: encrypted size = %d, want %d",
				tt.level, tt.plaintextLen, len(encrypted), tt.wantBucket)
		}
	}
}

func TestSalamanderPaddingLevels(t *testing.T) {
	secret := []byte("test")
	plaintext := make([]byte, 100)

	tests := []struct {
		level       PaddingLevel
		wantBuckets []int
		minOverhead int
		maxOverhead int
	}{
		{Conservative, []int{512, 1024, 1452}, 5, 10},
		{Balanced, []int{400, 800, 1200, 1400}, 15, 25},
		{Aggressive, []int{300, 600, 900, 1200, 1400}, 30, 50},
	}

	for _, tt := range tests {
		padder := NewSalamanderPadder(secret, tt.level)

		// Check buckets
		buckets := padder.GetBuckets()
		if !equalIntSlice(buckets, tt.wantBuckets) {
			t.Errorf("Level %v: buckets = %v, want %v", tt.level, buckets, tt.wantBuckets)
		}

		// Check overhead
		minOver, maxOver := padder.GetOverheadPercentage()
		if minOver != tt.minOverhead || maxOver != tt.maxOverhead {
			t.Errorf("Level %v: overhead = %d-%d%%, want %d-%d%%",
				tt.level, minOver, maxOver, tt.minOverhead, tt.maxOverhead)
		}

		// Verify actual padding
		encrypted, _ := padder.Encrypt(plaintext)
		actualOverhead := float64(len(encrypted)-len(plaintext)) / float64(len(plaintext)) * 100

		// For small plaintexts (100 bytes), overhead will be large due to bucketing
		// Don't check exact percentage, just verify encryption works
		if len(encrypted) <= len(plaintext) {
			t.Errorf("Level %v: encrypted size %d <= plaintext size %d",
				tt.level, len(encrypted), len(plaintext))
		}

		t.Logf("Level %v: actual overhead = %.1f%% (expected range %d-%d%%)",
			tt.level, actualOverhead, tt.minOverhead, tt.maxOverhead)
	}
}

func TestSalamanderSetLevel(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Conservative)

	// Initially conservative
	if padder.GetLevel() != Conservative {
		t.Error("Initial level not Conservative")
	}

	// Change to aggressive
	padder.SetLevel(Aggressive)
	if padder.GetLevel() != Aggressive {
		t.Error("Level not updated to Aggressive")
	}

	// Buckets should update
	buckets := padder.GetBuckets()
	expectedBuckets := getBucketsForLevel(Aggressive)
	if !equalIntSlice(buckets, expectedBuckets) {
		t.Errorf("Buckets not updated: got %v, want %v", buckets, expectedBuckets)
	}
}

func TestSalamanderEstimatePaddedSize(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Balanced)

	tests := []struct {
		plaintextLen int
		wantSize     int
	}{
		{10, 400},
		{390, 400},
		{400, 800},
		{1000, 1200},
	}

	for _, tt := range tests {
		estimate := padder.EstimatePaddedSize(tt.plaintextLen)
		if estimate != tt.wantSize {
			t.Errorf("EstimatePaddedSize(%d) = %d, want %d",
				tt.plaintextLen, estimate, tt.wantSize)
		}
	}
}

func TestSalamanderEmptyPlaintext(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Balanced)

	_, err := padder.Encrypt([]byte{})
	if err == nil {
		t.Error("Expected error for empty plaintext, got nil")
	}
}

func TestSalamanderShortCiphertext(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Balanced)

	// Ciphertext too short (< 8 bytes salt)
	_, err := padder.Decrypt([]byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for short ciphertext, got nil")
	}
}

func TestSalamanderRandomSalts(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Conservative)
	plaintext := []byte("same message")

	// Encrypt same plaintext multiple times
	ciphertexts := make([][]byte, 5)
	for i := range ciphertexts {
		ciphertexts[i], _ = padder.Encrypt(plaintext)
	}

	// Salts should be different (first 8 bytes)
	for i := 1; i < len(ciphertexts); i++ {
		salt1 := ciphertexts[0][:8]
		salt2 := ciphertexts[i][:8]

		if bytes.Equal(salt1, salt2) {
			t.Errorf("Ciphertext %d has same salt as ciphertext 0 (weak RNG?)", i)
		}
	}

	// But all should decrypt to same plaintext
	for i, ct := range ciphertexts {
		decrypted, _ := padder.DecryptWithLength(ct, len(plaintext))
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Ciphertext %d failed to decrypt", i)
		}
	}
}

func TestSalamanderObfuscateAlias(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Balanced)
	plaintext := []byte("test message")

	// Obfuscate and Encrypt should be same
	obfuscated, _ := padder.Obfuscate(plaintext)
	encrypted, _ := padder.Encrypt(plaintext)

	// Both should decrypt successfully
	_, err1 := padder.Deobfuscate(obfuscated)
	_, err2 := padder.Decrypt(encrypted)

	if err1 != nil || err2 != nil {
		t.Error("Alias methods failed")
	}
}

func TestLevelFromString(t *testing.T) {
	tests := []struct {
		input string
		want  PaddingLevel
	}{
		{"conservative", Conservative},
		{"low", Conservative},
		{"1", Conservative},
		{"balanced", Balanced},
		{"medium", Balanced},
		{"2", Balanced},
		{"aggressive", Aggressive},
		{"high", Aggressive},
		{"3", Aggressive},
		{"invalid", Balanced}, // Default
		{"", Balanced},
	}

	for _, tt := range tests {
		got := LevelFromString(tt.input)
		if got != tt.want {
			t.Errorf("LevelFromString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLevelToString(t *testing.T) {
	tests := []struct {
		input PaddingLevel
		want  string
	}{
		{Conservative, "conservative"},
		{Balanced, "balanced"},
		{Aggressive, "aggressive"},
		{PaddingLevel(99), "balanced"}, // Invalid → default
	}

	for _, tt := range tests {
		got := LevelToString(tt.input)
		if got != tt.want {
			t.Errorf("LevelToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSalamanderLargePayload(t *testing.T) {
	secret := []byte("test")
	padder := NewSalamanderPadder(secret, Aggressive)

	// 10KB payload
	plaintext := make([]byte, 10*1024)
	rand.Read(plaintext)

	encrypted, err := padder.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt large payload failed: %v", err)
	}

	decrypted, err := padder.DecryptWithLength(encrypted, len(plaintext))
	if err != nil {
		t.Fatalf("Decrypt large payload failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Large payload symmetry broken")
	}
}

// Benchmark tests

func BenchmarkSalamanderEncrypt_100B(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Balanced)
	plaintext := make([]byte, 100)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padder.Encrypt(plaintext)
	}
}

func BenchmarkSalamanderEncrypt_1KB(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Balanced)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padder.Encrypt(plaintext)
	}
}

func BenchmarkSalamanderEncrypt_10KB(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Balanced)
	plaintext := make([]byte, 10*1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padder.Encrypt(plaintext)
	}
}

func BenchmarkSalamanderDecrypt_1KB(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Balanced)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encrypted, _ := padder.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padder.DecryptWithLength(encrypted, len(plaintext))
	}
}

func BenchmarkSalamanderRoundtrip_1KB(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Balanced)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := padder.Encrypt(plaintext)
		padder.DecryptWithLength(encrypted, len(plaintext))
	}
}

func BenchmarkSalamanderConservative_1KB(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Conservative)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padder.Encrypt(plaintext)
	}
}

func BenchmarkSalamanderAggressive_1KB(b *testing.B) {
	secret := []byte("benchmark-secret")
	padder := NewSalamanderPadder(secret, Aggressive)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padder.Encrypt(plaintext)
	}
}

// Helper functions

func equalIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
