package padding

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
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

// --- Bug-regression tests (Phase 0 safety net) ---

// TestSalamanderWriteToLargePayloadShouldError verifies that SalamanderPacketConn.WriteTo
// rejects payloads larger than 65535 bytes.
//
// Bug: WriteTo stores len(p) as uint16 which silently wraps for len(p) > 65535.
// The receiver gets a corrupted length prefix [0,0], causing framing corruption.
// After fix: WriteTo returns an error instead of silently sending corrupt data.
func TestSalamanderWriteToLargePayloadShouldError(t *testing.T) {
	mc := newChanPacketConn()
	defer mc.Close()
	padder := NewSalamanderPadder([]byte("secret"), Balanced)
	conn := NewSalamanderPacketConn(mc, padder)

	_, err := conn.WriteTo(make([]byte, 65536), mc.LocalAddr())
	if err == nil {
		t.Fatal("WriteTo with len(p)=65536 must return error: uint16 length prefix wraps to 0 silently")
	}
}

// TestMultiSecretWriteToLargePayloadShouldError verifies the same uint16 truncation
// in MultiSecretSalamanderPacketConn.WriteTo.
func TestMultiSecretWriteToLargePayloadShouldError(t *testing.T) {
	mc := newChanPacketConn()
	defer mc.Close()
	conn := NewMultiSecretSalamanderPacketConn(mc, []byte("secret"), Balanced, nil)

	_, err := conn.WriteTo(make([]byte, 65536), mc.LocalAddr())
	if err == nil {
		t.Fatal("MultiSecret WriteTo with len(p)=65536 must return error: uint16 wraps silently")
	}
}

// TestMultiSecretGlobalFallbackMisdecrypts verifies the global-fallback bug:
// when no known secret matches an incoming packet, MultiSecretSalamanderPacketConn
// calls globalPadder.Decrypt without validation and returns garbage instead of an error.
//
// Bug location: salamander_multi.go lines 131-139.
// After fix: ReadFrom returns error (or drops packet) for unknown secrets.
func TestMultiSecretGlobalFallbackMisdecrypts(t *testing.T) {
	secretA := []byte("server-secret-A")
	secretB := []byte("unrelated-client-secret-B")

	// Encrypt a packet with secretB (unknown to server)
	padderB := NewSalamanderPadder(secretB, Balanced)
	// Build payload with valid-looking length prefix so tryDecrypt may accept it
	payload := make([]byte, 12)
	payload[0] = 0
	payload[1] = 10 // dataLen = 10
	copy(payload[2:], []byte("helloworld"))

	encrypted, err := padderB.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Server knows only secretA - ReadFrom should return an error or drop the packet
	mc := newChanPacketConn()
	defer mc.Close()
	go func() { mc.inject(encrypted) }()

	serverConn := NewMultiSecretSalamanderPacketConn(mc, secretA, Balanced, nil)
	serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	p := make([]byte, 65536)
	n, _, readErr := serverConn.ReadFrom(p)
	_ = n

	// A packet encrypted with an unknown secret must be rejected: the keyed tag
	// in the UDP framing won't match secretA's keystream.
	if readErr == nil {
		t.Fatalf("expected ReadFrom to reject packet encrypted with unknown secret, got nil error")
	}
}

// TestSalamanderUDPRoundtrip verifies the tag-verified UDP framing roundtrips a
// payload across the full bucket range, mirroring real QUIC packet sizes.
func TestSalamanderUDPRoundtrip(t *testing.T) {
	secret := []byte("shared-secret-1234567890")
	padder := NewSalamanderPadder(secret, Balanced)

	for _, sz := range []int{1, 2, 20, 30, 1200, 1232, 1350, 1392} {
		payload := make([]byte, sz)
		rand.Read(payload)

		enc, err := padder.EncryptUDP(payload)
		if err != nil {
			t.Fatalf("size %d: EncryptUDP: %v", sz, err)
		}
		got, ok := padder.DecryptUDP(enc)
		if !ok {
			t.Fatalf("size %d: DecryptUDP rejected a self-encrypted packet", sz)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("size %d: payload mismatch", sz)
		}
	}
}

// TestSalamanderUDPWrongSecretRejected ensures a wrong secret can never
// false-accept a UDP packet. This is the regression guard for the QUIC
// Salamander "no matching secret" / per-address cache poisoning bug, where the
// old length-prefix + 0x80 long-header heuristic accepted ~50% of garbage.
//
// The zero threshold is only meaningful because the tag is udpTagLen bytes
// wide. At 8 bytes the expected number of false accepts over n trials is
// n*2^-64 ~ 1e-15, so a single accept here means the check is broken, not
// unlucky. At the earlier width of 2 bytes the expectation was n*2^-16 ~ 0.3
// and this test failed roughly one run in four - it was a coin flip, and it did
// come up heads in CI. The assertion below is therefore deliberately exact; do
// not "fix" a failure by allowing a nonzero budget.
func TestSalamanderUDPWrongSecretRejected(t *testing.T) {
	if udpTagLen < 8 {
		t.Fatalf("udpTagLen=%d: a tag narrower than 8 bytes makes this test statistical, not deterministic", udpTagLen)
	}

	right := NewSalamanderPadder([]byte("the-correct-secret-AAAAA"), Balanced)
	wrong := NewSalamanderPadder([]byte("a-different-secret-BBBBB"), Balanced)

	falseAccepts := 0
	const n = 20000
	for i := 0; i < n; i++ {
		payload := make([]byte, 1200)
		rand.Read(payload)
		enc, err := right.EncryptUDP(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := wrong.DecryptUDP(enc); ok {
			falseAccepts++
		}
	}
	if falseAccepts != 0 {
		t.Fatalf("wrong secret false-accepted %d/%d packets, want 0", falseAccepts, n)
	}

	// Positive control: the same loop with the right secret must accept every
	// packet. Without it, "zero false accepts" is indistinguishable from
	// DecryptUDP rejecting everything unconditionally.
	for i := 0; i < 100; i++ {
		payload := make([]byte, 1200)
		rand.Read(payload)
		enc, err := right.EncryptUDP(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := right.DecryptUDP(enc); !ok {
			t.Fatalf("right secret rejected its own packet at iteration %d", i)
		}
	}
}

// TestSalamanderUDPTagCheckedInFull verifies that every byte of the tag takes
// part in the accept decision. A comparison that stops early - or a tag widened
// in EncryptUDP but still compared two bytes deep in DecryptUDP - would leave
// the trailing bytes free, silently restoring the old 2^-16 odds while the
// constant says 8. Corrupting each tag position in turn is the only way to see
// that; a single flip at position 0 would pass either way.
func TestSalamanderUDPTagCheckedInFull(t *testing.T) {
	padder := NewSalamanderPadder([]byte("tag-coverage-secret"), Balanced)
	payload := []byte("payload under a fully checked tag")

	for i := 0; i < udpTagLen; i++ {
		enc, err := padder.EncryptUDP(payload)
		if err != nil {
			t.Fatal(err)
		}
		// Tag byte i sits at offset 8+i: the 8-byte salt is sent in the clear
		// and the masked header follows it, so flipping a ciphertext bit there
		// flips exactly one decrypted tag byte.
		enc[8+i] ^= 0x01
		if _, ok := padder.DecryptUDP(enc); ok {
			t.Errorf("tag byte %d corrupted, packet still accepted: tag not compared in full", i)
		}
	}
}

// TestSalamanderUDPWireSizeStable pins the observable datagram sizes that the
// UDP framing produces. This is the property Salamander exists for, and it is
// what a wider tag threatens: the tag lives inside the padded region, so a
// packet that no longer fits its bucket jumps to the next one and the size
// distribution on the wire moves.
//
// Two claims are checked. First, that for the payload sizes QUIC actually
// emits - small ACK/control datagrams and full-size packets around the
// quic-go default of 1280 - the datagram size is exactly what it was with the
// old 2-byte tag. Second, that below the largest bucket the size alphabet is
// the bucket list and nothing else, which is what makes the first claim more
// than a lookup table.
func TestSalamanderUDPWireSizeStable(t *testing.T) {
	padder := NewSalamanderPadder([]byte("wire-size-secret"), Balanced)
	buckets := padder.GetBuckets() // 400, 800, 1200, 1400

	// Sizes a quic-go connection puts on the wire: bare ACKs and probes at the
	// low end, Initial and full data packets at InitialPacketSize=1280. The
	// wanted values were produced by the 2-byte-tag build and are frozen here.
	quicSizes := []struct {
		payload  int
		wantWire int
	}{
		{21, 400}, {25, 400}, {33, 400}, {42, 400}, {55, 400}, {68, 400},
		{120, 400}, {256, 400}, {512, 800}, {700, 800}, {900, 1200},
		{1024, 1200}, {1200, 1400}, {1252, 1400}, {1280, 1400},
	}
	for _, tc := range quicSizes {
		enc, err := padder.EncryptUDP(make([]byte, tc.payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) != tc.wantWire {
			t.Errorf("payload %d: datagram %d bytes, want %d - the tag widening moved this size into another bucket",
				tc.payload, len(enc), tc.wantWire)
		}
	}

	// Every payload that still fits the largest bucket must come out as one of
	// the bucket values. Anything else means padding stopped normalising and
	// the payload length is leaking directly.
	maxPadded := buckets[len(buckets)-1] - 8 - udpHeaderLen
	inBucket := make(map[int]bool, len(buckets))
	for _, b := range buckets {
		inBucket[b] = true
	}
	for n := 1; n <= maxPadded; n++ {
		enc, err := padder.EncryptUDP(make([]byte, n))
		if err != nil {
			t.Fatal(err)
		}
		if !inBucket[len(enc)] {
			t.Fatalf("payload %d: datagram %d bytes is not a bucket %v", n, len(enc), buckets)
		}
	}
}

// TestSalamanderUDPBucketBoundaries records exactly where the payload-to-bucket
// boundaries sit now, so the shift caused by the wider tag is written down
// rather than discovered later on a packet capture. Each boundary moved down by
// six bytes (2-byte tag -> 8-byte tag), which means payloads in the six-byte
// window below each old boundary - 383..388, 783..788, 1183..1188, 1383..1388 -
// now travel one bucket up. None of those windows carries QUIC traffic in the
// configurations this code ships with, see TestSalamanderUDPWireSizeStable.
//
// Above the largest bucket the padder gives up and sends payload+8+udpHeaderLen
// verbatim, so there the datagram grew by the full six bytes and the exact
// payload length is on the wire. That leak predates this change; the tag only
// shifted it by six.
func TestSalamanderUDPBucketBoundaries(t *testing.T) {
	padder := NewSalamanderPadder([]byte("boundary-secret"), Balanced)

	cases := []struct {
		payload  int
		wantWire int
	}{
		{382, 400}, {383, 800}, // was 388/389
		{782, 800}, {783, 1200}, // was 788/789
		{1182, 1200}, {1183, 1400}, // was 1188/1189
		{1382, 1400}, {1383, 1401}, // was 1388/1389, and 1389 went out as 1401 too
	}
	for _, tc := range cases {
		enc, err := padder.EncryptUDP(make([]byte, tc.payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) != tc.wantWire {
			t.Errorf("payload %d: datagram %d bytes, want %d", tc.payload, len(enc), tc.wantWire)
		}
	}
}

// TestMultiSecretManySecretsNoFalseAccept exercises the path where a narrow tag
// hurts most. ReadFrom walks the whole secret registry looking for a match, so
// one unmatched packet costs one trial per registered secret and the odds of a
// false accept scale with the registry size. With 512 secrets a 2-byte tag
// would have accepted roughly one packet in 128 and cached the wrong secret for
// that address, which then also corrupts every reply written back to it.
//
// The rejection half is paired with an acceptance half using a secret buried in
// the middle of the registry: "nothing was accepted" would otherwise be
// satisfied by a ReadFrom that rejects unconditionally.
func TestMultiSecretManySecretsNoFalseAccept(t *testing.T) {
	const numSecrets = 512

	secrets := make([][]byte, numSecrets)
	for i := range secrets {
		s := make([]byte, 32)
		rand.Read(s)
		secrets[i] = s
	}
	provider := func() [][]byte { return secrets }

	globalSecret := []byte("server-global-secret")
	stranger := NewSalamanderPadder([]byte("secret-of-nobody-in-the-registry"), Balanced)

	// Rejection: packets from a secret the server does not hold.
	const rounds = 200
	for i := 0; i < rounds; i++ {
		enc, err := stranger.EncryptUDP(make([]byte, 1200))
		if err != nil {
			t.Fatal(err)
		}

		mc := newChanPacketConn()
		conn := NewMultiSecretSalamanderPacketConn(mc, globalSecret, Balanced, provider)
		mc.inject(enc)

		if _, _, err := conn.ReadFrom(make([]byte, 65536)); err == nil {
			conn.Close()
			t.Fatalf("round %d: packet from an unregistered secret accepted after %d trials", i, numSecrets)
		}
		conn.Close()
	}

	// Acceptance: a secret in the middle of the registry must still be found,
	// and the payload must come back intact.
	client := NewSalamanderPadder(secrets[numSecrets/2], Balanced)
	payload := make([]byte, 1200)
	rand.Read(payload)
	enc, err := client.EncryptUDP(payload)
	if err != nil {
		t.Fatal(err)
	}

	mc := newChanPacketConn()
	conn := NewMultiSecretSalamanderPacketConn(mc, globalSecret, Balanced, provider)
	defer conn.Close()
	mc.inject(enc)

	buf := make([]byte, 65536)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("registered client secret rejected: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Error("payload corrupted through the multi-secret path")
	}
}

// chanPacketConn is a minimal in-memory net.PacketConn for unit tests.
type chanPacketConn struct {
	packets chan []byte
	closed  chan struct{}
}

func newChanPacketConn() *chanPacketConn {
	return &chanPacketConn{
		packets: make(chan []byte, 64),
		closed:  make(chan struct{}),
	}
}

func (c *chanPacketConn) inject(b []byte) {
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case c.packets <- cp:
	case <-c.closed:
	}
}

func (c *chanPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.packets:
		return copy(p, pkt), &chanAddr{}, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *chanPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case c.packets <- cp:
	case <-c.closed:
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *chanPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *chanPacketConn) LocalAddr() net.Addr                { return &chanAddr{} }
func (c *chanPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *chanPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *chanPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

type chanAddr struct{}

func (a *chanAddr) Network() string { return "udp" }
func (a *chanAddr) String() string  { return "127.0.0.1:9999" }

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
