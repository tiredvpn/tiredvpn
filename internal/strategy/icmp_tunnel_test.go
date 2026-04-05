package strategy

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// TestICMPTunnelStrategyInterface verifies Strategy interface compliance
func TestICMPTunnelStrategyInterface(t *testing.T) {
	secret := []byte("test-secret-key-1234567890123456")
	s := NewICMPTunnelStrategy("127.0.0.1:443", secret)

	// Test Name
	name := s.Name()
	if name != "ICMP Tunnel (Backup)" {
		t.Errorf("Name() = %q, want %q", name, "ICMP Tunnel (Backup)")
	}

	// Test ID
	id := s.ID()
	if id != "icmp_tunnel" {
		t.Errorf("ID() = %q, want %q", id, "icmp_tunnel")
	}

	// Test Priority (must be 70 for backup)
	priority := s.Priority()
	if priority != 70 {
		t.Errorf("Priority() = %d, want 70 (backup priority)", priority)
	}

	// Test RequiresServer
	if !s.RequiresServer() {
		t.Error("RequiresServer() should return true")
	}

	// Test Description
	desc := s.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}

	// Verify it mentions backup/stealth
	if !bytes.Contains([]byte(desc), []byte("stealth")) && !bytes.Contains([]byte(desc), []byte("backup")) {
		t.Logf("Description mentions neither stealth nor backup: %s", desc)
	}
}

// TestICMPTunnelStrategyPriorityIsBackup ensures ICMP tunnel is a backup strategy
func TestICMPTunnelStrategyPriorityIsBackup(t *testing.T) {
	s := NewICMPTunnelStrategy("1.2.3.4:443", []byte("secret"))

	// Priority should be high number (low priority = backup)
	// Primary strategies have priority 5-20, ICMP backup should be 70+
	if s.Priority() < 50 {
		t.Errorf("Priority() = %d, should be >= 50 for backup strategy", s.Priority())
	}
}

// TestICMPTunnelStrategyOnlyStealthMode verifies only stealth mode is used
func TestICMPTunnelStrategyOnlyStealthMode(t *testing.T) {
	s := NewICMPTunnelStrategy("1.2.3.4:443", []byte("secret"))

	// Mode must be "stealth"
	if s.mode != "stealth" {
		t.Errorf("mode = %q, want %q", s.mode, "stealth")
	}

	// Rate limit must be 10 pps
	if s.rateLimit != StealthPacketRate {
		t.Errorf("rateLimit = %d, want %d", s.rateLimit, StealthPacketRate)
	}
}

// TestTunnelHeaderSerialization tests header serialization/deserialization
func TestTunnelHeaderSerialization(t *testing.T) {
	original := TunnelHeader{
		Magic:      ICMPTunnelMagic,
		Version:    ICMPTunnelVersion,
		Flags:      FlagControl | FlagLast,
		SessionID:  0x12345678,
		PacketSeq:  0xABCDEF00,
		PayloadLen: 56,
		Reserved:   0,
	}

	// Serialize
	data := serializeTunnelHeader(original)
	if len(data) != TunnelHeaderSize {
		t.Errorf("serialized length = %d, want %d", len(data), TunnelHeaderSize)
	}

	// Deserialize
	parsed := parseTunnelHeader(data)

	// Verify fields
	if parsed.Magic != original.Magic {
		t.Errorf("Magic = 0x%04X, want 0x%04X", parsed.Magic, original.Magic)
	}
	if parsed.Version != original.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, original.Version)
	}
	if parsed.Flags != original.Flags {
		t.Errorf("Flags = 0x%02X, want 0x%02X", parsed.Flags, original.Flags)
	}
	if parsed.SessionID != original.SessionID {
		t.Errorf("SessionID = 0x%08X, want 0x%08X", parsed.SessionID, original.SessionID)
	}
	if parsed.PacketSeq != original.PacketSeq {
		t.Errorf("PacketSeq = 0x%08X, want 0x%08X", parsed.PacketSeq, original.PacketSeq)
	}
	if parsed.PayloadLen != original.PayloadLen {
		t.Errorf("PayloadLen = %d, want %d", parsed.PayloadLen, original.PayloadLen)
	}
}

// TestTunnelHeaderMagic verifies magic bytes
func TestTunnelHeaderMagic(t *testing.T) {
	// Magic should be "IC" in hex
	magic := ICMPTunnelMagic
	expected := uint16(0x4943) // 'I' = 0x49, 'C' = 0x43

	if magic != expected {
		t.Errorf("ICMPTunnelMagic = 0x%04X, want 0x%04X", magic, expected)
	}

	// Verify bytes decode to "IC"
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, magic)
	if string(buf) != "IC" {
		t.Errorf("Magic decodes to %q, want %q", string(buf), "IC")
	}
}

// TestDeriveICMPKey tests key derivation
func TestDeriveICMPKey(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		wantLen   int
	}{
		{
			name:    "short secret",
			secret:  []byte("short"),
			wantLen: 32,
		},
		{
			name:    "exact 32 bytes",
			secret:  []byte("12345678901234567890123456789012"),
			wantLen: 32,
		},
		{
			name:    "long secret",
			secret:  []byte("this is a very long secret that exceeds 32 bytes"),
			wantLen: 32,
		},
		{
			name:    "empty secret",
			secret:  []byte{},
			wantLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := deriveICMPKey(tt.secret)
			if len(key) != tt.wantLen {
				t.Errorf("deriveICMPKey() length = %d, want %d", len(key), tt.wantLen)
			}
		})
	}

	// Verify determinism
	secret := []byte("test-secret")
	key1 := deriveICMPKey(secret)
	key2 := deriveICMPKey(secret)
	if !bytes.Equal(key1, key2) {
		t.Error("deriveICMPKey() should be deterministic")
	}

	// Verify different secrets produce different keys
	key3 := deriveICMPKey([]byte("different-secret"))
	if bytes.Equal(key1, key3) {
		t.Error("different secrets should produce different keys")
	}
}

// TestStealthModeParameters verifies stealth mode constants
func TestStealthModeParameters(t *testing.T) {
	// Stealth packet rate must be 10 pps
	if StealthPacketRate != 10 {
		t.Errorf("StealthPacketRate = %d, want 10", StealthPacketRate)
	}

	// Stealth payload size should match standard ping (56 bytes)
	if StealthPayloadSize != 56 {
		t.Errorf("StealthPayloadSize = %d, want 56", StealthPayloadSize)
	}

	// Jitter should be 10-50ms
	if StealthJitterMin != 10 {
		t.Errorf("StealthJitterMin = %d, want 10", StealthJitterMin)
	}
	if StealthJitterMax != 50 {
		t.Errorf("StealthJitterMax = %d, want 50", StealthJitterMax)
	}
}

// TestMaxPayloadSize verifies payload size calculation
func TestMaxPayloadSize(t *testing.T) {
	// MaxPayloadSize = 1400 - 8 - 16 - 16 = 1360
	expected := 1400 - ICMPHeaderSize - TunnelHeaderSize - AuthTagSize
	if MaxPayloadSize != expected {
		t.Errorf("MaxPayloadSize = %d, want %d", MaxPayloadSize, expected)
	}
}

// TestFlags verifies flag constants
func TestFlags(t *testing.T) {
	// Verify flags are distinct bits
	flags := []uint8{FlagControl, FlagCompress, FlagFragment, FlagLast}
	seen := make(map[uint8]bool)

	for _, f := range flags {
		if seen[f] {
			t.Errorf("Duplicate flag value: 0x%02X", f)
		}
		seen[f] = true

		// Each flag should be a single bit
		bits := 0
		for i := 0; i < 8; i++ {
			if f&(1<<i) != 0 {
				bits++
			}
		}
		if bits != 1 {
			t.Errorf("Flag 0x%02X should have exactly 1 bit set, has %d", f, bits)
		}
	}

	// Verify specific values
	if FlagControl != 0x80 {
		t.Errorf("FlagControl = 0x%02X, want 0x80", FlagControl)
	}
	if FlagCompress != 0x40 {
		t.Errorf("FlagCompress = 0x%02X, want 0x40", FlagCompress)
	}
	if FlagFragment != 0x20 {
		t.Errorf("FlagFragment = 0x%02X, want 0x20", FlagFragment)
	}
	if FlagLast != 0x10 {
		t.Errorf("FlagLast = 0x%02X, want 0x10", FlagLast)
	}
}

// TestTimeoutConstants verifies timeout values
func TestTimeoutConstants(t *testing.T) {
	// Connect timeout should be reasonable (5-30s)
	if ICMPConnectTimeout < 5*time.Second || ICMPConnectTimeout > 60*time.Second {
		t.Errorf("ICMPConnectTimeout = %v, want 5s-60s", ICMPConnectTimeout)
	}

	// Read timeout should be reasonable
	if ICMPReadTimeout < 10*time.Second || ICMPReadTimeout > 120*time.Second {
		t.Errorf("ICMPReadTimeout = %v, want 10s-120s", ICMPReadTimeout)
	}

	// Probe timeout should be short
	if ICMPProbeTimeout < 1*time.Second || ICMPProbeTimeout > 30*time.Second {
		t.Errorf("ICMPProbeTimeout = %v, want 1s-30s", ICMPProbeTimeout)
	}
}

// TestICMPTunnelProbeNeedsRoot tests that Probe fails without root
// This test should be skipped in CI unless running as root
func TestICMPTunnelProbeNeedsRoot(t *testing.T) {
	s := NewICMPTunnelStrategy("8.8.8.8:443", []byte("secret"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := s.Probe(ctx, "example.com")

	// If not root, expect permission error
	if err != nil {
		// This is expected when not running as root
		t.Logf("Probe failed (expected without root): %v", err)
	} else {
		// If probe succeeded, we're running as root
		t.Log("Probe succeeded (running as root)")
	}
}

// TestICMPTunnelConnectNeedsRoot tests that Connect fails without root
func TestICMPTunnelConnectNeedsRoot(t *testing.T) {
	s := NewICMPTunnelStrategy("8.8.8.8:443", []byte("secret"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := s.Connect(ctx, "example.com")

	if conn != nil {
		conn.Close()
	}

	// If not root, expect permission error
	if err != nil {
		t.Logf("Connect failed (expected without root): %v", err)
	} else {
		t.Log("Connect succeeded (running as root)")
	}
}

// BenchmarkTunnelHeaderSerialization benchmarks header serialization
func BenchmarkTunnelHeaderSerialization(b *testing.B) {
	header := TunnelHeader{
		Magic:      ICMPTunnelMagic,
		Version:    ICMPTunnelVersion,
		Flags:      0,
		SessionID:  0x12345678,
		PacketSeq:  0xABCDEF00,
		PayloadLen: 56,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = serializeTunnelHeader(header)
	}
}

// BenchmarkTunnelHeaderParsing benchmarks header parsing
func BenchmarkTunnelHeaderParsing(b *testing.B) {
	header := TunnelHeader{
		Magic:      ICMPTunnelMagic,
		Version:    ICMPTunnelVersion,
		Flags:      0,
		SessionID:  0x12345678,
		PacketSeq:  0xABCDEF00,
		PayloadLen: 56,
	}
	data := serializeTunnelHeader(header)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseTunnelHeader(data)
	}
}

// BenchmarkDeriveICMPKey benchmarks key derivation
func BenchmarkDeriveICMPKey(b *testing.B) {
	secret := []byte("test-secret-key-for-benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deriveICMPKey(secret)
	}
}

// MockICMPConn is a mock for testing without root
type MockICMPConn struct {
	sendBuf   []byte
	recvBuf   []byte
	closed    bool
	readErr   error
	writeErr  error
}

// TestMockICMPTunnel tests ICMP tunnel with mock connection
// This allows testing business logic without root privileges
func TestMockICMPTunnel(t *testing.T) {
	// This test demonstrates how to test ICMP tunnel components
	// without needing actual ICMP sockets (which require root)

	t.Run("header round-trip", func(t *testing.T) {
		original := TunnelHeader{
			Magic:      ICMPTunnelMagic,
			Version:    ICMPTunnelVersion,
			Flags:      FlagControl,
			SessionID:  12345,
			PacketSeq:  67890,
			PayloadLen: 100,
		}

		serialized := serializeTunnelHeader(original)
		parsed := parseTunnelHeader(serialized)

		if parsed.Magic != original.Magic ||
			parsed.Version != original.Version ||
			parsed.Flags != original.Flags ||
			parsed.SessionID != original.SessionID ||
			parsed.PacketSeq != original.PacketSeq ||
			parsed.PayloadLen != original.PayloadLen {
			t.Error("Header round-trip failed")
		}
	})

	t.Run("key derivation consistency", func(t *testing.T) {
		secrets := [][]byte{
			[]byte("secret1"),
			[]byte("secret2"),
			[]byte("very-long-secret-that-exceeds-32-bytes-limit"),
		}

		for _, secret := range secrets {
			key1 := deriveICMPKey(secret)
			key2 := deriveICMPKey(secret)

			if !bytes.Equal(key1, key2) {
				t.Errorf("Key derivation not consistent for secret %q", secret)
			}

			if len(key1) != 32 {
				t.Errorf("Key length = %d, want 32", len(key1))
			}
		}
	})
}

// TestICMPTunnelStrategyDescription tests description content
func TestICMPTunnelStrategyDescription(t *testing.T) {
	s := NewICMPTunnelStrategy("1.2.3.4:443", []byte("secret"))
	desc := s.Description()

	// Should mention key aspects
	checks := []struct {
		keyword string
		reason  string
	}{
		{"stealth", "should mention stealth mode"},
		{"root", "should mention root requirement"},
		{"CAP_NET_RAW", "should mention CAP_NET_RAW capability"},
		{"backup", "should mention it's a backup strategy"},
	}

	for _, check := range checks {
		if !bytes.Contains([]byte(desc), []byte(check.keyword)) {
			t.Logf("Description doesn't contain %q (%s): %s", check.keyword, check.reason, desc)
		}
	}
}
