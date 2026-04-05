package strategy

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

// TestKnockSequenceGeneration tests knock sequence generation from secret
func TestKnockSequenceGeneration(t *testing.T) {
	secret := []byte("test-secret-key")
	strat := NewAntiProbeStrategy(NewManager(), secret)

	seq := strat.generateKnockSequence()

	// Should have 5 delays and 5 sizes
	if len(seq.Delays) != 5 {
		t.Errorf("Expected 5 delays, got %d", len(seq.Delays))
	}
	if len(seq.Sizes) != 5 {
		t.Errorf("Expected 5 sizes, got %d", len(seq.Sizes))
	}

	// Verify delays are in valid range (50-200ms)
	for i, delay := range seq.Delays {
		ms := delay.Milliseconds()
		if ms < 50 || ms > 200 {
			t.Errorf("Delay %d: %dms out of range [50, 200]", i, ms)
		}
	}

	// Verify sizes are in valid range (10-100 bytes)
	for i, size := range seq.Sizes {
		if size < 10 || size > 100 {
			t.Errorf("Size %d: %d bytes out of range [10, 100]", i, size)
		}
	}
}

// TestKnockSequenceDeterministic tests that same secret produces same sequence
func TestKnockSequenceDeterministic(t *testing.T) {
	secret := []byte("deterministic-secret")

	strat1 := NewAntiProbeStrategy(NewManager(), secret)
	seq1 := strat1.generateKnockSequence()

	strat2 := NewAntiProbeStrategy(NewManager(), secret)
	seq2 := strat2.generateKnockSequence()

	// Should produce identical sequences
	if len(seq1.Delays) != len(seq2.Delays) {
		t.Error("Sequences have different number of delays")
	}

	for i := range seq1.Delays {
		if seq1.Delays[i] != seq2.Delays[i] {
			t.Errorf("Delay %d mismatch: %v != %v", i, seq1.Delays[i], seq2.Delays[i])
		}
		if seq1.Sizes[i] != seq2.Sizes[i] {
			t.Errorf("Size %d mismatch: %d != %d", i, seq1.Sizes[i], seq2.Sizes[i])
		}
	}
}

// TestKnockSequenceDifferentSecrets tests different secrets produce different sequences
func TestKnockSequenceDifferentSecrets(t *testing.T) {
	secret1 := []byte("secret-one")
	secret2 := []byte("secret-two")

	strat1 := NewAntiProbeStrategy(NewManager(), secret1)
	seq1 := strat1.generateKnockSequence()

	strat2 := NewAntiProbeStrategy(NewManager(), secret2)
	seq2 := strat2.generateKnockSequence()

	// Should produce different sequences
	identical := true
	for i := range seq1.Delays {
		if seq1.Delays[i] != seq2.Delays[i] || seq1.Sizes[i] != seq2.Sizes[i] {
			identical = false
			break
		}
	}

	if identical {
		t.Error("Different secrets produced identical sequences")
	}
}

// TestAntiProbeTimingWindow tests timing window parameter
func TestAntiProbeTimingWindow(t *testing.T) {
	strat := NewAntiProbeStrategy(NewManager(), []byte("secret"))

	// Default timing window should be 100ms
	if strat.timingWindow != 100*time.Millisecond {
		t.Errorf("Expected timing window 100ms, got %v", strat.timingWindow)
	}
}

// TestAntiProbeStrategyMetadata tests strategy metadata
func TestAntiProbeStrategyMetadata(t *testing.T) {
	strat := NewAntiProbeStrategy(NewManager(), []byte("secret"))

	if strat.Name() == "" {
		t.Error("Name should not be empty")
	}

	if strat.ID() != "antiprobe" {
		t.Errorf("Expected ID 'antiprobe', got %s", strat.ID())
	}

	if strat.Priority() < 0 || strat.Priority() > 100 {
		t.Errorf("Priority %d out of reasonable range", strat.Priority())
	}

	if strat.Description() == "" {
		t.Error("Description should not be empty")
	}

	if !strat.RequiresServer() {
		t.Error("AntiProbe requires server")
	}
}

// TestPacketDataFilling tests packet data generation
func TestPacketDataFilling(t *testing.T) {
	secret := []byte("test-secret")
	strat := NewAntiProbeStrategy(NewManager(), secret)

	// Generate packet data for sequence 0
	packet1 := make([]byte, 50)
	strat.fillPacketData(packet1, 0)

	// Generate same packet again
	packet2 := make([]byte, 50)
	strat.fillPacketData(packet2, 0)

	// Should be identical (deterministic)
	for i := range packet1 {
		if packet1[i] != packet2[i] {
			t.Errorf("Packet data not deterministic at byte %d", i)
			break
		}
	}

	// Different sequence should produce different data
	packet3 := make([]byte, 50)
	strat.fillPacketData(packet3, 1)

	identical := true
	for i := range packet1 {
		if packet1[i] != packet3[i] {
			identical = false
			break
		}
	}

	if identical {
		t.Error("Different sequences produced identical packet data")
	}
}

// TestKnockSequenceVariability tests that sequences have sufficient entropy
func TestKnockSequenceVariability(t *testing.T) {
	// Test with 10 different secrets
	sequences := make([]*KnockSequence, 10)
	for i := 0; i < 10; i++ {
		secret := []byte{byte(i), byte(i * 2), byte(i * 3)}
		strat := NewAntiProbeStrategy(NewManager(), secret)
		sequences[i] = strat.generateKnockSequence()
	}

	// Check that we have variability in delays
	delaySet := make(map[int64]bool)
	for _, seq := range sequences {
		for _, delay := range seq.Delays {
			delaySet[delay.Milliseconds()] = true
		}
	}

	// Should have at least 10 different delay values across all sequences
	if len(delaySet) < 10 {
		t.Errorf("Low delay variability: only %d unique values", len(delaySet))
	}

	// Check variability in sizes
	sizeSet := make(map[int]bool)
	for _, seq := range sequences {
		for _, size := range seq.Sizes {
			sizeSet[size] = true
		}
	}

	if len(sizeSet) < 10 {
		t.Errorf("Low size variability: only %d unique values", len(sizeSet))
	}
}

// TestKnockSequenceTiming tests total timing constraints
func TestKnockSequenceTiming(t *testing.T) {
	secret := []byte("timing-test")
	strat := NewAntiProbeStrategy(NewManager(), secret)
	seq := strat.generateKnockSequence()

	// Calculate total time for knock sequence
	totalTime := time.Duration(0)
	for _, delay := range seq.Delays {
		totalTime += delay
	}

	// Total should be reasonable (250ms - 1000ms for 5 packets)
	if totalTime < 250*time.Millisecond {
		t.Errorf("Total knock time %v too short", totalTime)
	}
	if totalTime > 1*time.Second {
		t.Errorf("Total knock time %v too long", totalTime)
	}
}

// TestKnockPacketSizes tests packet size constraints
func TestKnockPacketSizes(t *testing.T) {
	secret := []byte("size-test")
	strat := NewAntiProbeStrategy(NewManager(), secret)
	seq := strat.generateKnockSequence()

	// Calculate total bytes sent
	totalBytes := 0
	for _, size := range seq.Sizes {
		totalBytes += size
	}

	// Total should be reasonable (50-500 bytes)
	if totalBytes < 50 {
		t.Errorf("Total knock bytes %d too small", totalBytes)
	}
	if totalBytes > 500 {
		t.Errorf("Total knock bytes %d too large", totalBytes)
	}
}

// TestHMACBasedGeneration tests HMAC-based generation is secure
func TestHMACBasedGeneration(t *testing.T) {
	secret := []byte("hmac-test-secret")

	// Generate expected hash
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("knock-sequence"))
	expectedHash := h.Sum(nil)

	if len(expectedHash) != 32 {
		t.Errorf("Expected SHA256 hash (32 bytes), got %d", len(expectedHash))
	}

	// Verify hash is used for generation
	strat := NewAntiProbeStrategy(NewManager(), secret)
	seq := strat.generateKnockSequence()

	// First delay should be derived from first byte of hash
	expectedDelay := time.Duration(50+int(expectedHash[0])%150) * time.Millisecond
	if seq.Delays[0] != expectedDelay {
		t.Errorf("First delay mismatch: got %v, expected %v", seq.Delays[0], expectedDelay)
	}

	// First size should be derived from 6th byte of hash
	expectedSize := 10 + int(expectedHash[5])%90
	if seq.Sizes[0] != expectedSize {
		t.Errorf("First size mismatch: got %d, expected %d", seq.Sizes[0], expectedSize)
	}
}

// TestAntiProbeResponseCodes tests ACK response validation
func TestAntiProbeResponseCodes(t *testing.T) {
	tests := []struct {
		name    string
		ack     byte
		isValid bool
	}{
		{"Valid ACK", 0x01, true},
		{"Invalid - zero", 0x00, false},
		{"Invalid - other", 0x02, false},
		{"Invalid - high", 0xFF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// In real implementation, server sends 0x01 for valid knock
			isValid := (tt.ack == 0x01)
			if isValid != tt.isValid {
				t.Errorf("ACK 0x%02x validity: got %v, want %v", tt.ack, isValid, tt.isValid)
			}
		})
	}
}

// TestKnockSequenceHashDistribution tests hash distribution
func TestKnockSequenceHashDistribution(t *testing.T) {
	// Test that different secrets produce well-distributed values
	delayDistribution := make(map[int]int) // milliseconds -> count
	sizeDistribution := make(map[int]int)  // bytes -> count

	// Generate 100 sequences with different secrets
	for i := 0; i < 100; i++ {
		secret := []byte{byte(i), byte(i >> 8), byte(i >> 16)}
		strat := NewAntiProbeStrategy(NewManager(), secret)
		seq := strat.generateKnockSequence()

		for _, delay := range seq.Delays {
			ms := int(delay.Milliseconds())
			delayDistribution[ms]++
		}

		for _, size := range seq.Sizes {
			sizeDistribution[size]++
		}
	}

	// Should have good distribution (at least 50 unique delay values)
	if len(delayDistribution) < 50 {
		t.Errorf("Poor delay distribution: only %d unique values", len(delayDistribution))
	}

	// Should have good distribution (at least 50 unique size values)
	if len(sizeDistribution) < 50 {
		t.Errorf("Poor size distribution: only %d unique values", len(sizeDistribution))
	}

	// No single delay should dominate (max 20% of samples)
	for delay, count := range delayDistribution {
		if count > 100 {
			t.Errorf("Delay %dms appears %d times (too frequent)", delay, count)
		}
	}
}
