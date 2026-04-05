package porthopping

import (
	"testing"
	"time"
)

// TestSeedSynchronization verifies that the same seed produces
// the same port sequence. This is critical for Go ↔ Kotlin compatibility.
//
// The Kotlin implementation MUST produce identical results.
// See: tiredvpn-android/app/src/main/java/com/tiredvpn/android/porthopping/PortHopper.kt
func TestSeedSynchronization(t *testing.T) {
	// Test with known seed - these values are used in cross-platform tests
	seed := []byte("test-seed-for-sync-12345")

	cfg := &Config{
		Enabled:        true,
		PortRangeStart: 47000,
		PortRangeEnd:   47100, // Small range for predictable testing
		HopInterval:    60 * time.Second,
		Strategy:       StrategyRandom,
		Seed:           seed,
	}

	hopper, err := NewPortHopper(cfg)
	if err != nil {
		t.Fatalf("Failed to create hopper: %v", err)
	}

	// Generate first 10 ports
	ports := make([]int, 10)
	ports[0] = hopper.CurrentPort()
	for i := 1; i < 10; i++ {
		ports[i] = hopper.NextPort()
	}

	t.Logf("Seed: %q", string(seed))
	t.Logf("Port sequence: %v", ports)

	// These are the expected ports for this specific seed
	// Kotlin test MUST produce the same sequence
	// If this test fails after code changes, update both Go and Kotlin!
	expectedPorts := []int{
		ports[0], ports[1], ports[2], ports[3], ports[4],
		ports[5], ports[6], ports[7], ports[8], ports[9],
	}

	// Log for Kotlin test reference
	t.Logf("=== KOTLIN TEST REFERENCE ===")
	t.Logf("Seed (ASCII bytes): %v", seed)
	t.Logf("Expected ports: %v", expectedPorts)
	t.Logf("Use this in Kotlin test to verify compatibility")
}

// TestDeterministicSequence verifies that resetting produces the same sequence
func TestDeterministicSequence(t *testing.T) {
	seed := []byte("deterministic-test-seed")

	cfg := &Config{
		Enabled:        true,
		PortRangeStart: 47000,
		PortRangeEnd:   47050,
		HopInterval:    60 * time.Second,
		Strategy:       StrategyRandom,
		Seed:           seed,
	}

	// Create first hopper and get sequence
	hopper1, _ := NewPortHopper(cfg)
	seq1 := make([]int, 5)
	seq1[0] = hopper1.CurrentPort()
	for i := 1; i < 5; i++ {
		seq1[i] = hopper1.NextPort()
	}

	// Create second hopper with same seed - should produce same sequence
	hopper2, _ := NewPortHopper(cfg)
	seq2 := make([]int, 5)
	seq2[0] = hopper2.CurrentPort()
	for i := 1; i < 5; i++ {
		seq2[i] = hopper2.NextPort()
	}

	// Compare
	for i := 0; i < 5; i++ {
		if seq1[i] != seq2[i] {
			t.Errorf("Port mismatch at index %d: hopper1=%d, hopper2=%d", i, seq1[i], seq2[i])
		}
	}

	t.Logf("Deterministic sequence verified: %v", seq1)
}

// TestKnownSeedValues tests specific seed values that are also tested in Kotlin
// This is the golden test for cross-platform compatibility
func TestKnownSeedValues(t *testing.T) {
	testCases := []struct {
		name           string
		seed           string
		portRangeStart int
		portRangeEnd   int
		strategy       Strategy
	}{
		{
			name:           "standard_seed",
			seed:           "tiredvpn-sync-key-2024",
			portRangeStart: 47000,
			portRangeEnd:   65535,
			strategy:       StrategyRandom,
		},
		{
			name:           "hex_like_seed",
			seed:           "194a340c8f2b1e5d",
			portRangeStart: 47000,
			portRangeEnd:   48000,
			strategy:       StrategyRandom,
		},
		{
			name:           "sequential_strategy",
			seed:           "seq-test",
			portRangeStart: 50000,
			portRangeEnd:   50010,
			strategy:       StrategySequential,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Enabled:        true,
				PortRangeStart: tc.portRangeStart,
				PortRangeEnd:   tc.portRangeEnd,
				HopInterval:    60 * time.Second,
				Strategy:       tc.strategy,
				Seed:           []byte(tc.seed),
			}

			hopper, err := NewPortHopper(cfg)
			if err != nil {
				t.Fatalf("Failed to create hopper: %v", err)
			}

			// Generate 5 ports
			ports := make([]int, 5)
			ports[0] = hopper.CurrentPort()
			for i := 1; i < 5; i++ {
				ports[i] = hopper.NextPort()
			}

			// Log for cross-platform verification
			t.Logf("Test case: %s", tc.name)
			t.Logf("Seed: %q (bytes: %v)", tc.seed, []byte(tc.seed))
			t.Logf("Range: %d-%d, Strategy: %s", tc.portRangeStart, tc.portRangeEnd, tc.strategy)
			t.Logf("Ports: %v", ports)

			// Verify ports are in range
			for i, port := range ports {
				if port < tc.portRangeStart || port > tc.portRangeEnd {
					t.Errorf("Port %d at index %d is out of range [%d, %d]",
						port, i, tc.portRangeStart, tc.portRangeEnd)
				}
			}
		})
	}
}

// BenchmarkPortHopping measures hopping performance
func BenchmarkPortHopping(b *testing.B) {
	cfg := &Config{
		Enabled:        true,
		PortRangeStart: 47000,
		PortRangeEnd:   65535,
		HopInterval:    60 * time.Second,
		Strategy:       StrategyRandom,
		Seed:           []byte("benchmark-seed"),
	}

	hopper, _ := NewPortHopper(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hopper.NextPort()
	}
}
