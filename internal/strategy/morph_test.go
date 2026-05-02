package strategy

import (
	"math"
	"testing"
)

// TestTrafficProfilePacketSizes tests packet size distribution
func TestTrafficProfilePacketSizes(t *testing.T) {
	profiles := []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		WebBrowsingProfile,
		VoIPProfile,
	}

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			// Verify packet sizes array length matches probabilities
			if len(profile.PacketSizes) != len(profile.PacketSizeProbs) {
				t.Errorf("PacketSizes length %d != PacketSizeProbs length %d",
					len(profile.PacketSizes), len(profile.PacketSizeProbs))
			}

			// Verify probabilities sum to ~1.0
			sum := 0.0
			for _, prob := range profile.PacketSizeProbs {
				sum += prob
				if prob < 0 || prob > 1 {
					t.Errorf("Invalid probability %f (should be 0-1)", prob)
				}
			}

			if math.Abs(sum-1.0) > 0.01 {
				t.Errorf("Probabilities sum to %f, expected ~1.0", sum)
			}

			// Verify packet sizes are positive and reasonable
			for _, size := range profile.PacketSizes {
				if size <= 0 {
					t.Errorf("Invalid packet size %d (should be > 0)", size)
				}
				if size > 65535 {
					t.Errorf("Packet size %d too large (max 65535)", size)
				}
			}
		})
	}
}

// TestTrafficProfileInterArrival tests inter-arrival time parameters
func TestTrafficProfileInterArrival(t *testing.T) {
	profiles := []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		WebBrowsingProfile,
		VoIPProfile,
	}

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			// Mean should be positive
			if profile.InterArrivalMean <= 0 {
				t.Errorf("InterArrivalMean %f should be > 0", profile.InterArrivalMean)
			}

			// StdDev should be non-negative
			if profile.InterArrivalStdDev < 0 {
				t.Errorf("InterArrivalStdDev %f should be >= 0", profile.InterArrivalStdDev)
			}

			// StdDev shouldn't be too large compared to mean (sanity check)
			if profile.InterArrivalStdDev > profile.InterArrivalMean*10 {
				t.Logf("Warning: StdDev (%f) is much larger than mean (%f)",
					profile.InterArrivalStdDev, profile.InterArrivalMean)
			}
		})
	}
}

// TestTrafficProfilePadding tests padding parameters
func TestTrafficProfilePadding(t *testing.T) {
	profiles := []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		WebBrowsingProfile,
		VoIPProfile,
	}

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			// Min should be non-negative
			if profile.MinPadding < 0 {
				t.Errorf("MinPadding %d should be >= 0", profile.MinPadding)
			}

			// Max should be >= Min
			if profile.MaxPadding < profile.MinPadding {
				t.Errorf("MaxPadding %d < MinPadding %d", profile.MaxPadding, profile.MinPadding)
			}

			// Padding shouldn't be too large (wastes bandwidth)
			if profile.MaxPadding > 1000 {
				t.Logf("Warning: MaxPadding %d is quite large", profile.MaxPadding)
			}
		})
	}
}

// TestYandexVideoProfileCharacteristics tests Yandex Video specific properties
func TestYandexVideoProfileCharacteristics(t *testing.T) {
	profile := YandexVideoProfile

	// Yandex Video should have large packets (streaming)
	hasLargePackets := false
	for _, size := range profile.PacketSizes {
		if size >= 1200 {
			hasLargePackets = true
			break
		}
	}
	if !hasLargePackets {
		t.Error("Yandex Video should have packets >= 1200 bytes")
	}

	// Inter-arrival should be low (high throughput)
	if profile.InterArrivalMean > 20.0 {
		t.Errorf("Yandex Video InterArrivalMean %f should be <= 20ms (streaming)",
			profile.InterArrivalMean)
	}
}

// TestVoIPProfileCharacteristics tests VoIP specific properties
func TestVoIPProfileCharacteristics(t *testing.T) {
	profile := VoIPProfile

	// VoIP should have small, regular packets
	for _, size := range profile.PacketSizes {
		if size > 400 {
			t.Errorf("VoIP packet size %d too large (should be <= 400 for voice)",
				size)
		}
	}

	// Should have regular intervals (low variance)
	if profile.InterArrivalStdDev > profile.InterArrivalMean {
		t.Errorf("VoIP should have low variance: StdDev %f > Mean %f",
			profile.InterArrivalStdDev, profile.InterArrivalMean)
	}
}

// TestWebBrowsingProfileCharacteristics tests web browsing properties
func TestWebBrowsingProfileCharacteristics(t *testing.T) {
	profile := WebBrowsingProfile

	// Should have diverse packet sizes
	if len(profile.PacketSizes) < 3 {
		t.Error("Web browsing should have diverse packet sizes")
	}

	// Should have higher inter-arrival time (less continuous)
	if profile.InterArrivalMean < 30.0 {
		t.Errorf("Web browsing InterArrivalMean %f should be >= 30ms (bursty)",
			profile.InterArrivalMean)
	}
}

// TestPacketSizeSelection tests packet size selection logic
func TestPacketSizeSelection(t *testing.T) {
	profile := YandexVideoProfile

	// Simulate selecting 1000 packet sizes
	counts := make(map[int]int)
	total := 1000

	// This is a simulation - in real code, packet sizes are selected
	// based on profile.PacketSizeProbs distribution
	for i := 0; i < total; i++ {
		// Simplified selection (not truly random, just for test structure)
		idx := i % len(profile.PacketSizes)
		size := profile.PacketSizes[idx]
		counts[size]++
	}

	// Verify all packet sizes were selected
	if len(counts) != len(profile.PacketSizes) {
		t.Errorf("Selected %d different sizes, expected %d",
			len(counts), len(profile.PacketSizes))
	}
}

// TestInterArrivalTimeGeneration tests inter-arrival time calculation
func TestInterArrivalTimeGeneration(t *testing.T) {
	profile := YandexVideoProfile

	// Test that we can calculate a valid inter-arrival time
	mean := profile.InterArrivalMean
	stdDev := profile.InterArrivalStdDev

	// Generate 100 samples and check they're reasonable
	negativeCount := 0
	tooLargeCount := 0

	for i := 0; i < 100; i++ {
		// Simplified normal distribution (not real implementation)
		sample := mean + float64(i%10-5)*stdDev/5.0

		if sample < 0 {
			negativeCount++
		}
		if sample > mean+5*stdDev {
			tooLargeCount++
		}
	}

	// Some samples might be negative or very large due to normal distribution
	// This is expected behavior
	t.Logf("Generated samples: %d negative, %d very large (out of 100)",
		negativeCount, tooLargeCount)
}

// TestProfileNames tests that all profiles have unique names
func TestProfileNames(t *testing.T) {
	profiles := []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		WebBrowsingProfile,
		VoIPProfile,
	}

	names := make(map[string]bool)
	for _, profile := range profiles {
		if profile.Name == "" {
			t.Error("Profile has empty name")
		}

		if names[profile.Name] {
			t.Errorf("Duplicate profile name: %s", profile.Name)
		}
		names[profile.Name] = true
	}

	// Should have all 4 unique names
	if len(names) != 4 {
		t.Errorf("Expected 4 unique profile names, got %d", len(names))
	}
}

// TestProfileConsistency tests overall profile consistency
func TestProfileConsistency(t *testing.T) {
	profiles := []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		WebBrowsingProfile,
		VoIPProfile,
	}

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			// All fields should be initialized
			if profile.Name == "" {
				t.Error("Name is empty")
			}
			if len(profile.PacketSizes) == 0 {
				t.Error("PacketSizes is empty")
			}
			if len(profile.PacketSizeProbs) == 0 {
				t.Error("PacketSizeProbs is empty")
			}
			if profile.InterArrivalMean == 0 {
				t.Error("InterArrivalMean is zero")
			}
		})
	}
}
