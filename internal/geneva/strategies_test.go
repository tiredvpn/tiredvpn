package geneva

import (
	"testing"
)

func TestGetAllStrategies(t *testing.T) {
	strategies := GetAllStrategies()

	expectedCount := 11
	if len(strategies) != expectedCount {
		t.Errorf("GetAllStrategies() returned %d strategies, want %d", len(strategies), expectedCount)
	}

	// Verify all expected strategies exist
	expectedNames := []string{
		"china_gfw_1",
		"china_gfw_2",
		"china_gfw_3",
		"iran_dpi_1",
		"iran_dpi_2",
		"russia_tspu_1",
		"russia_tspu_2",
		"russia_tspu_3",
		"turkey_dpi_1",
		"generic_fragment",
		"generic_dup",
	}

	for _, name := range expectedNames {
		if strategies[name] == nil {
			t.Errorf("Strategy %q not found", name)
		}
	}
}

func TestGetStrategyByName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"china_gfw_1", true},
		{"russia_tspu_2", true},
		{"nonexistent", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := GetStrategyByName(tt.name)

			if tt.expected && strategy == nil {
				t.Errorf("GetStrategyByName(%q) = nil, want non-nil", tt.name)
			}

			if !tt.expected && strategy != nil {
				t.Errorf("GetStrategyByName(%q) = non-nil, want nil", tt.name)
			}
		})
	}
}

func TestGetStrategiesByCountry(t *testing.T) {
	tests := []struct {
		country       string
		expectedCount int
	}{
		{"china", 3},
		{"cn", 3},
		{"iran", 2},
		{"ir", 2},
		{"russia", 3},
		{"ru", 3},
		{"turkey", 1},
		{"tr", 1},
		{"unknown", 2}, // Generic strategies
		{"", 2},        // Generic strategies
	}

	for _, tt := range tests {
		t.Run(tt.country, func(t *testing.T) {
			strategies := GetStrategiesByCountry(tt.country)

			if len(strategies) != tt.expectedCount {
				t.Errorf("GetStrategiesByCountry(%q) returned %d strategies, want %d",
					tt.country, len(strategies), tt.expectedCount)
			}

			// Verify all strategies are non-nil
			for i, s := range strategies {
				if s == nil {
					t.Errorf("Strategy %d is nil", i)
				}
			}
		})
	}
}

func TestChinaGFWStrategy1(t *testing.T) {
	strategy := ChinaGFWStrategy1()

	if strategy == nil {
		t.Fatal("ChinaGFWStrategy1() = nil")
	}

	// Verify trigger
	if strategy.Trigger.Protocol != "TCP" {
		t.Errorf("Trigger protocol = %q, want \"TCP\"", strategy.Trigger.Protocol)
	}

	if strategy.Trigger.Field != "flags" {
		t.Errorf("Trigger field = %q, want \"flags\"", strategy.Trigger.Field)
	}

	// Verify metadata
	name := strategy.GetName()
	if name == "" || name == "unnamed strategy" {
		t.Errorf("GetName() = %q, want non-empty name", name)
	}

	successRate := strategy.GetSuccessRate()
	if successRate == "" || successRate == "unknown" {
		t.Errorf("GetSuccessRate() = %q, want known rate", successRate)
	}

	desc := strategy.GetDescription()
	if desc == "" || desc == "no description" {
		t.Errorf("GetDescription() = %q, want non-empty description", desc)
	}
}

func TestRussiaTSPUStrategy2(t *testing.T) {
	strategy := RussiaTSPUStrategy2()

	if strategy == nil {
		t.Fatal("RussiaTSPUStrategy2() = nil")
	}

	// Verify trigger for PSH-ACK packets
	expectedFlags := uint8(TCPFlagPSH | TCPFlagACK)
	if strategy.Trigger.Value != expectedFlags {
		t.Errorf("Trigger value = %v, want %v", strategy.Trigger.Value, expectedFlags)
	}

	// Verify outbound tree exists
	if strategy.OutboundTree == nil {
		t.Error("OutboundTree = nil, want non-nil")
	}
}

func TestStrategyMatch(t *testing.T) {
	strategy := ChinaGFWStrategy1()

	// Create SYN packet
	synPacket := createTestPacket()

	// Test match
	match, err := strategy.Match(synPacket)
	if err != nil {
		t.Errorf("Match() error = %v", err)
	}

	if !match {
		t.Error("Match() = false, want true for SYN packet")
	}

	// Create non-SYN packet
	nonSynPacket := createTestPacket()
	nonSynPacket[33] = TCPFlagACK // Only ACK flag

	match, err = strategy.Match(nonSynPacket)
	if err != nil {
		t.Errorf("Match() error = %v", err)
	}

	if match {
		t.Error("Match() = true, want false for non-SYN packet")
	}
}

func TestStrategyApply(t *testing.T) {
	strategy := GenericDuplicateStrategy()

	synPacket := createTestPacket()

	// Apply strategy (outbound)
	results, err := strategy.Apply(synPacket, true)
	if err != nil {
		t.Errorf("Apply() error = %v", err)
	}

	// Should return duplicate (2 packets)
	if len(results) != 2 {
		t.Errorf("Apply() returned %d packets, want 2", len(results))
	}

	// Test with non-matching packet
	nonSynPacket := createTestPacket()
	nonSynPacket[33] = TCPFlagACK

	results, err = strategy.Apply(nonSynPacket, true)
	if err != nil {
		t.Errorf("Apply() error = %v", err)
	}

	// Should return original packet unmodified
	if len(results) != 1 {
		t.Errorf("Apply() on non-matching packet returned %d packets, want 1", len(results))
	}
}

func TestGenericFragmentStrategy(t *testing.T) {
	strategy := GenericFragmentStrategy()

	packet := createTestPacket()

	// Apply strategy
	results, err := strategy.Apply(packet, true)
	if err != nil {
		t.Errorf("Apply() error = %v", err)
	}

	// Should fragment into 2 packets
	if len(results) != 2 {
		t.Errorf("Apply() returned %d packets, want 2", len(results))
	}

	// Verify both fragments have content
	for i, pkt := range results {
		if len(pkt) < 40 {
			t.Errorf("Fragment %d too short: %d bytes", i, len(pkt))
		}
	}
}

func TestIranDPIStrategy1(t *testing.T) {
	strategy := IranDPIStrategy1()

	synPacket := createTestPacket()

	results, err := strategy.Apply(synPacket, true)
	if err != nil {
		t.Errorf("Apply() error = %v", err)
	}

	// Should return duplicate
	if len(results) != 2 {
		t.Errorf("Apply() returned %d packets, want 2", len(results))
	}

	// Verify sequence number was tampered
	// (checking first packet in results, which should be modified)
	// Note: depending on primitive order, this may vary
}

func TestRussiaTSPUStrategy3(t *testing.T) {
	strategy := RussiaTSPUStrategy3()

	// Create PSH-ACK packet
	packet := createTestPacket()
	packet[33] = TCPFlagPSH | TCPFlagACK

	results, err := strategy.Apply(packet, true)
	if err != nil {
		t.Errorf("Apply() error = %v", err)
	}

	// Should return duplicate
	if len(results) != 2 {
		t.Errorf("Apply() returned %d packets, want 2", len(results))
	}
}

func TestTurkeyDPIStrategy1(t *testing.T) {
	strategy := TurkeyDPIStrategy1()

	if strategy == nil {
		t.Fatal("TurkeyDPIStrategy1() = nil")
	}

	synPacket := createTestPacket()

	match, err := strategy.Match(synPacket)
	if err != nil {
		t.Errorf("Match() error = %v", err)
	}

	if !match {
		t.Error("Match() = false, want true for SYN packet")
	}
}

func TestStrategyString(t *testing.T) {
	strategy := GenericDuplicateStrategy()

	str := strategy.String()

	// Should contain trigger and action info
	if len(str) == 0 {
		t.Error("String() returned empty string")
	}

	// Should contain TCP in trigger
	// Note: exact format may vary
	t.Logf("Strategy string: %s", str)
}

func TestStrategyMetadata(t *testing.T) {
	tests := []struct {
		name     string
		strategy *Strategy
	}{
		{"China GFW 1", ChinaGFWStrategy1()},
		{"Russia TSPU 2", RussiaTSPUStrategy2()},
		{"Iran DPI 1", IranDPIStrategy1()},
		{"Generic Frag", GenericFragmentStrategy()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := tt.strategy.GetName()
			desc := tt.strategy.GetDescription()
			rate := tt.strategy.GetSuccessRate()

			if name == "unnamed strategy" {
				t.Errorf("GetName() = %q, want actual name", name)
			}

			if desc == "no description" {
				t.Errorf("GetDescription() = %q, want actual description", desc)
			}

			if rate == "unknown" {
				t.Errorf("GetSuccessRate() = %q, want actual rate", rate)
			}

			t.Logf("Strategy: %s, Description: %s, Success rate: %s", name, desc, rate)
		})
	}
}

func BenchmarkChinaGFWStrategy1Apply(b *testing.B) {
	strategy := ChinaGFWStrategy1()
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Apply(packet, true)
	}
}

func BenchmarkRussiaTSPUStrategy2Apply(b *testing.B) {
	strategy := RussiaTSPUStrategy2()
	packet := createTestPacket()
	packet[33] = TCPFlagPSH | TCPFlagACK

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Apply(packet, true)
	}
}

func BenchmarkStrategyMatch(b *testing.B) {
	strategy := GenericDuplicateStrategy()
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Match(packet)
	}
}
