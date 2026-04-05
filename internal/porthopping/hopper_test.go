package porthopping

import (
	"sync"
	"testing"
	"time"
)

func TestNewPortHopper(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		config := DefaultConfig()
		hopper, err := NewPortHopper(config)
		if err != nil {
			t.Fatalf("failed to create hopper: %v", err)
		}

		port := hopper.CurrentPort()
		if port < config.PortRangeStart || port > config.PortRangeEnd {
			t.Errorf("initial port %d outside range [%d, %d]",
				port, config.PortRangeStart, config.PortRangeEnd)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewPortHopper(nil)
		if err != ErrNilConfig {
			t.Errorf("expected ErrNilConfig, got %v", err)
		}
	})

	t.Run("invalid port range", func(t *testing.T) {
		config := DefaultConfig()
		config.PortRangeStart = 65535
		config.PortRangeEnd = 1000

		_, err := NewPortHopper(config)
		if err != ErrInvalidPortRange {
			t.Errorf("expected ErrInvalidPortRange, got %v", err)
		}
	})

	t.Run("invalid strategy", func(t *testing.T) {
		config := DefaultConfig()
		config.Strategy = "invalid"

		_, err := NewPortHopper(config)
		if err != ErrInvalidStrategy {
			t.Errorf("expected ErrInvalidStrategy, got %v", err)
		}
	})
}

func TestPortHopperRandom(t *testing.T) {
	config := DefaultConfig()
	config.Strategy = StrategyRandom

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	ports := make(map[int]bool)
	for i := 0; i < 100; i++ {
		port := hopper.NextPort()
		if port < config.PortRangeStart || port > config.PortRangeEnd {
			t.Errorf("port %d outside range [%d, %d]",
				port, config.PortRangeStart, config.PortRangeEnd)
		}
		ports[port] = true
	}

	// Random strategy should produce diverse ports
	// With 100 iterations over 18535 port range, expect significant diversity
	if len(ports) < 50 {
		t.Errorf("random strategy produced only %d unique ports in 100 hops, expected more diversity", len(ports))
	}
}

func TestPortHopperSequential(t *testing.T) {
	config := DefaultConfig()
	config.Strategy = StrategySequential
	config.PortRangeStart = 47000
	config.PortRangeEnd = 47010

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	firstPort := hopper.CurrentPort()

	// Test sequential increment
	for i := 0; i < 15; i++ {
		port := hopper.NextPort()
		expectedPort := config.PortRangeStart + ((firstPort - config.PortRangeStart + i + 1) % (config.PortRangeEnd - config.PortRangeStart + 1))

		if port != expectedPort {
			t.Errorf("iteration %d: got port %d, expected %d", i, port, expectedPort)
		}
	}
}

func TestPortHopperFibonacci(t *testing.T) {
	config := DefaultConfig()
	config.Strategy = StrategyFibonacci
	config.PortRangeStart = 47000
	config.PortRangeEnd = 47100

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	ports := make([]int, 20)
	for i := 0; i < 20; i++ {
		ports[i] = hopper.NextPort()
		if ports[i] < config.PortRangeStart || ports[i] > config.PortRangeEnd {
			t.Errorf("fibonacci port %d outside range", ports[i])
		}
	}

	// Fibonacci should produce non-uniform distribution
	uniquePorts := make(map[int]bool)
	for _, p := range ports {
		uniquePorts[p] = true
	}

	// Should have some diversity
	if len(uniquePorts) < 5 {
		t.Errorf("fibonacci produced only %d unique ports, expected more", len(uniquePorts))
	}
}

func TestPortHopperSeedDeterminism(t *testing.T) {
	seed := []byte("test-seed-for-sync")

	config1 := DefaultConfig()
	config1.Strategy = StrategyRandom
	config1.Seed = seed

	config2 := DefaultConfig()
	config2.Strategy = StrategyRandom
	config2.Seed = seed

	hopper1, err := NewPortHopper(config1)
	if err != nil {
		t.Fatalf("failed to create hopper1: %v", err)
	}

	hopper2, err := NewPortHopper(config2)
	if err != nil {
		t.Fatalf("failed to create hopper2: %v", err)
	}

	// With same seed, should produce same sequence
	for i := 0; i < 50; i++ {
		port1 := hopper1.NextPort()
		port2 := hopper2.NextPort()

		if port1 != port2 {
			t.Errorf("iteration %d: hopper1=%d, hopper2=%d (should be equal with same seed)",
				i, port1, port2)
		}
	}
}

func TestPortHopperShouldHop(t *testing.T) {
	config := DefaultConfig()
	config.HopInterval = 50 * time.Millisecond

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	// Initially should not need hop (just created)
	if hopper.ShouldHop() {
		t.Error("should not hop immediately after creation")
	}

	// Wait for interval (with some buffer for jitter)
	time.Sleep(100 * time.Millisecond)

	if !hopper.ShouldHop() {
		t.Error("should hop after interval elapsed")
	}

	// After hop, should not need another hop
	hopper.NextPort()
	if hopper.ShouldHop() {
		t.Error("should not hop immediately after NextPort")
	}
}

func TestPortHopperDisabled(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = false

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	initialPort := hopper.CurrentPort()

	// ShouldHop should always return false when disabled
	if hopper.ShouldHop() {
		t.Error("disabled hopper should never signal hop")
	}

	// NextPort should return same port when disabled
	for i := 0; i < 10; i++ {
		port := hopper.NextPort()
		if port != initialPort {
			t.Errorf("disabled hopper changed port from %d to %d", initialPort, port)
		}
	}
}

func TestPortHopperJitter(t *testing.T) {
	config := DefaultConfig()
	config.HopInterval = 100 * time.Millisecond

	intervals := make([]time.Duration, 100)

	for i := 0; i < 100; i++ {
		hopper, err := NewPortHopper(config)
		if err != nil {
			t.Fatalf("failed to create hopper: %v", err)
		}
		intervals[i] = hopper.TimeUntilNextHop()
	}

	// Check jitter range (70% to 130% of base interval)
	minExpected := time.Duration(float64(config.HopInterval) * 0.7)
	maxExpected := time.Duration(float64(config.HopInterval) * 1.3)

	min, max := intervals[0], intervals[0]
	for _, d := range intervals {
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}

	// Allow some tolerance
	tolerance := 10 * time.Millisecond
	if min < minExpected-tolerance {
		t.Errorf("minimum interval %v below expected %v", min, minExpected)
	}
	if max > maxExpected+tolerance {
		t.Errorf("maximum interval %v above expected %v", max, maxExpected)
	}

	// Check that there's actual variation (not all same)
	if max-min < 20*time.Millisecond {
		t.Errorf("jitter variation too small: min=%v, max=%v", min, max)
	}
}

func TestPortHopperCallback(t *testing.T) {
	config := DefaultConfig()
	config.Strategy = StrategySequential
	config.PortRangeStart = 47000
	config.PortRangeEnd = 47100

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	var callbackCalled bool
	var callbackOldPort, callbackNewPort int
	var wg sync.WaitGroup
	wg.Add(1)

	hopper.OnHop(func(oldPort, newPort int) {
		callbackOldPort = oldPort
		callbackNewPort = newPort
		callbackCalled = true
		wg.Done()
	})

	oldPort := hopper.CurrentPort()
	newPort := hopper.NextPort()

	// Wait for callback with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Callback was called
	case <-time.After(100 * time.Millisecond):
		t.Fatal("callback was not called within timeout")
	}

	if !callbackCalled {
		t.Error("callback was not called")
	}
	if callbackOldPort != oldPort {
		t.Errorf("callback oldPort=%d, expected %d", callbackOldPort, oldPort)
	}
	if callbackNewPort != newPort {
		t.Errorf("callback newPort=%d, expected %d", callbackNewPort, newPort)
	}
}

func TestPortHopperStats(t *testing.T) {
	config := DefaultConfig()
	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	stats := hopper.Stats()
	if !stats.Enabled {
		t.Error("stats.Enabled should be true")
	}
	if stats.HopCount != 0 {
		t.Errorf("initial hop count should be 0, got %d", stats.HopCount)
	}
	if stats.Strategy != StrategyRandom {
		t.Errorf("stats.Strategy should be random, got %s", stats.Strategy)
	}

	// Perform some hops
	for i := 0; i < 5; i++ {
		hopper.NextPort()
	}

	stats = hopper.Stats()
	if stats.HopCount != 5 {
		t.Errorf("hop count should be 5, got %d", stats.HopCount)
	}
}

func TestPortHopperReset(t *testing.T) {
	config := DefaultConfig()
	config.Seed = []byte("test-seed")

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	initialPort := hopper.CurrentPort()

	// Perform some hops
	for i := 0; i < 10; i++ {
		hopper.NextPort()
	}

	stats := hopper.Stats()
	if stats.HopCount == 0 {
		t.Error("hop count should be non-zero before reset")
	}

	// Reset
	hopper.Reset()

	stats = hopper.Stats()
	if stats.HopCount != 0 {
		t.Errorf("hop count should be 0 after reset, got %d", stats.HopCount)
	}

	// With same seed, should start from same initial port sequence
	resetPort := hopper.CurrentPort()
	if resetPort != initialPort {
		t.Errorf("reset port %d != initial port %d", resetPort, initialPort)
	}
}

func TestPortHopperConcurrency(t *testing.T) {
	config := DefaultConfig()
	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				port := hopper.CurrentPort()
				if port < config.PortRangeStart || port > config.PortRangeEnd {
					t.Errorf("concurrent read got invalid port %d", port)
				}

				if j%10 == 0 {
					hopper.NextPort()
				}

				hopper.ShouldHop()
				hopper.Stats()
			}
		}()
	}

	wg.Wait()
}

func TestPortHopperPortList(t *testing.T) {
	config := DefaultConfig()
	config.Seed = []byte("test-seed")
	config.Strategy = StrategyRandom

	hopper, err := NewPortHopper(config)
	if err != nil {
		t.Fatalf("failed to create hopper: %v", err)
	}

	ports := hopper.PortList(50)
	if len(ports) < 10 {
		t.Errorf("expected at least 10 ports, got %d", len(ports))
	}

	// All ports should be in range
	for _, port := range ports {
		if port < config.PortRangeStart || port > config.PortRangeEnd {
			t.Errorf("port %d outside valid range", port)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*Config)
		expectError error
	}{
		{
			name:        "valid config",
			modify:      func(c *Config) {},
			expectError: nil,
		},
		{
			name:        "port range start too low",
			modify:      func(c *Config) { c.PortRangeStart = 0 },
			expectError: ErrInvalidPortRange,
		},
		{
			name:        "port range end too high",
			modify:      func(c *Config) { c.PortRangeEnd = 70000 },
			expectError: ErrInvalidPortRange,
		},
		{
			name:        "port range inverted",
			modify:      func(c *Config) { c.PortRangeStart = 50000; c.PortRangeEnd = 40000 },
			expectError: ErrInvalidPortRange,
		},
		{
			name:        "negative hop interval",
			modify:      func(c *Config) { c.HopInterval = -1 * time.Second },
			expectError: ErrInvalidHopInterval,
		},
		{
			name:        "invalid strategy",
			modify:      func(c *Config) { c.Strategy = "unknown" },
			expectError: ErrInvalidStrategy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			tt.modify(config)
			err := config.Validate()

			if err != tt.expectError {
				t.Errorf("expected error %v, got %v", tt.expectError, err)
			}
		})
	}
}

func BenchmarkPortHopperNextPort(b *testing.B) {
	config := DefaultConfig()
	hopper, _ := NewPortHopper(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hopper.NextPort()
	}
}

func BenchmarkPortHopperCurrentPort(b *testing.B) {
	config := DefaultConfig()
	hopper, _ := NewPortHopper(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hopper.CurrentPort()
	}
}

func BenchmarkPortHopperConcurrent(b *testing.B) {
	config := DefaultConfig()
	hopper, _ := NewPortHopper(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			hopper.CurrentPort()
			if hopper.ShouldHop() {
				hopper.NextPort()
			}
		}
	})
}
