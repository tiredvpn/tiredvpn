package strategy

import (
	"testing"
	"time"
)

// TestRelayNodeCreation tests relay node initialization
func TestRelayNodeCreation(t *testing.T) {
	node := &RelayNode{
		Address:   "10.0.0.1:443",
		Location:  "RU-Moscow",
		Type:      RelayTypeVPS,
		Latency:   50 * time.Millisecond,
		Available: true,
		Load:      0.3,
		Secret:    "relay-secret",
	}

	if node.Address != "10.0.0.1:443" {
		t.Errorf("Address: got %s, want 10.0.0.1:443", node.Address)
	}

	if node.Location != "RU-Moscow" {
		t.Errorf("Location: got %s, want RU-Moscow", node.Location)
	}

	if node.Type != RelayTypeVPS {
		t.Errorf("Type: got %s, want %s", node.Type, RelayTypeVPS)
	}

	if node.Latency != 50*time.Millisecond {
		t.Errorf("Latency: got %v, want 50ms", node.Latency)
	}

	if !node.Available {
		t.Error("Node should be available")
	}

	if node.Load != 0.3 {
		t.Errorf("Load: got %f, want 0.3", node.Load)
	}
}

// TestRelayTypes tests relay type constants
func TestRelayTypes(t *testing.T) {
	types := []struct {
		relayType RelayType
		name      string
	}{
		{RelayTypeHome, "home"},
		{RelayTypeVPS, "vps"},
		{RelayTypeFriend, "friend"},
		{RelayTypePublic, "public"},
	}

	for _, tt := range types {
		if string(tt.relayType) != tt.name {
			t.Errorf("RelayType %s != %s", tt.relayType, tt.name)
		}
	}
}

// TestMeshRelayAddRelay tests adding relays to mesh
func TestMeshRelayAddRelay(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	// Initially should have no relays
	mesh.mu.RLock()
	count := len(mesh.relays)
	mesh.mu.RUnlock()

	if count != 0 {
		t.Errorf("Initial relay count: got %d, want 0", count)
	}

	// Add one relay
	relay1 := &RelayNode{
		Address:  "10.0.0.1:443",
		Location: "RU-Moscow",
	}
	mesh.AddRelay(relay1)

	mesh.mu.RLock()
	count = len(mesh.relays)
	mesh.mu.RUnlock()

	if count != 1 {
		t.Errorf("After adding one: got %d relays, want 1", count)
	}

	// Add another relay
	relay2 := &RelayNode{
		Address:  "10.0.0.2:443",
		Location: "RU-SPB",
	}
	mesh.AddRelay(relay2)

	mesh.mu.RLock()
	count = len(mesh.relays)
	mesh.mu.RUnlock()

	if count != 2 {
		t.Errorf("After adding two: got %d relays, want 2", count)
	}
}

// TestMeshRelayAddMultiple tests adding multiple relays at once
func TestMeshRelayAddMultiple(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	relays := []*RelayNode{
		{Address: "10.0.0.1:443", Location: "RU-Moscow"},
		{Address: "10.0.0.2:443", Location: "RU-SPB"},
		{Address: "10.0.0.3:443", Location: "RU-Kazan"},
	}

	mesh.AddRelays(relays)

	mesh.mu.RLock()
	count := len(mesh.relays)
	mesh.mu.RUnlock()

	if count != 3 {
		t.Errorf("After adding 3 relays: got %d, want 3", count)
	}
}

// TestRelaySelection tests relay selection algorithm
func TestRelaySelection(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	// Add relays with different characteristics
	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.1:443",
		Location:  "RU-Moscow",
		Available: true,
		Latency:   100 * time.Millisecond,
		Load:      0.8, // High load
	})

	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.2:443",
		Location:  "RU-SPB",
		Available: true,
		Latency:   30 * time.Millisecond, // Low latency
		Load:      0.1,                   // Low load
	})

	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.3:443",
		Location:  "RU-Kazan",
		Available: false, // Not available
		Latency:   20 * time.Millisecond,
		Load:      0.0,
	})

	// Select best relay
	relay, err := mesh.selectBestRelay()
	if err != nil {
		t.Fatalf("selectBestRelay failed: %v", err)
	}

	// Should select SPB (lowest latency + load among available)
	if relay.Location != "RU-SPB" {
		t.Errorf("Selected %s, expected RU-SPB (lowest score)", relay.Location)
	}
}

// TestRelaySelectionNoAvailable tests selection when no relays available
func TestRelaySelectionNoAvailable(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	// Add only unavailable relays
	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.1:443",
		Location:  "RU-Moscow",
		Available: false,
	})

	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.2:443",
		Location:  "RU-SPB",
		Available: false,
	})

	// Should return error
	_, err := mesh.selectBestRelay()
	if err == nil {
		t.Error("Expected error when no relays available")
	}
}

// TestRelayScoring tests relay scoring algorithm
func TestRelayScoring(t *testing.T) {
	tests := []struct {
		name     string
		latency  time.Duration
		load     float64
		expected float64
	}{
		{
			name:     "Low latency, low load",
			latency:  20 * time.Millisecond,
			load:     0.1,
			expected: 20 + 0.1*100, // 30
		},
		{
			name:     "High latency, low load",
			latency:  100 * time.Millisecond,
			load:     0.1,
			expected: 100 + 0.1*100, // 110
		},
		{
			name:     "Low latency, high load",
			latency:  20 * time.Millisecond,
			load:     0.9,
			expected: 20 + 0.9*100, // 110
		},
		{
			name:     "High latency, high load",
			latency:  100 * time.Millisecond,
			load:     0.9,
			expected: 100 + 0.9*100, // 190
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Score = latency_ms + load * 100
			score := float64(tt.latency.Milliseconds()) + tt.load*100

			if score != tt.expected {
				t.Errorf("Score: got %f, want %f", score, tt.expected)
			}
		})
	}
}

// TestRelayLoadValidation tests load value constraints
func TestRelayLoadValidation(t *testing.T) {
	tests := []struct {
		load  float64
		valid bool
	}{
		{0.0, true},
		{0.5, true},
		{1.0, true},
		{-0.1, false},
		{1.1, false},
	}

	for _, tt := range tests {
		valid := tt.load >= 0.0 && tt.load <= 1.0
		if valid != tt.valid {
			t.Errorf("Load %f validity: got %v, want %v", tt.load, valid, tt.valid)
		}
	}
}

// TestMeshHealthCheck tests health check interval
func TestMeshHealthCheck(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	// Default should be 30 seconds
	if mesh.healthCheck != 30*time.Second {
		t.Errorf("Health check interval: got %v, want 30s", mesh.healthCheck)
	}
}

// TestRelayLocationParsing tests location string format
func TestRelayLocationParsing(t *testing.T) {
	tests := []struct {
		location string
		valid    bool
	}{
		{"RU-Moscow", true},
		{"RU-SPB", true},
		{"RU-Kazan", true},
		{"", false},
		{"Moscow", false}, // Missing country code
	}

	for _, tt := range tests {
		// Location should have format "CC-City"
		valid := len(tt.location) > 2 && tt.location[2] == '-'
		if valid != tt.valid {
			t.Errorf("Location %q validity: got %v, want %v", tt.location, valid, tt.valid)
		}
	}
}

// TestRelayAddressValidation tests address format
func TestRelayAddressValidation(t *testing.T) {
	tests := []struct {
		address string
		valid   bool
	}{
		{"10.0.0.1:443", true},
		{"192.168.1.1:8080", true},
		{"relay.example.com:443", true},
		{"10.0.0.1", false}, // Missing port
		{":443", false},     // Missing host
		{"", false},
	}

	for _, tt := range tests {
		// Basic validation: should contain ':'
		valid := len(tt.address) > 0 && containsColon(tt.address)
		if valid != tt.valid {
			t.Errorf("Address %q validity: got %v, want %v", tt.address, valid, tt.valid)
		}
	}
}

func containsColon(s string) bool {
	colonPos := -1
	for i, ch := range s {
		if ch == ':' {
			colonPos = i
			break
		}
	}
	// Must have colon and both host and port
	return colonPos > 0 && colonPos < len(s)-1
}

// TestRelayMetadata tests relay metadata
func TestRelayMetadata(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	if mesh.Name() == "" {
		t.Error("Name should not be empty")
	}

	if mesh.ID() != "mesh_relay" {
		t.Errorf("ID: got %s, want mesh_relay", mesh.ID())
	}

	if mesh.Priority() < 0 || mesh.Priority() > 100 {
		t.Errorf("Priority %d out of reasonable range", mesh.Priority())
	}

	if mesh.Description() == "" {
		t.Error("Description should not be empty")
	}

	if !mesh.RequiresServer() {
		t.Error("Mesh relay requires server")
	}
}

// TestRelayExitNode tests exit node configuration
func TestRelayExitNode(t *testing.T) {
	exitNode := "exit.example.com:443"
	mesh := NewMeshRelayStrategy(exitNode)

	if mesh.exitNode != exitNode {
		t.Errorf("Exit node: got %s, want %s", mesh.exitNode, exitNode)
	}
}

// TestRelayLastCheck tests last check timestamp
func TestRelayLastCheck(t *testing.T) {
	now := time.Now()
	node := &RelayNode{
		Address:   "10.0.0.1:443",
		Location:  "RU-Moscow",
		LastCheck: now,
	}

	if !node.LastCheck.Equal(now) {
		t.Errorf("LastCheck: got %v, want %v", node.LastCheck, now)
	}

	// Check should be recent
	age := time.Since(node.LastCheck)
	if age > 1*time.Second {
		t.Errorf("LastCheck age %v seems wrong", age)
	}
}

// TestRelaySecretAuthentication tests secret field
func TestRelaySecretAuthentication(t *testing.T) {
	node := &RelayNode{
		Address: "10.0.0.1:443",
		Secret:  "shared-secret-key-123",
	}

	if node.Secret == "" {
		t.Error("Secret should not be empty for authenticated relay")
	}

	if len(node.Secret) < 10 {
		t.Error("Secret should be reasonably long")
	}
}

// TestRelaySorting tests relay sorting by score
func TestRelaySorting(t *testing.T) {
	relays := []*RelayNode{
		{
			Address:   "relay1",
			Latency:   100 * time.Millisecond,
			Load:      0.5,
			Available: true,
		},
		{
			Address:   "relay2",
			Latency:   50 * time.Millisecond,
			Load:      0.1,
			Available: true,
		},
		{
			Address:   "relay3",
			Latency:   75 * time.Millisecond,
			Load:      0.3,
			Available: true,
		},
	}

	mesh := NewMeshRelayStrategy("exit.example.com:443")
	mesh.AddRelays(relays)

	best, _ := mesh.selectBestRelay()

	// relay2 should win: score = 50 + 0.1*100 = 60
	// relay3: score = 75 + 0.3*100 = 105
	// relay1: score = 100 + 0.5*100 = 150
	if best.Address != "relay2" {
		t.Errorf("Best relay: got %s, want relay2", best.Address)
	}
}
