package toml

import "testing"

// TestExampleConfigs_LoadCleanly is a regression check for the user-facing
// configs/*.example.toml files. If somebody adds a required field or renames
// a key without updating the examples, this test fails first.
func TestExampleConfigs_LoadCleanly(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		if _, err := LoadClient("../../../configs/client.example.toml"); err != nil {
			t.Fatalf("client example: %v", err)
		}
	})
	t.Run("server", func(t *testing.T) {
		if _, err := LoadServer("../../../configs/server.example.toml"); err != nil {
			t.Fatalf("server example: %v", err)
		}
	})
}
