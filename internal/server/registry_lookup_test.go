package server

import (
	"net"
	"strings"
	"testing"
	"time"
)

// newPopulatedRegistry builds a registry with three clients (enabled, disabled,
// expired) without touching Redis: Start/reload are the only store-backed
// paths, and the lookup surface below is deliberately independent of them.
func newPopulatedRegistry(t *testing.T) *ClientRegistry {
	t.Helper()
	r := NewClientRegistry(nil)

	clients := []*ClientConfig{
		{ID: "enabled", Name: "alice", Secret: "secret-enabled", Enabled: true, MaxConns: 2},
		{ID: "disabled", Name: "bob", Secret: "secret-disabled", Enabled: false},
		{ID: "expired", Name: "carol", Secret: "secret-expired", Enabled: true,
			ExpiresAt: time.Now().Add(-time.Hour)},
	}
	for _, c := range clients {
		r.byID[c.ID] = c
		r.bySecret[c.Secret] = c
		var conns, up, down int64
		r.totalConns[c.ID] = &conns
		r.bytesUp[c.ID] = &up
		r.bytesDown[c.ID] = &down
	}
	return r
}

// TestClientRegistryLookups covers the two indexes the auth path uses. A secret
// that resolves to the wrong client (or to nothing) is an authentication bug,
// so both directions are pinned.
func TestClientRegistryLookups(t *testing.T) {
	r := newPopulatedRegistry(t)

	if got := r.GetByID("enabled"); got == nil || got.Name != "alice" {
		t.Errorf("GetByID(enabled) = %+v, want alice", got)
	}
	if got := r.GetByID("nobody"); got != nil {
		t.Errorf("GetByID(nobody) = %+v, want nil", got)
	}
	if got := r.GetByID(""); got != nil {
		t.Errorf("GetByID(\"\") = %+v, want nil", got)
	}

	if got := r.GetBySecret("secret-enabled"); got == nil || got.ID != "enabled" {
		t.Errorf("GetBySecret = %+v, want the enabled client", got)
	}
	// An empty secret must never match: a client that sends nothing would
	// otherwise authenticate as whichever entry happens to have a blank key.
	if got := r.GetBySecret(""); got != nil {
		t.Errorf("GetBySecret(\"\") = %+v, want nil", got)
	}
	if got := r.GetBySecret("wrong"); got != nil {
		t.Errorf("GetBySecret(wrong) = %+v, want nil", got)
	}

	if got := r.ClientCount(); got != 3 {
		t.Errorf("ClientCount = %d, want 3", got)
	}
	if got := len(r.ListClients()); got != 3 {
		t.Errorf("ListClients returned %d entries, want 3", got)
	}
}

// TestClientRegistryAuthenticate pins the three rejection reasons apart. The
// caller logs the message, so collapsing them would make an expired
// subscription indistinguishable from a stolen secret.
func TestClientRegistryAuthenticate(t *testing.T) {
	r := newPopulatedRegistry(t)

	cfg, err := r.Authenticate("secret-enabled")
	if err != nil {
		t.Fatalf("Authenticate(valid): %v", err)
	}
	if cfg.ID != "enabled" {
		t.Errorf("authenticated as %s, want enabled", cfg.ID)
	}

	tests := []struct {
		name       string
		secret     string
		wantReason string
	}{
		{"unknown secret", "not-a-secret", "invalid secret"},
		{"empty secret", "", "invalid secret"},
		{"disabled client", "secret-disabled", "client disabled"},
		{"expired client", "secret-expired", "client expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := r.Authenticate(tt.secret)
			if err == nil {
				t.Fatalf("Authenticate(%q) = %+v, want an error", tt.secret, cfg)
			}
			if cfg != nil {
				t.Errorf("Authenticate(%q) returned a config alongside its error: %+v", tt.secret, cfg)
			}
			if !strings.Contains(err.Error(), tt.wantReason) {
				t.Errorf("err = %q, want it to state %q", err, tt.wantReason)
			}
		})
	}

	// A client whose expiry is in the future authenticates normally; only a
	// past expiry rejects.
	r.byID["future"] = &ClientConfig{ID: "future", Secret: "s-future", Enabled: true,
		ExpiresAt: time.Now().Add(time.Hour)}
	r.bySecret["s-future"] = r.byID["future"]
	if _, err := r.Authenticate("s-future"); err != nil {
		t.Errorf("a client expiring in an hour must authenticate: %v", err)
	}
}

// TestClientRegistryStatsAccounting covers the byte and connection counters
// that back both /metrics and the per-client quota. Counters that do not move
// (or that leak across clients) break billing and rate limiting alike.
func TestClientRegistryStatsAccounting(t *testing.T) {
	r := newPopulatedRegistry(t)

	r.AddBytes("enabled", 100, 200)
	r.AddBytes("enabled", 50, 25)
	// An unknown client must be a silent no-op rather than a panic on a nil
	// counter pointer.
	r.AddBytes("ghost", 999, 999)

	stats := r.GetStats("enabled")
	if stats.ClientID != "enabled" {
		t.Errorf("ClientID = %q, want enabled", stats.ClientID)
	}
	if stats.BytesUp != 150 || stats.BytesDown != 225 {
		t.Errorf("bytes up/down = %d/%d, want 150/225", stats.BytesUp, stats.BytesDown)
	}
	if stats.ActiveConns != 0 || stats.TotalConns != 0 {
		t.Errorf("connections = %d active / %d total, want 0/0", stats.ActiveConns, stats.TotalConns)
	}
	if stats.LastSeen.IsZero() {
		t.Error("LastSeen is zero; the API renders it as 1970")
	}

	// Counters must not bleed into another client.
	if other := r.GetStats("disabled"); other.BytesUp != 0 || other.BytesDown != 0 {
		t.Errorf("disabled client picked up %d/%d bytes", other.BytesUp, other.BytesDown)
	}
	// An unknown client returns a zero-valued record rather than failing.
	if ghost := r.GetStats("ghost"); ghost.BytesUp != 0 || ghost.TotalConns != 0 {
		t.Errorf("GetStats(unknown) = %+v, want zeroes", ghost)
	}

	// AddConnection feeds both the active gauge and the lifetime counter.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := r.AddConnection("enabled", a); err != nil {
		t.Fatalf("AddConnection: %v", err)
	}
	stats = r.GetStats("enabled")
	if stats.ActiveConns != 1 || stats.TotalConns != 1 {
		t.Errorf("after connect: %d active / %d total, want 1/1", stats.ActiveConns, stats.TotalConns)
	}
	r.RemoveConnection("enabled", a)
	stats = r.GetStats("enabled")
	if stats.ActiveConns != 0 {
		t.Errorf("active = %d after disconnect, want 0", stats.ActiveConns)
	}
	if stats.TotalConns != 1 {
		t.Errorf("total = %d after disconnect, want 1 (lifetime counter must not decrement)", stats.TotalConns)
	}
}

// TestClientRegistryMaxConns pins the per-client connection limit, which is the
// only thing stopping one secret from being shared across an arbitrary number
// of devices.
func TestClientRegistryMaxConns(t *testing.T) {
	r := newPopulatedRegistry(t) // "enabled" has MaxConns: 2

	conns := make([]net.Conn, 0, 3)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < 2; i++ {
		c, peer := net.Pipe()
		conns = append(conns, c, peer)
		if err := r.AddConnection("enabled", c); err != nil {
			t.Fatalf("connection %d rejected below the limit: %v", i+1, err)
		}
	}

	third, peer := net.Pipe()
	conns = append(conns, third, peer)
	err := r.AddConnection("enabled", third)
	if err == nil {
		t.Fatal("third connection accepted despite MaxConns=2")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("err = %q, want it to mention the limit", err)
	}

	// MaxConns 0 means unlimited: the disabled entry has no limit set, and the
	// registry must not treat 0 as "no connections allowed".
	for i := 0; i < 5; i++ {
		c, p := net.Pipe()
		conns = append(conns, c, p)
		if err := r.AddConnection("disabled", c); err != nil {
			t.Fatalf("MaxConns=0 must mean unlimited, connection %d rejected: %v", i+1, err)
		}
	}

	// An unknown client is rejected outright rather than tracked.
	unknown, p := net.Pipe()
	conns = append(conns, unknown, p)
	if err := r.AddConnection("ghost", unknown); err == nil {
		t.Error("AddConnection accepted an unregistered client")
	}
}

// TestClientRegistryRemoveClient covers the deletion path Redis "del" events
// drive: the client must vanish from both indexes AND its live connections must
// be torn down, otherwise a revoked secret keeps working until the peer
// disconnects on its own.
func TestClientRegistryRemoveClient(t *testing.T) {
	r := newPopulatedRegistry(t)

	server, client := net.Pipe()
	defer client.Close()
	if err := r.AddConnection("enabled", server); err != nil {
		t.Fatalf("AddConnection: %v", err)
	}

	r.removeClient("enabled")

	if got := r.GetByID("enabled"); got != nil {
		t.Errorf("GetByID after removal = %+v, want nil", got)
	}
	if got := r.GetBySecret("secret-enabled"); got != nil {
		t.Errorf("GetBySecret after removal = %+v, want nil (revoked secret still resolves)", got)
	}
	if got := r.GetActiveConns("enabled"); got != 0 {
		t.Errorf("active connections after removal = %d, want 0", got)
	}
	if got := r.ClientCount(); got != 2 {
		t.Errorf("ClientCount = %d, want 2", got)
	}

	// The connection was closed, so the peer's read ends immediately rather
	// than blocking.
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("connection of a removed client is still open")
	}

	// Removing a client that is not registered must be harmless.
	r.removeClient("ghost")
	r.removeClient("enabled")
	if got := r.ClientCount(); got != 2 {
		t.Errorf("ClientCount = %d after redundant removals, want 2", got)
	}
}

// TestClientRegistryStop confirms Stop closes the reload channel exactly once
// so the poll goroutine exits; a second Stop is a programming error and is not
// exercised here (it would panic on a closed channel, by design).
func TestClientRegistryStop(t *testing.T) {
	r := NewClientRegistry(nil)
	r.Stop()

	select {
	case <-r.stopReload:
	default:
		t.Error("Stop did not close stopReload; the poll goroutine would leak")
	}
}
