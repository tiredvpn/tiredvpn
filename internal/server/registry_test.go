package server

import (
	"context"
	"net"
	"testing"
)

// TestClientRegistry_SwapConn verifies that SwapConn replaces a stored
// connection pointer without affecting the active-connections counter.
// This is needed by handlers that hand the socket over to kTLS after
// AddConnection has already registered the original *tls.Conn.
func TestClientRegistry_SwapConn(t *testing.T) {
	r := NewClientRegistry(nil)
	r.byID["c1"] = &ClientConfig{ID: "c1", MaxConns: 5}

	a, _ := net.Pipe()
	b, _ := net.Pipe()
	defer a.Close()
	defer b.Close()

	if err := r.AddConnection("c1", a); err != nil {
		t.Fatalf("AddConnection: %v", err)
	}
	if got := r.GetActiveConns("c1"); got != 1 {
		t.Fatalf("active=%d, want 1 after AddConnection", got)
	}

	r.SwapConn("c1", a, b)

	if got := r.GetActiveConns("c1"); got != 1 {
		t.Fatalf("active=%d, want 1 after SwapConn (counter must not change)", got)
	}

	r.RemoveConnection("c1", b)
	if got := r.GetActiveConns("c1"); got != 0 {
		t.Fatalf("active=%d, want 0 after RemoveConnection on swapped conn", got)
	}
}

// TestClientRegistry_SwapConn_NoMatch confirms SwapConn is a no-op when
// the old connection is not stored — must not corrupt counters.
func TestClientRegistry_SwapConn_NoMatch(t *testing.T) {
	r := NewClientRegistry(nil)
	r.byID["c1"] = &ClientConfig{ID: "c1", MaxConns: 5}

	a, _ := net.Pipe()
	b, _ := net.Pipe()
	c, _ := net.Pipe()
	defer a.Close()
	defer b.Close()
	defer c.Close()

	r.AddConnection("c1", a)
	r.SwapConn("c1", b, c) // b is not stored, swap should no-op

	if got := r.GetActiveConns("c1"); got != 1 {
		t.Fatalf("active=%d, want 1 (unchanged)", got)
	}
}

// TestRegistryGenerationMovesOnEveryChange: the B1 gate's index compares it
// to tell that a client was added, changed or removed (P3-2 of the round-5
// review). Each of the three ways the client set changes must move it.
func TestRegistryGenerationMovesOnEveryChange(t *testing.T) {
	rdb := startRedis(t)
	store, err := NewRedisStore(rdb.Options().Addr, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg, err := store.CreateClient(ctx, "carol", "", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := NewClientRegistry(store)
	for _, step := range []struct {
		name string
		do   func()
	}{
		{"reload", func() { _ = r.reload(ctx) }},
		{"reloadClient", func() { r.reloadClient(ctx, cfg.ID) }},
		{"removeClient", func() { r.removeClient(cfg.ID) }},
	} {
		before := r.Generation()
		step.do()
		if r.Generation() == before {
			t.Fatalf("%s left the generation at %d", step.name, before)
		}
	}
}
