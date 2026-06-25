package server

import (
	"net"
	"testing"
)

func newTestPool(t *testing.T) *IPPool {
	t.Helper()
	p, err := NewIPPool(IPPoolConfig{
		Network:  "10.8.0.0/24",
		ServerIP: "10.8.0.1",
	}, nil) // nil redis -> in-memory only
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	return p
}

// A client that reconnects must always receive the same IP it was first given,
// even when it keeps sending its own auto/requested IP. This is what stops the
// client TUN address (and L3 routes) from flapping on every reconnect.
func TestAllocateStickyByClient(t *testing.T) {
	p := newTestPool(t)
	cid := "reality:deadbeef"

	first, err := p.Allocate(cid, net.IPv4zero, "")
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}

	for i := 0; i < 5; i++ {
		got, err := p.Allocate(cid, net.IPv4zero, "")
		if err != nil {
			t.Fatalf("reconnect %d allocate: %v", i, err)
		}
		if !got.Equal(first) {
			t.Fatalf("reconnect %d: IP flapped %s -> %s", i, first, got)
		}
	}
}

// Distinct clients must never collide on the same IP.
func TestAllocateNoCollision(t *testing.T) {
	p := newTestPool(t)
	a, _ := p.Allocate("client-a", net.IPv4zero, "")
	b, _ := p.Allocate("client-b", net.IPv4zero, "")
	if a.Equal(b) {
		t.Fatalf("two clients got the same IP: %s", a)
	}
}

// A free, in-network requested IP (-tun-ip) should be honored.
func TestAllocateRespectsRequestedIP(t *testing.T) {
	p := newTestPool(t)
	req := net.ParseIP("10.8.0.42")
	got, err := p.Allocate("client-c", req, "")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if !got.Equal(req) {
		t.Fatalf("requested %s, got %s", req, got)
	}
	// And it stays sticky on reconnect.
	again, _ := p.Allocate("client-c", req, "")
	if !again.Equal(req) {
		t.Fatalf("requested IP not sticky: %s -> %s", req, again)
	}
}
