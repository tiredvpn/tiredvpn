package server

import (
	"net"
	"testing"
	"time"
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

// An auto-allocated (dynamic) lease must always carry a finite TTL even when the
// pool is configured permanent (LeaseTime == 0), otherwise the disconnect path
// (which never calls Release) leaks the pool. CleanupExpired must reclaim it
// once the TTL has passed.
func TestDynamicLeaseExpiresViaTTL(t *testing.T) {
	p := newTestPool(t)

	ip, err := p.Allocate("ephemeral-client", net.IPv4zero, "")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	lease := p.GetLease(ip)
	if lease == nil {
		t.Fatalf("no lease recorded for %s", ip)
	}
	if lease.ExpiresAt.IsZero() {
		t.Fatalf("dynamic lease for %s is permanent (zero ExpiresAt) - pool will leak", ip)
	}
	if got := time.Until(lease.ExpiresAt); got <= 0 || got > dynamicLeaseTTL+time.Minute {
		t.Fatalf("unexpected TTL for dynamic lease: %v (want ~%v)", got, dynamicLeaseTTL)
	}

	// Force the lease past its TTL and confirm CleanupExpired reclaims it.
	lease.ExpiresAt = time.Now().Add(-time.Second)
	if cleaned := p.CleanupExpired(); cleaned != 1 {
		t.Fatalf("CleanupExpired reclaimed %d leases, want 1", cleaned)
	}
	if p.GetLease(ip) != nil {
		t.Fatalf("lease %s still present after cleanup", ip)
	}
	if got := p.GetClientIP("ephemeral-client"); got != nil {
		t.Fatalf("client mapping survived cleanup: %s", got)
	}
}

// Reconnect within the lease TTL must return the SAME IP (sticky), and it must
// not be reclaimed by CleanupExpired while still valid. This guards the ccd8d1e
// non-flapping behavior against the TTL change.
func TestStickyReconnectWithinTTL(t *testing.T) {
	p := newTestPool(t)
	cid := "reality:cafef00d"

	first, err := p.Allocate(cid, net.IPv4zero, "")
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}

	// A cleanup pass on a still-valid lease must NOT reclaim it.
	if cleaned := p.CleanupExpired(); cleaned != 0 {
		t.Fatalf("CleanupExpired reclaimed a still-valid lease (%d)", cleaned)
	}

	again, err := p.Allocate(cid, net.IPv4zero, "")
	if err != nil {
		t.Fatalf("reconnect allocate: %v", err)
	}
	if !again.Equal(first) {
		t.Fatalf("sticky reconnect flapped: %s -> %s", first, again)
	}
}

// A requested IP already held by a different client must never be handed out a
// second time; the second client gets a distinct auto-allocated IP.
func TestRequestedIPCollisionNoDoubleAllocation(t *testing.T) {
	p := newTestPool(t)
	req := net.ParseIP("10.8.0.50")

	a, err := p.Allocate("owner", req, "")
	if err != nil || !a.Equal(req) {
		t.Fatalf("owner allocate: ip=%s err=%v", a, err)
	}

	b, err := p.Allocate("intruder", req, "")
	if err != nil {
		t.Fatalf("intruder allocate: %v", err)
	}
	if b.Equal(a) {
		t.Fatalf("double allocation: intruder got owner's IP %s", a)
	}

	// Owner still owns its IP after the collision.
	if got := p.GetClientIP("owner"); got == nil || !got.Equal(req) {
		t.Fatalf("owner lost its IP after collision: %s", got)
	}
}

// An out-of-network requested IP must be ignored in favor of a valid in-network
// auto-allocation rather than being handed back verbatim.
func TestRequestedIPOutOfNetworkFallsBack(t *testing.T) {
	p := newTestPool(t)
	bad := net.ParseIP("192.168.99.5") // outside 10.8.0.0/24

	got, err := p.Allocate("client-x", bad, "")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if !p.network.Contains(got) {
		t.Fatalf("out-of-network IP %s honored; expected in-network auto-allocation", got)
	}
}
