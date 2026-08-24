package server

import (
	"errors"
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

func newDualStackTestPool(t *testing.T) *IPPool {
	t.Helper()
	p, err := NewIPPool(IPPoolConfig{
		Network:   "10.8.0.0/24",
		ServerIP:  "10.8.0.1",
		NetworkV6: "fd00:10:8::/64",
	}, nil)
	if err != nil {
		t.Fatalf("NewIPPool dual-stack: %v", err)
	}
	return p
}

// A pool without -ip-pool-v6 must stay strictly IPv4: no v6 methods return
// anything and behavior is unchanged.
func TestPoolV4OnlyNoDualStack(t *testing.T) {
	p := newTestPool(t)
	if p.DualStack() {
		t.Fatal("v4-only pool reports DualStack()")
	}
	c6, err := p.ClientIP6(net.IPv4(10, 8, 0, 2))
	if err != nil {
		t.Fatalf("v4-only pool ClientIP6: unexpected error %v", err)
	}
	if p.V6Prefix() != nil || p.ServerIP6() != nil || c6 != nil {
		t.Fatal("v4-only pool returned v6 addresses")
	}
}

// The derivation rule: server = prefix::1, client = prefix with its v4 lease
// embedded in the low 32 bits.
func TestDualStackDerivation(t *testing.T) {
	p := newDualStackTestPool(t)
	if !p.DualStack() {
		t.Fatal("dual-stack pool reports !DualStack()")
	}

	if got := p.ServerIP6().String(); got != "fd00:10:8::1" {
		t.Errorf("ServerIP6 = %s, want fd00:10:8::1", got)
	}

	client4 := net.IPv4(10, 8, 0, 2)
	c6, err := p.ClientIP6(client4)
	if err != nil {
		t.Fatalf("ClientIP6: %v", err)
	}
	if got, want := c6.String(), "fd00:10:8::a08:2"; got != want {
		t.Errorf("ClientIP6 = %s, want %s", got, want)
	}

	// Round-trip: the dispatcher recovers the v4 lease key from the low 32
	// bits of the derived v6 address.
	if got := net.IP(c6[12:16]); !got.Equal(client4.To4()) {
		t.Errorf("round-trip v4 = %s, want %s", got, client4)
	}

	// Prefix membership and injectivity across distinct v4 leases.
	other, err := p.ClientIP6(net.IPv4(10, 8, 0, 99))
	if err != nil {
		t.Fatalf("ClientIP6 (second lease): %v", err)
	}
	if !p.V6Prefix().Contains(c6) || !p.V6Prefix().Contains(other) {
		t.Error("derived client addresses must lie inside the pool prefix")
	}
	if c6.Equal(other) {
		t.Error("distinct v4 leases must derive distinct v6 addresses")
	}
}

// The handshake seam (deriveDualStackAddrs) and the pool must agree
// bit-for-bit — one derivation rule, two entry points.
func TestDualStackPoolMatchesHandshakeDerivation(t *testing.T) {
	p := newDualStackTestPool(t)
	d := deriveDualStackAddrs("fd00:10:8::/64", hsClientIP)
	if d == nil {
		t.Fatal("deriveDualStackAddrs returned nil for a valid pool")
	}
	if !d.ServerIP6.Equal(p.ServerIP6()) {
		t.Errorf("server6 mismatch: handshake=%s pool=%s", d.ServerIP6, p.ServerIP6())
	}
	poolClient6, err := p.ClientIP6(hsClientIP)
	if err != nil {
		t.Fatalf("pool ClientIP6: %v", err)
	}
	if !d.ClientIP6.Equal(poolClient6) {
		t.Errorf("client6 mismatch: handshake=%s pool=%s", d.ClientIP6, poolClient6)
	}
}

// Prefixes whose host part cannot hold a 32-bit v4 address, non-CIDRs and
// IPv4 CIDRs must be rejected at pool construction (fails server startup).
func TestDualStackInvalidPrefixRejected(t *testing.T) {
	for _, bad := range []string{
		"fd00:10:8::/97",  // <32 host bits
		"fd00:10:8::/128", // <32 host bits
		"not-a-cidr",
		"10.8.0.0/24", // IPv4 CIDR
	} {
		_, err := NewIPPool(IPPoolConfig{
			Network:   "10.8.0.0/24",
			ServerIP:  "10.8.0.1",
			NetworkV6: bad,
		}, nil)
		if err == nil {
			t.Errorf("NetworkV6 %q: expected error, got nil", bad)
		}
	}

	// /96 is the longest valid prefix (exactly 32 host bits).
	if _, err := NewIPPool(IPPoolConfig{
		Network:   "10.8.0.0/24",
		ServerIP:  "10.8.0.1",
		NetworkV6: "fd00:10:8:1:2:3::/96",
	}, nil); err != nil {
		t.Errorf("/96 prefix should be accepted: %v", err)
	}
}

// The in-tunnel v6 pool is NAT66'd private space, so only ULA (fc00::/7)
// prefixes are accepted. Everything else — global unicast, link-local,
// multicast, and the ::/N block whose server address would land on ::1 — must
// fail at pool construction, i.e. at server startup.
func TestDualStackNonULAPrefixRejected(t *testing.T) {
	for _, bad := range []string{
		"2001:db8:1::/64", // documentation / global unicast
		"2000::/3",        // global unicast block
		"fe80::/64",       // link-local
		"ff00::/8",        // multicast
		"::/64",           // unspecified/loopback-adjacent: server would be ::1
		"::/0",            // catch-all
		"fb00::/8",        // one bit below the ULA block
		"fe00::/8",        // one bit above the ULA block
	} {
		if _, err := parsePoolV6(bad); err == nil {
			t.Errorf("parsePoolV6(%q): expected rejection, got nil", bad)
		}
		if _, err := NewIPPool(IPPoolConfig{
			Network:   "10.8.0.0/24",
			ServerIP:  "10.8.0.1",
			NetworkV6: bad,
		}, nil); err == nil {
			t.Errorf("NetworkV6 %q: expected error, got nil", bad)
		}
	}

	// Both halves of fc00::/7 stay valid.
	for _, ok := range []string{"fc00::/64", "fd00:10:8::/64", "fdff:ffff:ffff:ffff::/64"} {
		if _, err := parsePoolV6(ok); err != nil {
			t.Errorf("parsePoolV6(%q): unexpected error %v", ok, err)
		}
	}
}

// prefix::1 belongs to the server (deriveServerIP6) and prefix:: is the
// subnet-router anycast address; neither may ever be handed to a client, and
// the caller must see an error rather than a silently shared fallback.
func TestDeriveClientIP6RejectsReservedAddresses(t *testing.T) {
	p := newDualStackTestPool(t)

	for _, v4 := range []net.IP{
		net.IPv4(0, 0, 0, 1), // would derive fd00:10:8::1 == ServerIP6
		net.IPv4zero,         // would derive fd00:10:8:: (subnet-router anycast)
	} {
		got, err := p.ClientIP6(v4)
		if err == nil {
			t.Errorf("ClientIP6(%s) = %s, want reserved-address error", v4, got)
			continue
		}
		if !errors.Is(err, errReservedTunnelIP6) {
			t.Errorf("ClientIP6(%s): err = %v, want errReservedTunnelIP6", v4, err)
		}
		if got != nil {
			t.Errorf("ClientIP6(%s) returned %s alongside an error", v4, got)
		}
	}

	// A lease that is not IPv4 has no derivation at all: erroring keeps the
	// mapping injective instead of parking every such client on one address.
	if got, err := p.ClientIP6(net.ParseIP("fd00:10:8::5")); err == nil {
		t.Errorf("ClientIP6(v6 lease) = %s, want error", got)
	}
	if got, err := p.ClientIP6(nil); err == nil {
		t.Errorf("ClientIP6(nil) = %s, want error", got)
	}

	// Every address the v4 pool can actually hand out still derives a unique,
	// non-reserved v6 address.
	seen := make(map[string]string, 254)
	server6 := p.ServerIP6().String()
	for i := 2; i < 255; i++ {
		v4 := net.IPv4(10, 8, 0, byte(i))
		got, err := p.ClientIP6(v4)
		if err != nil {
			t.Fatalf("ClientIP6(%s): %v", v4, err)
		}
		if got.String() == server6 {
			t.Fatalf("ClientIP6(%s) collides with ServerIP6 %s", v4, server6)
		}
		if prev, dup := seen[got.String()]; dup {
			t.Fatalf("ClientIP6(%s) collides with lease %s at %s", v4, prev, got)
		}
		seen[got.String()] = v4.String()
	}
}

// Adding a v6 prefix must not perturb v4 allocation: sticky leases and
// auto-allocation behave exactly as in a v4-only pool.
func TestDualStackDoesNotChangeV4Allocation(t *testing.T) {
	p := newDualStackTestPool(t)
	ip, err := p.Allocate("dual-client", net.IPv4zero, "")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if !p.network.Contains(ip) {
		t.Fatalf("allocated %s outside %s", ip, p.network)
	}
	again, err := p.Allocate("dual-client", net.IPv4zero, "")
	if err != nil || !again.Equal(ip) {
		t.Fatalf("sticky lease flapped: %s -> %s (err=%v)", ip, again, err)
	}
}
