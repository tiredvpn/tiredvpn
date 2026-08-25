package server

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestDeriveClientIP6InjectiveAcrossPrefixSizes is the property the downlink
// dispatcher depends on: for any prefix, distinct IPv4 leases derive distinct
// IPv6 addresses, every derived address lies inside the prefix, and the low 32
// bits recover the lease exactly. If two leases ever collided the dispatcher
// would deliver one client's IPv6 traffic to another.
func TestDeriveClientIP6InjectiveAcrossPrefixSizes(t *testing.T) {
	prefixes := []string{
		"fd00:10:8::/64",
		"fc00::/7",
		"fd12:3456:789a:bcde::/64",
		"fd00:10:8:1:2:3::/96", // the tightest prefix that still fits a v4 host part
		"fdff:ffff:ffff:ffff:ffff:ffff::/96",
	}

	for _, cidr := range prefixes {
		t.Run(cidr, func(t *testing.T) {
			prefix, err := parsePoolV6(cidr)
			if err != nil {
				t.Fatalf("parsePoolV6(%q): %v", cidr, err)
			}
			server6 := deriveServerIP6(prefix)

			// Walk the whole allocatable range of a /24 v4 pool.
			seen := make(map[string]string, 254)
			for i := 2; i < 255; i++ {
				v4 := net.IPv4(10, 8, 0, byte(i))
				got, err := deriveClientIP6(prefix, v4)
				if err != nil {
					t.Fatalf("deriveClientIP6(%s): %v", v4, err)
				}
				if !prefix.Contains(got) {
					t.Fatalf("derived %s for lease %s falls outside %s", got, v4, prefix)
				}
				if got.Equal(server6) {
					t.Fatalf("lease %s derives the server's own address %s", v4, server6)
				}
				if prev, dup := seen[got.String()]; dup {
					t.Fatalf("leases %s and %s both derive %s", prev, v4, got)
				}
				seen[got.String()] = v4.String()

				// Reverse lookup: the dispatcher reads the v4 lease key back
				// out of the low 32 bits.
				if back := net.IP(got[12:16]); !back.Equal(v4.To4()) {
					t.Fatalf("round-trip of %s gave %s", v4, back)
				}
			}
			if len(seen) != 253 {
				t.Errorf("derived %d distinct addresses, want 253", len(seen))
			}
		})
	}
}

// TestDeriveClientIP6NeverYieldsPrefixOne guards the one address the server
// keeps for itself. prefix::1 is the tunnel gateway on every client's routing
// table; handing it to a client would put two peers on one address and black
// hole the gateway.
func TestDeriveClientIP6NeverYieldsPrefixOne(t *testing.T) {
	for _, cidr := range []string{"fd00:10:8::/64", "fc00::/7", "fd00:10:8:1:2:3::/96"} {
		prefix, err := parsePoolV6(cidr)
		if err != nil {
			t.Fatalf("parsePoolV6(%q): %v", cidr, err)
		}
		server6 := deriveServerIP6(prefix).String()

		// The only v4 value that could derive prefix::1 is 0.0.0.1, and it is
		// rejected; sweep the rest of the low byte space to confirm nothing
		// else lands there.
		for a := 0; a < 256; a += 37 {
			for d := 0; d < 256; d++ {
				v4 := net.IPv4(byte(a), 0, 0, byte(d))
				got, err := deriveClientIP6(prefix, v4)
				if err != nil {
					continue // reserved derivations are rejected, which is the point
				}
				if got.String() == server6 {
					t.Fatalf("%s: lease %s derives the server address %s", cidr, v4, server6)
				}
			}
		}
	}
}

// TestDeriveClientIP6ReservedErrorIdentity pins the error identity, not just
// its presence: callers (the handshake seam, the pool) branch on
// errors.Is(err, errReservedTunnelIP6) to degrade the session to IPv4-only
// rather than abort it, so a wrapped-away sentinel would turn a recoverable
// collision into a failed connect.
func TestDeriveClientIP6ReservedErrorIdentity(t *testing.T) {
	prefix, err := parsePoolV6("fd00:10:8::/64")
	if err != nil {
		t.Fatalf("parsePoolV6: %v", err)
	}

	for _, v4 := range []net.IP{net.IPv4zero, net.IPv4(0, 0, 0, 1)} {
		got, err := deriveClientIP6(prefix, v4)
		if err == nil {
			t.Fatalf("deriveClientIP6(%s) = %s, want an error", v4, got)
		}
		if !errors.Is(err, errReservedTunnelIP6) {
			t.Errorf("deriveClientIP6(%s): err = %v, want errReservedTunnelIP6", v4, err)
		}
		if got != nil {
			t.Errorf("deriveClientIP6(%s) returned %s alongside its error", v4, got)
		}
	}

	// A non-IPv4 lease is a different failure: no derivation exists at all, so
	// it must NOT masquerade as the reserved-address case.
	_, err = deriveClientIP6(prefix, net.ParseIP("fd00:10:8::5"))
	if err == nil {
		t.Fatal("deriveClientIP6(v6 lease) = nil error, want an error")
	}
	if errors.Is(err, errReservedTunnelIP6) {
		t.Error("a non-IPv4 lease must not report itself as a reserved-address collision")
	}

	// The same identity has to survive the pool wrapper.
	p := newDualStackTestPool(t)
	if _, err := p.ClientIP6(net.IPv4(0, 0, 0, 1)); !errors.Is(err, errReservedTunnelIP6) {
		t.Errorf("IPPool.ClientIP6: err = %v, want errReservedTunnelIP6", err)
	}
}

// TestParsePoolV6PrefixLengthBoundary pins the /96 cutoff. /96 leaves exactly
// the 32 host bits a client's IPv4 address needs; /97 leaves 31, which would
// silently truncate the embedded lease and break the reverse lookup, so it must
// be rejected at parse time rather than produce colliding addresses later.
func TestParsePoolV6PrefixLengthBoundary(t *testing.T) {
	if _, err := parsePoolV6("fd00:10:8:1:2:3::/96"); err != nil {
		t.Errorf("/96 must be accepted (exactly 32 host bits): %v", err)
	}
	for _, tooLong := range []string{"fd00:10:8::/97", "fd00:10:8::/112", "fd00:10:8::1/128"} {
		if _, err := parsePoolV6(tooLong); err == nil {
			t.Errorf("parsePoolV6(%q) = nil, want rejection (<32 host bits)", tooLong)
		}
	}
	// Shorter prefixes are all fine, down to the ULA block itself.
	for _, ok := range []string{"fc00::/7", "fd00::/8", "fd00:10:8::/48", "fd00:10:8::/64", "fd00:10:8::/95"} {
		if _, err := parsePoolV6(ok); err != nil {
			t.Errorf("parsePoolV6(%q) = %v, want nil", ok, err)
		}
	}
}

// TestParsePoolV6EmptyIsNoDualStack pins the "" contract: no error and no
// prefix. NewIPPool passes the flag straight through, so returning an error
// here would make every IPv4-only server fail to start.
func TestParsePoolV6EmptyIsNoDualStack(t *testing.T) {
	prefix, err := parsePoolV6("")
	if err != nil {
		t.Errorf("parsePoolV6(\"\") = %v, want nil error", err)
	}
	if prefix != nil {
		t.Errorf("parsePoolV6(\"\") = %v, want nil prefix", prefix)
	}
}

// TestParsePoolV6MasksHostBits confirms the returned prefix is the masked
// network, not the address the operator typed. Derivation ORs the v4 lease into
// the low 32 bits, so leftover host bits in the prefix would corrupt every
// derived address.
func TestParsePoolV6MasksHostBits(t *testing.T) {
	prefix, err := parsePoolV6("fd00:10:8::dead:beef/64")
	if err != nil {
		t.Fatalf("parsePoolV6: %v", err)
	}
	if got := prefix.IP.String(); got != "fd00:10:8::" {
		t.Errorf("prefix IP = %s, want the masked network fd00:10:8::", got)
	}
	client6, err := deriveClientIP6(prefix, net.IPv4(10, 8, 0, 2))
	if err != nil {
		t.Fatalf("deriveClientIP6: %v", err)
	}
	if got := client6.String(); got != "fd00:10:8::a08:2" {
		t.Errorf("derived %s from an unmasked-looking prefix, want fd00:10:8::a08:2", got)
	}
}

// TestPoolClientIP6EmptyPoolNoError pins the (nil, nil) contract of the v4-only
// pool. Callers treat a non-nil error as "this lease has no v6 address" and log
// it; an IPv4-only server would then log a warning on every single connect.
func TestPoolClientIP6EmptyPoolNoError(t *testing.T) {
	p := newTestPool(t)
	for _, v4 := range []net.IP{
		net.IPv4(10, 8, 0, 2),
		net.IPv4zero,         // reserved on a dual-stack pool, irrelevant here
		net.IPv4(0, 0, 0, 1), // ditto
		nil,                  // no lease at all
		net.ParseIP("fd00::5"),
	} {
		got, err := p.ClientIP6(v4)
		if err != nil {
			t.Errorf("v4-only pool ClientIP6(%v) = %v, want nil error", v4, err)
		}
		if got != nil {
			t.Errorf("v4-only pool ClientIP6(%v) = %s, want nil", v4, got)
		}
	}
	if p.ServerIP6() != nil {
		t.Errorf("v4-only pool ServerIP6() = %s, want nil", p.ServerIP6())
	}
	if p.V6Prefix() != nil {
		t.Errorf("v4-only pool V6Prefix() = %v, want nil", p.V6Prefix())
	}
}

// TestDeriveServerIP6IsPrefixOne pins the single derivation rule the pool, the
// handshake and the TUN setup all share. If the three ever disagreed the client
// would install a default route toward an address the server does not answer on.
func TestDeriveServerIP6IsPrefixOne(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"fd00:10:8::/64", "fd00:10:8::1"},
		{"fc00::/7", "fc00::1"},
		{"fd12:3456::/32", "fd12:3456::1"},
		{"fd00:10:8:1:2:3::/96", "fd00:10:8:1:2:3:0:1"},
	}
	for _, tt := range tests {
		prefix, err := parsePoolV6(tt.cidr)
		if err != nil {
			t.Fatalf("parsePoolV6(%q): %v", tt.cidr, err)
		}
		if got := deriveServerIP6(prefix).String(); got != tt.want {
			t.Errorf("deriveServerIP6(%s) = %s, want %s", tt.cidr, got, tt.want)
		}
		// The pool wrapper must return the same address.
		p, err := NewIPPool(IPPoolConfig{Network: "10.8.0.0/24", ServerIP: "10.8.0.1", NetworkV6: tt.cidr}, nil)
		if err != nil {
			t.Fatalf("NewIPPool(%q): %v", tt.cidr, err)
		}
		if got := p.ServerIP6().String(); got != tt.want {
			t.Errorf("IPPool.ServerIP6() = %s, want %s", got, tt.want)
		}
	}
}

// TestPoolReleaseAndStats covers the allocate/release accounting. A lease that
// survives release leaks a pool slot on every reconnect, which on a /24 exhausts
// the pool within a day.
func TestPoolReleaseAndStats(t *testing.T) {
	p := newTestPool(t)

	total, used, available := p.Stats()
	if used != 0 || available != total {
		t.Fatalf("fresh pool: total=%d used=%d available=%d, want used=0", total, used, available)
	}

	ip, err := p.Allocate("release-client", net.IPv4zero, "")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if _, used, _ = p.Stats(); used != 1 {
		t.Errorf("after allocate: used=%d, want 1", used)
	}
	if leases := p.ListLeases(); len(leases) != 1 || leases[0].IP != ip.String() {
		t.Errorf("ListLeases = %+v, want the single lease for %s", leases, ip)
	}

	p.Release(ip)
	if _, used, available = p.Stats(); used != 0 || available != total {
		t.Errorf("after Release: used=%d available=%d, want 0/%d", used, available, total)
	}
	if p.GetLease(ip) != nil {
		t.Errorf("lease for %s survived Release", ip)
	}
	if leases := p.ListLeases(); len(leases) != 0 {
		t.Errorf("ListLeases = %+v after Release, want empty", leases)
	}

	// Releasing an IP that was never leased must be a silent no-op, not a panic
	// or a negative counter.
	p.Release(net.ParseIP("10.8.0.200"))
	p.Release(nil)
	if _, used, _ = p.Stats(); used != 0 {
		t.Errorf("used=%d after releasing unleased IPs, want 0", used)
	}
}

// TestPoolReleaseByClient covers the disconnect path, which knows the client ID
// rather than the address it was given.
func TestPoolReleaseByClient(t *testing.T) {
	p := newTestPool(t)

	ip, err := p.Allocate("bye-client", net.IPv4zero, "")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	// An unknown client must not disturb anybody else's lease.
	p.ReleaseByClient("never-connected")
	if p.GetLease(ip) == nil {
		t.Fatal("releasing an unknown client dropped an unrelated lease")
	}

	p.ReleaseByClient("bye-client")
	if p.GetLease(ip) != nil {
		t.Errorf("lease %s survived ReleaseByClient", ip)
	}
	if got := p.GetClientIP("bye-client"); got != nil {
		t.Errorf("client mapping survived ReleaseByClient: %s", got)
	}

	// Repeat calls stay harmless.
	p.ReleaseByClient("bye-client")
}

// TestPoolStaticLeaseNotReleased pins the exemption for statically assigned
// addresses (a client with a configured -tun-ip): releasing one would let the
// next client take a pinned address the operator handed out by hand.
func TestPoolStaticLeaseNotReleased(t *testing.T) {
	p := newTestPool(t)

	req := net.ParseIP("10.8.0.77")
	ip, err := p.Allocate("static-client", req, "static-host")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	lease := p.GetLease(ip)
	if lease == nil {
		t.Fatalf("no lease recorded for %s", ip)
	}
	if !lease.Static {
		t.Fatalf("a lease for an explicitly requested IP must be marked static: %+v", lease)
	}
	if lease.Hostname != "static-host" {
		t.Errorf("lease hostname = %q, want %q", lease.Hostname, "static-host")
	}

	p.Release(ip)
	if p.GetLease(ip) == nil {
		t.Error("static lease was released by Release")
	}
	p.ReleaseByClient("static-client")
	if p.GetLease(ip) == nil {
		t.Error("static lease was released by ReleaseByClient")
	}
}

// TestPoolListLeasesSkipsExpired confirms ListLeases reports live leases only.
// The API and the metrics both read this list, so an expired entry would show a
// client as connected long after it disappeared.
func TestPoolListLeasesSkipsExpired(t *testing.T) {
	p := newTestPool(t)

	live, err := p.Allocate("live-client", net.IPv4zero, "")
	if err != nil {
		t.Fatalf("allocate live: %v", err)
	}
	stale, err := p.Allocate("stale-client", net.IPv4zero, "")
	if err != nil {
		t.Fatalf("allocate stale: %v", err)
	}
	p.GetLease(stale).ExpiresAt = time.Now().Add(-time.Hour)

	leases := p.ListLeases()
	if len(leases) != 1 {
		t.Fatalf("ListLeases returned %d leases, want 1 (the expired one must be hidden)", len(leases))
	}
	if leases[0].IP != live.String() {
		t.Errorf("ListLeases returned %s, want the live lease %s", leases[0].IP, live)
	}
}
