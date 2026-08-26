package tun

import (
	"net"
	"testing"
)

// TestDeriveClientIP6Injective sweeps a whole /24 pool. The exit hands every
// client a distinct IPv4 and derives its IPv6 from it, so two clients sharing a
// derived v6 would share a tunnel address: their traffic collides and one of
// them is silently unreachable over v6 while v4 keeps working. The mapping is
// the only thing preventing that, so it is checked over the entire pool rather
// than at a couple of sample points.
func TestDeriveClientIP6Injective(t *testing.T) {
	base := net.ParseIP("fd00:10:8::")
	seen := make(map[string]net.IP, 256)

	for i := range 256 {
		v4 := net.IPv4(10, 8, 0, byte(i))
		got := deriveClientIP6(base, v4)
		if got == nil {
			t.Fatalf("deriveClientIP6(%s, %s) = nil", base, v4)
		}
		if prev, dup := seen[got.String()]; dup {
			t.Fatalf("%s and %s both derive to %s", prev, v4, got)
		}
		seen[got.String()] = v4

		// The prefix is the pool's; only the last 4 bytes carry the v4.
		if !got[:12].Equal(base.To16()[:12]) {
			t.Errorf("deriveClientIP6(%s) = %s, prefix drifted from %s", v4, got, base)
		}
		if !net.IP(got[12:16]).Equal(v4.To4()) {
			t.Errorf("deriveClientIP6(%s) = %s, suffix is not the v4 address", v4, got)
		}
	}

	if len(seen) != 256 {
		t.Errorf("derived %d distinct addresses from 256 inputs", len(seen))
	}
}

// TestDeriveClientIP6PreservesPrefix checks the reassignment case the function
// exists for: after the exit moves a client to a new v4, the v6 must stay
// inside the same pool prefix. A derived address outside the pool is not
// masqueraded by the NAT66 rules, so it leaves the exit unmasqueraded, is a
// ULA, and nothing ever comes back.
func TestDeriveClientIP6PreservesPrefix(t *testing.T) {
	_, pool, err := net.ParseCIDR("fd00:10:8::/64")
	if err != nil {
		t.Fatal(err)
	}
	old6 := net.ParseIP("fd00:10:8::a08:2")

	for _, v4 := range []string{"10.8.0.3", "10.8.0.254", "10.8.1.1", "172.16.0.1"} {
		got := deriveClientIP6(old6, net.ParseIP(v4))
		if got == nil {
			t.Fatalf("deriveClientIP6(%s, %s) = nil", old6, v4)
		}
		if !pool.Contains(got) {
			t.Errorf("deriveClientIP6(%s) = %s, outside pool %s", v4, got, pool)
		}
	}
}

// TestDeriveClientIP6RejectsBadInput covers the argument shapes that must not
// produce an address. A v6 built from a v4-mapped or otherwise wrong input
// would be installed on the link and routed to, with no way to notice from the
// client side.
func TestDeriveClientIP6RejectsBadInput(t *testing.T) {
	old6 := net.ParseIP("fd00:10:8::a08:2")

	for _, tc := range []struct {
		name       string
		old6, newV net.IP
	}{
		{"nil v6", nil, net.ParseIP("10.8.0.9")},
		{"nil v4", old6, nil},
		{"v4 in the v6 slot", net.ParseIP("10.8.0.2"), net.ParseIP("10.8.0.9")},
		{"v6 in the v4 slot", old6, net.ParseIP("fd00:10:8::9")},
		{"empty v6", net.IP{}, net.ParseIP("10.8.0.9")},
		{"empty v4", old6, net.IP{}},
		{"malformed v6 length", net.IP{1, 2, 3}, net.ParseIP("10.8.0.9")},
		{"malformed v4 length", old6, net.IP{1, 2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveClientIP6(tc.old6, tc.newV); got != nil {
				t.Errorf("deriveClientIP6 = %s, want nil", got)
			}
		})
	}
}

// TestDeriveClientIP6DoesNotAliasInput checks that the result is a fresh
// address. The caller keeps the old v6 around to withdraw it from the link
// after the new one is installed; aliasing the backing array would have the
// withdrawal target the new address instead.
func TestDeriveClientIP6DoesNotAliasInput(t *testing.T) {
	old6 := net.ParseIP("fd00:10:8::a08:2")
	before := old6.String()

	got := deriveClientIP6(old6, net.ParseIP("10.8.0.9"))
	if got == nil {
		t.Fatal("deriveClientIP6 = nil")
	}
	got[15] = 0xff
	if old6.String() != before {
		t.Errorf("input mutated to %s, was %s", old6, before)
	}
}

// TestDualStackAddrPlanFormsDiffer pins that the two forms are distinguishable.
// EnableDualStack records which one the kernel accepted and every later
// operation matches on it, so if the fallback were shaped like the peer form a
// delete would match the wrong address: the stale one survives a lease change
// and the replacement add collides with it.
func TestDualStackAddrPlanFormsDiffer(t *testing.T) {
	client6 := net.ParseIP("fd00:10:8::a08:2")
	server6 := net.ParseIP("fd00:10:8::1")

	p2pLocal, p2pPeer, fallback, err := dualStackAddrPlan(client6, server6)
	if err != nil {
		t.Fatalf("dualStackAddrPlan: %v", err)
	}

	if p2pLocal.String() == fallback.String() {
		t.Fatalf("peer and fallback forms are identical: %s", fallback)
	}
	if ones, bits := p2pLocal.Mask.Size(); ones != 128 || bits != 128 {
		t.Errorf("p2p local mask = /%d (of %d), want /128", ones, bits)
	}
	if ones, bits := fallback.Mask.Size(); ones != 64 || bits != 128 {
		t.Errorf("fallback mask = /%d (of %d), want /64", ones, bits)
	}
	// Both local forms carry the client address; only the peer is the server.
	if !p2pLocal.IP.Equal(client6) || !fallback.IP.Equal(client6) {
		t.Errorf("local forms = %s / %s, want both to carry %s", p2pLocal.IP, fallback.IP, client6)
	}
	if !p2pPeer.IP.Equal(server6) {
		t.Errorf("peer = %s, want %s", p2pPeer.IP, server6)
	}
	// The /64 fallback has to cover the peer, otherwise the client has no
	// on-link route to the exit once the peer form is unavailable.
	if !fallback.Contains(server6) {
		t.Errorf("fallback %s does not cover the server %s", fallback, server6)
	}
}

// TestDualStackAddrPlanRejectsBadInput covers the inputs that must not yield a
// plan. These addresses come straight off the handshake wire, so a malformed
// or v4 address reaching the link configuration is a live possibility rather
// than a theoretical one.
func TestDualStackAddrPlanRejectsBadInput(t *testing.T) {
	client6 := net.ParseIP("fd00:10:8::a08:2")
	server6 := net.ParseIP("fd00:10:8::1")

	for _, tc := range []struct {
		name           string
		client, server net.IP
	}{
		{"both nil", nil, nil},
		{"empty client", net.IP{}, server6},
		{"empty server", client6, net.IP{}},
		{"malformed client length", net.IP{1, 2, 3}, server6},
		{"malformed server length", client6, net.IP{1, 2, 3}},
		// A v4-mapped address has a 16-byte representation, so it survives
		// To16() and only the To4() check catches it.
		{"v4-mapped client", net.ParseIP("::ffff:10.8.0.2"), server6},
		{"v4-mapped server", client6, net.ParseIP("::ffff:10.8.0.1")},
		{"4-byte v4 client", net.IPv4(10, 8, 0, 2).To4(), server6},
		{"4-byte v4 server", client6, net.IPv4(10, 8, 0, 1).To4()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, peer, fallback, err := dualStackAddrPlan(tc.client, tc.server)
			if err == nil {
				t.Fatalf("accepted bad input: %s / %s / %s", local, peer, fallback)
			}
			if local != nil || peer != nil || fallback != nil {
				t.Errorf("error path returned non-nil nets: %v / %v / %v", local, peer, fallback)
			}
		})
	}
}

// TestDualStackAddrPlanDoesNotAliasInput guards against the plan sharing
// backing arrays with the caller's addresses. All three nets are handed to
// netlink separately; a shared array means editing one edits the others.
func TestDualStackAddrPlanDoesNotAliasInput(t *testing.T) {
	client6 := net.ParseIP("fd00:10:8::a08:2")
	server6 := net.ParseIP("fd00:10:8::1")

	p2pLocal, _, fallback, err := dualStackAddrPlan(client6, server6)
	if err != nil {
		t.Fatalf("dualStackAddrPlan: %v", err)
	}
	// The two local forms must not be the same slice: they differ only in
	// mask, and masking one in place would corrupt the other.
	if ones, _ := p2pLocal.Mask.Size(); ones != 128 {
		t.Fatalf("precondition: p2p local is not a /128")
	}
	if ones, _ := fallback.Mask.Size(); ones != 64 {
		t.Fatalf("precondition: fallback is not a /64")
	}
	if &p2pLocal.Mask[0] == &fallback.Mask[0] {
		t.Error("the two forms share one mask array")
	}
}

// TestDualStackRouteNetsRejectsBadCIDR exercises the guard on the route
// constants. The list is compiled in, so this can only fire after somebody
// edits it — which is exactly when a silent nil route slice would install no
// IPv6 routes at all and leave the tunnel v4-only with no error anywhere.
func TestDualStackRouteNetsRejectsBadCIDR(t *testing.T) {
	saved := dualStackRouteCIDRs
	t.Cleanup(func() { dualStackRouteCIDRs = saved })

	dualStackRouteCIDRs = []string{"::/1", "not-a-cidr"}
	nets, err := dualStackRouteNets()
	if err == nil {
		t.Fatalf("bad CIDR accepted: %v", nets)
	}
	if nets != nil {
		t.Errorf("error path returned %v, want nil", nets)
	}
}

// TestV6HalfDefaultPriorityDistinctPerLink checks the property the metric
// exists for: two tunnels on the same host must not produce the same
// (destination, metric) pair, because that is one kernel routing entry and the
// second tunnel's install would take it over from the first — leaving the first
// with a v6 address and no route the moment the second one goes away.
func TestV6HalfDefaultPriorityDistinctPerLink(t *testing.T) {
	seen := make(map[int]int, 64)
	for idx := 1; idx <= 64; idx++ {
		p := v6HalfDefaultPriority(idx)
		if p == 0 {
			t.Fatalf("linkIndex %d: priority 0 leaves the kernel default (1024), which collides", idx)
		}
		if p < v6HalfDefaultMetricBase {
			t.Errorf("linkIndex %d: priority %d is below the base %d, so a foreign ::/1 could outrank us",
				idx, p, v6HalfDefaultMetricBase)
		}
		if prev, dup := seen[p]; dup {
			t.Errorf("linkIndex %d and %d share priority %d", prev, idx, p)
		}
		seen[p] = idx
	}

	// The earlier-started tunnel has the lower index and must win.
	if v6HalfDefaultPriority(3) >= v6HalfDefaultPriority(9) {
		t.Errorf("lower link index must get the lower (better) metric: %d vs %d",
			v6HalfDefaultPriority(3), v6HalfDefaultPriority(9))
	}

	// A metric below the base would let another VPN's kernel-default ::/1 or a
	// hand-added low-metric route beat ours; the guard clamps instead.
	if got := v6HalfDefaultPriority(-1); got != v6HalfDefaultMetricBase {
		t.Errorf("v6HalfDefaultPriority(-1) = %d, want the base %d", got, v6HalfDefaultMetricBase)
	}

	// The base has to beat the kernel default another VPN's half-default gets,
	// or a full tunnel stops being full.
	if v6HalfDefaultMetricBase >= 1024 {
		t.Errorf("base %d does not outrank the kernel default 1024", v6HalfDefaultMetricBase)
	}
}

// TestDualStackRouteNetsCoverAddressSpace checks the property the two
// half-defaults exist for: together they cover every address a client can
// reach, while each is a /1 and so outranks an RA-learned ::/0 on prefix
// length. A blanket ::/0 here would replace the host's own default route
// instead of outranking it, and removing it on teardown would leave the host
// with no IPv6 at all.
func TestDualStackRouteNetsCoverAddressSpace(t *testing.T) {
	nets, err := dualStackRouteNets()
	if err != nil {
		t.Fatalf("dualStackRouteNets: %v", err)
	}

	for _, addr := range []string{
		"2001:db8::1",          // documentation
		"2606:4700:4700::1111", // a real public resolver
		"fd00:10:8::1",         // ULA, the tunnel's own pool
		"fe80::1",              // link-local
		"::1",                  // loopback
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // the top of the space
		"8000::", // the boundary between the two halves
		"7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // just below it
	} {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("bad test address %q", addr)
		}
		covered := 0
		for _, dst := range nets {
			if dst.Contains(ip) {
				covered++
			}
		}
		if covered != 1 {
			t.Errorf("%s is covered by %d of the half-defaults, want exactly 1", addr, covered)
		}
	}
}
