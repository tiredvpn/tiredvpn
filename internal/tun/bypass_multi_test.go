//go:build linux

package tun

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func timeAfterShort() <-chan time.Time { return time.After(2 * time.Second) }

func ips(t *testing.T, addrs ...string) []net.IP {
	t.Helper()
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("bad test address %q", a)
		}
		out = append(out, ip)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRoutesCoverAnyIP is the gate that decides whether the bypass machinery
// runs at all. With a server list it has to answer for the whole set: checking
// only the endpoint currently in use leaves the SECOND server unpinned, and a
// full-tunnel dial to an unpinned address goes into the tunnel and dies there.
func TestRoutesCoverAnyIP(t *testing.T) {
	cases := []struct {
		name   string
		routes []string
		ips    []net.IP
		want   bool
	}{
		{"no addresses", []string{"0.0.0.0/0"}, nil, false},
		{"single covered", []string{"0.0.0.0/0"}, ips(t, "31.44.3.165"), true},
		{"single uncovered", []string{"10.8.0.0/24"}, ips(t, "31.44.3.165"), false},
		// The point of the multi-address form: one match is enough.
		{"second of two covered", []string{"128.0.0.0/1"},
			ips(t, "31.44.3.165", "203.0.113.9"), true},
		{"first of two covered", []string{"0.0.0.0/1"},
			ips(t, "31.44.3.165", "203.0.113.9"), true},
		{"neither covered", []string{"10.8.0.0/24"},
			ips(t, "31.44.3.165", "203.0.113.9"), false},
		{"half defaults cover both", []string{"0.0.0.0/1", "128.0.0.0/1"},
			ips(t, "31.44.3.165", "203.0.113.9"), true},
		{"v6 default vs mixed set", []string{"::/0"},
			ips(t, "31.44.3.165", "2001:db8::1"), true},
		{"v6 default vs v4-only set", []string{"::/0"},
			ips(t, "31.44.3.165", "203.0.113.9"), false},
		{"nil among real addresses", []string{"0.0.0.0/0"},
			[]net.IP{nil, net.ParseIP("31.44.3.165")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := routesCoverAnyIP(c.routes, c.ips); got != c.want {
				t.Errorf("routesCoverAnyIP(%v, %v) = %v, want %v",
					c.routes, ipStrings(c.ips), got, c.want)
			}
		})
	}
}

// TestSetServerBypassIPsKeepsTheWholeSet: every endpoint has to be recorded,
// because all of them are pinned at startup rather than at the moment the
// client switches - which is what removes the "switched but not yet pinned"
// race.
func TestSetServerBypassIPsKeepsTheWholeSet(t *testing.T) {
	d := &TUNDevice{}
	d.SetServerBypassIPs(ips(t, "31.44.3.165", "203.0.113.9", "2001:db8::1"))

	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"31.44.3.165", "203.0.113.9", "2001:db8::1"}) {
		t.Fatalf("bypassIPs = %v, want all three in order", got)
	}
	if got := ipStrings(d.bypassIPsFamily(false)); !sameStrings(got, []string{"31.44.3.165", "203.0.113.9"}) {
		t.Errorf("v4 set = %v, want both v4 addresses", got)
	}
	if got := ipStrings(d.bypassIPsFamily(true)); !sameStrings(got, []string{"2001:db8::1"}) {
		t.Errorf("v6 set = %v, want the single v6 address", got)
	}
}

func TestSetServerBypassIPsDropsNilAndDuplicates(t *testing.T) {
	d := &TUNDevice{}
	d.SetServerBypassIPs([]net.IP{
		net.ParseIP("31.44.3.165"),
		nil,
		net.ParseIP("31.44.3.165"),
		net.ParseIP("203.0.113.9"),
	})
	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"31.44.3.165", "203.0.113.9"}) {
		t.Fatalf("bypassIPs = %v, want the two distinct addresses", got)
	}
}

// TestLegacyBypassSettersCompose: the single-address setters are what macOS,
// the benchmarks and the older tests call. Each replaces its own family and
// leaves the other alone, which is exactly what the two fields they replaced
// did.
func TestLegacyBypassSettersCompose(t *testing.T) {
	d := &TUNDevice{}
	d.SetServerBypassIP(net.ParseIP("31.44.3.165"))
	d.SetServerBypassIP6(net.ParseIP("2001:db8::1"))

	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"31.44.3.165", "2001:db8::1"}) {
		t.Fatalf("bypassIPs = %v, want one address per family", got)
	}

	// Replacing v4 must not disturb v6.
	d.SetServerBypassIP(net.ParseIP("203.0.113.9"))
	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"2001:db8::1", "203.0.113.9"}) {
		t.Fatalf("after replacing v4: %v, want the v6 address kept", got)
	}

	// A v4 address handed to the v6 setter is ignored, as before: the v4 bypass
	// already covers it, and accepting it would install a /128 for a v4 host.
	d.SetServerBypassIP6(net.ParseIP("198.51.100.1"))
	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"2001:db8::1", "203.0.113.9"}) {
		t.Fatalf("a v4 address reached the v6 setter: %v", got)
	}

	// nil clears just that family.
	d.SetServerBypassIP(nil)
	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"2001:db8::1"}) {
		t.Fatalf("after clearing v4: %v, want only the v6 address", got)
	}
}

// TestSetServerBypassIPsReplacesEverything guards the plural setter against
// accumulating stale endpoints across a config reload.
func TestSetServerBypassIPsReplacesEverything(t *testing.T) {
	d := &TUNDevice{}
	d.SetServerBypassIPs(ips(t, "31.44.3.165", "2001:db8::1"))
	d.SetServerBypassIPs(ips(t, "203.0.113.9"))
	if got := ipStrings(d.bypassIPs()); !sameStrings(got, []string{"203.0.113.9"}) {
		t.Fatalf("bypassIPs = %v, want only the new set", got)
	}
}

func hostRoute(t *testing.T, addr string) *netlink.Route {
	t.Helper()
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("bad test address %q", addr)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &netlink.Route{Dst: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}}
}

// TestTeardownSpareseOperatorRoutesPerAddress is the multi-address form of the
// rule teardown has always followed: delete only the routes we pinned
// ourselves. With one address per family a pair of booleans said it; with a
// server list the answer differs PER ENDPOINT - one server reachable only
// through an operator-installed host route says nothing about the others - so
// getting this wrong strands exactly the endpoints that need it most.
func TestTeardownSparesOperatorRoutesPerAddress(t *testing.T) {
	ours := hostRoute(t, "31.44.3.165")
	theirs := hostRoute(t, "203.0.113.9")
	oursV6 := hostRoute(t, "2001:db8::1")
	theirsV6 := hostRoute(t, "2001:db8::2")

	routes := map[string]*netlink.Route{
		"31.44.3.165": ours,
		"203.0.113.9": theirs,
		"2001:db8::1": oursV6,
		"2001:db8::2": theirsV6,
	}
	preexisted := map[string]bool{
		"203.0.113.9": true,
		"2001:db8::2": true,
	}

	got := bypassRoutesToDelete(routes, preexisted)
	deleted := make(map[string]bool, len(got))
	for _, r := range got {
		deleted[r.Dst.IP.String()] = true
	}

	for _, addr := range []string{"31.44.3.165", "2001:db8::1"} {
		if !deleted[addr] {
			t.Errorf("teardown left our own route to %s behind", addr)
		}
	}
	for _, addr := range []string{"203.0.113.9", "2001:db8::2"} {
		if deleted[addr] {
			t.Errorf("teardown deleted the operator's route to %s", addr)
		}
	}
	if len(got) != 2 {
		t.Fatalf("teardown picked %d routes, want exactly our two", len(got))
	}
}

func TestBypassRoutesToDeleteEdgeCases(t *testing.T) {
	if got := bypassRoutesToDelete(nil, nil); len(got) != 0 {
		t.Errorf("empty maps yielded %d routes, want none", len(got))
	}
	// A nil entry is skipped rather than handed to RouteDel.
	routes := map[string]*netlink.Route{"31.44.3.165": nil}
	if got := bypassRoutesToDelete(routes, nil); len(got) != 0 {
		t.Errorf("a nil route was returned for deletion: %v", got)
	}
	// Everything pre-existing: nothing to delete at all.
	all := map[string]*netlink.Route{
		"31.44.3.165": hostRoute(t, "31.44.3.165"),
		"203.0.113.9": hostRoute(t, "203.0.113.9"),
	}
	pre := map[string]bool{"31.44.3.165": true, "203.0.113.9": true}
	if got := bypassRoutesToDelete(all, pre); len(got) != 0 {
		t.Errorf("deleted %d operator-owned routes, want none", len(got))
	}
}

// TestWatchServerBypassStopsWithoutAddresses pins the cheap exit: with no
// bypass configured the watcher must not start a 5-second ticker for nothing.
// It returns immediately, so calling it on the test goroutine is safe.
func TestWatchServerBypassStopsWithoutAddresses(t *testing.T) {
	d := &TUNDevice{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.WatchServerBypass(nil)
	}()
	select {
	case <-done:
	case <-timeAfterShort():
		t.Fatal("WatchServerBypass did not return with an empty bypass set")
	}
}
