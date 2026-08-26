//go:build linux

package tun

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// listV6Routes reads the main table. The nil-filter form of RouteListFiltered
// panics in this netlink version, so the table filter is always supplied.
func listV6Routes(t *testing.T) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("RouteListFiltered: %v", err)
	}
	return routes
}

// The tests below talk to the real routing table and create interfaces, so
// they are opt-in and want a network namespace of their own:
//
//	go test -c -o /tmp/tun.test ./internal/tun/
//	sudo unshare -n env TIREDVPN_NETNS_TESTS=1 /tmp/tun.test -test.run TestRoot -test.v
//
// The opt-in is a separate switch from root because a root CI container would
// otherwise have these adding dummy links to whatever namespace it shares.

func rootOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("TIREDVPN_NETNS_TESTS") != "1" {
		t.Skip("opt-in: set TIREDVPN_NETNS_TESTS=1 and run inside a network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: creates links and routes")
	}
}

// dummyLink creates an up dummy interface and returns its index. It is the
// stand-in for a TUN: the half-defaults do not care what kind of link they
// point at, only that two of them have different indices.
func dummyLink(t *testing.T, name string) int {
	t.Helper()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Skipf("cannot create dummy link %s (no dummy module?): %v", name, err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("LinkSetUp(%s): %v", name, err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", name, err)
	}
	return l.Attrs().Index
}

// halfDefaultsOn returns the link indices carrying a ::/1 route right now.
func halfDefaultsOn(t *testing.T) []int {
	t.Helper()
	var idx []int
	for _, r := range listV6Routes(t) {
		if r.Dst != nil && r.Dst.String() == "::/1" {
			idx = append(idx, r.LinkIndex)
		}
	}
	return idx
}

// TestRootTwoTunnelsKeepTheirHalfDefaults is the end-to-end check on the
// defect: two dual-stack tunnels on one host must each keep their own ::/1,
// and tearing one down must leave the other's route in place.
//
// It carries its own positive control. The same sequence is run first WITHOUT
// the metric — the pre-fix behaviour — and the collision has to be visible
// there, otherwise the test is not able to see the thing it claims to prove.
func TestRootTwoTunnelsKeepTheirHalfDefaults(t *testing.T) {
	rootOnly(t)

	_, dst, err := net.ParseCIDR("::/1")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	idxA := dummyLink(t, "tvtesta")
	idxB := dummyLink(t, "tvtestb")

	// Positive control: no metric, exactly as the code did before this fix.
	// The second install must swallow the first, leaving a single entry.
	for _, idx := range []int{idxA, idxB} {
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: idx, Dst: dst}); err != nil {
			t.Fatalf("RouteReplace(no metric, link %d): %v", idx, err)
		}
	}
	if got := halfDefaultsOn(t); len(got) != 1 {
		t.Fatalf("control: metric-less installs produced %d ::/1 entries on links %v, "+
			"want the 1 that made this a bug", len(got), got)
	}
	if got := halfDefaultsOn(t); got[0] != idxB {
		t.Errorf("control: surviving ::/1 is on link %d, want the second installer %d", got[0], idxB)
	}
	// Clean the control's entry out before the real run.
	if err := netlink.RouteDel(&netlink.Route{LinkIndex: idxB, Dst: dst}); err != nil {
		t.Fatalf("RouteDel(control): %v", err)
	}

	// The fix: per-link metrics, so both entries live.
	devA := &TUNDevice{name: "tvtesta"}
	devB := &TUNDevice{name: "tvtestb"}
	for _, c := range []struct {
		dev *TUNDevice
		idx int
	}{{devA, idxA}, {devB, idxB}} {
		route := v6HalfDefaultRoute(c.idx, dst)
		c.dev.trackRoute(route)
		if err := netlink.RouteReplace(route); err != nil {
			t.Fatalf("RouteReplace(link %d): %v", c.idx, err)
		}
	}
	got := halfDefaultsOn(t)
	if len(got) != 2 {
		t.Fatalf("::/1 present on %v, want both links %d and %d", got, idxA, idxB)
	}

	// A reconnect re-asserts the same route: it must refresh our entry, not add
	// a third one.
	if err := netlink.RouteReplace(v6HalfDefaultRoute(idxA, dst)); err != nil {
		t.Fatalf("RouteReplace(re-add on link %d): %v", idxA, err)
	}
	if got := halfDefaultsOn(t); len(got) != 2 {
		t.Errorf("re-add produced %d ::/1 entries on %v, want 2 (RouteReplace not idempotent)", len(got), got)
	}

	// Teardown of B: its own route goes, A's stays.
	for _, spec := range devB.routeDelSpecs(idxB) {
		if err := netlink.RouteDel(spec); err != nil {
			t.Fatalf("RouteDel(link %d, metric %d): %v", spec.LinkIndex, spec.Priority, err)
		}
	}
	got = halfDefaultsOn(t)
	if len(got) != 1 || got[0] != idxA {
		t.Fatalf("after tearing down link %d, ::/1 is on %v, want exactly [%d] — "+
			"the surviving tunnel lost its route and its IPv6 leaks past the tunnel", idxB, got, idxA)
	}

	// Teardown of A removes the last one, so nothing is left behind.
	for _, spec := range devA.routeDelSpecs(idxA) {
		if err := netlink.RouteDel(spec); err != nil {
			t.Fatalf("RouteDel(link %d, metric %d): %v", spec.LinkIndex, spec.Priority, err)
		}
	}
	if got := halfDefaultsOn(t); len(got) != 0 {
		t.Errorf("::/1 still present on %v after both teardowns", got)
	}
}

// TestRootRouteDelMetricSemantics records what the kernel actually does with
// the metric on deletion, measured rather than assumed.
//
// The assumption going in was that a deletion omitting the metric would not
// match a route that has one, which would make carrying the metric through
// addedRoutes load-bearing against a route outliving its tunnel. Measurement
// says otherwise: with the destination and the interface given, the kernel
// deletes the entry whatever its metric (checked here and, independently,
// with `ip -6 route del`). So teardown was never at risk from the metric.
//
// The metric is still carried into the deletion, and the test pins that it
// works, because reproducing the install exactly is an invariant that does not
// depend on how lenient the matcher happens to be. This test is what would
// notice if that leniency ever went away.
func TestRootRouteDelMetricSemantics(t *testing.T) {
	rootOnly(t)

	_, dst, err := net.ParseCIDR("8000::/1")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	idx := dummyLink(t, "tvtestc")

	present := func() bool {
		for _, r := range listV6Routes(t) {
			if r.Dst != nil && r.Dst.String() == "8000::/1" && r.LinkIndex == idx {
				return true
			}
		}
		return false
	}

	// The deletion our code builds must remove the route it installed. This is
	// the assertion the shipped teardown path depends on.
	route := v6HalfDefaultRoute(idx, dst)
	if err := netlink.RouteReplace(route); err != nil {
		t.Fatalf("RouteReplace: %v", err)
	}
	if !present() {
		t.Fatal("route not installed, nothing to conclude from the deletion")
	}
	if err := netlink.RouteDel(route); err != nil {
		t.Fatalf("RouteDel with the install spec: %v", err)
	}
	if present() {
		t.Error("route survived a deletion carrying its own metric")
	}

	// And the measured leniency, recorded so a future kernel that tightens it
	// turns this into a failure instead of a silent stranded route somewhere.
	if err := netlink.RouteReplace(route); err != nil {
		t.Fatalf("RouteReplace (leniency case): %v", err)
	}
	err = netlink.RouteDel(&netlink.Route{LinkIndex: idx, Dst: dst})
	if err != nil || present() {
		t.Errorf("metric-less RouteDel no longer matches a route with a metric "+
			"(err=%v, still present=%v); deletions must now be built from the "+
			"install spec everywhere, or routes outlive their tunnel", err, present())
	}
}
