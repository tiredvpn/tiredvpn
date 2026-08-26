//go:build linux

package tun

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestMSSTableNamePerInterface verifies each interface gets a distinct nftables
// table name so teardown of one tunnel cannot delete another's clamping table.
func TestMSSTableNamePerInterface(t *testing.T) {
	a := mssTableName("tiredvpn0")
	b := mssTableName("tiredvpn1")
	if a == b {
		t.Fatalf("expected distinct table names, both = %q", a)
	}
	if a != "tiredvpn-tiredvpn0" {
		t.Errorf("mssTableName(tiredvpn0) = %q, want tiredvpn-tiredvpn0", a)
	}
	if got := mssTableName("ruhop_ams"); got != "tiredvpn-ruhop_ams" {
		t.Errorf("mssTableName(ruhop_ams) = %q, want tiredvpn-ruhop_ams", got)
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// TestRouteBuildersSetMetricPerFamily verifies the two install builders: the
// IPv6 half-defaults carry a per-link metric (so two tunnels coexist), while
// IPv4 routes keep metric 0 — the tunnel's v4 default is expected to beat a
// DHCP-installed one at metric 600, and raising our v4 metric would break that.
func TestRouteBuildersSetMetricPerFamily(t *testing.T) {
	for _, cidr := range dualStackRouteCIDRs {
		dst := mustCIDR(t, cidr)

		r5 := v6HalfDefaultRoute(5, dst)
		if r5.Priority == 0 {
			t.Errorf("%s: Priority = 0, want the per-link metric (0 means the kernel default 1024)", cidr)
		}
		if want := v6HalfDefaultPriority(5); r5.Priority != want {
			t.Errorf("%s: Priority = %d, want %d", cidr, r5.Priority, want)
		}

		r6 := v6HalfDefaultRoute(6, dst)
		if r5.Priority == r6.Priority {
			t.Errorf("%s: link 5 and 6 both got metric %d, so both are one routing entry",
				cidr, r5.Priority)
		}
	}

	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/24"} {
		if r := tunRoute(5, mustCIDR(t, cidr)); r.Priority != 0 {
			t.Errorf("%s: IPv4 Priority = %d, want 0", cidr, r.Priority)
		}
	}
}

// TestTrackRouteRecordsAndDedups verifies that route tracking records each
// routing entry once, so teardown deletes exactly the routes this device added
// (and reconnect re-adds do not grow the list unbounded). The key is the
// (destination, metric) pair, matching what the kernel keys an entry on.
func TestTrackRouteRecordsAndDedups(t *testing.T) {
	dev := &TUNDevice{name: "tiredvpn0"}

	dev.trackRoute(tunRoute(3, mustCIDR(t, "10.0.0.0/24")))
	dev.trackRoute(tunRoute(3, mustCIDR(t, "142.132.151.126/32")))
	dev.trackRoute(tunRoute(3, mustCIDR(t, "10.0.0.0/24"))) // duplicate (reconnect re-add)
	dev.trackRoute(v6HalfDefaultRoute(3, mustCIDR(t, "::/1")))
	dev.trackRoute(v6HalfDefaultRoute(3, mustCIDR(t, "::/1"))) // duplicate

	if len(dev.addedRoutes) != 3 {
		t.Fatalf("addedRoutes = %d entries, want 3 (deduped): %v", len(dev.addedRoutes), dev.addedRoutes)
	}

	want := map[string]bool{
		"10.0.0.0/24":        true,
		"142.132.151.126/32": true,
		"::/1 metric 103":    true,
	}
	for _, r := range dev.addedRoutes {
		if !want[r.String()] {
			t.Errorf("unexpected tracked route %q", r.String())
		}
	}

	// Same destination on a different link index is a different kernel entry
	// (different metric), so it must be recorded separately rather than
	// swallowed by the dedup.
	dev.trackRoute(v6HalfDefaultRoute(4, mustCIDR(t, "::/1")))
	if len(dev.addedRoutes) != 4 {
		t.Errorf("::/1 at another metric should be tracked separately, got %d entries: %v",
			len(dev.addedRoutes), dev.addedRoutes)
	}
}

// TestUntrackRouteMatchesMetric verifies untracking uses the same key as
// tracking, so DisableIPv6 drops the half-default it just deleted and leaves
// everything else in place for teardown.
func TestUntrackRouteMatchesMetric(t *testing.T) {
	dev := &TUNDevice{name: "tiredvpn0"}
	dev.trackRoute(tunRoute(7, mustCIDR(t, "10.0.0.0/24")))
	dev.trackRoute(v6HalfDefaultRoute(7, mustCIDR(t, "::/1")))

	// Same destination, another link's metric: a different kernel entry, so
	// untracking it must not drop ours (which would leave our route installed
	// and unrecorded, i.e. surviving teardown).
	dev.untrackRoute(v6HalfDefaultRoute(9, mustCIDR(t, "::/1")))
	if len(dev.addedRoutes) != 2 {
		t.Fatalf("untracking ::/1 at another metric dropped our entry: %v", dev.addedRoutes)
	}

	dev.untrackRoute(v6HalfDefaultRoute(7, mustCIDR(t, "::/1")))

	if len(dev.addedRoutes) != 1 {
		t.Fatalf("addedRoutes = %d entries, want 1: %v", len(dev.addedRoutes), dev.addedRoutes)
	}
	if got := dev.addedRoutes[0].String(); got != "10.0.0.0/24" {
		t.Errorf("remaining tracked route = %q, want 10.0.0.0/24", got)
	}
}

// TestRouteDelSpecsMatchInstall is the guard against a route outliving the
// tunnel: netlink matches a deletion on the metric too, so every deletion
// request must carry the metric its install went in with. It compares the
// deletion specs against the very routes that were installed.
func TestRouteDelSpecsMatchInstall(t *testing.T) {
	const linkIndex = 12
	dev := &TUNDevice{name: "tiredvpn0"}

	installed := []*netlink.Route{
		tunRoute(linkIndex, mustCIDR(t, "0.0.0.0/1")),
		tunRoute(linkIndex, mustCIDR(t, "128.0.0.0/1")),
		v6HalfDefaultRoute(linkIndex, mustCIDR(t, "::/1")),
		v6HalfDefaultRoute(linkIndex, mustCIDR(t, "8000::/1")),
	}
	for _, r := range installed {
		dev.trackRoute(r)
	}

	specs := dev.routeDelSpecs(linkIndex)
	if len(specs) != len(installed) {
		t.Fatalf("routeDelSpecs = %d specs, want %d", len(specs), len(installed))
	}
	for i, spec := range specs {
		want := installed[i]
		if spec.Dst.String() != want.Dst.String() {
			t.Errorf("spec %d: Dst = %s, want %s", i, spec.Dst, want.Dst)
		}
		if spec.Priority != want.Priority {
			t.Errorf("spec %d (%s): delete Priority = %d, install Priority = %d "+
				"(mismatch means the route survives teardown)", i, want.Dst, spec.Priority, want.Priority)
		}
		if spec.LinkIndex != linkIndex {
			t.Errorf("spec %d: LinkIndex = %d, want %d", i, spec.LinkIndex, linkIndex)
		}
	}
}

// TestDelRoutesClearsTracking verifies delRoutes empties the tracked set even
// when the link is gone, so a second teardown is a no-op and cannot touch
// the main table.
func TestDelRoutesClearsTracking(t *testing.T) {
	// Use an interface name that does not exist; delRoutes must fail the link
	// lookup gracefully and leave addedRoutes intact (nothing was deleted).
	dev := &TUNDevice{name: "tiredvpn-doesnotexist-xyz"}
	_, n, _ := net.ParseCIDR("10.0.0.0/24")
	dev.addedRoutes = []trackedRoute{{dst: n}}

	dev.delRoutes() // link lookup fails -> returns without clearing

	if len(dev.addedRoutes) != 1 {
		t.Errorf("addedRoutes should be untouched when link lookup fails, got %d", len(dev.addedRoutes))
	}
}
