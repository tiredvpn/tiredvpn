//go:build linux

package tun

import (
	"net"
	"testing"
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

// TestTrackRouteRecordsAndDedups verifies that route tracking records each
// destination once, so teardown deletes exactly the routes this device added
// (and reconnect re-adds do not grow the list unbounded).
func TestTrackRouteRecordsAndDedups(t *testing.T) {
	dev := &TUNDevice{name: "tiredvpn0"}

	mustCIDR := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", s, err)
		}
		return n
	}

	dev.trackRoute(mustCIDR("10.0.0.0/24"))
	dev.trackRoute(mustCIDR("142.132.151.126/32"))
	dev.trackRoute(mustCIDR("10.0.0.0/24")) // duplicate (reconnect re-add)

	if len(dev.addedRoutes) != 2 {
		t.Fatalf("addedRoutes = %d entries, want 2 (deduped): %v", len(dev.addedRoutes), dev.addedRoutes)
	}

	want := map[string]bool{"10.0.0.0/24": true, "142.132.151.126/32": true}
	for _, r := range dev.addedRoutes {
		if !want[r.String()] {
			t.Errorf("unexpected tracked route %q", r.String())
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
	dev.addedRoutes = []*net.IPNet{n}

	dev.delRoutes() // link lookup fails -> returns without clearing

	if len(dev.addedRoutes) != 1 {
		t.Errorf("addedRoutes should be untouched when link lookup fails, got %d", len(dev.addedRoutes))
	}
}
