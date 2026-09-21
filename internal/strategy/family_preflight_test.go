package strategy

import (
	"net"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestFamilyReachabilityPreflightExcludesNoRouteFamily proves the preflight
// step drops a family with no physical route before any strategy scan, using
// only the local route verdict (the injected probe sends no packets - rule 8).
//
// Discriminator: with SetRouteReachable never called (nil probe) the preflight
// is a no-op and both families stay reachable; wiring the probe flips the v6
// verdict. The positive control (rule 2) is v4: the same probe reports it
// routable, and it must stay in play - the fix excludes only the routeless
// family, never the working one.
func TestFamilyReachabilityPreflightExcludesNoRouteFamily(t *testing.T) {
	m := NewManager()
	eps := []endpoint.Endpoint{{Name: "srv", V6: "[2001:db8::1]:443", V4: "203.0.113.1:443"}}
	if err := m.SetEndpoints(eps, endpoint.PreferV6); err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	sel := m.selector()

	// Control: no probe wired -> preflight changes nothing.
	m.familyReachabilityPreflight(sel)
	if !sel.Reachable("[2001:db8::1]:443") || !sel.Reachable("203.0.113.1:443") {
		t.Fatal("control: with no probe both families must stay reachable")
	}

	// Host has no IPv6: the probe knows v4 is routable and v6 is not.
	m.SetRouteReachable(func(addr string) (routable, known bool) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if net.ParseIP(host).To4() == nil {
			return false, true // v6: definite "no route"
		}
		return true, true // v4: routable (positive control)
	})

	m.familyReachabilityPreflight(sel)
	if sel.Reachable("[2001:db8::1]:443") {
		t.Fatal("v6 with no physical route must be excluded by the preflight")
	}
	if !sel.Reachable("203.0.113.1:443") {
		t.Fatal("v4 is routable and must stay in play")
	}
}

// TestSetEndpointReachableIPMapsByHost proves the bypass-watcher path: a
// net.IP verdict (no port) is mapped onto the matching candidate address and
// re-admitted when the route returns.
func TestSetEndpointReachableIPMapsByHost(t *testing.T) {
	m := NewManager()
	eps := []endpoint.Endpoint{{Name: "srv", V6: "[2001:db8::1]:443", V4: "203.0.113.1:443"}}
	if err := m.SetEndpoints(eps, endpoint.PreferV6); err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	sel := m.selector()

	m.SetEndpointReachableIP(net.ParseIP("2001:db8::1"), false)
	if sel.Reachable("[2001:db8::1]:443") {
		t.Fatal("watcher marked v6 unroutable; candidate should read unreachable")
	}
	if !sel.Reachable("203.0.113.1:443") {
		t.Fatal("the v4 candidate must be untouched by a v6 verdict")
	}

	m.SetEndpointReachableIP(net.ParseIP("2001:db8::1"), true)
	if !sel.Reachable("[2001:db8::1]:443") {
		t.Fatal("watcher reported the route back; candidate should be re-admitted")
	}
}
