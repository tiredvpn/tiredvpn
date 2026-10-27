package server

import (
	"net"
	"testing"
)

// TestAPoolTooSmallForAClientIsRefused is finding 3 of the round-13 review:
// on a /31 or /32 the allocatable range wrapped, and every allocation -
// from the bottom and from the top - handed out an address outside the
// network. Such a pool is refused at startup; a /30 still works and stays
// inside its network.
func TestAPoolTooSmallForAClientIsRefused(t *testing.T) {
	for _, network := range []string{"10.8.7.0/31", "10.8.7.0/32"} {
		if _, err := NewIPPool(IPPoolConfig{Network: network, ServerIP: "10.8.7.1"}, nil); err == nil {
			t.Errorf("a pool on %s was accepted", network)
		}
	}
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.7.0/30", ServerIP: "10.8.7.1"}, nil)
	if err != nil {
		t.Fatalf("a /30 was refused: %v", err)
	}
	_, inside, _ := net.ParseCIDR("10.8.7.0/30")
	for _, alloc := range []func() (net.IP, error){
		func() (net.IP, error) { return pool.Allocate("a", nil, "") },
		func() (net.IP, error) { return pool.AllocateAvoiding("b", net.IPv4(10, 8, 7, 9)) },
	} {
		ip, err := alloc()
		if err == nil && !inside.Contains(ip) {
			t.Fatalf("the /30 handed out %s", ip)
		}
	}
}
