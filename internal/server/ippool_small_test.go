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

// TestARefusedRequestIsServedFromAnywhereInThePool is finding 5 of the
// round-13 review: served from the top down, every refused box got .254 -
// as common a hand-configured address as .2 - and a box configured with it
// took it over. Over fresh pools a refused request lands all over the
// pool, never on what it asked for.
func TestARefusedRequestIsServedFromAnywhereInThePool(t *testing.T) {
	const runs = 400
	seen := map[string]int{}
	for range runs {
		pool, err := NewIPPool(IPPoolConfig{Network: "10.8.7.0/24", ServerIP: "10.8.7.1"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := pool.AllocateAvoiding("box", net.IPv4(10, 8, 7, 2))
		if err != nil {
			t.Fatal(err)
		}
		if ip.Equal(net.IPv4(10, 8, 7, 2)) {
			t.Fatal("a refused request got the address it asked for")
		}
		seen[ip.String()]++
	}
	// 253 addresses, 400 draws: a uniform start gives about 200 distinct
	// ones. .3 also takes the starts on .1 (the server's) and .2 (the
	// refused), 3 in 253: a mean of 4.7 hits, and more than 20 about once
	// in 10^6 runs. Top-down put all 400 on one address.
	if len(seen) < 120 {
		t.Fatalf("400 refused requests landed on %d addresses", len(seen))
	}
	for ip, n := range seen {
		if n > 20 {
			t.Fatalf("%s got %d of 400 refused requests", ip, n)
		}
	}
}
