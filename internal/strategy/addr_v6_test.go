package strategy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestInitManagerTransport_NormalizesLegacyAddrs: a manager built straight from
// DefaultManagerConfig with a raw -server-v6 value (no Endpoints list) must
// dial [v6]:port, the same form client.ResolveEndpoints produces.
func TestInitManagerTransport_NormalizesLegacyAddrs(t *testing.T) {
	for _, v6 := range []string{"2001:db8::2", "[2001:db8::2]"} {
		mgr := NewDefaultManager(DefaultManagerConfig{
			ServerAddr:   "203.0.113.10:995",
			ServerAddrV6: v6,
			PreferIPv6:   true,
			FallbackToV4: true,
			Secret:       []byte("test-secret"),
		})
		states := mgr.EndpointStates()
		if len(states) != 2 || states[0].Addr != "[2001:db8::2]:995" || states[1].Addr != "203.0.113.10:995" {
			t.Fatalf("-server-v6 %q: candidates = %+v", v6, states)
		}
	}
}

// TestCheckICMP_IPv6Host: the reachability fallback dials host:443 and host:80.
// Spliced with "+", an IPv6 host became "::1:443", which net.Dial rejects as
// an address before a packet is sent; the verdict was then "unreachable" for
// every IPv6 server, whatever the network said.
func TestCheckICMP_IPv6Host(t *testing.T) {
	c := NewConnectivityChecker("[::1]:995", time.Second, false)
	c.auxTimeout = time.Second
	err := c.checkICMP(context.Background(), "::1")
	if _, isAddrErr := errors.AsType[*net.AddrError](err); isAddrErr {
		t.Fatalf("checkICMP built an undialable address: %v", err)
	}
}
