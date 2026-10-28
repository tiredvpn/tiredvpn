package strategy

import (
	"testing"
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
