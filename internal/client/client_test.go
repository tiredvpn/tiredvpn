package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// These tests cover the wiring, not the policy: that NewDefaultManager turns the
// legacy -server / -server-v6 / -prefer-ipv6 / -fallback-v4 flags into the same
// dial target the old one-shot IPv6 check produced. The policy itself is
// exercised in internal/endpoint and internal/strategy.
//
// The family verdict is no longer computed inside GetServerAddr - that getter
// sits on the path of every strategy in a scan and must not dial. It is
// computed once per connect cycle by ProbeEndpointFamily, which is what these
// tests call.

func TestIPv6Dial(t *testing.T) {
	// Try to create IPv6 server
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available on this system: %v", err)
		return
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Start accepting connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Create manager with IPv6 config
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:   "127.0.0.1:12345", // IPv4 fallback (not used in this test)
		ServerAddrV6: addr,
		PreferIPv6:   true,
		FallbackToV4: false, // Disable fallback for this test
		Secret:       []byte("test-secret"),
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get effective server address - should be IPv6
	effectiveAddr := mgr.ProbeEndpointFamily(ctx)
	assert.Equal(t, addr, effectiveAddr, "Should return IPv6 address")
	assert.Equal(t, addr, mgr.GetServerAddr(ctx), "Pinned address must match the probe verdict")

	// Verify it's actually IPv6 by parsing
	host, _, err := net.SplitHostPort(effectiveAddr)
	require.NoError(t, err)
	ip := net.ParseIP(host)
	assert.NotNil(t, ip, "Should parse as valid IP")
	assert.Nil(t, ip.To4(), "Should be IPv6 (To4() returns nil for IPv6)")
}

func TestIPv4Fallback(t *testing.T) {
	// Test fallback logic without requiring actual IPv6 connectivity
	// Use a definitely unreachable IPv6 address

	// Create manager with IPv6 config pointing to invalid address
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:   "127.0.0.1:443",
		ServerAddrV6: "[::1]:99999", // Invalid port - will fail connectivity check
		PreferIPv6:   true,
		FallbackToV4: true, // Enable fallback
		Secret:       []byte("test-secret"),
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should fall back to IPv4 once the probe finds the v6 address unreachable.
	assert.Equal(t, "127.0.0.1:443", mgr.ProbeEndpointFamily(ctx),
		"Should fallback to IPv4 address when IPv6 check fails")
	assert.Equal(t, "127.0.0.1:443", mgr.GetServerAddr(ctx),
		"The fallback must be pinned, not recomputed per call")
}

func TestIPv6PreferenceDisabled(t *testing.T) {
	// Create manager with IPv6 config but preference disabled
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:   "127.0.0.1:443",
		ServerAddrV6: "[::1]:443",
		PreferIPv6:   false, // Disable IPv6 preference
		FallbackToV4: true,
		Secret:       []byte("test-secret"),
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	ctx := context.Background()

	// -prefer-ipv6=false is a "keep this client off IPv6" knob: IPv4 is the only
	// candidate, so neither the probe nor the getter may surface the v6 address.
	assert.Equal(t, "127.0.0.1:443", mgr.ProbeEndpointFamily(ctx), "Should use IPv4 when PreferIPv6=false")
	assert.Equal(t, "127.0.0.1:443", mgr.GetServerAddr(ctx), "Should use IPv4 when PreferIPv6=false")
}

func TestIPv6NoFallback(t *testing.T) {
	// Create manager with IPv6 config, no fallback
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:   "127.0.0.1:443",
		ServerAddrV6: "[::1]:99999", // Invalid - will fail
		PreferIPv6:   true,
		FallbackToV4: false, // No fallback
		Secret:       []byte("test-secret"),
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// -fallback-v4=false is an explicit "never touch IPv4" knob; silently
	// dropping to v4 here would defeat it and leak onto the blocked family.
	assert.Equal(t, "[::1]:99999", mgr.ProbeEndpointFamily(ctx),
		"Should return IPv6 address even when fallback disabled")
	assert.Equal(t, "[::1]:99999", mgr.GetServerAddr(ctx),
		"Should return IPv6 address even when fallback disabled")
}

// TestIPv6ResetCheck covers the network-change path: after a reset the verdict
// is recomputed instead of surviving into a network where it is meaningless.
func TestIPv6ResetCheck(t *testing.T) {
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:   "127.0.0.1:443",
		ServerAddrV6: "[::1]:99999", // unreachable, so the probe falls back
		PreferIPv6:   true,
		FallbackToV4: true,
		Secret:       []byte("test-secret"),
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	ctx := context.Background()

	assert.Equal(t, "127.0.0.1:443", mgr.ProbeEndpointFamily(ctx), "unreachable v6 must fall back")

	mgr.ResetIPv6Check()
	assert.Equal(t, "[::1]:99999", mgr.GetServerAddr(ctx),
		"reset must put the preferred family back before the next probe")
	assert.Equal(t, "127.0.0.1:443", mgr.ProbeEndpointFamily(ctx),
		"the re-probe must reach the same verdict, not a cached one")
}
