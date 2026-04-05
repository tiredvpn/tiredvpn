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
	effectiveAddr := mgr.GetServerAddr(ctx)
	assert.Equal(t, addr, effectiveAddr, "Should return IPv6 address")

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

	// Get effective server address - should fallback to IPv4 due to failed connectivity check
	effectiveAddr := mgr.GetServerAddr(ctx)

	// Should fallback to IPv4 address
	assert.Equal(t, "127.0.0.1:443", effectiveAddr, "Should fallback to IPv4 address when IPv6 check fails")
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

	// Get effective server address - should be IPv4 even though IPv6 is configured
	effectiveAddr := mgr.GetServerAddr(ctx)
	assert.Equal(t, "127.0.0.1:443", effectiveAddr, "Should use IPv4 when PreferIPv6=false")
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

	// Get effective server address - should still return IPv6 even though it will fail
	effectiveAddr := mgr.GetServerAddr(ctx)
	assert.Equal(t, "[::1]:99999", effectiveAddr, "Should return IPv6 address even when fallback disabled")
}

func TestIPv6ResetCheck(t *testing.T) {
	// Create manager
	mgrCfg := strategy.DefaultManagerConfig{
		ServerAddr:   "127.0.0.1:443",
		ServerAddrV6: "[::1]:443",
		PreferIPv6:   true,
		FallbackToV4: true,
		Secret:       []byte("test-secret"),
	}
	mgr := strategy.NewDefaultManager(mgrCfg)

	ctx := context.Background()

	// First call - will check IPv6 connectivity
	_ = mgr.GetServerAddr(ctx)

	// Reset check
	mgr.ResetIPv6Check()

	// Next call should re-check IPv6 connectivity
	_ = mgr.GetServerAddr(ctx)

	// Test passes if no panic/error occurs
}
