package client

import (
	"strings"
	"testing"
)

// TestNewTUNVPNConfigIPv6Allow is the callsite test for -tun-ipv6-allow: the
// value has to survive the trip from the client config into the TUN layer's
// VPNConfig. Parsing it correctly and then leaving it behind here would look
// exactly like never passing the flag.
func TestNewTUNVPNConfigIPv6Allow(t *testing.T) {
	cfg := &Config{
		TunName:    "tiredvpn0",
		TunIP:      "10.8.0.2",
		TunPeerIP:  "10.8.0.1",
		ServerAddr: "203.0.113.10:443",
		// The ruhop spelling: an interface and the prefix behind it.
		TunIPv6Allow: "he6,2001:db8:77b::/64",
	}

	vpnCfg, err := newTUNVPNConfig(cfg, nil)
	if err != nil {
		t.Fatalf("newTUNVPNConfig: %v", err)
	}
	if got := vpnCfg.IPv6Allow.Interfaces; len(got) != 1 || got[0] != "he6" {
		t.Errorf("IPv6Allow.Interfaces = %v, want [he6]", got)
	}
	if got := vpnCfg.IPv6Allow.Prefixes; len(got) != 1 || got[0].String() != "2001:db8:77b::/64" {
		t.Errorf("IPv6Allow.Prefixes = %v, want [2001:db8:77b::/64]", got)
	}
}

// TestNewTUNVPNConfigIPv6AllowEmpty: an unset flag must leave the block exactly
// as it was, not produce a one-entry list of "".
func TestNewTUNVPNConfigIPv6AllowEmpty(t *testing.T) {
	vpnCfg, err := newTUNVPNConfig(&Config{TunIP: "10.8.0.2", ServerAddr: "203.0.113.10:443"}, nil)
	if err != nil {
		t.Fatalf("newTUNVPNConfig: %v", err)
	}
	if !vpnCfg.IPv6Allow.Empty() {
		t.Errorf("an unset -tun-ipv6-allow produced %v", vpnCfg.IPv6Allow)
	}
}

// TestNewTUNVPNConfigIPv6AllowBadSpec: a malformed prefix stops the client
// instead of quietly leaving the operator with a hole that was never punched.
func TestNewTUNVPNConfigIPv6AllowBadSpec(t *testing.T) {
	_, err := newTUNVPNConfig(&Config{
		TunIP:        "10.8.0.2",
		ServerAddr:   "203.0.113.10:443",
		TunIPv6Allow: "he6,2001:db8:::/64",
	}, nil)
	if err == nil {
		t.Fatal("a malformed prefix started the client anyway")
	}
	if !strings.Contains(err.Error(), "tun-ipv6-allow") {
		t.Errorf("error %q does not name the flag at fault", err)
	}
}
