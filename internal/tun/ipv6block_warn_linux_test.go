//go:build linux
// +build linux

package tun

import (
	"net"
	"strings"
	"testing"
)

// heTunnel is the interface the flag was written for: the Hurricane Electric
// 6in4 link on the ruhop node, a sit device with a global address.
func heTunnel() hostV6Iface {
	return hostV6Iface{
		Name:   "he6",
		Kind:   "sit",
		Global: []net.IP{net.ParseIP("2001:db8:77b::2")},
	}
}

func wan() hostV6Iface {
	return hostV6Iface{
		Name:   "eth0",
		Kind:   "device",
		Global: []net.IP{net.ParseIP("2a01:4f8::10")},
	}
}

func mustAllow(t *testing.T, spec string) IPv6AllowList {
	t.Helper()
	a, err := ParseIPv6AllowList(spec)
	if err != nil {
		t.Fatalf("ParseIPv6AllowList(%q): %v", spec, err)
	}
	return a
}

// TestIPv6BlockWarningsTunnelInterface covers the message that would have saved
// the ruhop outage: a v6 tunnel the block is about to cut, named, with the flag
// that spares it.
func TestIPv6BlockWarningsTunnelInterface(t *testing.T) {
	st := hostV6State{Ifaces: []hostV6Iface{wan(), heTunnel()}}

	got := ipv6BlockWarnings("tiredvpn0", IPv6AllowList{}, st)
	if len(got) != 1 {
		t.Fatalf("warnings = %v, want exactly the tunnel one", got)
	}
	for _, want := range []string{"he6", "sit", "-tun-ipv6-allow=he6"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("warning does not mention %q: %s", want, got[0])
		}
	}
	// eth0 losing its global IPv6 is the block working as intended and must
	// not be reported as a problem, or the message becomes noise on every
	// laptop.
	if strings.Contains(got[0], "eth0") {
		t.Errorf("the WAN interface is named in the warning: %s", got[0])
	}
}

// TestIPv6BlockWarningsSilencedByException checks that acting on the warning
// makes it stop — by name or by prefix, since either one spares the interface.
func TestIPv6BlockWarningsSilencedByException(t *testing.T) {
	st := hostV6State{Ifaces: []hostV6Iface{heTunnel()}}

	for _, spec := range []string{"he6", "2001:db8:77b::/64"} {
		if got := ipv6BlockWarnings("tiredvpn0", mustAllow(t, spec), st); len(got) != 0 {
			t.Errorf("-tun-ipv6-allow=%s still warns: %v", spec, got)
		}
	}
	// A prefix that does not cover the interface's address is not an
	// exception for it.
	if got := ipv6BlockWarnings("tiredvpn0", mustAllow(t, "2001:db8:77c::/64"), st); len(got) != 1 {
		t.Errorf("an unrelated prefix silenced the warning: %v", got)
	}
}

// TestIPv6BlockWarningsIgnoresOwnTunnel: our own TUN device is a "tun" kind
// with, once dual-stack is up, a global address of its own. Warning about the
// interface the block was built around would be nonsense.
func TestIPv6BlockWarningsIgnoresOwnTunnel(t *testing.T) {
	st := hostV6State{Ifaces: []hostV6Iface{{
		Name:   "tiredvpn0",
		Kind:   "tun",
		Global: []net.IP{net.ParseIP("2001:db8:ff::2")},
	}}}
	if got := ipv6BlockWarnings("tiredvpn0", IPv6AllowList{}, st); len(got) != 0 {
		t.Errorf("warned about our own tunnel: %v", got)
	}
}

// TestIPv6BlockWarningsForwarding is the operator's request, held to what is
// actually true: the chain is hooked at output, so forwarded traffic is not
// touched. A message claiming transit breaks would be a lie, and the test says
// so in both directions — the words that must be there and the claim that must
// not.
func TestIPv6BlockWarningsForwarding(t *testing.T) {
	st := hostV6State{Forwarding: true}
	got := ipv6BlockWarnings("tiredvpn0", IPv6AllowList{}, st)
	if len(got) != 1 {
		t.Fatalf("warnings = %v, want exactly the forwarding one", got)
	}
	msg := got[0]
	for _, want := range []string{"output", "not affected", "own outbound IPv6"} {
		if !strings.Contains(msg, want) {
			t.Errorf("forwarding warning does not say %q: %s", want, msg)
		}
	}

	st.Forwarding = false
	if got := ipv6BlockWarnings("tiredvpn0", IPv6AllowList{}, st); len(got) != 0 {
		t.Errorf("a host that forwards nothing was warned about forwarding: %v", got)
	}
}

// TestIPv6BlockWarningsOrder: on the node that has both, the tunnel message
// comes first. The forwarding note only exists to place it correctly, and a
// reader who stops after the first line should get the actionable one.
func TestIPv6BlockWarningsOrder(t *testing.T) {
	st := hostV6State{Forwarding: true, Ifaces: []hostV6Iface{heTunnel()}}
	got := ipv6BlockWarnings("tiredvpn0", IPv6AllowList{}, st)
	if len(got) != 2 {
		t.Fatalf("warnings = %v, want two", got)
	}
	if !strings.Contains(got[0], "he6") {
		t.Errorf("first warning is not the tunnel one: %s", got[0])
	}
	if !strings.Contains(got[1], "forward") {
		t.Errorf("second warning is not the forwarding one: %s", got[1])
	}
}

// TestIPv6ForwardingEnabledReadsSysctl guards the one place the warning touches
// the host: an unreadable or absent sysctl reads as off rather than as a crash
// or a warning about procfs.
func TestIPv6ForwardingEnabledReadsSysctl(t *testing.T) {
	// The real path either exists (any Linux) or does not; both answers are
	// valid, the call must simply not panic.
	_ = ipv6ForwardingEnabled()
}
