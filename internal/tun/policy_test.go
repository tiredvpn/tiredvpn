package tun

import (
	"net"
	"testing"
)

// TestDefaultIPv6Policy pins what an unset -tun-ipv6 means. Since 1.4.1 that
// is "dual": IPv6 goes into the tunnel, and is blocked when the exit cannot
// carry it. The default used to be "off", which left every dual-stack host
// reaching the internet over IPv6 outside the VPN (issue #55).
func TestDefaultIPv6Policy(t *testing.T) {
	got, err := ParseIPv6Policy(DefaultIPv6Policy)
	if err != nil {
		t.Fatalf("ParseIPv6Policy(DefaultIPv6Policy=%q): %v", DefaultIPv6Policy, err)
	}
	if got != IPv6PolicyDual {
		t.Errorf("default policy = %v, want %v", got, IPv6PolicyDual)
	}
	if got.String() != DefaultIPv6Policy {
		t.Errorf("round-trip: %q -> %v -> %q", DefaultIPv6Policy, got, got.String())
	}
}

// TestIPv6PolicyPredicates pins the two questions the rest of the code asks a
// policy: does it change the handshake version byte, and does it block IPv6
// that did not make it into the tunnel.
//
// The block policy answering false to NegotiatesDualStack is the load-bearing
// row: it is what keeps a kill-switch-only client byte-identical on the wire
// to a v4-only one.
func TestIPv6PolicyPredicates(t *testing.T) {
	for _, tc := range []struct {
		policy     IPv6Policy
		negotiates bool
		blocks     bool
	}{
		{IPv6PolicyOff, false, false},
		{IPv6PolicyDual, true, true},
		{IPv6PolicyBlock, false, true},
	} {
		if got := tc.policy.NegotiatesDualStack(); got != tc.negotiates {
			t.Errorf("%v.NegotiatesDualStack() = %v, want %v", tc.policy, got, tc.negotiates)
		}
		if got := tc.policy.BlocksLeakedIPv6(); got != tc.blocks {
			t.Errorf("%v.BlocksLeakedIPv6() = %v, want %v", tc.policy, got, tc.blocks)
		}
	}
}

// TestIPv6ActionFor covers the post-handshake decision table, including the
// case the whole phase exists for: dual was asked for, the exit declined, and
// the answer is to block rather than to shrug.
func TestIPv6ActionFor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policy     IPv6Policy
		owns       bool
		negotiated bool
		want       ipv6Action
	}{
		{"off leaves the host alone", IPv6PolicyOff, true, false, ipv6ActionNone},
		{"off ignores a negotiated exit", IPv6PolicyOff, true, true, ipv6ActionNone},
		{"dual + negotiated enables v6", IPv6PolicyDual, true, true, ipv6ActionEnableDual},
		{"dual + declined blocks", IPv6PolicyDual, true, false, ipv6ActionBlock},
		{"block never enables", IPv6PolicyBlock, true, true, ipv6ActionBlock},
		{"block without negotiation", IPv6PolicyBlock, true, false, ipv6ActionBlock},
		{"host-owned interface: dual", IPv6PolicyDual, false, true, ipv6ActionNone},
		{"host-owned interface: declined dual", IPv6PolicyDual, false, false, ipv6ActionNone},
		{"host-owned interface: block", IPv6PolicyBlock, false, false, ipv6ActionNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ipv6ActionFor(tc.policy, tc.owns, tc.negotiated); got != tc.want {
				t.Errorf("ipv6ActionFor(%v, owns=%v, negotiated=%v) = %v, want %v",
					tc.policy, tc.owns, tc.negotiated, got, tc.want)
			}
		})
	}
}

// TestIPv6PolicyOrLegacy checks that the deprecated VPNConfig.DualStack bool
// still selects the dual policy for callers that have not moved over (macOS,
// benchmarks), and that an explicit IPv6Policy wins over it.
func TestIPv6PolicyOrLegacy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  VPNConfig
		want IPv6Policy
	}{
		{"zero value", VPNConfig{}, IPv6PolicyOff},
		{"legacy bool", VPNConfig{DualStack: true}, IPv6PolicyDual},
		{"explicit dual", VPNConfig{IPv6Policy: IPv6PolicyDual}, IPv6PolicyDual},
		{"explicit block", VPNConfig{IPv6Policy: IPv6PolicyBlock}, IPv6PolicyBlock},
		{"explicit block wins over legacy", VPNConfig{IPv6Policy: IPv6PolicyBlock, DualStack: true}, IPv6PolicyBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.ipv6PolicyOrLegacy(); got != tc.want {
				t.Errorf("ipv6PolicyOrLegacy() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestServerIP6s covers the allow list the leak block punches for the client's
// own transport. Getting this wrong blocks the client out of its own exit, so
// both configured addresses are collected, IPv4 is ignored (the block is ip6
// only) and duplicates are dropped.
func TestServerIP6s(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  VPNConfig
		want []string
	}{
		{
			name: "no v6 anywhere",
			cfg:  VPNConfig{ServerAddr: "203.0.113.10:995"},
		},
		{
			name: "-server-v6 only",
			cfg:  VPNConfig{ServerAddr: "203.0.113.10:995", ServerAddrV6: "[2001:db8::10]:995"},
			want: []string{"2001:db8::10"},
		},
		{
			name: "v6 literal in -server",
			cfg:  VPNConfig{ServerAddr: "[2001:db8::20]:995"},
			want: []string{"2001:db8::20"},
		},
		{
			name: "both, different exits",
			cfg:  VPNConfig{ServerAddr: "[2001:db8::20]:995", ServerAddrV6: "[2001:db8::10]:995"},
			want: []string{"2001:db8::10", "2001:db8::20"},
		},
		{
			name: "both, same address deduped",
			cfg:  VPNConfig{ServerAddr: "[2001:db8::10]:443", ServerAddrV6: "[2001:db8::10]:995"},
			want: []string{"2001:db8::10"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := serverIP6s(tc.cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("serverIP6s = %v, want %v", got, tc.want)
			}
			for i, want := range tc.want {
				if !got[i].Equal(net.ParseIP(want)) {
					t.Errorf("serverIP6s[%d] = %s, want %s", i, got[i], want)
				}
			}
		})
	}
}
