package tun

import (
	"net"
	"strings"
	"testing"
)

// TestParseIPv6AllowList pins the flag surface: which entries are interfaces,
// which are prefixes, and which stop the client from starting at all. The last
// group is the one that matters most — an exception silently dropped leaves the
// operator with a block they believe has a hole in it.
func TestParseIPv6AllowList(t *testing.T) {
	for _, tc := range []struct {
		name       string
		spec       string
		wantIfaces []string
		wantNets   []string
		wantErr    string
	}{
		{name: "empty", spec: ""},
		{name: "only separators", spec: " , ,"},
		{
			name:       "interface",
			spec:       "he6",
			wantIfaces: []string{"he6"},
		},
		{
			name:     "prefix",
			spec:     "2001:db8:77b::/64",
			wantNets: []string{"2001:db8:77b::/64"},
		},
		{
			name:     "bare address becomes a /128",
			spec:     "2001:db8:77b::2",
			wantNets: []string{"2001:db8:77b::2/128"},
		},
		{
			name:     "host bits in a prefix do not narrow it",
			spec:     "2001:db8:77b::2/64",
			wantNets: []string{"2001:db8:77b::/64"},
		},
		{
			name:       "mixed, with whitespace",
			spec:       " he6 , 2001:db8:77b::/64 ,wg0",
			wantIfaces: []string{"he6", "wg0"},
			wantNets:   []string{"2001:db8:77b::/64"},
		},
		{
			// An interface that does not exist yet is deliberately accepted:
			// the 6in4 unit may start after the client, and nftables matches
			// an oifname that appears later.
			name:       "unknown interface is not an error",
			spec:       "definitely-no",
			wantIfaces: []string{"definitely-no"},
		},
		{
			name:    "malformed prefix",
			spec:    "he6,2001:db8:::/64",
			wantErr: "not a valid IPv6 prefix",
		},
		{
			name:    "prefix length out of range",
			spec:    "2001:db8:77b::/129",
			wantErr: "not a valid IPv6 prefix",
		},
		{
			name:    "IPv4 prefix",
			spec:    "192.0.2.0/24",
			wantErr: "only filters IPv6",
		},
		{
			name:    "IPv4 address",
			spec:    "192.0.2.1",
			wantErr: "only filters IPv6",
		},
		{
			name:    "interface name longer than IFNAMSIZ",
			spec:    "a-very-long-interface-name",
			wantErr: "the kernel allows at most",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseIPv6AllowList(tc.spec)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseIPv6AllowList(%q) = %v, want error containing %q", tc.spec, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not mention %q", err, tc.wantErr)
				}
				if !got.Empty() {
					t.Errorf("a failed parse returned %v, want nothing usable", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIPv6AllowList(%q): %v", tc.spec, err)
			}
			if !equalStrings(got.Interfaces, tc.wantIfaces) {
				t.Errorf("interfaces = %v, want %v", got.Interfaces, tc.wantIfaces)
			}
			var nets []string
			for _, n := range got.Prefixes {
				nets = append(nets, n.String())
			}
			if !equalStrings(nets, tc.wantNets) {
				t.Errorf("prefixes = %v, want %v", nets, tc.wantNets)
			}
			if want := len(tc.wantIfaces)+len(tc.wantNets) == 0; got.Empty() != want {
				t.Errorf("Empty() = %v, want %v", got.Empty(), want)
			}
		})
	}
}

// TestIPv6AllowListLookups covers the two questions the router warning asks of
// a parsed list: is this interface excepted, and is this address already inside
// an excepted prefix.
func TestIPv6AllowListLookups(t *testing.T) {
	a, err := ParseIPv6AllowList("he6,2001:db8:77b::/64")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !a.hasInterface("he6") {
		t.Error("he6 is in the list but hasInterface says no")
	}
	if a.hasInterface("he60") {
		t.Error("he60 is not in the list but hasInterface says yes")
	}
	if !a.coversIP(net.ParseIP("2001:db8:77b::2")) {
		t.Error("an address inside the excepted prefix reads as not covered")
	}
	if a.coversIP(net.ParseIP("2001:db8:77c::2")) {
		t.Error("an address outside the excepted prefix reads as covered")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
