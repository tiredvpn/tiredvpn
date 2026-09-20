package tun

import (
	"strings"
	"testing"
)

// TestIPv6RouteSpecStringAndCIDRs covers the two log/command-line renderings of
// a parsed -tun-routes6 value across its three states: unset (half-defaults),
// the explicit "none", and an operator-supplied list. String() is what a log
// line shows; CIDRs() is what a platform that shells out to `ip route` installs.
func TestIPv6RouteSpecStringAndCIDRs(t *testing.T) {
	halfDefaults := strings.Join(dualStackRouteCIDRs, ",")

	for _, tc := range []struct {
		name      string
		spec      string
		wantStr   string
		wantCIDRs []string
	}{
		{
			name:      "unset uses the half-defaults",
			spec:      "",
			wantStr:   halfDefaults,
			wantCIDRs: dualStackRouteCIDRs,
		},
		{
			name:      "none claims no destination",
			spec:      "none",
			wantStr:   "none",
			wantCIDRs: nil,
		},
		{
			name:      "explicit list renders as written",
			spec:      "2001:db8::/64,2001:db8:1::1",
			wantStr:   "2001:db8::/64,2001:db8:1::1",
			wantCIDRs: []string{"2001:db8::/64", "2001:db8:1::1/128"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ParseIPv6Routes(tc.spec)
			if err != nil {
				t.Fatalf("ParseIPv6Routes(%q): %v", tc.spec, err)
			}
			if got := spec.String(); got != tc.wantStr {
				t.Errorf("String() = %q, want %q", got, tc.wantStr)
			}
			cidrs, err := spec.CIDRs()
			if err != nil {
				t.Fatalf("CIDRs(): %v", err)
			}
			if len(cidrs) != len(tc.wantCIDRs) {
				t.Fatalf("CIDRs() = %v, want %v", cidrs, tc.wantCIDRs)
			}
			for i, want := range tc.wantCIDRs {
				if cidrs[i] != want {
					t.Errorf("CIDRs()[%d] = %q, want %q", i, cidrs[i], want)
				}
			}
		})
	}
}

// TestIPv6AllowListString pins the log rendering of a parsed -tun-ipv6-allow
// value: interfaces first (as written), then prefixes in canonical form, joined
// by commas. An empty list renders empty.
func TestIPv6AllowListString(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		want string
	}{
		{"empty", "", ""},
		{"interface only", "he6", "he6"},
		{"prefix only", "2001:db8:77b::/64", "2001:db8:77b::/64"},
		{"bare address becomes /128", "2001:db8:77b::2", "2001:db8:77b::2/128"},
		{"interfaces before prefixes", "he6,2001:db8:77b::/64,wg0", "he6,wg0,2001:db8:77b::/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseIPv6AllowList(tc.spec)
			if err != nil {
				t.Fatalf("ParseIPv6AllowList(%q): %v", tc.spec, err)
			}
			if got := a.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}
