package strategy

import "testing"

// TestReplacePortIPv6 guards net.JoinHostPort over fmt.Sprintf("%s:%d"): for an
// IPv6 endpoint the bare format produced 2001:db8::1:47000, an unparseable
// address, breaking every port hop on v6.
//
// Predicated against the broken code: restore the Sprintf in replacePort and the
// IPv6 case fails.
func TestReplacePortIPv6(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Close)

	cases := []struct {
		name   string
		target string
		port   int
		want   string
	}{
		{"ipv6", "[2001:db8::1]:995", 47000, "[2001:db8::1]:47000"},
		{"ipv4", "31.44.3.165:995", 47000, "31.44.3.165:47000"},
	}
	for _, tc := range cases {
		if got := m.replacePort(tc.target, tc.port); got != tc.want {
			t.Errorf("%s: replacePort(%q,%d)=%q, want %q", tc.name, tc.target, tc.port, got, tc.want)
		}
	}
}
