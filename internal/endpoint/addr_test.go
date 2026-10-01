package endpoint

import "testing"

func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in      string
		def     int
		want    string
		wantErr bool
	}{
		{in: "2001:db8::2", def: 995, want: "[2001:db8::2]:995"},
		{in: "[2001:db8::2]", def: 995, want: "[2001:db8::2]:995"},
		{in: "[2001:db8::2]:8443", def: 995, want: "[2001:db8::2]:8443"},
		{in: " 2001:db8::2 ", def: 995, want: "[2001:db8::2]:995"},
		{in: "fe80::1%eth0", def: 995, want: "[fe80::1%eth0]:995"},
		// A bare literal cannot carry a port: the trailing group is address.
		{in: "2001:db8::2:995", def: 443, want: "[2001:db8::2:995]:443"},
		{in: "203.0.113.10", def: 995, want: "203.0.113.10:995"},
		{in: "203.0.113.10:8443", def: 995, want: "203.0.113.10:8443"},
		{in: "vpn.example.org", def: 995, want: "vpn.example.org:995"},
		{in: "vpn.example.org:8443", def: 995, want: "vpn.example.org:8443"},
		{in: "", def: 995, want: ""},

		{in: "2001:db8::2", def: 0, wantErr: true},
		{in: "203.0.113.10", def: 0, wantErr: true},
		{in: "[2001:db8::2", def: 995, wantErr: true},
		{in: "[203.0.113.10]", def: 995, wantErr: true},
		{in: "2001:db8::zz", def: 995, wantErr: true},
		{in: "vpn.example.org:0", def: 995, wantErr: true},
		{in: "vpn.example.org:65536", def: 995, wantErr: true},
		{in: "vpn.example.org:", def: 995, wantErr: true},
		{in: ":995", def: 995, wantErr: true},
		{in: "vpn.example.org", def: 70000, wantErr: true},
	}
	for _, tc := range cases {
		got, err := NormalizeAddr(tc.in, tc.def)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeAddr(%q, %d) = %q, want an error", tc.in, tc.def, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("NormalizeAddr(%q, %d) = %q, %v; want %q", tc.in, tc.def, got, err, tc.want)
		}
		// Idempotent: the output fed back in comes out unchanged.
		if again, err := NormalizeAddr(got, tc.def); err != nil || again != got {
			t.Errorf("NormalizeAddr(%q) not idempotent: %q, %v", got, again, err)
		}
	}
}

func TestNormalizePair_PortFromTheOtherFamily(t *testing.T) {
	cases := []struct {
		v4, v6       string
		want4, want6 string
		wantErr      bool
	}{
		{"203.0.113.10:995", "2001:db8::2", "203.0.113.10:995", "[2001:db8::2]:995", false},
		{"203.0.113.10:995", "[2001:db8::2]", "203.0.113.10:995", "[2001:db8::2]:995", false},
		{"203.0.113.10:995", "[2001:db8::2]:8443", "203.0.113.10:995", "[2001:db8::2]:8443", false},
		{"203.0.113.10", "[2001:db8::2]:995", "203.0.113.10:995", "[2001:db8::2]:995", false},
		{"", "[2001:db8::2]:995", "", "[2001:db8::2]:995", false},
		{"203.0.113.10:995", "", "203.0.113.10:995", "", false},
		// Neither names a port: there is nothing to default from.
		{"203.0.113.10", "2001:db8::2", "", "", true},
		{"", "2001:db8::2", "", "", true},
	}
	for _, tc := range cases {
		g4, g6, err := NormalizePair(tc.v4, tc.v6)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizePair(%q, %q) = %q, %q; want an error", tc.v4, tc.v6, g4, g6)
			}
			continue
		}
		if err != nil || g4 != tc.want4 || g6 != tc.want6 {
			t.Errorf("NormalizePair(%q, %q) = %q, %q, %v; want %q, %q", tc.v4, tc.v6, g4, g6, err, tc.want4, tc.want6)
		}
	}
}

// TestCandidateStringOfNormalizedEndpoint pins the symptom the bug was found
// by: the log line for an IPv6 candidate read "2001:db8::2/v6".
func TestCandidateStringOfNormalizedEndpoint(t *testing.T) {
	ep, err := Endpoint{V4: "203.0.113.10:995", V6: "2001:db8::2"}.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	cands := buildCandidates([]Endpoint{ep}, PreferV6, []int{0})
	if got := cands[0].String(); got != "[2001:db8::2]:995/v6" {
		t.Fatalf("candidate = %q, want [2001:db8::2]:995/v6", got)
	}
}
