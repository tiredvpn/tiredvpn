package tun

import "testing"

func TestNormalizeRoute(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "bare ipv4 gets /32", in: "142.132.151.126", want: "142.132.151.126/32"},
		{name: "bare ipv4 zero", in: "10.0.0.1", want: "10.0.0.1/32"},
		{name: "bare ipv6 gets /128", in: "2001:db8::1", want: "2001:db8::1/128"},
		{name: "ipv4 cidr unchanged", in: "10.0.0.0/24", want: "10.0.0.0/24"},
		{name: "ipv4 host cidr unchanged", in: "10.0.0.5/32", want: "10.0.0.5/32"},
		{name: "ipv6 cidr unchanged", in: "2001:db8::/32", want: "2001:db8::/32"},
		{name: "default route unchanged", in: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "garbage errors", in: "not-an-ip", wantErr: true},
		{name: "empty errors", in: "", wantErr: true},
		{name: "bad mask errors", in: "10.0.0.0/99", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeRoute(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeRoute(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeRoute(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("normalizeRoute(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
