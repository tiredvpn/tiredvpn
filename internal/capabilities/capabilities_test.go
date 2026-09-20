package capabilities

import (
	"strings"
	"testing"
)

func TestSetString(t *testing.T) {
	for _, c := range []struct {
		name string
		set  Set
		want string
	}{
		{
			name: "none",
			set:  Set{},
			want: "missing=[CAP_NET_ADMIN,CAP_NET_RAW,/dev/net/tun]",
		},
		{
			name: "all",
			set:  Set{HasNetAdmin: true, HasNetRaw: true, HasTUNDevice: true},
			want: "have=[CAP_NET_ADMIN,CAP_NET_RAW,/dev/net/tun]",
		},
		{
			name: "admin only",
			set:  Set{HasNetAdmin: true},
			want: "have=[CAP_NET_ADMIN] missing=[CAP_NET_RAW,/dev/net/tun]",
		},
		{
			name: "raw and tun",
			set:  Set{HasNetRaw: true, HasTUNDevice: true},
			want: "have=[CAP_NET_RAW,/dev/net/tun] missing=[CAP_NET_ADMIN]",
		},
		{
			name: "tun only",
			set:  Set{HasTUNDevice: true},
			want: "have=[/dev/net/tun] missing=[CAP_NET_ADMIN,CAP_NET_RAW]",
		},
	} {
		if got := c.set.String(); got != c.want {
			t.Errorf("%s: String() = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSetStringOrderAndPartition pins that every capability appears exactly
// once, in declaration order, split across have/missing by its flag.
func TestSetStringOrderAndPartition(t *testing.T) {
	s := Set{HasNetAdmin: true, HasNetRaw: false, HasTUNDevice: true}
	got := s.String()
	for _, name := range []string{"CAP_NET_ADMIN", "CAP_NET_RAW", "/dev/net/tun"} {
		if strings.Count(got, name) != 1 {
			t.Errorf("String()=%q: %q should appear exactly once", got, name)
		}
	}
	// CAP_NET_ADMIN before /dev/net/tun in the "have" list preserves label order.
	if !strings.Contains(got, "have=[CAP_NET_ADMIN,/dev/net/tun]") {
		t.Errorf("String()=%q: have list wrong order/content", got)
	}
}

// TestProbeSmoke verifies Probe runs without panic and returns a Set whose
// String() accounts for all three capabilities exactly once (each is either
// held or missing, never both, never absent). Works on every platform: on
// non-linux Probe returns the zero Set (all missing).
func TestProbeSmoke(t *testing.T) {
	s := Probe()
	str := s.String()
	for _, name := range []string{"CAP_NET_ADMIN", "CAP_NET_RAW", "/dev/net/tun"} {
		if strings.Count(str, name) != 1 {
			t.Errorf("Probe().String()=%q: %q not accounted for exactly once", str, name)
		}
	}
}
