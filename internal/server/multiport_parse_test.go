package server

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// TestParsePort covers the single-port validator behind every -port flag form.
// Port 0 and anything above 65535 must be refused here, because the listener
// would otherwise bind an arbitrary kernel-chosen port and the published
// endpoint would silently stop matching what clients dial.
func TestParsePort(t *testing.T) {
	valid := []struct {
		in   string
		want int
	}{
		{"995", 995},
		{"1", 1},
		{"65535", 65535},
		{" 47000 ", 47000},
		{"\t443\t", 443},
	}
	for _, tt := range valid {
		got, err := parsePort(tt.in)
		if err != nil {
			t.Errorf("parsePort(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parsePort(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}

	for _, bad := range []string{"", "0", "-1", "65536", "99999", "abc", "  "} {
		if got, err := parsePort(bad); err == nil {
			t.Errorf("parsePort(%q) = %d, want an error", bad, got)
		}
	}
}

// TestParsePortRange covers the flag values an operator actually types. A range
// that silently collapses to one port takes port hopping offline without any
// visible error.
func TestParsePortRange(t *testing.T) {
	t.Run("single port", func(t *testing.T) {
		got, err := ParsePortRange("995", 0)
		if err != nil {
			t.Fatalf("ParsePortRange: %v", err)
		}
		if len(got) != 1 || got[0] != 995 {
			t.Errorf("got %v, want [995]", got)
		}
	})

	t.Run("range", func(t *testing.T) {
		got, err := ParsePortRange("47000-47004", 0)
		if err != nil {
			t.Fatalf("ParsePortRange: %v", err)
		}
		want := []int{47000, 47001, 47002, 47003, 47004}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})

	t.Run("range with whitespace", func(t *testing.T) {
		got, err := ParsePortRange(" 47000 - 47002 ", 0)
		if err != nil {
			t.Fatalf("ParsePortRange: %v", err)
		}
		if len(got) != 3 {
			t.Errorf("got %v, want 3 ports", got)
		}
	})

	t.Run("reversed range is normalised", func(t *testing.T) {
		got, err := ParsePortRange("47100-47000", 0)
		if err != nil {
			t.Fatalf("ParsePortRange: %v", err)
		}
		if len(got) != 101 {
			t.Errorf("got %d ports, want 101 (the bounds must be swapped, not rejected)", len(got))
		}
	})

	t.Run("maxPorts caps the list", func(t *testing.T) {
		got, err := ParsePortRange("47000-47100", 10)
		if err != nil {
			t.Fatalf("ParsePortRange: %v", err)
		}
		if len(got) != 10 {
			t.Fatalf("got %d ports, want 10", len(got))
		}
		seen := make(map[int]bool, len(got))
		for _, p := range got {
			if p < 47000 || p > 47100 {
				t.Errorf("port %d is outside the requested range", p)
			}
			if seen[p] {
				t.Errorf("port %d appears twice; each listener needs its own port", p)
			}
			seen[p] = true
		}
	})

	t.Run("single port ignores maxPorts", func(t *testing.T) {
		got, err := ParsePortRange("995", 5)
		if err != nil {
			t.Fatalf("ParsePortRange: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("got %v, want a single port", got)
		}
	})

	t.Run("empty value", func(t *testing.T) {
		_, err := ParsePortRange("", 0)
		if !errors.Is(err, ErrInvalidRange) {
			t.Errorf("err = %v, want ErrInvalidRange", err)
		}
	})

	rejections := []struct {
		in         string
		wantReason string
	}{
		{"abc", "invalid port"},
		{"0", "invalid port"},
		{"70000", "invalid port"},
		{"abc-47100", "invalid start port"},
		{"47000-xyz", "invalid end port"},
		{"47000-70000", "invalid end port"},
		{"0-47100", "invalid start port"},
	}
	for _, tt := range rejections {
		t.Run("reject "+tt.in, func(t *testing.T) {
			got, err := ParsePortRange(tt.in, 0)
			if err == nil {
				t.Fatalf("ParsePortRange(%q) = %v, want an error", tt.in, got)
			}
			if !strings.Contains(err.Error(), tt.wantReason) {
				t.Errorf("err = %q, want it to say %q", err, tt.wantReason)
			}
		})
	}

	// A leading "-" is not a range separator (Index returns 0, not > 0), so the
	// whole value is parsed as one port and rejected as negative.
	if _, err := ParsePortRange("-995", 0); err == nil {
		t.Error("ParsePortRange(\"-995\") = nil error, want a rejection")
	}
}

// TestNewMultiPortListenerFromRange covers the constructor's two shapes: one
// port yields a plain listener, several yield the fan-in listener. Ports are
// requested as :0 so the test never fights an occupied port.
func TestNewMultiPortListenerFromRange(t *testing.T) {
	t.Run("invalid range fails before binding", func(t *testing.T) {
		if ln, err := NewMultiPortListenerFromRange("127.0.0.1", "not-a-port", 0); err == nil {
			ln.Close()
			t.Error("a bad port range produced a listener")
		}
	})

	t.Run("single port", func(t *testing.T) {
		// Find a free port, release it, then ask the constructor for it.
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("cannot bind a local port in this environment: %v", err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		probe.Close()

		ln, err := NewMultiPortListenerFromRange("127.0.0.1", itoa(port), 0)
		if err != nil {
			t.Skipf("port %d was taken between probe and bind: %v", port, err)
		}
		defer ln.Close()

		if got := ln.Addr().(*net.TCPAddr).Port; got != port {
			t.Errorf("listener bound port %d, want %d", got, port)
		}
	})
}
