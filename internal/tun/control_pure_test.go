package tun

import (
	"net"
	"testing"
	"time"
)

// TestIPString covers the nil->"" mapping that keeps the omitempty JSON field
// absent when dual-stack was not negotiated. A non-nil address must render
// canonically; nil must be the empty string, not "<nil>".
func TestIPString(t *testing.T) {
	if got := ipString(nil); got != "" {
		t.Errorf("ipString(nil) = %q, want empty", got)
	}
	if got := ipString(net.IPv4(10, 8, 0, 2)); got != "10.8.0.2" {
		t.Errorf("ipString(v4) = %q, want 10.8.0.2", got)
	}
	if got := ipString(net.ParseIP("fd00:10:8::a08:2")); got != "fd00:10:8::a08:2" {
		t.Errorf("ipString(v6) = %q, want fd00:10:8::a08:2", got)
	}
}

// TestAddAutoReconnectJitter mirrors TestAddJitter for the control-server
// backoff: factor 0.3 means every draw stays inside [0.7d, 1.3d] and never goes
// negative. Only the envelope is asserted (verification rule 3).
func TestAddAutoReconnectJitter(t *testing.T) {
	const d = 4 * time.Second
	lo := time.Duration(float64(d) * 0.7)
	hi := time.Duration(float64(d) * 1.3)
	for i := 0; i < 10000; i++ {
		got := addAutoReconnectJitter(d)
		if got < lo || got > hi {
			t.Fatalf("addAutoReconnectJitter(%v) = %v, outside [%v, %v]", d, got, lo, hi)
		}
		if got < 0 {
			t.Fatalf("addAutoReconnectJitter(%v) = %v is negative", d, got)
		}
	}
	if got := addAutoReconnectJitter(0); got != 0 {
		t.Errorf("addAutoReconnectJitter(0) = %v, want 0", got)
	}
}
