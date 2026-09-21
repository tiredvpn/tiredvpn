//go:build linux

package tun

import (
	"net"
	"sync"
	"testing"
)

// TestBypassUnroutableIsEdgeTriggered is the unit under the log-spam fix. The
// watcher calls the pin path every 5s; the reported bug was two WARN lines per
// v6 address on every one of those ticks, forever. The state machine that stops
// it must report a change exactly ONCE per transition, so the caller logs (and
// notifies the selector) once, not on every tick.
//
// Discriminator (rule 1): the pre-fix path logged unconditionally, which is the
// same as markBypassUnroutable always reporting a change. This test asserts the
// callback fires exactly once across five ticks, so that behaviour turns it red.
func TestBypassUnroutableIsEdgeTriggered(t *testing.T) {
	td := &TUNDevice{}

	var mu sync.Mutex
	var events []bool // one entry per notification, value = unroutable
	td.SetBypassUnroutableFunc(func(_ net.IP, unroutable bool) {
		mu.Lock()
		events = append(events, unroutable)
		mu.Unlock()
	})

	ip := net.ParseIP("2001:db8::1")

	// Five watcher ticks, all finding no physical route.
	changes := 0
	for range 5 {
		if td.markBypassUnroutable(ip) {
			changes++
		}
	}
	if changes != 1 {
		t.Fatalf("markBypassUnroutable reported %d changes over 5 ticks, want 1 (the rest are silent)", changes)
	}
	if !td.isBypassUnroutable(ip) {
		t.Fatal("address should read unroutable after the first tick")
	}

	// The route comes back: exactly one clear transition, then silence.
	if !td.clearBypassUnroutable(ip) {
		t.Fatal("clearBypassUnroutable should report the recovery transition")
	}
	if td.clearBypassUnroutable(ip) {
		t.Fatal("a second clear must be silent - nothing changed")
	}
	if td.isBypassUnroutable(ip) {
		t.Fatal("address should read routable after the route returned")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0] != true || events[1] != false {
		t.Fatalf("callback events = %v, want exactly [true false] (one exclude, one re-admit)", events)
	}
}

// TestBypassUnroutablePerAddress: one family losing its route must not touch
// another address's verdict - the v4 bypass keeps working when v6 has no route.
func TestBypassUnroutablePerAddress(t *testing.T) {
	td := &TUNDevice{}
	v6 := net.ParseIP("2001:db8::1")
	v4 := net.ParseIP("203.0.113.1")

	td.markBypassUnroutable(v6)
	if !td.isBypassUnroutable(v6) {
		t.Fatal("v6 should be unroutable")
	}
	if td.isBypassUnroutable(v4) {
		t.Fatal("v4 must be unaffected by the v6 verdict")
	}
}
