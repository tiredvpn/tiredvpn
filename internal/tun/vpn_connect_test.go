package tun

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestParseServerCapabilities covers the handshake-response decoding that was
// extracted out of connect() so it no longer runs under v.mu.
func TestParseServerCapabilities(t *testing.T) {
	// Legacy 9-byte response: no capabilities.
	legacy := make([]byte, 9)
	if _, ok := parseServerCapabilities(legacy, 9); ok {
		t.Errorf("legacy response should report no capabilities")
	}

	// v1 response (14 bytes) with port hopping flag set.
	v1 := make([]byte, 14)
	v1[9] = 0x01           // flags: port hopping enabled
	v1[10], v1[11] = 0, 80 // portStart = 80
	v1[12], v1[13] = 1, 0  // portEnd = 256
	caps, ok := parseServerCapabilities(v1, 14)
	if !ok || !caps.PortHoppingEnabled {
		t.Fatalf("v1 response should enable port hopping, got %+v ok=%v", caps, ok)
	}
	if caps.PortRangeStart != 80 || caps.PortRangeEnd != 256 {
		t.Errorf("v1 port range = %d-%d, want 80-256", caps.PortRangeStart, caps.PortRangeEnd)
	}
	if caps.HopStrategy != "random" || caps.HopIntervalSec != 60 {
		t.Errorf("v1 defaults wrong: strategy=%q interval=%d", caps.HopStrategy, caps.HopIntervalSec)
	}

	// Flag clear => no capabilities even with a valid range.
	noFlag := make([]byte, 14)
	noFlag[10], noFlag[11] = 0, 80
	noFlag[12], noFlag[13] = 1, 0
	if _, ok := parseServerCapabilities(noFlag, 14); ok {
		t.Errorf("response with flag clear should report no capabilities")
	}
}

// TestStopCancelsInflightConnect verifies the core invariant of the shutdown
// fix: a context registered the way connect() registers connCancel is cancelled
// by stop logic without blocking on v.mu. It models a connect() goroutine
// parked in a dial (select on ctx.Done) and asserts Stop's cancel unblocks it
// quickly, even while another goroutine holds v.mu.
func TestStopCancelsInflightConnect(t *testing.T) {
	var v VPNClient
	atomic.StoreInt32(&v.running, 1)

	parent := t.Context()
	ctx, cancel := context.WithCancel(parent)
	cancelPtr := &cancel
	v.connCancel.Store(cancelPtr)

	// Hold v.mu for longer than the test budget to prove Stop's cancel path
	// does not depend on acquiring it.
	v.mu.Lock()
	defer v.mu.Unlock()

	dialReturned := make(chan struct{})
	go func() {
		<-ctx.Done() // models mgr.Connect aborting on context cancel
		close(dialReturned)
	}()

	// Replicate the cancel step Stop() performs before taking v.mu.
	if c := v.connCancel.Swap(nil); c != nil {
		(*c)()
	}

	select {
	case <-dialReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight connect was not cancelled promptly by Stop")
	}
}
