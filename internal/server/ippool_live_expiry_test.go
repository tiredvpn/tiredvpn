package server

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestADynamicLeaseDoesNotExpireUnderALiveSession is P2-4 of the round-11
// review: a dynamic lease carries a finite TTL, only a handshake renewed it,
// and cleanup and the free-address scan reclaimed it whether a session was
// registered on it or not - so a session that outlived its lease had its
// address handed to another client, of another credential too. Memory and
// Redis pools, the lease time cut to 200 ms.
func TestADynamicLeaseDoesNotExpireUnderALiveSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		redis func(*testing.T) *redis.Client
	}{
		{"memory", func(*testing.T) *redis.Client { return nil }},
		{"redis", startRedis},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewIPPool(IPPoolConfig{Network: "10.8.0.0/24", ServerIP: "10.8.0.1", LeaseTime: 200 * time.Millisecond}, tc.redis(t))
			if err != nil {
				t.Fatal(err)
			}
			// The live lease is not the pool's first address, so a reclaimed
			// one cannot come back by chance on the next allocation.
			if _, err := p.Allocate("filler", nil, ""); err != nil {
				t.Fatal(err)
			}
			a, err := p.Allocate("global@203.0.113.7#saaaa", nil, "")
			if err != nil {
				t.Fatal(err)
			}
			// A TUN with a session on a, wired as the exit wires it.
			st := newTestSharedTUN(t)
			bindPoolToTUN(p, st)
			st.RegisterClientGated(a, "global", "203.0.113.7", nil, nil, nil)
			time.Sleep(400 * time.Millisecond)
			// Each place that reclaims a run-out lease, on its own: the
			// cleanup, the session's own handshake, the free-address scan.
			p.CleanupExpired()
			if got, err := p.Allocate("global@203.0.113.7#saaaa", nil, ""); err != nil || !got.Equal(a) {
				t.Fatalf("the live session's key now gets %v (%v), want %s", got, err, a)
			}
			time.Sleep(400 * time.Millisecond)
			b, err := p.Allocate("carol", nil, "")
			if err != nil {
				t.Fatal(err)
			}
			if b.Equal(a) {
				t.Fatalf("another credential got %s while a session was registered on it", a)
			}
			time.Sleep(400 * time.Millisecond)
			if got, err := p.Allocate("global@203.0.113.7#saaaa", nil, ""); err != nil || !got.Equal(a) {
				t.Fatalf("after its lease ran out, the live session's key gets %v (%v), want %s", got, err, a)
			}
			// Control: once the session is gone, the lease runs out as before.
			st.UnregisterClient(a, nil)
			time.Sleep(400 * time.Millisecond)
			if n := p.CleanupExpired(); n == 0 {
				t.Fatal("an expired lease with no session was not reclaimed")
			}
		})
	}
}
