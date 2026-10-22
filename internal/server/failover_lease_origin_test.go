package server

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

// registryCtx is a server context with one registry client, c1.
func registryCtx(secret []byte) *serverContext {
	reg := NewClientRegistry(nil)
	c1 := &ClientConfig{ID: "c1", Secret: string(secret), Enabled: true}
	reg.byID[c1.ID] = c1
	reg.bySecret[c1.Secret] = c1
	return &serverContext{cfg: &Config{}, registry: reg}
}

// TestRegistryRealityLeaseFromAnotherOrigin is P3-6 of the round-3 review of
// PR #126. A registry client's REALITY lease was keyed "reality:<hmac>@origin"
// by older servers. The fold looked only under the origin the client comes from
// now, so a client that changed networks since (a phone moving from Wi-Fi to
// LTE) left its old lease behind for good - requested leases are permanent in
// Redis - and was handed a new address. Its key is origin-free now, so any
// origin's REALITY lease is its own.
//
// Run in memory, and through Redis after a restart of a pool whose leases are
// not reloaded at startup (outside 10.0.0.0/8, see leaseKeyPattern).
func TestRegistryRealityLeaseFromAnotherOrigin(t *testing.T) {
	secret := []byte("a-registry-client-secret-32bytes")
	srvCtx := registryCtx(secret)
	reality := realityIdentityFor(t, srvCtx, secret)
	const oldOrigin, newOrigin = "192.0.2.170", "198.51.100.152"
	oldKey := reality.id + "@" + oldOrigin

	for _, tc := range []struct {
		name    string
		network string
		redis   bool
	}{
		{"memory", "10.8.1.0/24", false},
		{"redis after restart", "172.20.1.0/24", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rdb *redis.Client
			if tc.redis {
				rdb = startRedis(t)
			}
			_, network, _ := net.ParseCIDR(tc.network)
			first := make(net.IP, 4)
			copy(first, network.IP.To4())
			first[3] = 7 // not the first free address, which a fresh allocation would get anyway
			cfg := IPPoolConfig{Network: tc.network, ServerIP: strings.TrimSuffix(tc.network, "0/24") + "1"}
			pool, err := NewIPPool(cfg, rdb)
			if err != nil {
				t.Fatal(err)
			}
			had, err := pool.Allocate(oldKey, first, "")
			if err != nil {
				t.Fatal(err)
			}
			if tc.redis {
				if pool, err = NewIPPool(cfg, rdb); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range []clientIdentity{reality, registryIdentity("c1")} {
				got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), id, newOrigin, nil)
				if err != nil || !got.Equal(had) {
					t.Fatalf("%s from %s got %v (%v); it holds %s from %s", id, newOrigin, got, err, had, oldOrigin)
				}
			}
			if _, left := leasesOf(pool)[oldKey]; left {
				t.Fatal("the lease under the old origin stayed behind")
			}
			if tc.redis {
				if n, _ := rdb.Exists(context.Background(), pool.redisClientKey(oldKey)).Result(); n != 0 {
					t.Fatal("the old origin's client key stayed in Redis")
				}
			}
		})
	}
}

// TestGlobalRealityLeaseOfAnotherOriginIsNotAdopted: on the global secret the
// REALITY key names a box, not a client - another origin's lease belongs to
// somebody else and must stay where it is.
func TestGlobalRealityLeaseOfAnotherOriginIsNotAdopted(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	srvCtx := &serverContext{cfg: &Config{Secret: global}}
	reality := realityIdentityFor(t, srvCtx, global)
	other := reality.id + "@192.0.2.170"

	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := pool.Allocate(other, net.ParseIP("10.8.1.2"), "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), reality, "198.51.100.152", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Equal(theirs) {
		t.Fatalf("a global-secret box took another origin's address %s", theirs)
	}
	if ip := leasesOf(pool)[other]; ip != theirs.String() {
		t.Fatalf("the other box's lease moved: %v", leasesOf(pool))
	}
}
