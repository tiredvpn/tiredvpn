package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
				got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), id, newOrigin, "", nil)
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
	got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), reality, "198.51.100.152", "", nil)
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

// commandCounter counts the Redis commands a client sends, by name.
type commandCounter struct{ get, scan, keys atomic.Int64 }

func (c *commandCounter) DialHook(next redis.DialHook) redis.DialHook { return next }
func (c *commandCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		switch cmd.Name() {
		case "get":
			c.get.Add(1)
		case "scan":
			c.scan.Add(1)
		case "keys":
			c.keys.Add(1)
		}
		return next(ctx, cmd)
	}
}
func (c *commandCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// TestRepeatedHandshakesDoNotAskRedisForOldLeases is the other half of P3-6:
// the fold ran on every TUN handshake, and every old key it missed in memory
// was a Redis GET (a SCAN for a registry client) under the pool lock - for keys
// that no current server writes. Once a credential is folded, its next
// handshakes go straight to the allocation.
func TestRepeatedHandshakesDoNotAskRedisForOldLeases(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	for _, tc := range []struct {
		name   string
		srvCtx *serverContext
		id     func(*serverContext) clientIdentity
	}{
		{"global secret", &serverContext{cfg: &Config{Secret: global}}, func(*serverContext) clientIdentity { return sharedIdentity(globalClientID) }},
		{"registry client over REALITY", registryCtx([]byte("a-registry-client-secret-32bytes")), func(c *serverContext) clientIdentity {
			return realityIdentityFor(t, c, []byte("a-registry-client-secret-32bytes"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rdb := startRedis(t)
			count := &commandCounter{}
			rdb.AddHook(count)
			pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, rdb)
			if err != nil {
				t.Fatal(err)
			}
			srvCtx := srvCtxWithPool(tc.srvCtx, pool)
			id := tc.id(tc.srvCtx)
			first, err := allocateTunnelIP(srvCtx, id, "192.0.2.170", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			gets, scans := count.get.Load(), count.scan.Load()
			for range 5 {
				got, err := allocateTunnelIP(srvCtx, id, "192.0.2.170", "", nil)
				if err != nil || !got.Equal(first) {
					t.Fatalf("got %v (%v), want %s", got, err, first)
				}
			}
			if n := count.get.Load() - gets; n != 0 {
				t.Errorf("5 more handshakes sent %d GETs", n)
			}
			if n := count.scan.Load() - scans; n != 0 {
				t.Errorf("5 more handshakes sent %d SCANs", n)
			}
		})
	}
}

// TestFoldedKeysStayBounded: a global-secret key carries its origin, so the
// fold record grows with every address such a client comes from. It stays
// under its cap, and an expired record lets the fold run again.
func TestFoldedKeysStayBounded(t *testing.T) {
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range adoptFoldMax + 100 {
		pool.AdoptAll(context.Background(), nil, nil, "global@"+net.IPv4(198, 51, byte(i>>8), byte(i)).String(), nil)
	}
	if n := len(pool.folded); n > adoptFoldMax {
		t.Fatalf("%d fold records, cap %d", n, adoptFoldMax)
	}
	// P3-12 of the round-6 review: a full map dropped every record, and
	// every key searched again at once. Half of them stay.
	if n := len(pool.folded); n < adoptFoldMax/2 {
		t.Fatalf("%d fold records left after the cap was hit: the throttle was cleared", n)
	}
	pool.folded["global@192.0.2.1"] = time.Now().Add(-time.Second) // the record has run out
	if _, err := pool.Allocate("polling:global@192.0.2.1", net.ParseIP("10.8.1.9"), ""); err != nil {
		t.Fatal(err)
	}
	pool.AdoptAll(context.Background(), []string{"polling:global@192.0.2.1"}, nil, "global@192.0.2.1", nil)
	if _, left := leasesOf(pool)["polling:global@192.0.2.1"]; left {
		t.Fatal("an expired fold record kept the fold from running")
	}
}

// scanGate holds every SCAN until release is closed, or fails it when fail
// is set.
type scanGate struct {
	release chan struct{}
	fail    atomic.Bool
	scans   atomic.Int64
}

func (g *scanGate) DialHook(next redis.DialHook) redis.DialHook { return next }
func (g *scanGate) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "scan" {
			g.scans.Add(1)
			if g.fail.Load() {
				return errors.New("scan refused")
			}
			<-g.release
		}
		return next(ctx, cmd)
	}
}
func (g *scanGate) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// TestTheLeaseSearchDoesNotHoldThePool is P3-4 of the round-4 review: the
// Redis SCAN for a registry client's old REALITY leases ran under the pool
// lock - up to 64 round trips - and every allocation of every other client
// waited behind it.
func TestTheLeaseSearchDoesNotHoldThePool(t *testing.T) {
	rdb := startRedis(t)
	gate := &scanGate{release: make(chan struct{})}
	rdb.AddHook(gate)
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, rdb)
	if err != nil {
		t.Fatal(err)
	}
	searched := make(chan struct{})
	go func() {
		pool.AdoptAll(context.Background(), nil, []string{"reality:abc@"}, "c1", nil)
		close(searched)
	}()
	for gate.scans.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	allocated := make(chan error, 1)
	go func() { _, err := pool.Allocate("someone-else", nil, ""); allocated <- err }()
	select {
	case err := <-allocated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(gate.release)
		<-searched
		t.Fatal("an allocation waited for another client's lease search")
	}
	close(gate.release)
	<-searched
}

// TestAnUnfinishedLeaseSearchIsRetried: a search that failed or was cut
// short was still recorded as folded for 10 minutes, and a lease it missed
// was missed again and again. Then it was not recorded at all, and on a Redis
// where the search never finishes every handshake paid for it again (P3-8 of
// the round-5 review). It is retried after adoptRetryAfter.
func TestAnUnfinishedLeaseSearchIsRetried(t *testing.T) {
	rdb := startRedis(t)
	gate := &scanGate{release: make(chan struct{})}
	close(gate.release)
	gate.fail.Store(true)
	rdb.AddHook(gate)
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, rdb)
	if err != nil {
		t.Fatal(err)
	}
	expire := func() {
		pool.mu.Lock()
		pool.folded["c1"] = time.Now().Add(-time.Second)
		pool.mu.Unlock()
	}
	pool.AdoptAll(context.Background(), nil, []string{"reality:abc@"}, "c1", nil)
	pool.AdoptAll(context.Background(), nil, []string{"reality:abc@"}, "c1", nil)
	if n := gate.scans.Load(); n != 1 {
		t.Fatalf("%d searches: an unfinished one was repeated on the next handshake", n)
	}
	pool.mu.Lock()
	wait := time.Until(pool.folded["c1"])
	pool.mu.Unlock()
	if wait > adoptRetryAfter || wait < adoptRetryAfter-time.Second {
		t.Fatalf("an unfinished search waits %v, want %v", wait, adoptRetryAfter)
	}
	gate.fail.Store(false)
	expire()
	pool.AdoptAll(context.Background(), nil, []string{"reality:abc@"}, "c1", nil)
	if n := gate.scans.Load(); n != 2 {
		t.Fatalf("%d searches, want the failed one retried once its wait ran out", n)
	}
	pool.AdoptAll(context.Background(), nil, []string{"reality:abc@"}, "c1", nil)
	if n := gate.scans.Load(); n != 2 {
		t.Fatal("a finished search was repeated within its record")
	}
}

// TestAFullFoldMapWithTiedRecordsStillShrinks is P3-12 of the round-7
// review: the half to drop was picked by a cut time, and with every record
// ending at the same moment the cut deleted nothing, so the map grew past its
// cap. The map is filled by hand with tied records; the next fold goes
// through AdoptAll.
func TestAFullFoldMapWithTiedRecordsStillShrinks(t *testing.T) {
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	pool.folded = make(map[string]time.Time)
	for i := range adoptFoldMax {
		pool.folded[fmt.Sprintf("global@tied-%d", i)] = until
	}
	pool.AdoptAll(context.Background(), nil, nil, "global@192.0.2.7", nil)
	if n := len(pool.folded); n > adoptFoldMax/2+1 {
		t.Fatalf("%d fold records after the cap was hit with tied records, want about half of %d", n, adoptFoldMax)
	}
}
