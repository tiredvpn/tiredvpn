package server

import (
	"context"
	"crypto/rand"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tiredvpn/tiredvpn/internal/log"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// realityIdentityFor runs the REALITY server's own authentication for a client
// holding secret and returns the identity the session gets - the path a REALITY
// handshake takes, from the auth token to realityClientIdentity.
func realityIdentityFor(t *testing.T, srvCtx *serverContext, secret []byte) clientIdentity {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	ext, err := customtls.NewClientREALITYExtension(secret, priv)
	if err != nil {
		t.Fatalf("NewClientREALITYExtension: %v", err)
	}
	_, id, _, ok := authenticateREALITYClient(srvCtx, ext, log.WithPrefix("test"))
	if !ok {
		t.Fatal("REALITY auth failed for a known secret")
	}
	return id
}

// TestOneClientKeepsItsLeaseAcrossTransports is N2 of the PR #126 acceptance
// run. The tunnel address is sticky per lease key, and the key was the
// identity as each transport spells it: "reality:<hmac>" for REALITY, "global"
// for Geneva/WS/confusion/SSH/IMAP, "polling:global" for HTTP polling. A client
// moving its live tunnel from Geneva to REALITY (the D3 upgrade) came back as
// somebody else - "Requested IP 10.8.1.2 already leased to client reality:...;
// will be auto-allocated a different IP" - and the move was thrown away every
// time.
//
// One secret, one client, one origin: every transport must land on one lease.
func TestOneClientKeepsItsLeaseAcrossTransports(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	perClient := []byte("a-registry-client-secret-32bytes")

	reg := NewClientRegistry(nil)
	c1 := &ClientConfig{ID: "c1", Name: "laptop", Secret: string(perClient), Enabled: true}
	reg.byID[c1.ID] = c1
	reg.bySecret[c1.Secret] = c1
	srvCtx := &serverContext{cfg: &Config{Secret: global}, registry: reg}

	const origin = "192.0.2.170"
	cases := []struct {
		name   string
		secret []byte
		others []clientIdentity // what the other transports resolve for it
	}{
		{"global secret", global, []clientIdentity{
			sharedIdentity(globalClientID),                     // Geneva, WS, confusion, SSH, IMAP, morph, QUIC
			sharedIdentity(globalClientID).prefixed("polling"), // HTTP polling
		}},
		{"registry client", perClient, []clientIdentity{
			registryIdentity("c1"),
			registryIdentity("c1").prefixed("polling"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reality := realityIdentityFor(t, srvCtx, tc.secret)
			want := allocationKey(reality, origin)
			for _, other := range tc.others {
				if got := allocationKey(other, origin); got != want {
					t.Errorf("%s keys lease %q, REALITY keys %q: one client, two addresses", other, got, want)
				}
			}

			// Against a real pool: the session that came in over another
			// transport holds the address, REALITY asks for it and gets it.
			pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			held, err := pool.Allocate(allocationKey(tc.others[0], origin), net.ParseIP("10.8.1.4"), "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := pool.Allocate(want, held, "")
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(held) {
				t.Fatalf("REALITY got %s while the same client holds %s over another transport", got, held)
			}
		})
	}
}

// TestGlobalSecretStillSeparatesOrigins: the cross-transport lease must not
// undo the global-secret collision fix. Two boxes on the global secret at two
// origins keep two leases, on any mix of transports.
func TestGlobalSecretStillSeparatesOrigins(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	srvCtx := &serverContext{cfg: &Config{Secret: global}}
	reality := realityIdentityFor(t, srvCtx, global)

	if allocationKey(reality, "192.0.2.161") == allocationKey(sharedIdentity(globalClientID), "198.51.100.152") {
		t.Fatal("two boxes on the global secret at two origins share a lease")
	}
	if allocationKey(reality, "192.0.2.161") == allocationKey(reality, "198.51.100.152") {
		t.Fatal("two REALITY boxes on the global secret at two origins share a lease")
	}
}

// TestLeaseCarriesOverFromTheOldKey: a client that held an address under the
// key an older server spelled for it - REALITY's "reality:<hmac>@origin" -
// keeps that address after the update, and the old key is gone. Requested
// leases are permanent in Redis; without the carry-over each client would leave
// an orphan and come back on another address.
func TestLeaseCarriesOverFromTheOldKey(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	srvCtx := &serverContext{cfg: &Config{Secret: global}}
	reality := realityIdentityFor(t, srvCtx, global)
	const origin = "192.0.2.170"

	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := reality.id + "@" + origin
	had, err := pool.Allocate(oldKey, net.ParseIP("10.8.1.2"), "")
	if err != nil {
		t.Fatal(err)
	}

	got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), reality, origin, had)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(had) {
		t.Fatalf("after the update the client got %s, it held %s", got, had)
	}
	if lease := pool.GetLease(had); lease == nil || lease.ClientID != allocationKey(reality, origin) {
		t.Fatalf("lease %s is held by %+v, want the new key", had, lease)
	}
	// And Geneva on the same client now lands on it too.
	geneva, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), sharedIdentity(globalClientID), origin, net.ParseIP("10.8.1.9"))
	if err != nil {
		t.Fatal(err)
	}
	if !geneva.Equal(had) {
		t.Fatalf("Geneva got %s, the client's address is %s", geneva, had)
	}
}

// TestRegistryRealityLeaseCarriesOver: a registry client on REALITY used to be
// keyed "reality:<hmac>@origin" (its REALITY id was classified as shared); the
// credential lease keys it on its client ID. The address comes along.
func TestRegistryRealityLeaseCarriesOver(t *testing.T) {
	secret := []byte("a-registry-client-secret-32bytes")
	reg := NewClientRegistry(nil)
	c1 := &ClientConfig{ID: "c1", Secret: string(secret), Enabled: true}
	reg.byID[c1.ID] = c1
	reg.bySecret[c1.Secret] = c1
	srvCtx := &serverContext{cfg: &Config{}, registry: reg}
	reality := realityIdentityFor(t, srvCtx, secret)
	const origin = "192.0.2.170"

	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	had, err := pool.Allocate(reality.id+"@"+origin, net.ParseIP("10.8.1.2"), "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), reality, origin, had)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(had) || allocationKey(reality, origin) != "c1" {
		t.Fatalf("registry REALITY client got %s under %q, it held %s", got, allocationKey(reality, origin), had)
	}
}

// startRedis runs a throwaway redis-server for the test, or skips.
func startRedis(t *testing.T) *redis.Client {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cmd := exec.Command(bin, "--port", strconv.Itoa(port), "--save", "", "--appendonly", "no")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	rdb := redis.NewClient(&redis.Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
	t.Cleanup(func() { rdb.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for rdb.Ping(context.Background()).Err() != nil {
		if time.Now().After(deadline) {
			t.Fatal("redis-server did not come up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return rdb
}

func leasesOf(pool *IPPool) map[string]string { // key -> ip
	out := map[string]string{}
	for _, l := range pool.ListLeases() {
		out[l.ClientID] = l.IP
	}
	return out
}

// TestLeaseMigrationLeavesNoOrphans is P2-6 of the round-2 review, through
// Redis and a restart. While N2 was unfixed a client could collect two leases
// - one under its REALITY key, one under the plain one - and Adopt returned
// early when the new key already had a lease, leaving the other permanent. A
// client whose old lease was REALITY and who came back over another transport
// was not migrated at all.
func TestLeaseMigrationLeavesNoOrphans(t *testing.T) {
	rdb := startRedis(t)
	global := []byte("the-global-secret-of-this-exit-32")
	srvCtx := &serverContext{cfg: &Config{Secret: global}}
	const origin = "192.0.2.170"
	realityOld := realityIdentityFor(t, srvCtx, global).id + "@" + origin
	cfg := IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}

	t.Run("both leases exist", func(t *testing.T) {
		pool, err := NewIPPool(cfg, rdb)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Allocate(realityOld, net.ParseIP("10.8.1.2"), ""); err != nil {
			t.Fatal(err)
		}
		plain, err := pool.Allocate("global@"+origin, net.ParseIP("10.8.1.4"), "")
		if err != nil {
			t.Fatal(err)
		}
		got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), sharedIdentity(globalClientID), origin, plain)
		if err != nil || !got.Equal(plain) {
			t.Fatalf("got %v (%v), want %s", got, err, plain)
		}
		if ip, left := leasesOf(pool)[realityOld]; left {
			t.Fatalf("the REALITY lease %s stayed behind as an orphan", ip)
		}

		// After a restart from Redis, still one lease.
		again, err := NewIPPool(cfg, rdb)
		if err != nil {
			t.Fatal(err)
		}
		if ip, left := leasesOf(again)[realityOld]; left {
			t.Fatalf("the orphan %s came back from Redis", ip)
		}
		rdb.FlushAll(context.Background())
	})

	t.Run("old lease on another transport", func(t *testing.T) {
		pool, err := NewIPPool(cfg, rdb)
		if err != nil {
			t.Fatal(err)
		}
		had, err := pool.Allocate(realityOld, net.ParseIP("10.8.1.2"), "")
		if err != nil {
			t.Fatal(err)
		}
		// The client comes back over Geneva, asking for some other address.
		got, err := allocateTunnelIP(srvCtxWithPool(srvCtx, pool), sharedIdentity(globalClientID), origin, net.ParseIP("10.8.1.9"))
		if err != nil || !got.Equal(had) {
			t.Fatalf("over Geneva the client got %v (%v), its address is %s", got, err, had)
		}
		if _, left := leasesOf(pool)[realityOld]; left {
			t.Fatal("the REALITY lease was not migrated")
		}
		rdb.FlushAll(context.Background())
	})

	t.Run("concurrent", func(t *testing.T) {
		pool, err := NewIPPool(cfg, rdb)
		if err != nil {
			t.Fatal(err)
		}
		had, err := pool.Allocate(realityOld, net.ParseIP("10.8.1.2"), "")
		if err != nil {
			t.Fatal(err)
		}
		reality := realityIdentityFor(t, srvCtx, global)
		var wg sync.WaitGroup
		got := make([]net.IP, 8)
		for i := range got {
			id := sharedIdentity(globalClientID)
			if i%2 == 0 {
				id = reality
			}
			wg.Go(func() {
				got[i], _ = allocateTunnelIP(srvCtxWithPool(srvCtx, pool), id, origin, nil)
			})
		}
		wg.Wait()
		for i, ip := range got {
			if !ip.Equal(had) {
				t.Fatalf("allocation %d got %v, want %s", i, ip, had)
			}
		}
		if n := len(leasesOf(pool)); n != 1 {
			t.Fatalf("%d leases after concurrent migration, want 1: %v", n, leasesOf(pool))
		}
	})
}

func srvCtxWithPool(srvCtx *serverContext, pool *IPPool) *serverContext {
	return &serverContext{cfg: srvCtx.cfg, registry: srvCtx.registry, ipPool: pool}
}
