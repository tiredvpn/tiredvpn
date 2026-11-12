package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeStats is the store side of FlushStats, with the semantics of
// addStatsScript: deltas add up, a deleted client is not written back.
type fakeStats struct {
	mu      sync.Mutex
	total   map[string]StatsDelta
	gone    map[string]bool
	fail    error         // every delta fails with it
	block   chan struct{} // AddStatsDeltas waits on it, for a stuck Redis
	batches int
}

func newFakeStats() *fakeStats {
	return &fakeStats{total: map[string]StatsDelta{}, gone: map[string]bool{}}
}

func (f *fakeStats) AddStatsDeltas(ctx context.Context, deltas []StatsDelta) []error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches++
	errs := make([]error, len(deltas))
	for i, d := range deltas {
		switch {
		case f.fail != nil:
			errs[i] = f.fail
		case f.gone[d.ClientID]:
			errs[i] = errClientGone
		default:
			cur := f.total[d.ClientID]
			cur.Conns += d.Conns
			cur.BytesUp += d.BytesUp
			cur.BytesDown += d.BytesDown
			cur.ActiveConns = d.ActiveConns
			if d.LastSeen.After(cur.LastSeen) {
				cur.LastSeen = d.LastSeen
			}
			f.total[d.ClientID] = cur
		}
	}
	return errs
}

func (f *fakeStats) get(id string) StatsDelta {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.total[id]
}

func statsRegistry(t *testing.T, store statsStore) *ClientRegistry {
	t.Helper()
	reg := trafficRegistry(t)
	reg.stats = store
	return reg
}

// TestFlushStatsAddsWhatMoved: each flush adds what moved since the last one,
// once, and a flush with nothing new writes nothing.
func TestFlushStatsAddsWhatMoved(t *testing.T) {
	store := newFakeStats()
	reg := statsRegistry(t, store)

	reg.AddBytes(trafficClient, 100, 900)
	if err := reg.FlushStats(t.Context()); err != nil {
		t.Fatal(err)
	}
	reg.AddBytes(trafficClient, 1, 2)
	reg.FlushStats(t.Context())
	if got := store.get(trafficClient); got.BytesUp != 101 || got.BytesDown != 902 {
		t.Fatalf("stored up/down = %d/%d, want 101/902", got.BytesUp, got.BytesDown)
	}

	batches := store.batches
	reg.FlushStats(t.Context())
	if store.batches != batches {
		t.Fatal("an idle flush wrote to the store")
	}
}

// TestFlushStatsSharedStoreAddsUp is the review's case: two servers on one
// Redis used to overwrite each other's totals (1200, then 1111, for a true
// 1211). Deltas add up, and each server reports only its own traffic.
func TestFlushStatsSharedStoreAddsUp(t *testing.T) {
	store := newFakeStats()
	store.total[trafficClient] = StatsDelta{BytesUp: 1000}
	a, b := statsRegistry(t, store), statsRegistry(t, store)

	a.AddBytes(trafficClient, 100, 0)
	a.FlushStats(t.Context())
	b.AddBytes(trafficClient, 10, 0)
	b.FlushStats(t.Context())
	a.AddBytes(trafficClient, 100, 0)
	a.FlushStats(t.Context())
	b.AddBytes(trafficClient, 1, 0)
	b.FlushStats(t.Context())

	if got := store.get(trafficClient).BytesUp; got != 1211 {
		t.Fatalf("stored bytes_up = %d, want 1211", got)
	}
	if ga, gb := a.GetStats(trafficClient).BytesUp, b.GetStats(trafficClient).BytesUp; ga != 200 || gb != 11 {
		t.Fatalf("servers report %d and %d, want their own 200 and 11 (a sum over servers must count each byte once)", ga, gb)
	}
}

// TestFlushStatsRetriesFailedDelta: a delta the store did not take goes out
// with the next flush, whole and once.
func TestFlushStatsRetriesFailedDelta(t *testing.T) {
	store := newFakeStats()
	store.fail = errors.New("redis down")
	reg := statsRegistry(t, store)

	reg.AddBytes(trafficClient, 5, 6)
	if err := reg.FlushStats(t.Context()); err == nil {
		t.Fatal("a flush the store refused reported success")
	}
	reg.AddBytes(trafficClient, 1, 1)
	store.mu.Lock()
	store.fail = nil
	store.mu.Unlock()
	reg.FlushStats(t.Context())
	reg.FlushStats(t.Context())
	if got := store.get(trafficClient); got.BytesUp != 6 || got.BytesDown != 7 {
		t.Fatalf("stored up/down = %d/%d, want 6/7", got.BytesUp, got.BytesDown)
	}
}

// TestFlushStatsDoesNotWriteBackDeletedClient: a client the store no longer
// has gets nothing written back and its counters go; one the registry dropped
// (disabled, expired, a missed delete event) goes once it is idle.
func TestFlushStatsDoesNotWriteBackDeletedClient(t *testing.T) {
	store := newFakeStats()
	reg := statsRegistry(t, store)

	reg.AddBytes(trafficClient, 5, 5)
	store.gone[trafficClient] = true
	reg.FlushStats(t.Context())
	if reg.lookupTraffic(trafficClient) != nil {
		t.Fatal("counters of a deleted client survived the flush")
	}
	if _, ok := store.total[trafficClient]; ok {
		t.Fatal("a deleted client's record was written back")
	}

	reg.AddBytes(quietClient, 1, 1)
	reg.FlushStats(t.Context())
	reg.mu.Lock()
	delete(reg.byID, quietClient)
	reg.mu.Unlock()
	reg.FlushStats(t.Context())
	if reg.lookupTraffic(quietClient) != nil {
		t.Fatal("counters of a client the registry dropped survived an idle flush")
	}
	if reg.traffic(quietClient) != nil {
		t.Fatal("counters were created for a client the registry does not have")
	}
}

// TestFlushStatsGivesUpBehindStuckFlush: a flush that cannot start within its
// context returns instead of waiting for one stuck on Redis. Before, the
// shutdown flush queued behind the periodic one and the process never exited.
func TestFlushStatsGivesUpBehindStuckFlush(t *testing.T) {
	store := newFakeStats()
	store.block = make(chan struct{})
	reg := statsRegistry(t, store)
	reg.AddBytes(trafficClient, 1, 1)

	stuck := make(chan struct{})
	go func() {
		defer close(stuck)
		reg.FlushStats(context.Background())
	}()
	for len(reg.flushSem) == 0 {
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := reg.FlushStats(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's deadline", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("gave up after %v", took)
	}
	close(store.block)
	<-stuck
}

// TestStatsLastSeen: last_seen is when the client was seen - a packet, a
// connection opening or closing - and a flush does not move it.
func TestStatsLastSeen(t *testing.T) {
	store := newFakeStats()
	reg := statsRegistry(t, store)

	if s := reg.GetStats(trafficClient); !s.LastSeen.IsZero() {
		t.Fatalf("never-seen client has last_seen %v", s.LastSeen)
	}
	reg.traffic(trafficClient).addDown(1)
	seen := reg.GetStats(trafficClient).LastSeen
	if seen.IsZero() || time.Since(seen) > 2*time.Second {
		t.Fatalf("last_seen after a packet = %v", seen)
	}
	reg.FlushStats(t.Context())
	time.Sleep(1100 * time.Millisecond)
	reg.FlushStats(t.Context())
	if got := reg.GetStats(trafficClient).LastSeen; !got.Equal(seen) {
		t.Fatalf("a flush moved last_seen from %v to %v", seen, got)
	}
	if got := store.get(trafficClient).LastSeen; !got.Equal(seen) {
		t.Fatalf("stored last_seen %v, want %v", got, seen)
	}
}

// testRedis starts a private redis-server for the test, or skips when there
// is none on the host. CI has none: the store's Lua script is exercised where
// a developer runs the suite.
func testRedis(t *testing.T) *RedisStore {
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
	cmd := exec.Command(bin, "--port", strconv.Itoa(port), "--bind", "127.0.0.1",
		"--save", "", "--appendonly", "no", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatalf("start redis-server: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; ; i++ {
		c := redis.NewClient(&redis.Options{Addr: addr})
		err := c.Ping(t.Context()).Err()
		c.Close()
		if err == nil {
			break
		}
		if i == 100 {
			t.Fatalf("redis-server did not come up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	store, err := NewRedisStore(addr, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// redisRecord reads a stats key raw, as an operator with redis-cli sees it.
func redisRecord(t *testing.T, store *RedisStore, id string) map[string]any {
	t.Helper()
	raw, err := store.client.Get(t.Context(), store.statsKey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("stats record %q is not JSON: %v", raw, err)
	}
	return m
}

func redisClient(t *testing.T, store *RedisStore, name string) *ClientConfig {
	t.Helper()
	cfg, err := store.CreateClient(t.Context(), name, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestRedisStatsDeltas drives the real script: deltas from two writers add
// up exactly, large totals keep their low digits, the record stays readable
// by GetStats, and the later last_seen wins.
func TestRedisStatsDeltas(t *testing.T) {
	store := testRedis(t)
	c := redisClient(t, store, "alice")
	ctx := t.Context()

	early := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)
	late := early.Add(time.Hour)
	const big = 1<<50 + 3
	for _, d := range []StatsDelta{
		{ClientID: c.ID, Conns: 2, BytesUp: big, BytesDown: 7, ActiveConns: 1, LastSeen: late},
		{ClientID: c.ID, Conns: 1, BytesUp: big, BytesDown: 0, ActiveConns: 0, LastSeen: early},
		{ClientID: c.ID, BytesDown: 5},
	} {
		if err := store.AddStatsDeltas(ctx, []StatsDelta{d})[0]; err != nil {
			t.Fatalf("AddStatsDeltas: %v", err)
		}
	}

	got, err := store.GetStats(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalConns != 3 || got.BytesUp != 2*big || got.BytesDown != 12 || got.ActiveConns != 0 {
		t.Fatalf("record conns/up/down/active = %d/%d/%d/%d, want 3/%d/12/0",
			got.TotalConns, got.BytesUp, got.BytesDown, got.ActiveConns, 2*big)
	}
	if !got.LastSeen.Equal(late) {
		t.Fatalf("last_seen = %v, want the later %v", got.LastSeen, late)
	}
	if rec := redisRecord(t, store, c.ID); rec["format"] != float64(statsRecordFormat) || rec["client_id"] != c.ID {
		t.Fatalf("record lacks its format marker or id: %v", rec)
	}
}

// TestRedisStatsLegacyRecordStartsOver: a record without the format marker was
// written by the shared counter of 1.11.8, which summed connections and some
// paths' bytes into all three fields. None of them is kept - whatever their
// values, including the N/N/N a new record can legitimately hold.
func TestRedisStatsLegacyRecordStartsOver(t *testing.T) {
	store := testRedis(t)
	ctx := t.Context()
	for name, legacy := range map[string]string{
		"conns as bytes":     `{"client_id":"x","total_conns":1611,"bytes_up":1611,"bytes_down":1611}`,
		"conns plus proxied": `{"client_id":"x","total_conns":85000012,"bytes_up":85000012,"bytes_down":85000012}`,
		"not json":           `garbage`,
		"another format":     `{"total_conns":9,"bytes_up":9,"bytes_down":9,"format":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := redisClient(t, store, name)
			store.client.Set(ctx, store.statsKey(c.ID), legacy, 0)
			if err := store.AddStatsDeltas(ctx, []StatsDelta{{ClientID: c.ID, Conns: 1, BytesUp: 7, BytesDown: 8}})[0]; err != nil {
				t.Fatal(err)
			}
			got, _ := store.GetStats(ctx, c.ID)
			if got.TotalConns != 1 || got.BytesUp != 7 || got.BytesDown != 8 {
				t.Fatalf("conns/up/down = %d/%d/%d, want 1/7/8", got.TotalConns, got.BytesUp, got.BytesDown)
			}
		})
	}
}

// TestRedisStatsDeletedClientStaysDeleted: after DeleteClient the flush must
// not recreate the stats key, and the registry drops the counters.
func TestRedisStatsDeletedClientStaysDeleted(t *testing.T) {
	store := testRedis(t)
	ctx := t.Context()
	c := redisClient(t, store, "bob")

	reg := NewClientRegistry(store)
	reg.byID[c.ID] = c
	reg.bySecret[c.Secret] = c
	reg.AddBytes(c.ID, 10, 10)
	if err := reg.FlushStats(ctx); err != nil {
		t.Fatal(err)
	}
	if redisRecord(t, store, c.ID) == nil {
		t.Fatal("first flush wrote no record")
	}

	if err := store.DeleteClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	reg.AddBytes(c.ID, 1, 1) // traffic of a session still open, or a missed delete event
	reg.FlushStats(ctx)
	if rec := redisRecord(t, store, c.ID); rec != nil {
		t.Fatalf("deleted client's record was written back: %v", rec)
	}
	if reg.lookupTraffic(c.ID) != nil {
		t.Fatal("counters of a deleted client survived the flush")
	}
}

// TestRedisStatsTwoServersOneStore is TestFlushStatsSharedStoreAddsUp on the
// real script, through FlushStats.
func TestRedisStatsTwoServersOneStore(t *testing.T) {
	store := testRedis(t)
	ctx := t.Context()
	c := redisClient(t, store, "carol")
	servers := make([]*ClientRegistry, 2)
	for i := range servers {
		servers[i] = NewClientRegistry(store)
		servers[i].byID[c.ID] = c
	}
	for round := range 5 {
		for i, r := range servers {
			r.AddBytes(c.ID, int64(10*(i+1)), int64(round))
			if err := r.FlushStats(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, _ := store.GetStats(ctx, c.ID)
	if got.BytesUp != 150 || got.BytesDown != 20 {
		t.Fatalf("stored up/down = %d/%d, want 150/20", got.BytesUp, got.BytesDown)
	}
}
