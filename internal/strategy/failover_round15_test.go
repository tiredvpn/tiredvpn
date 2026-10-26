package strategy

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestTwoSwallowingServersWithRunningOutParksReachTheThird is R1 of the
// fix13c stand (rt3-seq-sw-p1-1, -2): a and b swallow every handshake on
// both families, c is healthy, and the client did not reach c in 6.5
// minutes, both runs. It went a, b, a, b: each server's park ran out while
// the other was being tried, the route rule spared the second server of each
// pair, and the move off a parked server took the first available one in
// preference order - a again - never c. Through Connect, on the selector's
// clock advanced by the stand's cycle, so parks run out as they did there.
func TestTwoSwallowingServersWithRunningOutParksReachTheThird(t *testing.T) {
	a6, a4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	b6, b4 := newBlackholeListenerAt(t, "[::1]:0"), newBlackholeListener(t)
	c6, c4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	clk := newEndpointClock()
	m := dualStackPool(t, 150*time.Millisecond, clk,
		[2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr}, [2]string{c6.addr, c4.addr})
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&protectedGreeter{id: "polling", priority: 6})
	m.Register(&protectedGreeter{id: "stego", priority: 7})
	m.Register(&protectedGreeter{id: "seqovl", priority: 8})
	markConnected(m, reality)

	names := map[string]string{a6.addr: "a6", a4.addr: "a4", b6.addr: "b6", b4.addr: "b4", c6.addr: "c6", c4.addr: "c4"}
	var path []string
	// 26 cycles of 15 s plus backoff is the stand's 6.5 minutes.
	for cycle := 1; cycle <= 26; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		conn, _, err := m.Connect(ctx, "")
		cancel()
		addr := m.GetServerAddr(context.Background())
		path = append(path, names[addr])
		if err == nil {
			conn.Close()
			if addr != c6.addr && addr != c4.addr {
				t.Fatalf("connected on %s: %v", names[addr], path)
			}
			t.Logf("on c in cycle %d: %v", cycle, path)
			if cycle > 14 {
				t.Fatalf("on c only in cycle %d: %v", cycle, path)
			}
			// a, then b, then c, each family of a server tried once before
			// the next server (N9 of the final 1.11.9 acceptance), and no
			// server again once left.
			var servers []byte
			for _, p := range path {
				if len(servers) == 0 || servers[len(servers)-1] != p[0] {
					servers = append(servers, p[0])
				}
			}
			if string(servers) != "abc" || !slices.Contains(path, "a4") || !slices.Contains(path, "b4") {
				t.Fatalf("path %v, want a's two families, b's two, then c", path)
			}
			return
		}
		clk.Advance(15*time.Second + min(time.Duration(cycle)*4*time.Second, 30*time.Second))
	}
	t.Fatalf("not on c after 26 cycles: %v", path)
}
