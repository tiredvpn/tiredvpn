package server

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNodeCapClientCeiling(t *testing.T) {
	t.Parallel()

	c := newNodeCap(3, 0, time.Hour)
	now := time.Now()

	var releases []func()
	for i, id := range []string{"alice", "bob", "carol"} {
		rel, ok := c.admit(id, now)
		if !ok {
			t.Fatalf("client %d (%s) refused below the ceiling", i, id)
		}
		releases = append(releases, rel)
	}

	if _, ok := c.admit("dave", now); ok {
		t.Fatal("a fourth client was admitted past a ceiling of three")
	}
	if c.refusedClients.Load() != 1 {
		t.Fatalf("refusal counter = %d, want 1", c.refusedClients.Load())
	}

	// A client already here does not consume a second slot: several sessions
	// from one person are one person as far as address reputation goes.
	if _, ok := c.admit("alice", now); !ok {
		t.Fatal("a second session from an admitted client was refused")
	}

	// Freeing a slot lets the next client in - existing sessions are never
	// disturbed to make room.
	releases[0]()
	releases[0]() // release is idempotent
	if _, ok := c.admit("dave", now); ok {
		t.Fatal("alice still holds a session, so the node is still full")
	}
	c.mu.Lock()
	alice := c.sessions["alice"]
	c.mu.Unlock()
	if alice != 1 {
		t.Fatalf("alice holds %d sessions, want 1", alice)
	}
}

func TestNodeCapTrafficCeiling(t *testing.T) {
	t.Parallel()

	c := newNodeCap(0, 1000, time.Hour)
	now := time.Now()

	if _, ok := c.admit("alice", now); !ok {
		t.Fatal("refused on an empty node")
	}
	c.recordBytes(600, now)
	if _, ok := c.admit("bob", now); !ok {
		t.Fatal("refused below the traffic ceiling")
	}

	c.recordBytes(500, now)
	if _, ok := c.admit("carol", now); ok {
		t.Fatal("admitted past the traffic ceiling")
	}
	if c.refusedTraffic.Load() != 1 {
		t.Fatalf("traffic refusal counter = %d, want 1", c.refusedTraffic.Load())
	}

	// Past the window the traffic is forgotten and the node opens again.
	later := now.Add(2 * time.Hour)
	if _, ok := c.admit("carol", later); !ok {
		t.Fatal("still refusing after the window rolled over")
	}
	if got := c.stats(later).BytesInWindow; got != 0 {
		t.Fatalf("bytes in window after rollover = %d, want 0", got)
	}
}

// TestNodeCapWindowSlides checks the traffic figure tracks a moving window
// rather than a total, which is what an operator watching for a ramp needs.
func TestNodeCapWindowSlides(t *testing.T) {
	t.Parallel()

	c := newNodeCap(0, 0, time.Hour)
	base := time.Now().Truncate(time.Hour)

	// One bucket every five minutes across a full hour.
	for i := range 12 {
		c.recordBytes(100, base.Add(time.Duration(i)*5*time.Minute))
	}
	at := base.Add(55 * time.Minute)
	if got := c.stats(at).BytesInWindow; got != 1200 {
		t.Fatalf("full window = %d, want 1200", got)
	}

	// Half an hour later, the first half has aged out.
	at = base.Add(85 * time.Minute)
	got := c.stats(at).BytesInWindow
	if got == 0 || got >= 1200 {
		t.Fatalf("window after 30 more minutes = %d, want something between 0 and 1200", got)
	}
}

// TestNodeCapExistingClientsAreNotDegraded is the acceptance criterion that
// matters most: reaching the ceiling must refuse newcomers, never disturb the
// people already connected. A node that starts dropping established sessions
// under pressure is worse than one that fills up.
func TestNodeCapExistingClientsAreNotDegraded(t *testing.T) {
	t.Parallel()

	c := newNodeCap(2, 0, time.Hour)
	now := time.Now()

	relA, okA := c.admit("alice", now)
	_, okB := c.admit("bob", now)
	if !okA || !okB {
		t.Fatal("setup: both clients should be admitted")
	}

	for range 50 {
		if _, ok := c.admit("stranger", now); ok {
			t.Fatal("admitted past the ceiling")
		}
	}

	// Alice is untouched by any of it.
	c.mu.Lock()
	_, stillHere := c.sessions["alice"]
	count := len(c.sessions)
	c.mu.Unlock()
	if !stillHere {
		t.Fatal("an established client was evicted to make room")
	}
	if count != 2 {
		t.Fatalf("node holds %d clients, want the 2 that were admitted", count)
	}
	relA()
}

// TestNodeCapIsInvisibleToUnauthenticatedPeers states the property the ceiling
// depends on, in the one place a reader will look for it.
//
// The ceiling is consulted from handleRawTunnel, which every transport reaches
// only after its client has authenticated. Move it earlier - to the accept loop
// where the admission semaphore lives - and anyone could open connections until
// refused and learn "this server takes exactly N", which is a sharper
// fingerprint than the reputation problem it was meant to solve.
func TestNodeCapIsInvisibleToUnauthenticatedPeers(t *testing.T) {
	t.Parallel()

	src := mustReadServerSource(t)

	callIdx := strings.Index(src, "nodeCapacity.admit(")
	if callIdx < 0 {
		t.Fatal("the node ceiling is no longer consulted from server.go")
	}
	tunnelIdx := strings.Index(src, "func handleRawTunnel(")
	if tunnelIdx < 0 || callIdx < tunnelIdx {
		t.Fatal("the node ceiling moved out of handleRawTunnel: an unauthenticated peer " +
			"can now measure it, which is a fingerprint of its own")
	}

	acceptIdx := strings.Index(src, "func initAdmissionControl(")
	if acceptIdx >= 0 && callIdx < tunnelIdx {
		t.Fatal("the ceiling is being applied on the accept path")
	}
}

func mustReadServerSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestNodeCapNilIsSafe covers the disabled case, since every call site relies
// on a nil ceiling behaving like an absent one.
func TestNodeCapNilIsSafe(t *testing.T) {
	t.Parallel()

	var c *nodeCap
	release, ok := c.admit("alice", time.Now())
	if !ok {
		t.Fatal("a nil ceiling refused a client")
	}
	release()
	c.recordBytes(1024, time.Now())
	if got := c.stats(time.Now()); got.Clients != 0 || got.MaxClients != 0 {
		t.Fatalf("nil stats = %+v, want zero", got)
	}
}

func TestNodeCapMetrics(t *testing.T) {
	saved := nodeCapacity
	t.Cleanup(func() { nodeCapacity = saved })

	nodeCapacity = newNodeCap(10, 1000, time.Hour)
	now := time.Now()
	rel, _ := nodeCapacity.admit("alice", now)
	defer rel()
	nodeCapacity.recordBytes(250, now)

	var sb testWriter
	writeNodeCapMetrics(&sb)
	out := sb.String()

	for _, want := range []string{
		"tiredvpn_node_clients 1",
		"tiredvpn_node_bytes_window 250",
		"tiredvpn_node_ceiling_clients 10",
		`tiredvpn_node_ceiling_used{limit="clients"} 0.1000`,
		`tiredvpn_node_ceiling_used{limit="bytes"} 0.2500`,
		`tiredvpn_node_refused_total{limit="clients"}`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q:\n%s", want, out)
		}
	}
}

// TestNodeCapFractionWithoutCeiling checks the alerting gauge stays sane when
// no ceiling is set, which is the default and therefore the common case.
func TestNodeCapFractionWithoutCeiling(t *testing.T) {
	t.Parallel()

	if got := fraction(500, 0); got != 0 {
		t.Fatalf("fraction of no ceiling = %v, want 0", got)
	}
	if got := fraction(250, 1000); got != 0.25 {
		t.Fatalf("fraction = %v, want 0.25", got)
	}
}

// TestNodeCapIgnoresUnauthenticatedSessions is the fix for a hole in the first
// version of this ceiling, found by asking the question the task asked: can an
// unauthenticated peer observe it?
//
// It could. handleTLSConnection reaches handleRawTunnel with an empty client id
// after nothing but a plain TLS handshake, which anyone completes because we
// serve a certificate to everyone. The ceiling therefore counted peers that had
// proved nothing - so a prober could open connections until refused and read
// the limit off, and could then hold those slots and lock real users out with
// no credential at all. Placing the ceiling after "authentication" is only
// worth anything if every path into it has actually authenticated.
func TestNodeCapIgnoresUnauthenticatedSessions(t *testing.T) {
	t.Parallel()

	c := newNodeCap(2, 0, time.Hour)
	now := time.Now()

	// A hundred sessions that could not say who they are must neither fill the
	// ceiling nor ever be refused: refusing them would leak the limit just as
	// surely as admitting them would let it be exhausted.
	for i := range 100 {
		if _, ok := c.admit("", now); !ok {
			t.Fatalf("session %d without an identity was refused, which tells a prober the limit exists", i)
		}
	}
	if got := c.stats(now).Clients; got != 0 {
		t.Fatalf("%d unauthenticated sessions occupy ceiling slots", got)
	}

	// And the ceiling still works for the peers it is meant to count.
	if _, ok := c.admit("alice", now); !ok {
		t.Fatal("a real client was refused on an empty node")
	}
	if _, ok := c.admit("bob", now); !ok {
		t.Fatal("a second real client was refused below the ceiling")
	}
	if _, ok := c.admit("carol", now); ok {
		t.Fatal("a third real client was admitted past a ceiling of two")
	}
}
