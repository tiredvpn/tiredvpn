package strategy

import (
	"context"
	"sync"
	"testing"
	"time"
)

// upgradeOffers records what the upgrade callback was handed.
type upgradeOffers struct {
	mu     sync.Mutex
	offers [][]string
	got    chan struct{}
}

func newUpgradeOffers() *upgradeOffers { return &upgradeOffers{got: make(chan struct{}, 16)} }

func (o *upgradeOffers) take(cands []Strategy) {
	ids := make([]string, len(cands))
	for i, c := range cands {
		ids[i] = c.ID()
	}
	o.mu.Lock()
	o.offers = append(o.offers, ids)
	o.mu.Unlock()
	o.got <- struct{}{}
}

// next waits for the next offer, or returns nil when none comes.
func (o *upgradeOffers) next(t *testing.T) []string {
	t.Helper()
	select {
	case <-o.got:
	case <-time.After(300 * time.Millisecond):
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.offers[len(o.offers)-1]
}

// TestReprobeOffersAnUpgrade is D3 of the 2026-10-21 stand report at the
// manager's end: the periodic reprobe, the only thing that runs on a live
// tunnel, used to refresh confidence and stop there. A client that came back
// from a fault on a fallback stayed on it as long as the session held.
//
// Driven through doPeriodicReprobe, the call site, against a live address: the
// offer has to carry the reachable strategies in priority order and leave out
// the one whose probe failed.
func TestReprobeOffersAnUpgrade(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	m.Register(&greetingStrategy{id: "stego", priority: 7, refuse: true})

	offers := newUpgradeOffers()
	m.SetStrategyUpgradeCallback(offers.take)
	m.doPeriodicReprobe(context.Background())

	got := offers.next(t)
	if len(got) != 2 || got[0] != "reality" || got[1] != "polling" {
		t.Fatalf("reprobe offered %v, want [reality polling]", got)
	}
}

// TestFailedUpgradesBackOff: a strategy whose upgrade dial keeps failing - the
// censor resets its handshake while its port answers the probe - must not be
// retried on every tick. The first failure is free (a fault that was just
// lifted is the common case); after that it sits out 1, 2, 4, then 6 reprobes.
func TestFailedUpgradesBackOff(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)
	reality := &greetingStrategy{id: "reality", priority: 5}
	m.Register(reality)

	offers := newUpgradeOffers()
	m.SetStrategyUpgradeCallback(offers.take)

	offered := func() bool {
		m.offerUpgrade([]Result{{Strategy: reality, Success: true}})
		return offers.next(t) != nil
	}
	fail := func() {
		m.mu.Lock()
		m.recordUpgradeResultLocked("reality", false)
		m.mu.Unlock()
	}

	// pattern[i] is whether reprobe i offers reality; a failed dial follows
	// every offer.
	want := []bool{
		true,        // fail #1: no skip
		true,        // fail #2: skip 1
		false, true, // fail #3: skip 2
		false, false, true, // fail #4: skip 4
		false, false, false, false, true, // fail #5: skip 6
		false, false, false, false, false, false, true,
	}
	for i, w := range want {
		got := offered()
		if got != w {
			t.Fatalf("reprobe %d: offered=%v, want %v (pattern %v)", i, got, w, want)
		}
		if got {
			fail()
		}
	}

	// One success clears the slate.
	m.mu.Lock()
	m.recordUpgradeResultLocked("reality", true)
	m.mu.Unlock()
	if !offered() {
		t.Fatal("a successful upgrade did not clear the backoff")
	}
}

// TestConnectStrategyDialsThePinnedEndpointAndBooksIt: the upgrade dial goes to
// the pinned endpoint and nowhere else, and a success makes the strategy the
// fast path's.
func TestConnectStrategyDialsThePinnedEndpointAndBooksIt(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)
	seen := &targetLog{}
	reality := &greetingStrategy{id: "reality", priority: 5, seen: seen}
	m.Register(reality)

	conn, err := m.ConnectStrategy(context.Background(), reality)
	if err != nil {
		t.Fatalf("ConnectStrategy: %v", err)
	}
	conn.Close()
	if got := seen.since(0); len(got) != 1 || got[0] != live.addr {
		t.Fatalf("dialled %v, want [%s]", got, live.addr)
	}
	m.mu.RLock()
	last := m.lastSuccessfulStrategy
	m.mu.RUnlock()
	if last != reality {
		t.Fatal("a successful upgrade dial did not become the fast-reconnect strategy")
	}
}
