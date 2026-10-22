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
	noUpgradeDelay(t)
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
	noUpgradeDelay(t)
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

// TestConnectStrategyDialsTheSessionEndpointAndWaits: the upgrade dial goes to
// the endpoint it is given and nowhere else, and a successful dial books
// nothing - P1-3 of the PR #126 review: success recorded at dial time meant a
// handshake that failed, a session the exit rejected or one that froze a second
// later all counted as upgrades that worked, so the backoff never engaged and
// the fast path went to a strategy that never carried a session.
func TestConnectStrategyDialsTheSessionEndpointAndWaits(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)
	seen := &targetLog{}
	reality := &greetingStrategy{id: "reality", priority: 5, seen: seen}
	m.Register(reality)

	cand, _ := m.CurrentCandidate()
	conn, err := m.ConnectStrategy(context.Background(), reality, cand)
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
	if last == reality {
		t.Fatal("a dial alone made the strategy the fast-reconnect one; only a confirmed upgrade may")
	}
	m.UpgradeOutcome(reality, true)
	m.mu.RLock()
	last = m.lastSuccessfulStrategy
	m.mu.RUnlock()
	if last != reality {
		t.Fatal("a confirmed upgrade did not become the fast-reconnect strategy")
	}
}

func noUpgradeDelay(t *testing.T) {
	t.Helper()
	old := upgradeDelay
	upgradeDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { upgradeDelay = old })
}

// TestUpgradeOfferIsNotOnTheReprobeGrid is P1-8 of the review: the offer went
// out 10 ms after "Periodic reprobe complete", so the switch inherited the
// reprobe's strict 5-minute grid and followed a probe burst at once. The delay
// varies, sits between its bounds, and is not one fixed value.
func TestUpgradeOfferIsNotOnTheReprobeGrid(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		d := upgradeDelay()
		if d < 20*time.Second || d > 4*time.Minute {
			t.Fatalf("upgrade delay %v outside [20s, 4m]", d)
		}
		seen[d] = true
	}
	if len(seen) < 50 {
		t.Fatalf("only %d distinct delays in 200 draws", len(seen))
	}

	// And the offer really waits for it.
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})
	old := upgradeDelay
	upgradeDelay = func() time.Duration { return 300 * time.Millisecond }
	t.Cleanup(func() { upgradeDelay = old })
	offers := newUpgradeOffers()
	m.SetStrategyUpgradeCallback(offers.take)
	start := time.Now()
	m.offerUpgrade([]Result{{Strategy: &greetingStrategy{id: "reality", priority: 5}, Success: true}})
	select {
	case <-offers.got:
	case <-time.After(2 * time.Second):
		t.Fatal("no offer")
	}
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Fatalf("offer went out %v after the reprobe, want after the delay", took)
	}
}

// TestReprobeIsNotAMetronome: the reprobe itself was a strict time.Ticker - a
// probe burst every 300.000 s from process start. Its pauses now vary around
// the interval within [interval/2, 2 x interval].
func TestReprobeIsNotAMetronome(t *testing.T) {
	const interval = 5 * time.Minute
	seen := map[time.Duration]bool{}
	var sum time.Duration
	for range 1000 {
		d := nextReprobeDelay(interval)
		if d < interval/2 || d > 2*interval {
			t.Fatalf("reprobe pause %v outside [%v, %v]", d, interval/2, 2*interval)
		}
		seen[d] = true
		sum += d
	}
	if len(seen) < 500 {
		t.Fatalf("only %d distinct pauses in 1000", len(seen))
	}
	if mean := sum / 1000; mean < 4*time.Minute || mean > 7*time.Minute {
		t.Fatalf("mean pause %v strays from the %v interval", mean, interval)
	}
}

// TestUpgradeRankKeepsTheScansPenalties is P1-5 of the review: the upgrade
// compared bare priorities, so on Android - where the scan puts QUIC (4) behind
// REALITY (5) until TCP has timed out - it moved the client to QUIC anyway, and
// with UDP excluded it still offered QUIC.
func TestUpgradeRankKeepsTheScansPenalties(t *testing.T) {
	m := NewManager()
	quic := &QUICStrategy{useSalamander: true}
	reality := &greetingStrategy{id: "reality", priority: 5}
	if !isUDPBasedStrategy(quic) {
		t.Skip("QUICStrategy no longer reads as UDP")
	}
	m.androidMode = true
	if m.UpgradeRank(quic) <= m.UpgradeRank(reality) {
		t.Fatalf("on Android QUIC ranks %.1f, REALITY %.1f: QUIC must not outrank REALITY before TCP times out",
			m.UpgradeRank(quic), m.UpgradeRank(reality))
	}

	noUpgradeDelay(t)
	offers := newUpgradeOffers()
	m.SetStrategyUpgradeCallback(offers.take)
	m.excludeUDPStrategies = true
	m.offerUpgrade([]Result{{Strategy: quic, Success: true}})
	if got := offers.next(t); got != nil {
		t.Fatalf("offered %v while UDP is excluded", got)
	}
}
