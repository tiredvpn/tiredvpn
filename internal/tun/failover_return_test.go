package tun

import (
	"errors"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestUnansweredCycleCapsTheBackoff is side finding 2 of the degraded-session
// report: after a session died, every reconnect cycle ended with no verdict
// (Geneva cut at half the cycle, Polling's handshake swallowed) and the
// backoff doubled to its 2-minute cap. Geneva on the stand came back 63 s
// after the fault ended. A cycle that heard nothing back caps at 30 s, as a
// silent one does.
func TestUnansweredCycleCapsTheBackoff(t *testing.T) {
	if d := nextReconnectDelay(64*time.Second, strategy.ErrCycleUnanswered); d != silentCycleMaxDelay {
		t.Fatalf("backoff after an unanswered cycle %v, want %v", d, silentCycleMaxDelay)
	}
}

// TestBlockedStrategiesKeepEndpointHealth: the reconnect loop's reset when
// every strategy is blocked used to be ResetForNetworkChange, once per failed
// cycle: it lifted the endpoint parks it had just set and wiped the run of
// swallowed cycles before it could reach its verdict.
func TestBlockedStrategiesKeepEndpointHealth(t *testing.T) {
	m, addrs, ps := poolManager(t, 2)
	setLog(t, &stampedLog{})
	cand, ok := m.CurrentCandidate()
	if !ok {
		t.Fatal("no candidate")
	}
	m.SessionEnded(strategy.SessionEnd{Strategy: ps.ID(), Endpoint: cand, HasEndpoint: true, Dead: true})
	if cooldownLeft(t, m, addrs[0]) <= 0 {
		t.Fatal("no park - the test proves nothing")
	}
	for range 10 {
		m.UpdateStrategyConfidence(ps.ID(), false) // blocked: confidence on the floor
	}
	if m.HasAvailableStrategies() {
		t.Fatal("strategies still available - the test proves nothing")
	}
	v := &VPNClient{manager: m}
	v.unblockStrategies()
	if !m.HasAvailableStrategies() {
		t.Fatal("the strategies are still blocked")
	}
	if cooldownLeft(t, m, addrs[0]) <= 0 {
		t.Fatal("resetting blocked strategies lifted an endpoint park")
	}
}

// TestAnUnansweredCycleDoesNotSleepTheOldBackoff is P3-2 of the round-4
// review: after answered failures had grown the backoff to 2 minutes, an
// unanswered cycle still slept those 2 minutes before the cap applied.
func TestAnUnansweredCycleDoesNotSleepTheOldBackoff(t *testing.T) {
	if d := capReconnectDelay(2*time.Minute, strategy.ErrCycleUnanswered); d != silentCycleMaxDelay {
		t.Fatalf("pause %v after an unanswered cycle, want %v", d, silentCycleMaxDelay)
	}
	if d := capReconnectDelay(2*time.Minute, errors.New("reset")); d != 2*time.Minute {
		t.Fatalf("an answered failure's pause changed to %v", d)
	}
}
