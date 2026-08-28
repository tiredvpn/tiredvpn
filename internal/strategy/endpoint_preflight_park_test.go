package strategy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// newGatedRestartedManager is newRestartedManager with the pre-flight
// connectivity gate wired up, which is what the phone runs and what the plain
// helper leaves out. The gate is the piece that turned out to undo the parking
// on the device, so a test without it cannot see the bug.
func newGatedRestartedManager(t *testing.T, tuning endpoint.Tuning, seen *targetLog, strategies int, addrs ...string) *Manager {
	t.Helper()
	m := newRestartedManager(t, tuning, 0, addrs...)
	for i := range strategies {
		m.Register(&greetingStrategy{id: fmt.Sprintf("s%d", i), priority: i + 1, seen: seen})
	}

	checker := NewConnectivityChecker(addrs[0], 500*time.Millisecond, true)
	checker.auxTimeout = 50 * time.Millisecond
	checker.auxGrace = 50 * time.Millisecond
	m.SetConnectivityChecker(checker)
	return m
}

// maskedTimeoutStrategy waits for the server to speak, exactly like
// greetingStrategy, but when the deadline fires it reports the failure the way
// REALITY reported it on the device: a wrapped "use of closed network
// connection", with no word in it that isTimeoutError recognises.
type maskedTimeoutStrategy struct {
	id       string
	priority int
}

func (s *maskedTimeoutStrategy) Name() string         { return s.id }
func (s *maskedTimeoutStrategy) ID() string           { return s.id }
func (s *maskedTimeoutStrategy) Priority() int        { return s.priority }
func (s *maskedTimeoutStrategy) RequiresServer() bool { return true }
func (s *maskedTimeoutStrategy) Description() string  { return "test strategy masking its timeout" }

func (s *maskedTimeoutStrategy) Probe(ctx context.Context, target string) error {
	conn, err := s.Connect(ctx, target)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *maskedTimeoutStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("masked: serverhello read failed: read tcp %s: use of closed network connection", target)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, nil
}

// TestPreflightDoesNotResurrectAParkedEndpoint replays what the Pixel 9 did
// with the silence fix already in place.
//
// The scan correctly gave up on the blackholed address and the loop moved to
// the next server. Then the pre-flight gate ran for that next server, walked
// the whole pool as it is meant to, and found the blackhole answering TCP -
// which it does, that is the entire point of a blackhole. The gate took the
// completed handshake as good news, cleared the cooldown, and pinned the client
// straight back onto the address the scan had just condemned. Eight connect
// attempts, one address, no parking anywhere in the log.
//
// The pool is arranged so the gate cannot pick the candidate the loop moved to:
// that one refuses connections outright, and the blackhole is the next address
// the gate tries.
func TestPreflightDoesNotResurrectAParkedEndpoint(t *testing.T) {
	silent := newBlackholeListener(t)
	closed := newHelloListener(t)
	closed.stop() // refuses connections: the gate cannot pick it
	live := newHelloListener(t)

	tuning := endpoint.Tuning{
		FailureThreshold: 2,
		Cooldown:         time.Minute,
		MinDwell:         5 * time.Minute,
	}
	const strategies = 4
	seen := &targetLog{}

	m := newGatedRestartedManager(t, tuning, seen, strategies, silent.addr, closed.addr, live.addr)
	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect never reached the live server: %v", err)
	}
	conn.Close()

	if got := m.GetServerAddr(context.Background()); got != live.addr {
		t.Fatalf("pinned %s, want the live server %s", got, live.addr)
	}

	// The abort fires after androidSilentScanAbort transports. Anything beyond
	// that means the blackhole was dialled a second time, which only happens if
	// something put the client back on it after the scan had condemned it.
	var dialled int
	for _, target := range seen.list {
		if target == silent.addr {
			dialled++
		}
	}
	if dialled == 0 {
		t.Fatal("the blackhole was never dialled - the test proves nothing")
	}
	if dialled > androidSilentScanAbort {
		t.Fatalf("the blackhole was dialled %d times, want at most %d: the pre-flight gate "+
			"un-parks it because its TCP port answers", dialled, androidSilentScanAbort)
	}
}

// TestSuccessfulProbeDoesNotLiftACooldown is the same rule one layer down, at
// the size a unit test can pin.
//
// ReportProbe's own contract says a completed TCP handshake is not evidence
// that the endpoint works - that asymmetry is why a probe success does not
// clear the failure streak. Clearing the cooldown did exactly what the contract
// forbids by another route: the parked candidate came back the moment its port
// answered, which for a censored address it always does.
func TestSuccessfulProbeDoesNotLiftACooldown(t *testing.T) {
	sel, err := endpoint.NewSelector(endpoint.Config{
		Endpoints: []endpoint.Endpoint{
			{Name: "a", V4: "198.51.100.1:443", Order: 0},
			{Name: "b", V4: "198.51.100.2:443", Order: 1},
		},
		Family:           endpoint.V4Only,
		FailureThreshold: 1,
		Cooldown:         time.Minute,
	})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	cand, _ := sel.Current()
	sel.ReportSilent(cand)
	if !parkedState(t, sel, cand.Addr).CooldownUntil.After(sel.Now()) {
		t.Fatal("ReportSilent did not park the candidate - the test proves nothing")
	}

	sel.ReportProbe(cand, true, 5*time.Millisecond)

	if st := parkedState(t, sel, cand.Addr); !st.CooldownUntil.After(sel.Now()) {
		t.Fatal("a TCP handshake lifted the cooldown of a candidate that answered no transport")
	}
}

func parkedState(t *testing.T, sel *endpoint.Selector, addr string) endpoint.CandidateState {
	t.Helper()
	for _, st := range sel.Snapshot() {
		if st.Addr == addr {
			return st
		}
	}
	t.Fatalf("no candidate for %s", addr)
	return endpoint.CandidateState{}
}

// TestSilenceIsMeasuredByTheClockNotTheErrorText is the second half of what the
// device showed. On the very first cycle REALITY timed out and the scan was
// abandoned as intended. On every cycle after that the same 10-second wait came
// back as "reality: serverhello read failed: ... use of closed network
// connection" - the deadline fired, something closed the socket, and the error
// no longer said "timeout". The scan read that as the address having answered
// and ran the whole list again.
//
// An attempt that burns the entire connect timeout heard nothing, whatever the
// error ended up being called. A refusal or a reset comes back in milliseconds.
func TestSilenceIsMeasuredByTheClockNotTheErrorText(t *testing.T) {
	silent := newBlackholeListener(t)
	live := newHelloListener(t)

	const strategies = 6
	m := newRestartedManager(t, endpoint.Tuning{FailureThreshold: 2}, 0, silent.addr, live.addr)
	for i := range strategies {
		m.Register(&maskedTimeoutStrategy{id: fmt.Sprintf("s%d", i), priority: i + 1})
	}

	// Between "two transports timed out" and "the whole list did", exactly as
	// the Android service's own deadline sits.
	budget := 3 * restartedManagerScanTimeout
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("Connect gave up on a pool with one live server: %v", err)
	}
	conn.Close()

	if got := m.GetServerAddr(context.Background()); got != live.addr {
		t.Fatalf("pinned %s, want the live server %s", got, live.addr)
	}
}
