package strategy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// TestTheReportingStrategiesReallyReportTheirDial is P3-12 of the round-3
// review: the strategies the scan lets run past the dial limit once connected
// were pinned by interface membership only. If one of them dialled on a
// context without the hooks, its connected handshakes would be cut at the
// dial limit and charged as silence. This runs each real Connect against a
// server that accepts and stays silent, and asks the hooks.
func TestTheReportingStrategiesReallyReportTheirDial(t *testing.T) {
	secret := []byte("dial-hook-secret")
	for _, tc := range []struct {
		name string
		make func(m *Manager) Strategy
	}{
		{"REALITY", func(m *Manager) Strategy { return NewREALITYStrategy(m, secret) }},
		{"Seqovl", func(m *Manager) Strategy { return NewSeqovlStrategy(m, secret, false) }},
		{"HTTP/2 Stego", func(m *Manager) Strategy { return NewHTTP2StegoStrategy(m, secret, "") }},
		{"HTTP Polling", func(m *Manager) Strategy { return NewHTTPPollingStrategy(m, secret) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			silent := newBlackholeListener(t)
			m := newSilenceManager(t, 2*time.Second, silent.addr)
			s := tc.make(m)
			if _, ok := s.(connectReporter); !ok {
				t.Fatalf("%T does not declare that it reports its connect", s)
			}
			var started, connected atomic.Int64
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			ctx = protect.WithDialHooks(m.withDialCandidate(ctx, m.selector().Candidates()[0]),
				func() { started.Add(1) }, func() { connected.Add(1) })
			if conn, err := s.Connect(ctx, silent.addr); err == nil {
				conn.Close()
				t.Fatal("connected to a silent server - the test proves nothing")
			}
			if started.Load() == 0 || connected.Load() == 0 {
				t.Fatalf("%s dialled the server without the hooks (started %d, connected %d): its handshakes would be cut as silence",
					tc.name, started.Load(), connected.Load())
			}
		})
	}
}

// secondDialStrategy is Stego with ECH: the first connect is answered and
// turned down, and the retry dials again - into a SYN nobody answers.
type secondDialStrategy struct{}

func (secondDialStrategy) Name() string                        { return "stego-ech" }
func (secondDialStrategy) ID() string                          { return "stego-ech" }
func (secondDialStrategy) Priority() int                       { return 5 }
func (secondDialStrategy) RequiresServer() bool                { return true }
func (secondDialStrategy) Description() string                 { return "two dials" }
func (secondDialStrategy) Probe(context.Context, string) error { return nil }
func (secondDialStrategy) reportsTCPConnect()                  {}
func (secondDialStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	first, err := (&protect.ProtectDialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	first.Close() // the ECH handshake was turned down
	stalled := &protect.ProtectDialer{Dialer: &net.Dialer{Control: func(string, string, syscall.RawConn) error {
		<-ctx.Done()
		return ctx.Err()
	}}}
	return stalled.DialContext(ctx, "tcp", target)
}

// TestASecondDialIsCutAtTheDialLimit is the ECH half of P3-12 of the round-3
// review: after the first connect the attempt counted as connected, so a
// second dial that went unanswered ran to the end of the cycle instead of
// being cut at the dial limit like any other.
func TestASecondDialIsCutAtTheDialLimit(t *testing.T) {
	addr := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, addr)
	start := time.Now()
	_, _, _, err := m.connectThroughRefusal(context.Background(), secondDialStrategy{}, addr,
		time.Second, 200*time.Millisecond, &scanState{})
	if took := time.Since(start); took > 600*time.Millisecond {
		t.Fatalf("the second dial ran %v, past the 200 ms dial limit", took)
	}
	if !errors.Is(err, errTCPConnectCut) {
		t.Fatalf("err = %v, want a dial cut", err)
	}
}
