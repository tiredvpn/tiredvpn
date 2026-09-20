package strategy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// nopConn is a minimal net.Conn: enough for a strategy to hand a "connection"
// back without a real socket. Reads block-free, writes are dropped.
type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, nil }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// countingStrategy records how many times Connect was invoked and either fails
// fast (a refusal, not a timeout) or hands back a nopConn.
type countingStrategy struct {
	id    string
	prio  int
	fail  bool
	calls int32
}

func (s *countingStrategy) Name() string                        { return s.id }
func (s *countingStrategy) ID() string                          { return s.id }
func (s *countingStrategy) Priority() int                       { return s.prio }
func (s *countingStrategy) Probe(context.Context, string) error { return nil }
func (s *countingStrategy) RequiresServer() bool                { return false }
func (s *countingStrategy) Description() string                 { return "counting strategy for audit tests" }
func (s *countingStrategy) Connect(context.Context, string) (net.Conn, error) {
	atomic.AddInt32(&s.calls, 1)
	if s.fail {
		return nil, errors.New("counting: refused")
	}
	return nopConn{}, nil
}

func (s *countingStrategy) count() int { return int(atomic.LoadInt32(&s.calls)) }

// TestEmergencyReprobeStopIsIdempotent guards the channel double-close: a second
// StopEmergencyReprobe, and a ResetForNetworkChange right after a stop, used to
// close an already-closed channel and panic.
//
// Predicated against the broken code: drop the "= nil" in StopEmergencyReprobe
// and this panics on the second Stop.
func TestEmergencyReprobeStopIsIdempotent(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Close)
	m.Register(&countingStrategy{id: "s1", prio: 1})

	m.TriggerEmergencyReprobe(context.Background())

	// Two stops in a row plus a network change: none may panic.
	m.StopEmergencyReprobe()
	m.StopEmergencyReprobe()
	m.ResetForNetworkChange()

	// And a fresh trigger + stop after all that still works.
	m.mu.Lock()
	m.lastEmergencyReprobe = time.Time{} // clear the throttle
	m.mu.Unlock()
	m.TriggerEmergencyReprobe(context.Background())
	m.StopEmergencyReprobe()
}
