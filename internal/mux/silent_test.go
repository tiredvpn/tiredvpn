package mux

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// TestSmuxSilentConfigIsAccepted checks smux takes the configuration at all.
// It rejects a zero interval and any timeout below the interval, so "disabled"
// has to be expressed as durations rather than as an off switch, and getting
// that wrong fails at session creation rather than visibly.
func TestSmuxSilentConfigIsAccepted(t *testing.T) {
	t.Parallel()

	c := SmuxSilentConfig()
	if err := smux.VerifyConfig(c); err != nil {
		t.Fatalf("smux rejected the silent config: %v", err)
	}
	if c.KeepAliveInterval < 12*time.Hour {
		t.Fatalf("interval %v is short enough for a long-lived session to reach", c.KeepAliveInterval)
	}
	if c.KeepAliveTimeout < c.KeepAliveInterval {
		t.Fatal("timeout below interval: smux requires otherwise and the session would die idle")
	}
}

// TestSilentSessionSendsNothingWhenIdle is the measurement the change exists
// for. With the default config an idle session emits a NOP every ten seconds, a
// perfectly periodic pulse recoverable from timestamps alone. Here it must emit
// nothing at all.
func TestSilentSessionSendsNothingWhenIdle(t *testing.T) {
	if testing.Short() {
		t.Skip("watches an idle session in real time")
	}
	t.Parallel()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	counted := &countingConn{Conn: clientRaw}
	sess, err := smux.Client(counted, SmuxSilentConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// Drain whatever the peer would read so the pipe never blocks.
	go func() { _, _ = io.Copy(io.Discard, serverRaw) }()

	// A default session would have sent two NOPs by now.
	time.Sleep(2500 * time.Millisecond)
	if n := counted.writes.Load(); n != 0 {
		t.Fatalf("an idle silent session wrote %d times; the default's ten-second NOP is exactly "+
			"the periodic pulse this removes", n)
	}
}

// TestSilentSessionSurvivesIdlePastTheOldTimeout covers the half of the change
// that is easy to forget. Silencing the sender alone leaves the receiver killing
// the session after the default thirty seconds of the quiet just created, so
// both parameters move together.
func TestSilentSessionSurvivesIdlePastTheOldTimeout(t *testing.T) {
	t.Parallel()

	c := SmuxSilentConfig()
	if c.KeepAliveTimeout <= 30*time.Second {
		t.Fatalf("timeout %v is at or below smux's default: an idle session would still be killed, "+
			"just by us instead of by the ticker", c.KeepAliveTimeout)
	}
}

// countingConn counts writes so a test can assert an idle session is silent.
type countingConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(b)
}
