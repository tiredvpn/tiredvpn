package tun

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// failingConn is a server connection whose every read fails with err.
type failingConn struct {
	net.Conn
	err error
}

func (c *failingConn) Read([]byte) (int, error)         { return 0, c.err }
func (c *failingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *failingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *failingConn) Close() error                     { return nil }

// stopOnDisconnectLog collects log output and stops the client as soon as
// the disconnect line is written, so the reconnect loop that follows it exits
// instead of dialing.
type stopOnDisconnectLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
	v   *VPNClient
}

func (w *stopOnDisconnectLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if bytes.Contains(p, []byte("VPN disconnected")) {
		atomic.StoreInt32(&w.v.running, 0)
	}
	return w.buf.Write(p)
}

func (w *stopOnDisconnectLog) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestDisconnectLogNamesTheCause drives the real read loop into a read error
// and checks the disconnect line carries the path, the error, the session age
// and the downlink silence. Before this, the line said only "VPN disconnected"
// and the cause stayed at Debug, so field disconnects could not be diagnosed.
func TestDisconnectLogNamesTheCause(t *testing.T) {
	readErr := errors.New("read tcp 10.0.0.2:5000->10.0.0.1:995: i/o timeout")
	now := time.Now()
	v := &VPNClient{
		running:     1,
		stopCh:      make(chan struct{}),
		conn:        &failingConn{err: readErr},
		connectedAt: now.Add(-90 * time.Second),
		lastRx:      now.Add(-31 * time.Second),
	}

	out := &stopOnDisconnectLog{v: v}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	done := make(chan struct{})
	go func() {
		v.readFromServer()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		atomic.StoreInt32(&v.running, 0)
		t.Fatalf("read loop did not return; log so far:\n%s", out)
	}

	var line string
	for l := range strings.Lines(out.String()) {
		if strings.Contains(l, "VPN disconnected") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("no disconnect line in log:\n%s", out)
	}
	for _, want := range []string{
		"server read: " + readErr.Error(),
		"strategy=unknown",
		"session=1m30",
		"last downlink 31",
		"WRN",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("disconnect line lacks %q:\n%s", want, line)
		}
	}
}
