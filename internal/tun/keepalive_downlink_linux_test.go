package tun

import (
	"bytes"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingConn is a server connection that accepts every write and counts
// the zero-length keepalive frames among them.
type recordingConn struct {
	net.Conn
	keepalives atomic.Int32
	frames     atomic.Int32
}

func (c *recordingConn) Write(p []byte) (int, error) {
	if bytes.Equal(p, []byte{0, 0, 0, 0}) {
		c.keepalives.Add(1)
	} else {
		c.frames.Add(1)
	}
	return len(p), nil
}
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) Close() error                     { return nil }

// runKeepaliveScenario runs the real TUN reader and keepalive sender for
// window while an app writes a packet into the TUN every 20ms. When
// downlinkAlive is set, the server is simulated as answering too. It returns
// the keepalive and data frame counts the server would have received.
func runKeepaliveScenario(t *testing.T, downlinkAlive bool) (keepalives, frames int32) {
	t.Helper()
	saved := SetKeepaliveInterval(100 * time.Millisecond)
	t.Cleanup(func() { SetKeepaliveInterval(saved) })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	conn := &recordingConn{}
	v := &VPNClient{
		running: 1,
		stopCh:  make(chan struct{}),
		conn:    conn,
		tun:     &TUNDevice{name: "test0", file: r, mtu: 1400},
		lastRx:  time.Now(),
	}

	var wg sync.WaitGroup
	wg.Go(v.readFromTun)
	wg.Go(v.sendKeepalive)

	// An IPv4/UDP packet to a host that never answers, every 20ms.
	pkt := make([]byte, 28)
	pkt[0], pkt[9] = 0x45, 17
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := w.Write(pkt); err != nil {
			t.Fatal(err)
		}
		if downlinkAlive {
			v.mu.Lock()
			v.lastRx = time.Now()
			v.mu.Unlock()
		}
		time.Sleep(20 * time.Millisecond)
	}

	atomic.StoreInt32(&v.running, 0)
	close(v.stopCh)
	w.Close()
	r.Close()
	wg.Wait()
	return conn.keepalives.Load(), conn.frames.Load()
}

// TestKeepaliveIgnoresUnansweredUplink: outgoing packets that draw no reply
// must not suppress the keepalive. The server only echoes keepalives, so
// without them nothing arrives within readTimeout and the client tears down a
// working tunnel. Seen on a field client as sessions dying after exactly 30s,
// reproduced on the VM stand with UDP every 3s into a blackhole.
func TestKeepaliveIgnoresUnansweredUplink(t *testing.T) {
	keepalives, frames := runKeepaliveScenario(t, false)
	if frames == 0 {
		t.Fatal("no data frames reached the server; the scenario did not drive uplink")
	}
	if keepalives < 3 {
		t.Fatalf("got %d keepalives in ~7 intervals of unanswered uplink, want at least 3", keepalives)
	}
}

// TestKeepaliveQuietWhileServerTalks: while the server keeps sending, no
// keepalive goes out. The fix must not add keepalive frames to a busy
// tunnel, which would be a new pattern on the wire.
func TestKeepaliveQuietWhileServerTalks(t *testing.T) {
	keepalives, frames := runKeepaliveScenario(t, true)
	if frames == 0 {
		t.Fatal("no data frames reached the server; the scenario did not drive uplink")
	}
	if keepalives != 0 {
		t.Fatalf("got %d keepalives while the server was sending, want 0", keepalives)
	}
}
