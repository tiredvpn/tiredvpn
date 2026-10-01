//go:build linux

package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testExit is the exit end of a session: it parses the frames the relay
// sends, can send frames back, and records whether the client closed the
// connection.
type testExit struct {
	cli, srv net.Conn

	upPkts atomic.Int64 // non-keepalive frames received from the client
	gone   atomic.Bool  // the client closed its end

	// split sends each downlink frame as header and body in two writes with
	// a pause between them, the way a frame cut across TCP segments arrives.
	// A reader interrupted mid-frame then loses the header and whoever reads
	// next is out of step with the stream.
	split atomic.Bool

	writeMu sync.Mutex
}

func (h *ctlHarness) newTestExit() *testExit {
	cli, srv := net.Pipe()
	e := &testExit{cli: cli, srv: srv}
	go func() {
		hdr := make([]byte, 4)
		for {
			if _, err := io.ReadFull(srv, hdr); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
					e.gone.Store(true)
				}
				return
			}
			n := binary.BigEndian.Uint32(hdr)
			if n == 0 {
				continue
			}
			if _, err := io.ReadFull(srv, make([]byte, n)); err != nil {
				e.gone.Store(true)
				return
			}
			e.upPkts.Add(1)
		}
	}()
	h.t.Cleanup(func() { cli.Close(); srv.Close() })
	return e
}

// send writes one downlink frame. A frame the client does not read within
// the timeout is reported as an error rather than blocking the test.
func (e *testExit) send(pkt []byte, timeout time.Duration) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	frame := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(frame, uint32(len(pkt)))
	copy(frame[4:], pkt)
	_ = e.srv.SetWriteDeadline(time.Now().Add(timeout))
	if e.split.Load() {
		if _, err := e.srv.Write(frame[:4]); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
		_, err := e.srv.Write(frame[4:])
		return err
	}
	_, err := e.srv.Write(frame)
	return err
}

// testPacket is a minimal IPv4 header with a marker byte in the payload, so a
// downlink packet can be recognised on the kernel side of the fake TUN.
func testPacket(marker byte) []byte {
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	pkt[9] = 17 // UDP: ClampTCPMSS leaves it alone
	pkt[59] = marker
	return pkt
}

// recvMarker waits for a packet carrying marker on the kernel side.
func (ft *fakeTun) recvMarker(marker byte, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		pfd := []unix.PollFd{{Fd: int32(ft.peer), Events: unix.POLLIN}}
		if n, err := unix.Poll(pfd, 20); err != nil || n == 0 || pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}
		r, err := unix.Read(ft.peer, buf)
		if err != nil || r == 0 {
			return false
		}
		if r == 60 && buf[59] == marker {
			return true
		}
	}
	return false
}

// attachExit makes e the session's server connection.
func (h *ctlHarness) attachExit(e *testExit) {
	h.cs.mu.Lock()
	h.cs.serverConn = e.cli
	h.cs.mu.Unlock()
}

// trafficBothWays keeps uplink packets flowing into whichever fake TUN is
// current and downlink frames flowing from whichever exit is current.
type trafficBothWays struct {
	mu   sync.Mutex
	tun  *fakeTun
	exit *testExit
	stop chan struct{}
	wg   sync.WaitGroup
}

func startTraffic(tun *fakeTun, exit *testExit) *trafficBothWays {
	tr := &trafficBothWays{tun: tun, exit: exit, stop: make(chan struct{})}
	tr.wg.Add(2)
	go func() {
		defer tr.wg.Done()
		pkt := testPacket(0x01)
		for {
			select {
			case <-tr.stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			tr.mu.Lock()
			peer := tr.tun.peer
			tr.mu.Unlock()
			_ = unix.Sendto(peer, pkt, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT, nil)
		}
	}()
	go func() {
		defer tr.wg.Done()
		pkt := testPacket(0x02)
		for {
			select {
			case <-tr.stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			tr.mu.Lock()
			exit := tr.exit
			tr.mu.Unlock()
			_ = exit.send(pkt, 50*time.Millisecond)
		}
	}()
	return tr
}

func (tr *trafficBothWays) retarget(tun *fakeTun, exit *testExit) {
	tr.mu.Lock()
	tr.tun, tr.exit = tun, exit
	tr.mu.Unlock()
}

func (tr *trafficBothWays) halt() {
	close(tr.stop)
	tr.wg.Wait()
}

// TestControlSwapKeepsSession is the hot-swap defect: the host replaces the
// TUN on a live session, and the session has to survive it. After every swap
// packets must flow in both directions through the new TUN, the exit
// connection must stay open, and the host must not be told connection_dead -
// on Android that event throws away the session and restarts the core.
//
// network_changed reconnects to a fresh exit connection by design (the old
// one belongs to the network that just went away), so for it the check is
// that the new connection is the one carrying traffic.
func TestControlSwapKeepsSession(t *testing.T) {
	for _, kind := range []string{"hot-swap", "network_changed"} {
		for _, traffic := range []bool{false, true} {
			for _, swaps := range []int{1, 2} {
				name := kind + "/idle"
				if traffic {
					name = kind + "/traffic"
				}
				name += map[int]string{1: "/one-swap", 2: "/two-swaps"}[swaps]
				t.Run(name, func(t *testing.T) {
					baseline := relayGoroutines()
					h := newCtlHarness(t)
					exit := h.newTestExit()
					h.attachExit(exit)
					var nextExit atomic.Pointer[testExit]
					h.cs.mu.Lock()
					h.cs.config.ReconnectFn = func(_ context.Context, _ net.IP, _ int) (ReconnectResult, error) {
						e := h.newTestExit()
						nextExit.Store(e)
						return ReconnectResult{Conn: e.cli, ServerIP: net.IPv4(10, 9, 0, 1), AssignedIP: net.IPv4(10, 9, 0, 2)}, nil
					}
					h.cs.mu.Unlock()

					cur := newFakeTun(t, false)
					if resp := h.send(`{"command":"set_fd"}`, cur.host); resp.Status != "connected" {
						t.Fatalf("set_fd: %+v", resp)
					}
					cur.dropHostCopy()

					var tr *trafficBothWays
					if traffic {
						exit.split.Store(true)
						tr = startTraffic(cur, exit)
						defer func() {
							if tr != nil {
								tr.halt()
							}
						}()
						if !waitFor(2*time.Second, func() bool { return exit.upPkts.Load() > 0 }) {
							t.Fatal("positive control: no uplink before the swap")
						}
					}

					cmd := `{"command":"set_fd"}`
					if kind == "network_changed" {
						cmd = `{"command":"network_changed","reason":"wifi_to_lte"}`
					}
					for i := range swaps {
						next := newFakeTun(t, false)
						if resp := h.send(cmd, next.host); resp.Status != "connected" {
							t.Fatalf("swap %d: %+v", i+1, resp)
						}
						next.dropHostCopy()
						cur = next
						if kind == "network_changed" {
							exit = nextExit.Load()
						}
						if tr != nil {
							tr.retarget(cur, exit)
						}
					}
					if tr != nil {
						tr.halt()
						tr = nil
					}
					exit.split.Store(false)

					// Uplink through the new TUN reaches the exit.
					before := exit.upPkts.Load()
					pkt := testPacket(0x03)
					_ = unix.Sendto(cur.peer, pkt, unix.MSG_NOSIGNAL, nil)
					if !waitFor(2*time.Second, func() bool { return exit.upPkts.Load() > before }) {
						t.Error("uplink dead after the swap: a packet written to the new TUN never reached the exit")
					}
					// Downlink from the exit reaches the new TUN.
					if err := exit.send(testPacket(0x7f), 2*time.Second); err != nil {
						t.Errorf("downlink dead after the swap: the relay is not reading the exit connection (%v)", err)
					} else if !cur.recvMarker(0x7f, 2*time.Second) {
						t.Error("downlink dead after the swap: the exit's packet never reached the new TUN")
					}

					if exit.gone.Load() {
						t.Error("the swap closed the session's exit connection")
					}
					time.Sleep(200 * time.Millisecond)
					if n := h.eventCount("connection_dead"); n != 0 {
						t.Errorf("host told connection_dead %d times during a swap of a live session", n)
					}
					if got := relayGoroutines(); got != baseline+4 {
						t.Errorf("want exactly one running relay after the swap: baseline %d, now %d", baseline, got)
					}
				})
			}
		}
	}
}

// TestControlDeadExitStillReported: keeping the connection across a swap must
// not hide a connection that really died. The exit going away, before or
// after a swap, has to reach the host as connection_dead.
func TestControlDeadExitStillReported(t *testing.T) {
	for _, afterSwap := range []bool{false, true} {
		name := "no-swap"
		if afterSwap {
			name = "after-hot-swap"
		}
		t.Run(name, func(t *testing.T) {
			h := newCtlHarness(t)
			exit := h.newTestExit()
			h.attachExit(exit)
			ft := newFakeTun(t, false)
			if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
				t.Fatalf("set_fd: %+v", resp)
			}
			ft.dropHostCopy()
			if afterSwap {
				next := newFakeTun(t, false)
				if resp := h.send(`{"command":"set_fd"}`, next.host); resp.Status != "connected" {
					t.Fatalf("hot-swap: %+v", resp)
				}
				next.dropHostCopy()
				time.Sleep(200 * time.Millisecond)
				if n := h.eventCount("connection_dead"); n != 0 {
					t.Fatalf("positive control: connection_dead already sent %d times by the swap itself", n)
				}
			}

			exit.srv.Close()
			if !waitFor(3*time.Second, func() bool { return h.eventCount("connection_dead") > 0 }) {
				t.Error("the exit closed the connection and the host was never told connection_dead")
			}
		})
	}
}

// failingWriteConn reads normally but fails every write once broken: an
// uplink that died while the downlink still looks open.
type failingWriteConn struct {
	net.Conn
	broken atomic.Bool
}

func (c *failingWriteConn) Write(p []byte) (int, error) {
	if c.broken.Load() {
		return 0, errors.New("write: broken pipe")
	}
	return c.Conn.Write(p)
}

// TestControlDeadUplinkReported: a write failure on the exit connection is a
// dead session too, even while reads would still block. It has to reach the
// host as connection_dead promptly, not after the 30s read timeout.
func TestControlDeadUplinkReported(t *testing.T) {
	h := newCtlHarness(t)
	exit := h.newTestExit()
	conn := &failingWriteConn{Conn: exit.cli}
	h.cs.mu.Lock()
	h.cs.serverConn = conn
	h.cs.mu.Unlock()
	ft := newFakeTun(t, false)
	if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
		t.Fatalf("set_fd: %+v", resp)
	}
	ft.dropHostCopy()

	conn.broken.Store(true)
	_ = unix.Sendto(ft.peer, testPacket(0x04), unix.MSG_NOSIGNAL, nil)
	if !waitFor(3*time.Second, func() bool { return h.eventCount("connection_dead") > 0 }) {
		t.Error("uplink writes fail and the host was never told connection_dead")
	}
}

// TestControlHotSwapOnDeadRelayRefused: once the relay has died (and the host
// has been told), a set_fd must not graft a new TUN onto it and answer
// "connected" for a session that no longer exists. The fd it carried is
// released.
func TestControlHotSwapOnDeadRelayRefused(t *testing.T) {
	h := newCtlHarness(t)
	exit := h.newTestExit()
	h.attachExit(exit)
	ft := newFakeTun(t, false)
	if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
		t.Fatalf("set_fd: %+v", resp)
	}
	ft.dropHostCopy()
	exit.srv.Close()
	if !waitFor(3*time.Second, func() bool { return h.eventCount("connection_dead") > 0 }) {
		t.Fatal("positive control: the relay did not die")
	}

	next := newFakeTun(t, false)
	if resp := h.send(`{"command":"set_fd"}`, next.host); resp.Status == "connected" {
		t.Errorf("hot-swap onto a dead relay answered %+v", resp)
	}
	next.dropHostCopy()
	if !next.peerSeesHangup(3 * time.Second) {
		t.Error("the refused hot-swap kept its fd")
	}
}

// TestTUNRelaySwapInternalStop: without an external stop channel a TUN read
// error stops the whole relay. The reader of a device the relay moved off
// must not take that path when its device is closed under it.
func TestTUNRelaySwapInternalStop(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() { _, _ = io.Copy(io.Discard, srv) }()

	oldTun := newFakeTun(t, false)
	newTun := newFakeTun(t, false)
	oldDev, err := CreateTUNFromFd(oldTun.host, "", 1280)
	if err != nil {
		t.Fatal(err)
	}
	oldTun.host = -1 // owned by oldDev now
	newDev, err := CreateTUNFromFd(newTun.host, "", 1280)
	if err != nil {
		t.Fatal(err)
	}
	newTun.host = -1
	t.Cleanup(func() { newDev.Close() })

	baseline := relayGoroutines()
	// Swapped right after start, typically before run has spun up its
	// goroutines: the swap must still replace the first reader, not add a
	// second one on the new device.
	r := startTUNRelay(oldDev, cli, net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), nil, nil)
	if !r.SwapTUN(newDev) {
		t.Fatal("SwapTUN on a running relay refused")
	}
	oldDev.Close()
	if !waitFor(2*time.Second, func() bool { return relayGoroutines() == baseline+4 }) {
		t.Errorf("want one relay with one TUN reader after the swap: baseline %d, now %d", baseline, relayGoroutines())
	}

	time.Sleep(100 * time.Millisecond)
	// The relay-wide stop channel, not r.done: a stopped relay only notices
	// at the next frame boundary, so r.done would still look open here.
	select {
	case <-r.stopCh:
		t.Fatal("closing the device the relay moved off stopped the relay")
	default:
	}
	frame := make([]byte, 4+60)
	binary.BigEndian.PutUint32(frame, 60)
	copy(frame[4:], testPacket(0x55))
	_ = srv.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := srv.Write(frame); err != nil {
		t.Fatalf("relay not reading the server connection: %v", err)
	}
	if !newTun.recvMarker(0x55, 2*time.Second) {
		t.Error("downlink did not reach the new device")
	}
	cli.Close()
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Error("relay did not stop after its connection closed")
	}
}

// TestTUNRelayOwnerStopKeepsConn pins the relay's side of the ownership
// split: with an external stop channel the server connection belongs to the
// session. A relay its owner stopped - even one whose read the owner cut
// short to make it notice - leaves the connection open and reports nothing.
func TestTUNRelayOwnerStopKeepsConn(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	ft := newFakeTun(t, false)
	dev, err := CreateTUNFromFd(ft.host, "", 1280)
	if err != nil {
		t.Fatal(err)
	}
	ft.host = -1
	t.Cleanup(func() { dev.Close() })

	var reported atomic.Int32
	stop := make(chan struct{})
	r := startTUNRelay(dev, cli, net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), stop, &RelayCallbacks{
		OnError: func(string) { reported.Add(1) },
	})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	_ = cli.SetReadDeadline(time.Now()) // the owner kicking a blocked read
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop")
	}
	if n := reported.Load(); n != 0 {
		t.Errorf("owner-stopped relay reported OnError %d times", n)
	}
	_ = srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := srv.Read(make([]byte, 1)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("owner-stopped relay closed the session's connection: %v", err)
	}
}
