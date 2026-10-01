//go:build linux

package tun

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests drive a real ControlServer over a real unix socket and hand it
// the TUN descriptor the way the Android host does: as SCM_RIGHTS ancillary
// data. The kernel installs a fresh descriptor in the receiver for that, so
// the core ends up owning its own copy of the host's open file, exactly as on
// a device. A SOCK_SEQPACKET socketpair stands in for /dev/tun: one end is
// what VpnService.establish() returns, the other plays the kernel side.
//
// "Closed" is checked at the OS level, never through a return value: the
// kernel-side end sees a hangup only when every descriptor referring to the
// host end's open file is gone. The test drops the host's own copy right after
// sending it (the host closing its ParcelFileDescriptor), so the hangup means
// precisely that the core's copy is closed - the same condition under which a
// real tun interface disappears.

// fakeTun is a stand-in for one VpnService interface.
type fakeTun struct {
	host int // the descriptor the host would hold and send over the socket
	peer int // the kernel side: writes here are packets the core reads
}

func newFakeTun(t *testing.T, blocking bool) *fakeTun {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	if !blocking {
		// O_NONBLOCK lives on the open file, so the copy the core receives
		// inherits it - which is what VpnService's default mode looks like.
		if err := unix.SetNonblock(fds[0], true); err != nil {
			t.Fatalf("set nonblock: %v", err)
		}
	}
	ft := &fakeTun{host: fds[0], peer: fds[1]}
	t.Cleanup(func() {
		if ft.host >= 0 {
			unix.Close(ft.host)
		}
		unix.Close(ft.peer)
	})
	return ft
}

// dropHostCopy closes the host's own descriptor, as the Android host does when
// it releases the ParcelFileDescriptor.
func (ft *fakeTun) dropHostCopy() {
	unix.Close(ft.host)
	ft.host = -1
}

// peerSeesHangup reports whether the far end of the core's copy has been
// closed by the kernel within the timeout.
func (ft *fakeTun) peerSeesHangup(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		pfd := []unix.PollFd{{Fd: int32(ft.peer), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, 20)
		if err != nil || n == 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLHUP != 0 {
			return true
		}
		if pfd[0].Revents&unix.POLLIN != 0 {
			r, _ := unix.Read(ft.peer, buf)
			if r == 0 {
				return true
			}
		}
	}
	return false
}

// pump writes small packets into the core's TUN until stopped.
func (ft *fakeTun) pump(stop <-chan struct{}) {
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = unix.Sendto(ft.peer, pkt, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT, nil)
		time.Sleep(2 * time.Millisecond)
	}
}

// relayGoroutines counts the goroutines a TUN relay runs.
func relayGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	s := string(buf)
	count := 0
	for _, fn := range []string{
		"tun.runTUNToServer(",
		"tun.runServerToTUN(",
		"tun.runKeepaliveSender(",
		"tun.runDeadConnectionMonitor(",
	} {
		count += strings.Count(s, fn)
	}
	return count
}

func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// ctlHarness is a ControlServer with a host connected to its control socket
// and an in-memory exit on the other side of its server connection.
type ctlHarness struct {
	t   *testing.T
	cs  *ControlServer
	ctl *net.UnixConn
	dec *json.Decoder

	exitBytes atomic.Int64 // bytes the relay framed toward the exit
}

func newCtlHarness(t *testing.T) *ctlHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ctl.sock")
	cs, err := NewControlServer(path, &ControlConfig{MTU: 1280})
	if err != nil {
		t.Fatalf("NewControlServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = cs.Run(ctx) }()

	h := &ctlHarness{t: t, cs: cs}
	h.attachSession()

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		cancel()
		t.Fatalf("dial control socket: %v", err)
	}
	h.ctl = conn
	h.dec = json.NewDecoder(conn)
	t.Cleanup(func() {
		conn.Close()
		cancel()
		cs.Close()
	})
	return h
}

// attachSession puts the server in the state a successful "connect" leaves it
// in: a handshaken exit connection and an fd awaited.
func (h *ctlHarness) attachSession() {
	cs := h.cs
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.serverConn = h.newExitConn()
	cs.assignedIP = net.IPv4(10, 9, 0, 2)
	cs.serverIP = net.IPv4(10, 9, 0, 1)
	cs.waitingForFd = true
}

// newExitConn returns the client end of an in-memory exit that swallows
// whatever the relay sends it.
func (h *ctlHarness) newExitConn() net.Conn {
	cli, srv := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := srv.Read(buf)
			h.exitBytes.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	h.t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli
}

// send writes one command, with fd attached when fd >= 0, and returns the
// response, skipping asynchronous events.
func (h *ctlHarness) send(cmd string, fd int) ControlResponse {
	h.t.Helper()
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	if _, _, err := h.ctl.WriteMsgUnix([]byte(cmd), oob, nil); err != nil {
		h.t.Fatalf("send %s: %v", cmd, err)
	}
	_ = h.ctl.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		var raw map[string]any
		if err := h.dec.Decode(&raw); err != nil {
			h.t.Fatalf("read response to %s: %v", cmd, err)
		}
		if _, isEvent := raw["event"]; isEvent {
			continue
		}
		data, _ := json.Marshal(raw)
		var resp ControlResponse
		_ = json.Unmarshal(data, &resp)
		return resp
	}
}

func (h *ctlHarness) coreFd() int {
	h.cs.mu.Lock()
	defer h.cs.mu.Unlock()
	return h.cs.tunFd
}

var fdModes = []struct {
	name     string
	blocking bool
}{
	{"blocking", true},
	{"nonblocking", false},
}

// TestControlCloseReleasesTunFd is the device report in test form: after
// Disconnect the core must not keep the TUN alive. Close() has to close the
// copy it received over SCM_RIGHTS and stop every relay goroutine - with and
// without traffic, and for both modes the host may hand over (VpnService
// returns a non-blocking descriptor by default; Builder.setBlocking(true)
// makes it blocking).
func TestControlCloseReleasesTunFd(t *testing.T) {
	for _, mode := range fdModes {
		for _, traffic := range []bool{false, true} {
			name := mode.name + "/idle"
			if traffic {
				name = mode.name + "/traffic"
			}
			t.Run(name, func(t *testing.T) {
				baseline := relayGoroutines()
				h := newCtlHarness(t)
				ft := newFakeTun(t, mode.blocking)

				if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
					t.Fatalf("set_fd: %+v", resp)
				}
				ft.dropHostCopy()

				stop := make(chan struct{})
				var pumpWG sync.WaitGroup
				if traffic {
					pumpWG.Add(1)
					go func() { defer pumpWG.Done(); ft.pump(stop) }()
					if !waitFor(2*time.Second, func() bool { return h.exitBytes.Load() > 0 }) {
						t.Fatal("positive control: no packet reached the exit, the relay is not running")
					}
				}
				defer func() { close(stop); pumpWG.Wait() }()

				// Positive controls: the relay is visible to the counter, and
				// the core's copy keeps the peer from seeing a hangup.
				if !waitFor(2*time.Second, func() bool { return relayGoroutines() >= baseline+4 }) {
					t.Fatalf("positive control: relay goroutines not visible (baseline %d, now %d)", baseline, relayGoroutines())
				}
				if ft.peerSeesHangup(100 * time.Millisecond) {
					t.Fatal("positive control: peer saw a hangup while the core still holds the fd")
				}

				if err := h.cs.Close(); err != nil {
					t.Logf("Close: %v", err)
				}

				if !ft.peerSeesHangup(3 * time.Second) {
					t.Error("TUN fd still open at the OS level 3s after Close(): the interface would stay up")
				}
				if !waitFor(3*time.Second, func() bool { return relayGoroutines() <= baseline }) {
					t.Errorf("relay goroutines still running 3s after Close(): baseline %d, now %d", baseline, relayGoroutines())
				}
			})
		}
	}
}

// sendAsync is send for use off the test goroutine: it reports instead of
// failing the test.
func (h *ctlHarness) sendAsync(cmd string, fd int) <-chan ControlResponse {
	out := make(chan ControlResponse, 1)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	if _, _, err := h.ctl.WriteMsgUnix([]byte(cmd), oob, nil); err != nil {
		out <- ControlResponse{Status: "send-failed", Error: err.Error()}
		return out
	}
	go func() {
		_ = h.ctl.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			var raw map[string]any
			if err := h.dec.Decode(&raw); err != nil {
				out <- ControlResponse{Status: "read-failed", Error: err.Error()}
				return
			}
			if _, isEvent := raw["event"]; isEvent {
				continue
			}
			data, _ := json.Marshal(raw)
			var resp ControlResponse
			_ = json.Unmarshal(data, &resp)
			out <- resp
			return
		}
	}()
	return out
}

// withReconnect makes network_changed reconnect to a fresh in-memory exit and
// counts the calls.
func (h *ctlHarness) withReconnect() *atomic.Int32 {
	var calls atomic.Int32
	h.cs.mu.Lock()
	h.cs.config.ReconnectFn = func(context.Context, net.IP, int) (ReconnectResult, error) {
		calls.Add(1)
		return ReconnectResult{
			Conn:       h.newExitConn(),
			ServerIP:   net.IPv4(10, 9, 0, 1),
			AssignedIP: net.IPv4(10, 9, 0, 2),
		}, nil
	}
	h.cs.mu.Unlock()
	return &calls
}

// plantCanary occupies descriptor number n with /dev/null. A later close of n
// by number - the double close fdsan aborts on - kills the canary.
func plantCanary(t *testing.T, n int) int {
	t.Helper()
	var spare []int
	defer func() {
		for _, fd := range spare {
			unix.Close(fd)
		}
	}()
	for range 1024 {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open /dev/null: %v", err)
		}
		if fd == n {
			t.Cleanup(func() { unix.Close(fd) })
			return fd
		}
		if fd > n {
			unix.Close(fd)
			t.Fatalf("fd %d is still in use, cannot plant a canary there", n)
		}
		spare = append(spare, fd)
	}
	t.Fatalf("could not reach fd %d", n)
	return -1
}

func canaryAlive(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFCHR && unix.Major(st.Rdev) == 1 && unix.Minor(st.Rdev) == 3
}

// TestControlCloseTwiceClosesTunFdOnce: a second Close must not reach the
// descriptor number again. By then the number may belong to someone else in
// the process; on Android closing it is a fdsan abort.
func TestControlCloseTwiceClosesTunFdOnce(t *testing.T) {
	for _, mode := range fdModes {
		t.Run(mode.name, func(t *testing.T) {
			h := newCtlHarness(t)
			ft := newFakeTun(t, mode.blocking)
			if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
				t.Fatalf("set_fd: %+v", resp)
			}
			ft.dropHostCopy()
			n := h.coreFd()

			_ = h.cs.Close()
			if !ft.peerSeesHangup(3 * time.Second) {
				t.Fatal("first Close did not release the TUN fd")
			}
			canary := plantCanary(t, n)
			_ = h.cs.Close()
			if !canaryAlive(canary) {
				t.Fatalf("second Close closed descriptor %d by number again", n)
			}
		})
	}
}

// TestControlFdSwapClosesOldFdOnce covers both ways the host replaces the TUN
// on a live session - set_fd on a running relay (hot-swap) and
// network_changed with a new fd. The superseded descriptor has to be closed
// right away even when it is blocking and idle (it is: the host has already
// moved its routes to the new interface), exactly once, and Close later must
// leave its recycled number alone.
func TestControlFdSwapClosesOldFdOnce(t *testing.T) {
	for _, cmd := range []string{
		`{"command":"set_fd"}`,
		`{"command":"network_changed","reason":"wifi_to_lte"}`,
	} {
		for _, mode := range fdModes {
			name := "hot-swap/" + mode.name
			if strings.Contains(cmd, "network_changed") {
				name = "network_changed/" + mode.name
			}
			t.Run(name, func(t *testing.T) {
				baseline := relayGoroutines()
				h := newCtlHarness(t)
				h.withReconnect()
				oldTun := newFakeTun(t, mode.blocking)
				if resp := h.send(`{"command":"set_fd"}`, oldTun.host); resp.Status != "connected" {
					t.Fatalf("set_fd: %+v", resp)
				}
				oldTun.dropHostCopy()
				oldNum := h.coreFd()

				newTun := newFakeTun(t, mode.blocking)
				if resp := h.send(cmd, newTun.host); resp.Status != "connected" {
					t.Fatalf("swap: %+v", resp)
				}
				newTun.dropHostCopy()

				if !oldTun.peerSeesHangup(3 * time.Second) {
					t.Fatal("superseded TUN fd still open 3s after the swap: one leaked interface per network change")
				}
				if newTun.peerSeesHangup(100 * time.Millisecond) {
					t.Fatal("the swap closed the new TUN fd")
				}
				// At most one relay's worth of goroutines: the old relay is gone.
				// Not "exactly one": on the hot-swap path the stopped relay
				// closes the server connection it shares with the new one, so
				// the new relay's server reader dies at once. That is a defect
				// of its own, outside this test.
				if !waitFor(3*time.Second, func() bool { return relayGoroutines() <= baseline+4 }) {
					t.Errorf("the superseded relay outlived the swap: baseline %d, now %d", baseline, relayGoroutines())
				}

				canary := plantCanary(t, oldNum)
				_ = h.cs.Close()
				if !canaryAlive(canary) {
					t.Fatalf("Close closed the superseded descriptor %d by number a second time", oldNum)
				}
				if !newTun.peerSeesHangup(3 * time.Second) {
					t.Error("Close did not release the current TUN fd")
				}
				if !waitFor(3*time.Second, func() bool { return relayGoroutines() <= baseline }) {
					t.Errorf("relay goroutines left after Close: baseline %d, now %d", baseline, relayGoroutines())
				}
			})
		}
	}
}

// TestControlCloseDuringSwap: both swap paths drop cs.mu mid-way to let the
// old relay drain. A Close (or disconnect) landing in that gap used to be
// followed by the swap starting a relay on the nil server connection it left
// behind, and on a fd nothing would close any more.
func TestControlCloseDuringSwap(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		inSwap  func(cs *ControlServer) bool
		reconns bool
	}{
		{
			name:   "hot-swap",
			cmd:    `{"command":"set_fd"}`,
			inSwap: func(cs *ControlServer) bool { return cs.relayStopCh == nil && !cs.waitingForFd },
		},
		{
			name:    "network_changed",
			cmd:     `{"command":"network_changed","reason":"wifi_to_lte"}`,
			inSwap:  func(cs *ControlServer) bool { return cs.reconnecting },
			reconns: true,
		},
	}
	for _, tc := range cases {
		for _, mode := range fdModes {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				baseline := relayGoroutines()
				h := newCtlHarness(t)
				calls := h.withReconnect()
				oldTun := newFakeTun(t, mode.blocking)
				if resp := h.send(`{"command":"set_fd"}`, oldTun.host); resp.Status != "connected" {
					t.Fatalf("set_fd: %+v", resp)
				}
				oldTun.dropHostCopy()

				newTun := newFakeTun(t, mode.blocking)
				respCh := h.sendAsync(tc.cmd, newTun.host)
				newTun.dropHostCopy()

				inGap := func() bool {
					h.cs.mu.Lock()
					defer h.cs.mu.Unlock()
					return tc.inSwap(h.cs)
				}
				if !waitFor(2*time.Second, inGap) {
					t.Fatal("swap never reached its unlocked window")
				}
				_ = h.cs.Close()

				select {
				case resp := <-respCh:
					if resp.Status != "error" {
						t.Errorf("swap racing Close answered %+v, want an error", resp)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("no answer to the swap")
				}
				if !oldTun.peerSeesHangup(3 * time.Second) {
					t.Error("old TUN fd still open after Close")
				}
				if !newTun.peerSeesHangup(3 * time.Second) {
					t.Error("new TUN fd still open: the swap adopted it after Close, or never released it")
				}
				if !waitFor(3*time.Second, func() bool { return relayGoroutines() <= baseline }) {
					t.Errorf("a relay outlived Close: baseline %d, now %d", baseline, relayGoroutines())
				}
				if tc.reconns && calls.Load() != 0 {
					t.Errorf("ReconnectFn called %d times after Close", calls.Load())
				}
			})
		}
	}
}

// TestControlReleasesUnusedFd: a descriptor that arrives with a command that
// does not adopt it is the core's to close, or it pins an interface for the
// life of the process.
func TestControlReleasesUnusedFd(t *testing.T) {
	t.Run("status carrying an fd", func(t *testing.T) {
		h := newCtlHarness(t)
		ft := newFakeTun(t, true)
		if resp := h.send(`{"command":"status"}`, ft.host); resp.Status != "ok" {
			t.Fatalf("status: %+v", resp)
		}
		ft.dropHostCopy()
		if !ft.peerSeesHangup(3 * time.Second) {
			t.Error("fd attached to status was never closed")
		}
	})
	t.Run("set_fd while not waiting", func(t *testing.T) {
		h := newCtlHarness(t)
		h.cs.mu.Lock()
		h.cs.waitingForFd = false
		h.cs.mu.Unlock()
		ft := newFakeTun(t, true)
		if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "error" {
			t.Fatalf("set_fd: %+v", resp)
		}
		ft.dropHostCopy()
		if !ft.peerSeesHangup(3 * time.Second) {
			t.Error("rejected set_fd leaked its fd")
		}
	})
	t.Run("set_fd after Close", func(t *testing.T) {
		h := newCtlHarness(t)
		// A round trip first, so the connection is accepted before Close
		// shuts the listener.
		if resp := h.send(`{"command":"status"}`, -1); resp.Status != "ok" {
			t.Fatalf("status: %+v", resp)
		}
		_ = h.cs.Close()
		ft := newFakeTun(t, true)
		if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "error" {
			t.Fatalf("set_fd after Close: %+v", resp)
		}
		ft.dropHostCopy()
		if !ft.peerSeesHangup(3 * time.Second) {
			t.Error("set_fd after Close leaked its fd")
		}
	})
	t.Run("connect after Close", func(t *testing.T) {
		h := newCtlHarness(t)
		var dials atomic.Int32
		h.cs.mu.Lock()
		h.cs.config.ConnectFn = func(context.Context) (net.IP, net.IP, net.Conn, error) {
			dials.Add(1)
			return net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), h.newExitConn(), nil
		}
		h.cs.mu.Unlock()
		if resp := h.send(`{"command":"status"}`, -1); resp.Status != "ok" {
			t.Fatalf("status: %+v", resp)
		}
		_ = h.cs.Close()
		if resp := h.send(`{"command":"connect"}`, -1); resp.Status != "error" {
			t.Errorf("connect after Close: %+v", resp)
		}
		if dials.Load() != 0 {
			t.Errorf("connect after Close dialled the exit %d times", dials.Load())
		}
	})
	t.Run("network_changed after Close", func(t *testing.T) {
		baseline := relayGoroutines()
		h := newCtlHarness(t)
		calls := h.withReconnect()
		if resp := h.send(`{"command":"status"}`, -1); resp.Status != "ok" {
			t.Fatalf("status: %+v", resp)
		}
		_ = h.cs.Close()
		ft := newFakeTun(t, true)
		if resp := h.send(`{"command":"network_changed","reason":"wifi_to_lte"}`, ft.host); resp.Status != "error" {
			t.Errorf("network_changed after Close: %+v", resp)
		}
		ft.dropHostCopy()
		if !ft.peerSeesHangup(3 * time.Second) {
			t.Error("network_changed after Close leaked its fd")
		}
		if calls.Load() != 0 {
			t.Errorf("network_changed after Close reconnected %d times", calls.Load())
		}
		if !waitFor(3*time.Second, func() bool { return relayGoroutines() <= baseline }) {
			t.Errorf("a relay started after Close: baseline %d, now %d", baseline, relayGoroutines())
		}
	})
}

// TestControlDisconnectReportsNoDeadConnection: tearing the session down makes
// the relay's server read fail. That failure is the teardown, not a dead
// tunnel, and must not reach the host as connection_dead.
func TestControlDisconnectReportsNoDeadConnection(t *testing.T) {
	h := newCtlHarness(t)
	ft := newFakeTun(t, false)
	if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
		t.Fatalf("set_fd: %+v", resp)
	}
	ft.dropHostCopy()
	if resp := h.send(`{"command":"disconnect"}`, -1); resp.Status != "ok" {
		t.Fatalf("disconnect: %+v", resp)
	}
	if !ft.peerSeesHangup(3 * time.Second) {
		t.Error("disconnect did not release the TUN fd")
	}
	_ = h.ctl.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		var ev EventMessage
		if err := h.dec.Decode(&ev); err != nil {
			return // deadline: nothing more was sent
		}
		if ev.Event == "connection_dead" {
			t.Fatalf("host told connection_dead after its own disconnect: %+v", ev)
		}
	}
}

// inode is the socket inode behind the fake TUN's host end. Every descriptor
// that refers to that open file - the host's and the copy SCM_RIGHTS installs
// in the core - reads back as "socket:[inode]" in /proc/self/fd.
func (ft *fakeTun) inode(t *testing.T) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(ft.host, &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	return st.Ino
}

// tunFdCount counts this process's open descriptors that point at any of the
// given fake TUNs: what `ls -l /proc/<pid>/fd` shows for /dev/tun on a device.
func tunFdCount(t *testing.T, inodes ...uint64) int {
	t.Helper()
	want := make(map[string]bool, len(inodes))
	for _, ino := range inodes {
		want[fmt.Sprintf("socket:[%d]", ino)] = true
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err == nil && want[target] {
			n++
		}
	}
	return n
}

// TestControlTunFdCount counts descriptors the way the on-device check does:
// the process holds one per TUN before set_fd (the host's), two after it (the
// core's copy), and is back to the host's one after Close.
func TestControlTunFdCount(t *testing.T) {
	for _, mode := range fdModes {
		t.Run(mode.name, func(t *testing.T) {
			h := newCtlHarness(t)
			ft := newFakeTun(t, mode.blocking)
			ino := ft.inode(t)

			before := tunFdCount(t, ino)
			if before != 1 {
				t.Fatalf("before set_fd: %d TUN fds, want 1 (the host's)", before)
			}
			if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
				t.Fatalf("set_fd: %+v", resp)
			}
			if got := tunFdCount(t, ino); got != before+1 {
				t.Fatalf("positive control: after set_fd %d TUN fds, want %d", got, before+1)
			}

			_ = h.cs.Close()
			if !waitFor(3*time.Second, func() bool { return tunFdCount(t, ino) == before }) {
				t.Errorf("after Close: %d TUN fds, want %d: the core kept its copy", tunFdCount(t, ino), before)
			}
		})
	}
}

// TestControlTunFdCountAcrossSwaps: one network change after another must not
// grow the number of TUN descriptors. With every host copy dropped, the
// process holds exactly the core's current one, and none after Close.
func TestControlTunFdCountAcrossSwaps(t *testing.T) {
	const swaps = 5
	for _, cmd := range []string{
		`{"command":"set_fd"}`,
		`{"command":"network_changed","reason":"wifi_to_lte"}`,
	} {
		kind := "hot-swap"
		if strings.Contains(cmd, "network_changed") {
			kind = "network_changed"
		}
		for _, mode := range fdModes {
			t.Run(kind+"/"+mode.name, func(t *testing.T) {
				h := newCtlHarness(t)
				h.withReconnect()
				var inodes []uint64

				first := newFakeTun(t, mode.blocking)
				inodes = append(inodes, first.inode(t))
				if resp := h.send(`{"command":"set_fd"}`, first.host); resp.Status != "connected" {
					t.Fatalf("set_fd: %+v", resp)
				}
				first.dropHostCopy()
				if got := tunFdCount(t, inodes...); got != 1 {
					t.Fatalf("positive control: %d TUN fds after set_fd, want 1", got)
				}

				for i := range swaps {
					next := newFakeTun(t, mode.blocking)
					inodes = append(inodes, next.inode(t))
					if resp := h.send(cmd, next.host); resp.Status != "connected" {
						t.Fatalf("swap %d: %+v", i+1, resp)
					}
					next.dropHostCopy()
					if !waitFor(3*time.Second, func() bool { return tunFdCount(t, inodes...) == 1 }) {
						t.Fatalf("after swap %d: %d TUN fds, want 1: superseded descriptors pile up", i+1, tunFdCount(t, inodes...))
					}
				}

				_ = h.cs.Close()
				if !waitFor(3*time.Second, func() bool { return tunFdCount(t, inodes...) == 0 }) {
					t.Errorf("after Close: %d TUN fds, want 0", tunFdCount(t, inodes...))
				}
			})
		}
	}
}
