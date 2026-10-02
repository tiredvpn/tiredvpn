//go:build linux

package tun

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The control socket is a byte stream (the Android host uses a SOCK_STREAM
// LocalSocket and writes one JSON command plus "\n" per write). Nothing in a
// stream keeps writes apart: two commands sent back to back can come out of
// one read, and one command can take several. These tests feed the server
// exactly that and check every command is still executed, in order, on a
// connection that stays open.

// write sends raw bytes on the control socket, with fd attached when >= 0.
func (h *ctlHarness) write(data string, fd int) {
	h.t.Helper()
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	if _, _, err := h.ctl.WriteMsgUnix([]byte(data), oob, nil); err != nil {
		h.t.Fatalf("write %q: %v", data, err)
	}
}

// collect reads the next n responses, failing on a closed connection or a
// timeout. A closed connection is what a parse error used to produce, and
// what the host answers with a full core restart.
func (h *ctlHarness) collect(n int, timeout time.Duration) []ControlResponse {
	h.t.Helper()
	var out []ControlResponse
	deadline := time.After(timeout)
	for len(out) < n {
		select {
		case resp, ok := <-h.respCh:
			if !ok {
				h.t.Fatalf("control connection closed after %d of %d responses %+v", len(out), n, out)
			}
			out = append(out, resp)
		case <-deadline:
			h.t.Fatalf("only %d of %d responses within %v: %+v", len(out), n, timeout, out)
		}
	}
	return out
}

func statuses(rs []ControlResponse) string {
	s := make([]string, len(rs))
	for i, r := range rs {
		s[i] = r.Status
	}
	return strings.Join(s, ",")
}

// stillServing checks the connection survived by running one more command.
func (h *ctlHarness) stillServing() {
	h.t.Helper()
	h.write(`{"command":"status"}`+"\n", -1)
	if got := h.collect(1, 5*time.Second); got[0].Status != "ok" {
		h.t.Fatalf("follow-up status: %+v", got[0])
	}
}

func TestControlFramingGluedCommands(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"two in one write",
			`{"command":"status"}` + "\n" + `{"command":"network_available","timestamp":1}` + "\n",
			"ok,ok"},
		{"three in one write",
			`{"command":"network_available","timestamp":1}` + "\n" + `{"command":"status"}` + "\n" + `{"command":"status"}` + "\n",
			"ok,ok,ok"},
		{"no separator between them",
			`{"command":"status"}{"command":"status"}`,
			"ok,ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCtlHarness(t)
			n := strings.Count(tc.want, ",") + 1
			h.write(tc.data, -1)
			if got := statuses(h.collect(n, 5*time.Second)); got != tc.want {
				t.Fatalf("responses %s, want %s", got, tc.want)
			}
			h.stillServing()
		})
	}
}

func TestControlFramingSplitCommand(t *testing.T) {
	cmd := `{"command":"network_available","timestamp":1790906835484}` + "\n"
	t.Run("two writes", func(t *testing.T) {
		h := newCtlHarness(t)
		h.write(cmd[:17], -1)
		time.Sleep(50 * time.Millisecond)
		h.write(cmd[17:], -1)
		if got := statuses(h.collect(1, 5*time.Second)); got != "ok" {
			t.Fatalf("responses %s", got)
		}
		h.stillServing()
	})
	t.Run("byte by byte", func(t *testing.T) {
		h := newCtlHarness(t)
		for i := range len(cmd) {
			h.write(cmd[i:i+1], -1)
			time.Sleep(2 * time.Millisecond)
		}
		if got := statuses(h.collect(1, 5*time.Second)); got != "ok" {
			t.Fatalf("responses %s", got)
		}
		h.stillServing()
	})
}

// TestControlFramingBrokenJSON: a malformed command is skipped up to the end
// of its line. Commands before it run, commands after it run, and the
// connection stays up - closing it is what turns one bad line into a full
// restart on the host.
func TestControlFramingBrokenJSON(t *testing.T) {
	h := newCtlHarness(t)
	h.write(`{"command":"status"}`+"\n"+`{"command": oops}`+"\n"+`{"command":"network_available","timestamp":1}`+"\n", -1)
	if got := statuses(h.collect(2, 5*time.Second)); got != "ok,ok" {
		t.Fatalf("responses %s, want ok,ok (the broken line skipped, its neighbours run)", got)
	}
	h.stillServing()
}

// TestControlFramingBrokenJSONReleasesFd: an fd that arrived with a line the
// server could not parse is closed, not leaked.
func TestControlFramingBrokenJSONReleasesFd(t *testing.T) {
	h := newCtlHarness(t)
	ft := newFakeTun(t, false)
	h.write(`{"command":"set_fd" oops}`+"\n", ft.host)
	ft.dropHostCopy()
	if !ft.peerSeesHangup(3 * time.Second) {
		t.Error("fd that came with a malformed command was never closed")
	}
	h.stillServing()
}

// TestControlFramingOversizedMessage: one message may not grow the buffer
// without bound. Past the limit the server drops the connection.
func TestControlFramingOversizedMessage(t *testing.T) {
	h := newCtlHarness(t)
	big := `{"command":"status","pad":"` + strings.Repeat("a", maxControlMessage) + `"}`
	go func() { _, _, _ = h.ctl.WriteMsgUnix([]byte(big), nil, nil) }()
	select {
	case _, ok := <-h.respCh:
		if ok {
			t.Fatal("an oversized message was answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized message neither answered nor refused: the server keeps buffering")
	}
}

// busyWithNetworkChanged starts a network_changed that keeps the server busy
// (it waits out the network handoff), so the next writes queue up in the
// socket and come out of a single read - the way the host's
// network_available and network_changed arrived together on a device.
func busyWithNetworkChanged(t *testing.T, h *ctlHarness) *fakeTun {
	t.Helper()
	first := newFakeTun(t, false)
	h.write(`{"command":"network_changed","reason":"wifi_to_lte"}`+"\n", first.host)
	first.dropHostCopy()
	time.Sleep(100 * time.Millisecond)
	return first
}

func sessionWithTun(t *testing.T) *ctlHarness {
	t.Helper()
	h := newCtlHarness(t)
	h.withReconnect()
	ft := newFakeTun(t, false)
	if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
		t.Fatalf("set_fd: %+v", resp)
	}
	ft.dropHostCopy()
	return h
}

// TestControlFramingFdFollowsItsCommand: when commands arrive together, the
// SCM_RIGHTS fd belongs to the command it was sent with. The kernel ends a
// read right after the bytes that carried an fd, so a command sent with an fd
// is always the last one to start in the read that delivers it.
func TestControlFramingFdFollowsItsCommand(t *testing.T) {
	t.Run("network_available then network_changed+fd", func(t *testing.T) {
		h := sessionWithTun(t)
		first := busyWithNetworkChanged(t, h)
		second := newFakeTun(t, false)
		secondIno := second.inode(t)
		h.write(`{"command":"network_available","timestamp":1}`+"\n", -1)
		h.write(`{"command":"network_changed","reason":"lte_to_wifi"}`+"\n", second.host)
		second.dropHostCopy()

		if got := statuses(h.collect(3, 10*time.Second)); got != "connected,ok,connected" {
			t.Fatalf("responses %s, want connected,ok,connected", got)
		}
		if n := tunFdCount(t, secondIno); n != 1 {
			t.Errorf("the second network_changed's fd: %d copies held, want 1 (the core's)", n)
		}
		if !first.peerSeesHangup(3 * time.Second) {
			t.Error("the superseded TUN fd was not closed")
		}
		h.stillServing()
	})
	t.Run("network_changed+fd then network_available", func(t *testing.T) {
		h := sessionWithTun(t)
		first := busyWithNetworkChanged(t, h)
		second := newFakeTun(t, false)
		secondIno := second.inode(t)
		h.write(`{"command":"network_changed","reason":"lte_to_wifi"}`+"\n", second.host)
		second.dropHostCopy()
		h.write(`{"command":"network_available","timestamp":1}`+"\n", -1)

		if got := statuses(h.collect(3, 10*time.Second)); got != "connected,connected,ok" {
			t.Fatalf("responses %s, want connected,connected,ok", got)
		}
		if n := tunFdCount(t, secondIno); n != 1 {
			t.Errorf("the second network_changed's fd: %d copies held, want 1", n)
		}
		if !first.peerSeesHangup(3 * time.Second) {
			t.Error("the superseded TUN fd was not closed")
		}
		h.stillServing()
	})
	t.Run("fd riding a command that takes none", func(t *testing.T) {
		h := sessionWithTun(t)
		busyWithNetworkChanged(t, h)
		stray := newFakeTun(t, false)
		h.write(`{"command":"network_available","timestamp":1}`+"\n", -1)
		h.write(`{"command":"status"}`+"\n", stray.host)
		stray.dropHostCopy()

		if got := statuses(h.collect(3, 10*time.Second)); got != "connected,ok,ok" {
			t.Fatalf("responses %s, want connected,ok,ok", got)
		}
		if !stray.peerSeesHangup(3 * time.Second) {
			t.Error("fd attached to status was not closed")
		}
		h.stillServing()
	})
}

// TestControlDeadRelayStopsItsMonitor: a relay that died on its own takes
// its keepalive sender and dead-connection monitor with it. A monitor left
// behind fires 45s later and reports connection_dead for a session that was
// already reported dead - after a restart, into a control connection that is
// gone ("Cannot send connection_dead").
func TestControlDeadRelayStopsItsMonitor(t *testing.T) {
	baseMon := countGoroutines("tun.runDeadConnectionMonitor(")
	baseKa := countGoroutines("tun.runKeepaliveSender(")
	h := newCtlHarness(t)
	exit := h.newTestExit()
	h.attachExit(exit)
	ft := newFakeTun(t, false)
	if resp := h.send(`{"command":"set_fd"}`, ft.host); resp.Status != "connected" {
		t.Fatalf("set_fd: %+v", resp)
	}
	ft.dropHostCopy()
	if !waitFor(2*time.Second, func() bool { return countGoroutines("tun.runDeadConnectionMonitor(") == baseMon+1 }) {
		t.Fatal("positive control: the monitor is not visible")
	}

	exit.srv.Close()
	if !waitFor(3*time.Second, func() bool { return h.eventCount("connection_dead") > 0 }) {
		t.Fatal("positive control: the relay did not die")
	}
	if !waitFor(3*time.Second, func() bool { return countGoroutines("tun.runDeadConnectionMonitor(") == baseMon }) {
		t.Errorf("the dead relay's monitor is still running (%d over baseline)", countGoroutines("tun.runDeadConnectionMonitor(")-baseMon)
	}
	if !waitFor(3*time.Second, func() bool { return countGoroutines("tun.runKeepaliveSender(") == baseKa }) {
		t.Errorf("the dead relay's keepalive sender is still running")
	}
}

func countGoroutines(fn string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), fn)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// TestControlFramingFdOnSplitCommand: the host's write can come apart in the
// stream. The fd arrives with the first piece and has to wait for the rest of
// its command; a piece that merely continues a command brings no fd of its
// own, and one that does anyway is closed.
func TestControlFramingFdOnSplitCommand(t *testing.T) {
	cmd := `{"command":"set_fd"}` + "\n"
	t.Run("fd with the first piece", func(t *testing.T) {
		h := newCtlHarness(t)
		ft := newFakeTun(t, false)
		ino := ft.inode(t)
		h.write(cmd[:8], ft.host)
		ft.dropHostCopy()
		time.Sleep(50 * time.Millisecond)
		h.write(cmd[8:], -1)
		if got := h.collect(1, 5*time.Second); got[0].Status != "connected" {
			t.Fatalf("split set_fd: %+v", got[0])
		}
		if n := tunFdCount(t, ino); n != 1 {
			t.Errorf("split set_fd: %d copies of its fd held, want 1 (the core's)", n)
		}
	})
	t.Run("stray fd on a continuation", func(t *testing.T) {
		h := newCtlHarness(t)
		stray := newFakeTun(t, false)
		status := `{"command":"status"}` + "\n"
		h.write(status[:8], -1)
		time.Sleep(50 * time.Millisecond)
		h.write(status[8:], stray.host)
		stray.dropHostCopy()
		if got := h.collect(1, 5*time.Second); got[0].Status != "ok" {
			t.Fatalf("status: %+v", got[0])
		}
		if !stray.peerSeesHangup(3 * time.Second) {
			t.Error("fd on a continuation piece was not closed")
		}
	})
	t.Run("connection lost mid-command", func(t *testing.T) {
		h := newCtlHarness(t)
		ft := newFakeTun(t, false)
		h.write(cmd[:8], ft.host)
		ft.dropHostCopy()
		time.Sleep(50 * time.Millisecond)
		h.ctl.Close()
		if !ft.peerSeesHangup(3 * time.Second) {
			t.Error("fd held for an unfinished command leaked when the connection closed")
		}
	})
}
