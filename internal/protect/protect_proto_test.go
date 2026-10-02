//go:build android || linux

package protect

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// useApp installs a protector pointed at app with the given protocol and
// restores every package knob afterwards. It waits for held protocol-1
// duplicates to drain so one test cannot leak into the next.
func useApp(t *testing.T, app *fakeApp, proto int) {
	t.Helper()
	prevP, prevProto := globalProtector, configuredProto.Load()
	prevTimeout, prevEOF, prevMax, prevLimit := protectTimeout, v1HoldAfterEOF, v1HoldMax, v1HoldLimit
	t.Cleanup(func() {
		app.hangUpAll()
		waitHeldZero(t)
		globalProtector = prevP
		configuredProto.Store(prevProto)
		downgraded.Store(false)
		protectTimeout, v1HoldAfterEOF, v1HoldMax, v1HoldLimit = prevTimeout, prevEOF, prevMax, prevLimit
	})
	downgraded.Store(false)
	SetProtocol(proto)
	globalProtector = &protector{path: app.path}
}

func waitHeldZero(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for heldV1.Load() != 0 {
		if time.Now().After(deadline) {
			t.Errorf("%d protocol-1 duplicates still held after the test", heldV1.Load())
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// heldSocket reports whether number n is open and still names the socket
// with inode ino.
func heldSocket(n int, ino uint64) bool { return fdOpen(n) && inodeOf(n) == ino }

func openFds(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

// --- compatibility matrix, cells with the new core --------------------------

// Old app (1.11.0) x new core: protocol 1, the app gets a number, and that
// number is a private duplicate of the caller's socket.
func TestMatrixOldAppNewCore(t *testing.T) {
	app := startFakeApp(t, false)
	useApp(t, app, ProtoV1) // the old app never sends -protect-proto
	client, _ := tcpPair(t)
	want := connInode(t, client)

	if err := ProtectConn(client); err != nil {
		t.Fatalf("ProtectConn: %v", err)
	}
	ev := app.next(t, time.Second)
	if ev.version != 1 || ev.ino != want {
		t.Fatalf("app saw version %d, inode %d; want version 1 on the caller's socket %d", ev.version, ev.ino, want)
	}
	if fd, _ := getConnFd(client); ev.number == fd {
		t.Errorf("app got the caller's own number %d; it must get a private duplicate", fd)
	}
}

// New app x new core: protocol 2, one descriptor over SCM_RIGHTS, the core
// keeps nothing afterwards.
func TestMatrixNewAppNewCore(t *testing.T) {
	app := startFakeApp(t, true)
	useApp(t, app, ProtoV2)
	client, peer := tcpPair(t)
	want := connInode(t, client)

	before := openFds(t)
	if err := ProtectConn(client); err != nil {
		t.Fatalf("ProtectConn: %v", err)
	}
	ev := app.next(t, time.Second)
	if ev.version != 2 || ev.fdCount != 1 || ev.ino != want {
		t.Fatalf("app saw version %d, %d fds, inode %d; want v2, 1 fd, inode %d", ev.version, ev.fdCount, ev.ino, want)
	}
	if after := openFds(t); after != before {
		t.Errorf("open descriptors %d -> %d: the core kept its duplicate", before, after)
	}
	// Nobody else holds the socket: closing the caller's conn sends FIN now.
	client.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("peer read after close = %v, want EOF", err)
	}
}

// New app x core configured for v1 (the new app talking to the protocol-1
// path, which is byte-for-byte what 1.11.x sends apart from the number): the
// dual app must take the v1 branch.
func TestMatrixNewAppV1Request(t *testing.T) {
	app := startFakeApp(t, true)
	useApp(t, app, ProtoV1)
	client, _ := tcpPair(t)
	want := connInode(t, client)
	if err := ProtectConn(client); err != nil {
		t.Fatalf("ProtectConn: %v", err)
	}
	if ev := app.next(t, time.Second); ev.version != 1 || ev.fdCount != 0 || ev.ino != want {
		t.Fatalf("app saw %+v, want a v1 request on inode %d", ev, want)
	}
}

// Safety net: the core speaks v2 but the app is the old one. The old app
// reads the magic as a negative number, protect() fails, it answers 0x01.
// The core must switch to protocol 1 for good and retry the same request.
func TestV2ToOldAppDowngradesAndRetries(t *testing.T) {
	app := startFakeApp(t, false)
	useApp(t, app, ProtoV2)
	client, _ := tcpPair(t)
	want := connInode(t, client)

	if err := ProtectConn(client); err != nil {
		t.Fatalf("ProtectConn against an old app in v2 mode: %v", err)
	}
	if ev := app.next(t, time.Second); ev.ino != 0 || ev.number >= 0 {
		t.Fatalf("first request should be the v2 header read as a negative number, got %+v", ev)
	}
	if ev := app.next(t, time.Second); ev.ino != want {
		t.Fatalf("retry should protect the caller's socket %d, got %+v", want, ev)
	}
	if !downgraded.Load() || effectiveProto() != ProtoV1 {
		t.Fatal("core did not switch to protocol 1 after a v1 answer")
	}

	// Sticky: the next request goes out as v1 straight away.
	client2, _ := tcpPair(t)
	if err := ProtectConn(client2); err != nil {
		t.Fatalf("second ProtectConn: %v", err)
	}
	if got := app.accepted.Load(); got != 3 {
		t.Errorf("app saw %d requests, want 3 (v2 probe, v1 retry, v1)", got)
	}
}

// --- protocol 2 answers -----------------------------------------------------

func TestV2Statuses(t *testing.T) {
	cases := []struct {
		name   string
		protOK bool
		wantOK bool
	}{
		{"ok", true, true},
		{"protect false", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := startFakeApp(t, true, func(a *fakeApp) { a.protOK = tc.protOK })
			useApp(t, app, ProtoV2)
			client, _ := tcpPair(t)
			err := ProtectConn(client)
			if (err == nil) != tc.wantOK {
				t.Fatalf("ProtectConn err = %v, want ok=%v", err, tc.wantOK)
			}
			if downgraded.Load() {
				t.Error("a v2 failure status must not downgrade the core")
			}
		})
	}
}

// rawReplyServer answers every request with fixed bytes, ignoring it.
func rawReplyServer(t *testing.T, reply []byte) string {
	t.Helper()
	app := startFakeApp(t, true) // only for the path and cleanup
	app.hangUpAll()
	path := app.path + ".raw"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			c.Read(buf)
			c.Write(reply)
			c.Close()
		}
	}()
	return path
}

func TestV2RejectsMalformedAnswers(t *testing.T) {
	for name, reply := range map[string][]byte{
		"fd count":    {v2ReplyMarker, v2StatusFdCount},
		"bad request": {v2ReplyMarker, v2StatusBadRequest},
		"unknown":     {v2ReplyMarker, 0x7f},
		"marker only": {v2ReplyMarker},
		"garbage":     {0x55, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			app := startFakeApp(t, true)
			useApp(t, app, ProtoV2)
			globalProtector = &protector{path: rawReplyServer(t, reply)}
			client, _ := tcpPair(t)
			if err := ProtectConn(client); err == nil {
				t.Fatalf("answer % x accepted", reply)
			}
			if downgraded.Load() {
				t.Error("only a bare 0x00/0x01 answer may downgrade")
			}
		})
	}
}

// --- the race: slow app -----------------------------------------------------

// Fast version of the slow-app race with shrunk timers, both protocols, and
// both protect paths a caller can take.
func TestSlowAppNeverHitsReusedNumber(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dual  bool
		proto int
	}{
		{"v1 old app", false, ProtoV1},
		{"v2 new app", true, ProtoV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := startFakeApp(t, tc.dual, func(a *fakeApp) { a.delay = 1200 * time.Millisecond })
			useApp(t, app, tc.proto)
			protectTimeout = 300 * time.Millisecond

			sockIno, ev := slowAppScenario(t, app, ProtectConn, 3*time.Second)
			if ev.ino != sockIno {
				t.Fatalf("late protect() acted on inode %d, the caller's socket was %d: the number was reused", ev.ino, sockIno)
			}
		})
	}
}

// The same with the production timers: the app answers 6 s after the
// request, a second after the core's 5 s timeout. Parallel, so both run at
// the end together and cost one wait.
func TestSlowAppProductionTimers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dual  bool
		proto int
	}{
		{"v1 old app", false, ProtoV1},
		{"v2 new app", true, ProtoV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := startFakeApp(t, tc.dual, func(a *fakeApp) { a.delay = 6 * time.Second })
			p := &protector{path: app.path}
			fn := func(c net.Conn) error {
				// Not through the globals: the other subtest runs alongside.
				raw, _ := c.(*net.TCPConn).SyscallConn()
				var err error
				raw.Control(func(fd uintptr) {
					p.mu.Lock()
					defer p.mu.Unlock()
					if tc.proto == ProtoV2 {
						err = p.roundTripV2(int(fd))
					} else {
						err = p.roundTripV1(int(fd))
					}
					if err != nil {
						unix.Shutdown(int(fd), unix.SHUT_RDWR)
					}
				})
				return err
			}
			sockIno, ev := slowAppScenario(t, app, fn, 4*time.Second)
			if ev.ino != sockIno {
				t.Fatalf("late protect() acted on inode %d, the caller's socket was %d", ev.ino, sockIno)
			}
			if d := time.Since(ev.at); d > time.Second {
				t.Logf("event age %v", d)
			}
		})
	}
}

// --- protocol-1 hold ----------------------------------------------------------

// v1: the duplicate stays while the request hangs and goes right after the
// late answer.
func TestV1HoldReleasedByAnswer(t *testing.T) {
	app := startFakeApp(t, false, func(a *fakeApp) { a.delay = 800 * time.Millisecond })
	useApp(t, app, ProtoV1)
	protectTimeout = 200 * time.Millisecond

	client, _ := tcpPair(t)
	ino := connInode(t, client)
	if err := ProtectConn(client); err == nil {
		t.Fatal("expected a timeout")
	}
	client.Close()
	if heldV1.Load() != 1 {
		t.Fatalf("held = %d after the timeout, want 1", heldV1.Load())
	}
	ev := app.next(t, 2*time.Second)
	if ev.ino != ino {
		t.Fatalf("protect() acted on inode %d, want the socket %d", ev.ino, ino)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for heldSocket(ev.number, ino) {
		if time.Now().After(deadline) {
			t.Fatalf("number %d still held 200 ms after the answer", ev.number)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// v1: the app hangs up without answering. The duplicate stays for
// v1HoldAfterEOF, protect() may still be running in the app.
func TestV1HoldAfterHangUp(t *testing.T) {
	app := startFakeApp(t, false, func(a *fakeApp) { a.noReply = true })
	useApp(t, app, ProtoV1)
	v1HoldAfterEOF = 700 * time.Millisecond

	client, _ := tcpPair(t)
	ino := connInode(t, client)
	if err := ProtectConn(client); err == nil {
		t.Fatal("expected an error on hang-up")
	}
	client.Close()
	ev := app.next(t, time.Second)
	hungUp := time.Now()

	time.Sleep(400 * time.Millisecond)
	if !heldSocket(ev.number, ino) {
		t.Fatalf("number %d released %v after hang-up, want it held for %v", ev.number, time.Since(hungUp), v1HoldAfterEOF)
	}
	deadline := hungUp.Add(v1HoldAfterEOF + 500*time.Millisecond)
	for heldSocket(ev.number, ino) {
		if time.Now().After(deadline) {
			t.Fatal("number not released after the hang-up grace")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// v1: the app neither answers nor hangs up. The hold ends at v1HoldMax.
func TestV1HoldCap(t *testing.T) {
	app := startFakeApp(t, false, func(a *fakeApp) { a.hang = true })
	useApp(t, app, ProtoV1)
	protectTimeout = 100 * time.Millisecond
	v1HoldMax = 600 * time.Millisecond

	client, _ := tcpPair(t)
	ino := connInode(t, client)
	start := time.Now()
	if err := ProtectConn(client); err == nil {
		t.Fatal("expected a timeout")
	}
	client.Close()
	ev := app.next(t, time.Second)

	time.Sleep(300 * time.Millisecond)
	if !heldSocket(ev.number, ino) {
		t.Fatal("number released before the cap")
	}
	for heldSocket(ev.number, ino) {
		if time.Since(start) > v1HoldMax+500*time.Millisecond {
			t.Fatal("number still held past the cap")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// v1: at most 64 held numbers; the 65th request fails without being sent.
func TestV1HoldLimit(t *testing.T) {
	app := startFakeApp(t, false, func(a *fakeApp) { a.hang = true })
	useApp(t, app, ProtoV1)
	protectTimeout = 30 * time.Millisecond
	v1HoldAfterEOF = 50 * time.Millisecond
	if v1HoldLimit != 64 {
		t.Fatalf("v1HoldLimit = %d, the contract says 64", v1HoldLimit)
	}

	for i := range 64 {
		client, _ := tcpPair(t)
		if err := ProtectConn(client); err == nil {
			t.Fatalf("request %d unexpectedly answered", i)
		}
		client.Close()
	}
	if got := heldV1.Load(); got != 64 {
		t.Fatalf("held = %d, want 64", got)
	}
	client, _ := tcpPair(t)
	start := time.Now()
	err := ProtectConn(client)
	if err == nil || !strings.Contains(err.Error(), "backlog") {
		t.Fatalf("65th request: err = %v, want a backlog error", err)
	}
	if d := time.Since(start); d >= protectTimeout {
		t.Errorf("65th request took %v, it must fail without waiting", d)
	}
	time.Sleep(50 * time.Millisecond)
	if got := app.accepted.Load(); got != 64 {
		t.Errorf("app received %d requests, want 64: the 65th must not be sent", got)
	}
}

// --- contract test 10: FIN is not delayed ------------------------------------

// The held duplicate (v1) and the app's copy (v2) keep the socket alive after
// the caller's close. The core must shut the socket down on the error path,
// so the peer sees FIN when the dial fails, not when the app gets around to
// answering.
func TestFailureSendsFINWithoutDelay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dual  bool
		proto int
	}{
		{"v1", false, ProtoV1},
		{"v2", true, ProtoV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := startFakeApp(t, tc.dual, func(a *fakeApp) { a.delay = 2 * time.Second })
			useApp(t, app, tc.proto)
			protectTimeout = 200 * time.Millisecond

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			peerCh := make(chan net.Conn, 1)
			go func() {
				c, _ := ln.Accept()
				peerCh <- c
			}()

			d := &ProtectDialer{}
			_, err = d.DialContext(context.Background(), "tcp", ln.Addr().String())
			failedAt := time.Now()
			if err == nil {
				t.Fatal("dial succeeded although protect timed out")
			}
			peer := <-peerCh
			defer peer.Close()
			peer.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			_, rerr := peer.Read(make([]byte, 1))
			if rerr != io.EOF {
				t.Fatalf("peer read = %v, want EOF", rerr)
			}
			if lag := time.Since(failedAt); lag > 500*time.Millisecond {
				t.Fatalf("FIN arrived %v after the dial failed", lag)
			}
			app.next(t, 3*time.Second) // let the app finish before cleanup
		})
	}
}

// --- rule 7: every entry point --------------------------------------------------

// Each exported entry point must reach the dup-based path: in v2 the app gets
// a descriptor for the caller's socket, in v1 a number that is not the
// caller's own but names the same socket.
func TestEveryEntryPointUsesDuplicate(t *testing.T) {
	type entry struct {
		name string
		call func(t *testing.T, addr string) (fd int, ino uint64)
	}
	viaConn := func(t *testing.T, addr string, f func(net.Conn) error) (int, uint64) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		fd, _ := getConnFd(c)
		ino := connInode(t, c)
		if err := f(c); err != nil {
			t.Fatalf("protect: %v", err)
		}
		return fd, ino
	}
	viaDial := func(t *testing.T, dial func() (net.Conn, error)) (int, uint64) {
		c, err := dial()
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		fd, _ := getConnFd(c)
		return fd, connInode(t, c)
	}
	entries := []entry{
		{"ProtectConn", func(t *testing.T, a string) (int, uint64) { return viaConn(t, a, ProtectConn) }},
		{"ProtectSocket", func(t *testing.T, a string) (int, uint64) {
			return viaConn(t, a, func(c net.Conn) error { fd, _ := getConnFd(c); return ProtectSocket(fd) })
		}},
		{"ProtectRawFd", func(t *testing.T, a string) (int, uint64) {
			return viaConn(t, a, func(c net.Conn) error { fd, _ := getConnFd(c); return ProtectRawFd(fd) })
		}},
		{"DialWithProtect", func(t *testing.T, a string) (int, uint64) {
			return viaDial(t, func() (net.Conn, error) { return DialWithProtect("tcp", a) })
		}},
		{"ProtectDialer.Dial", func(t *testing.T, a string) (int, uint64) {
			return viaDial(t, func() (net.Conn, error) { return (&ProtectDialer{}).Dial("tcp", a) })
		}},
		{"ProtectDialer.DialContext", func(t *testing.T, a string) (int, uint64) {
			return viaDial(t, func() (net.Conn, error) {
				return (&ProtectDialer{}).DialContext(context.Background(), "tcp", a)
			})
		}},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	for _, proto := range []int{ProtoV1, ProtoV2} {
		for _, e := range entries {
			t.Run(e.name+"/v"+string(rune('0'+proto)), func(t *testing.T) {
				app := startFakeApp(t, true)
				useApp(t, app, proto)
				fd, ino := e.call(t, ln.Addr().String())
				ev := app.next(t, time.Second)
				if ev.version != proto || ev.ino != ino {
					t.Fatalf("app saw %+v; want version %d on inode %d", ev, proto, ino)
				}
				if proto == ProtoV2 && ev.fdCount != 1 {
					t.Fatalf("v2 request carried %d descriptors", ev.fdCount)
				}
				if proto == ProtoV1 && ev.number == fd {
					t.Fatalf("v1 request carried the caller's own number %d", fd)
				}
			})
		}
	}
}

// UDP sockets (QUIC) go through ProtectConn too, and shutdown on them is
// harmless.
func TestUDPSocketProtect(t *testing.T) {
	app := startFakeApp(t, true)
	useApp(t, app, ProtoV2)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	if err := ProtectConn(pc.(net.Conn)); err != nil {
		t.Fatalf("ProtectConn(udp): %v", err)
	}
	if ev := app.next(t, time.Second); ev.version != 2 || ev.fdCount != 1 {
		t.Fatalf("app saw %+v", ev)
	}
}
