//go:build android || linux

package protect

// Stand-ins for the Android protect server, old and new, plus the
// slow-app reuse scenario. Only the standard library and x/sys/unix are used
// on purpose: the same file is dropped next to the real v1.11.4 protect.go to
// show that the scenario does catch the race there (positive control, see the
// PR description).

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// What a fake app saw for one request.
type appEvent struct {
	version int       // 1 or 2, as the app classified the request
	number  int       // v1: the descriptor number from the request; v2: -1
	fdCount int       // descriptors that arrived via SCM_RIGHTS
	ino     uint64    // inode of what protect() acted on, 0 if nothing was open
	at      time.Time // when protect() ran
}

type fakeApp struct {
	path   string
	events chan appEvent

	// dual: classify requests the way the new app does (magic -> v2, else
	// v1). Without it the app is the 1.11.0 one: plain read of 4 bytes, the
	// number goes straight to protect().
	dual bool

	delay    time.Duration // before protect()
	protOK   bool          // what protect() returns if the target is open
	noReply  bool          // read the request, then hang up without answering
	hang     bool          // read the request, then never answer nor hang up
	accepted atomic.Int32

	mu    sync.Mutex
	conns []net.Conn
}

// startFakeApp starts the server. Knobs are set through opts, before the
// accept loop exists, so the race detector sees them ordered.
func startFakeApp(t *testing.T, dual bool, opts ...func(*fakeApp)) *fakeApp {
	t.Helper()
	a := &fakeApp{
		path:   filepath.Join(t.TempDir(), "protect.sock"),
		events: make(chan appEvent, 128),
		dual:   dual,
		protOK: true,
	}
	for _, o := range opts {
		o(a)
	}
	ln, err := net.Listen("unix", a.path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			a.mu.Lock()
			a.conns = append(a.conns, c)
			a.mu.Unlock()
			go a.serve(c.(*net.UnixConn))
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		a.hangUpAll()
	})
	return a
}

// hangUpAll closes every connection the app still holds.
func (a *fakeApp) hangUpAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.conns {
		c.Close()
	}
	a.conns = nil
}

func inodeOf(fd int) uint64 {
	var st unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &st) != nil {
		return 0
	}
	return st.Ino
}

// protect plays VpnService.protect(int): it acts on whatever holds the
// number right now. The inode records what that was.
func (a *fakeApp) protect(fd int) (uint64, bool) {
	time.Sleep(a.delay)
	ino := inodeOf(fd)
	return ino, ino != 0 && a.protOK
}

func (a *fakeApp) finish(c *net.UnixConn, reply []byte) {
	switch {
	case a.hang:
		return // the cleanup closes it
	case a.noReply:
		c.Close()
	default:
		_, _ = c.Write(reply)
		c.Close()
	}
}

func (a *fakeApp) serve(c *net.UnixConn) {
	if !a.dual {
		// 1.11.0: Os.read, i.e. read(2) without a control buffer. Any
		// SCM_RIGHTS descriptor is dropped by the kernel.
		var req [4]byte
		if _, err := readFull(c, req[:]); err != nil {
			c.Close()
			return
		}
		a.accepted.Add(1)
		n := int(int32(binary.LittleEndian.Uint32(req[:])))
		ino, ok := a.protect(n)
		a.events <- appEvent{version: 1, number: n, ino: ino, at: time.Now()}
		a.finish(c, []byte{boolByte(!ok)})
		return
	}

	var hdr [8]byte
	var fds []int
	got := 0
	readSome := func(want int) bool {
		for got < want {
			oob := make([]byte, unix.CmsgSpace(4*4))
			n, oobn, _, _, err := c.ReadMsgUnix(hdr[got:want], oob)
			if oobn > 0 {
				if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
					for _, m := range msgs {
						if r, rerr := unix.ParseUnixRights(&m); rerr == nil {
							fds = append(fds, r...)
						}
					}
				}
			}
			if err != nil || n == 0 {
				return false
			}
			got += n
		}
		return true
	}
	closeFds := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	if !readSome(4) {
		closeFds()
		c.Close()
		return
	}
	a.accepted.Add(1)
	if [4]byte(hdr[:4]) != v2Magic {
		closeFds()
		n := int(int32(binary.LittleEndian.Uint32(hdr[:4])))
		ino, ok := a.protect(n)
		a.events <- appEvent{version: 1, number: n, ino: ino, at: time.Now()}
		a.finish(c, []byte{boolByte(!ok)})
		return
	}
	if !readSome(8) {
		closeFds()
		c.Close()
		return
	}
	ev := appEvent{version: 2, number: -1, fdCount: len(fds)}
	status := byte(v2StatusOK)
	switch {
	case hdr[4] != v2Version || hdr[5] != v2OpProtect || hdr[6] != 0 || hdr[7] != 0:
		status = v2StatusBadRequest
	case len(fds) != 1:
		status = v2StatusFdCount
	default:
		ino, ok := a.protect(fds[0])
		ev.ino = ino
		if !ok {
			status = v2StatusProtectErr
		}
	}
	ev.at = time.Now()
	closeFds() // the copy goes before the answer
	a.events <- ev
	a.finish(c, []byte{v2ReplyMarker, status})
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func (a *fakeApp) next(t *testing.T, within time.Duration) appEvent {
	t.Helper()
	select {
	case ev := <-a.events:
		return ev
	case <-time.After(within):
		t.Fatalf("app saw no request within %v", within)
		return appEvent{}
	}
}

func fdOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

// tcpPair returns a dialed TCP conn and the accepted peer side.
func tcpPair(t *testing.T) (client, peer net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acc <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	peer = <-acc
	t.Cleanup(func() {
		client.Close()
		if peer != nil {
			peer.Close()
		}
	})
	return client, peer
}

func connInode(t *testing.T, c net.Conn) uint64 {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var ino uint64
	raw.Control(func(fd uintptr) { ino = inodeOf(int(fd)) })
	return ino
}

// slowAppScenario is the race itself. The app answers late, after the core
// has given up; the caller closes its socket as every dial helper does, and
// the freed low numbers are taken by unrelated files right away. Returns the
// inode of the caller's socket and what the app's protect() acted on.
func slowAppScenario(t *testing.T, app *fakeApp, protectFn func(net.Conn) error, wait time.Duration) (sockIno uint64, ev appEvent) {
	t.Helper()
	client, _ := tcpPair(t)
	sockIno = connInode(t, client)

	start := time.Now()
	if err := protectFn(client); err == nil {
		t.Fatal("protect succeeded although the app answers after the timeout")
	}
	t.Logf("protect gave up after %v", time.Since(start).Round(time.Millisecond))
	client.Close()

	// Occupy the lowest free numbers the way the rest of the process would.
	var squatters []*os.File
	for range 16 {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("open %s: %v", os.DevNull, err)
		}
		squatters = append(squatters, f)
	}
	defer func() {
		for _, f := range squatters {
			f.Close()
		}
	}()

	ev = app.next(t, wait)
	return sockIno, ev
}
