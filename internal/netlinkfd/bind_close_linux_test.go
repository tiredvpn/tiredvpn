//go:build linux

package netlinkfd

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// When bind(2) on a fresh netlink socket fails (Android denies it for apps
// with EACCES), the library must release the fd exactly once. netlink v1.3.1
// closed the raw fd while the *os.File wrapping it stayed alive, so the GC
// finalizer later closed the same number again - by then usually reused by an
// unrelated file. On Android the reused fd is often owned by fdsan, which
// aborts the process.
//
// Detector: make bind (or SetNonblock) fail on this thread only (seccomp),
// let the library close its socket, open a new fd that takes the freed
// number, force the finalizers and check that the new fd survived.

// seccompArch maps GOARCH to the AUDIT_ARCH value seen in seccomp_data.arch.
var seccompArch = map[string]uint32{
	"amd64": unix.AUDIT_ARCH_X86_64,
	"arm64": unix.AUDIT_ARCH_AARCH64,
}

// denyOnThisThread installs a seccomp filter on the calling OS thread that
// makes syscall nr fail with EACCES. If withArg1 is set, only calls whose
// second argument equals arg1 are denied. The caller must hold
// runtime.LockOSThread and never unlock it, so the thread is discarded when
// the goroutine exits.
func denyOnThisThread(nr uintptr, withArg1 bool, arg1 uint32) error {
	arch, ok := seccompArch[runtime.GOARCH]
	if !ok {
		return errors.ErrUnsupported
	}
	const (
		offNr      = 0  // offsetof(struct seccomp_data, nr)
		offArch    = 4  // offsetof(struct seccomp_data, arch)
		offArg1Low = 24 // low 32 bits of args[1] (little endian)
	)
	allow := unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}
	deny := unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)}
	var filter []unix.SockFilter
	if withArg1 {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 0, Jf: 5},
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offNr},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(nr), Jt: 0, Jf: 3},
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArg1Low},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arg1, Jt: 0, Jf: 1},
			deny,
			allow,
		}
	} else {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 0, Jf: 3},
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offNr},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(nr), Jt: 0, Jf: 1},
			deny,
			allow,
		}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
}

// denyBind makes bind(2) fail, the way Android denies it to apps.
func denyBind() error { return denyOnThisThread(unix.SYS_BIND, false, 0) }

// denySetNonblock makes fcntl(F_SETFL) fail, i.e. unix.SetNonblock.
func denySetNonblock() error { return denyOnThisThread(unix.SYS_FCNTL, true, unix.F_SETFL) }

// lowestFreeFd returns the number the next open/socket call will get.
func lowestFreeFd(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close: %v", err)
	}
	return fd
}

func fdOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

// assertSingleClose runs open on a thread restricted by deny, expects it to
// fail with EACCES, and checks that the socket fd was closed exactly once:
// not leaked, and not closed again later by a finalizer.
func assertSingleClose(t *testing.T, deny func() error, open func() error) {
	t.Helper()

	// Warm up the runtime poller so its epoll/eventfd descriptors are not
	// allocated in the middle of the scenario and do not shift fd numbers.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	want := lowestFreeFd(t)

	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the filtered thread dies with the goroutine
		if err := deny(); err != nil {
			errc <- errors.Join(errors.New("install seccomp filter"), err)
			return
		}
		errc <- open()
	}()
	err = <-errc
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skipf("seccomp filter not implemented for GOARCH=%s", runtime.GOARCH)
	}
	// Positive control: the error path under test was really taken.
	if !errors.Is(err, unix.EACCES) {
		t.Fatalf("expected the denied syscall to fail with EACCES, got %v", err)
	}

	if fdOpen(want) {
		t.Fatalf("fd %d still open after the failed call: the socket was leaked", want)
	}

	// Reuse the freed number, the way an unrelated part of the process would.
	reused, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer func() {
		if fdOpen(reused) {
			_ = unix.Close(reused)
		}
	}()
	if reused != want {
		t.Fatalf("fd numbering shifted (got %d, socket was %d); detector is not aimed at the socket fd", reused, want)
	}

	// Run finalizers of everything the failed call left behind.
	for range 10 {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		if !fdOpen(reused) {
			t.Fatalf("fd %d (reused by another file) was closed by a finalizer: double close of the netlink socket fd", reused)
		}
	}
}

// Request path: every package-level call (LinkByName, RouteList, ...) opens a
// socket through nl.getNetlinkSocket.
func TestNetlinkRequestBindFailureClosesFdOnce(t *testing.T) {
	assertSingleClose(t, denyBind, func() error {
		_, err := netlink.LinkByName("lo")
		return err
	})
}

// Subscription path: LinkSubscribe/RouteSubscribe/AddrSubscribe go through
// nl.Subscribe.
func TestNetlinkSubscribeBindFailureClosesFdOnce(t *testing.T) {
	assertSingleClose(t, denyBind, func() error {
		done := make(chan struct{})
		defer close(done)
		return netlink.LinkSubscribe(make(chan netlink.LinkUpdate), done)
	})
}

// Handle path: NewHandle opens one socket per family through
// nl.GetNetlinkSocketAt -> getNetlinkSocket.
func TestNetlinkNewHandleBindFailureClosesFdOnce(t *testing.T) {
	assertSingleClose(t, denyBind, func() error {
		h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
		if err == nil {
			h.Close()
		}
		return err
	})
}

// A SetNonblock failure happens before the *os.File exists; the raw fd must be
// closed rather than leaked.
func TestNetlinkRequestSetNonblockFailureClosesFd(t *testing.T) {
	assertSingleClose(t, denySetNonblock, func() error {
		_, err := netlink.LinkByName("lo")
		return err
	})
}

func TestNetlinkSubscribeSetNonblockFailureClosesFd(t *testing.T) {
	assertSingleClose(t, denySetNonblock, func() error {
		done := make(chan struct{})
		defer close(done)
		return netlink.LinkSubscribe(make(chan netlink.LinkUpdate), done)
	})
}
