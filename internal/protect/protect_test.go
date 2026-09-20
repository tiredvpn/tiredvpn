//go:build android || linux

package protect

import (
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// resetProtector clears the package global and restores it after the test,
// so cases that install a protector do not leak state into others.
func resetProtector(t *testing.T) {
	t.Helper()
	prev := globalProtector
	globalProtector = nil
	t.Cleanup(func() { globalProtector = prev })
}

// fakeProtectServer stands in for the Android VpnService protect() handler:
// it accepts one connection, reads the 4-byte little-endian fd, records it,
// and replies with a single status byte.
func fakeProtectServer(t *testing.T, reply []byte, closeWithoutReply bool) (path string, gotFd <-chan uint32) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "protect.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	fdCh := make(chan uint32, 4)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4)
			if _, err := conn.Read(buf); err != nil {
				conn.Close()
				continue
			}
			fdCh <- binary.LittleEndian.Uint32(buf)
			if !closeWithoutReply {
				_, _ = conn.Write(reply)
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return path, fdCh
}

func TestInitAndroidProtectorEmpty(t *testing.T) {
	resetProtector(t)
	if err := InitAndroidProtector(""); err != nil {
		t.Fatalf("empty path should be a no-op, got %v", err)
	}
	if IsProtectorActive() {
		t.Error("protector must stay inactive for empty path")
	}
}

func TestInitAndroidProtectorConnectFail(t *testing.T) {
	resetProtector(t)
	err := InitAndroidProtector(filepath.Join(t.TempDir(), "does-not-exist.sock"))
	if err == nil {
		t.Fatal("expected error connecting to nonexistent socket")
	}
	if IsProtectorActive() {
		t.Error("protector must not activate on connect failure")
	}
}

func TestInitAndroidProtectorSuccess(t *testing.T) {
	resetProtector(t)
	path, _ := fakeProtectServer(t, []byte{0}, false)
	if err := InitAndroidProtector(path); err != nil {
		t.Fatalf("InitAndroidProtector: %v", err)
	}
	if !IsProtectorActive() {
		t.Error("protector should be active after successful init")
	}
}

func TestProtectSocketNoProtector(t *testing.T) {
	resetProtector(t)
	if err := ProtectSocket(42); err != nil {
		t.Errorf("ProtectSocket without protector should be nil, got %v", err)
	}
	if err := ProtectRawFd(42); err != nil {
		t.Errorf("ProtectRawFd without protector should be nil, got %v", err)
	}
	if err := ProtectConn(nil); err != nil {
		t.Errorf("ProtectConn(nil) without protector should be nil, got %v", err)
	}
}

func TestProtectRawFdSuccess(t *testing.T) {
	resetProtector(t)
	path, gotFd := fakeProtectServer(t, []byte{0}, false)
	globalProtector = &protector{path: path}

	if err := ProtectRawFd(1234); err != nil {
		t.Fatalf("ProtectRawFd success path returned %v", err)
	}
	select {
	case fd := <-gotFd:
		if fd != 1234 {
			t.Errorf("server received fd=%d, want 1234 (little-endian wire check)", fd)
		}
	case <-time.After(time.Second):
		t.Fatal("server never received the fd")
	}
}

func TestProtectRawFdFailureReply(t *testing.T) {
	resetProtector(t)
	// Positive control is TestProtectRawFdSuccess (reply 0 => nil). Here reply 1
	// must turn into an error.
	path, _ := fakeProtectServer(t, []byte{1}, false)
	globalProtector = &protector{path: path}

	if err := ProtectRawFd(7); err == nil {
		t.Fatal("reply byte 1 must produce an error")
	}
}

func TestProtectRawFdNoReply(t *testing.T) {
	resetProtector(t)
	path, _ := fakeProtectServer(t, nil, true) // reads fd, closes without replying
	globalProtector = &protector{path: path}

	if err := ProtectRawFd(7); err == nil {
		t.Fatal("closed connection without reply must produce a read error")
	}
}

func TestProtectRawFdDialFail(t *testing.T) {
	resetProtector(t)
	globalProtector = &protector{path: filepath.Join(t.TempDir(), "gone.sock")}
	if err := ProtectRawFd(7); err == nil {
		t.Fatal("dialing a missing protect socket must fail")
	}
}

// getConnFd on a real TCP connection must return a valid (>=0) descriptor.
func TestGetConnFdTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fd, err := getConnFd(conn)
	if err != nil {
		t.Fatalf("getConnFd: %v", err)
	}
	if fd < 0 {
		t.Errorf("TCP conn fd = %d, want >= 0", fd)
	}
}

// nonSyscallConn is a net.Conn that does not expose SyscallConn.
type nonSyscallConn struct{}

func (nonSyscallConn) Read([]byte) (int, error)         { return 0, nil }
func (nonSyscallConn) Write([]byte) (int, error)        { return 0, nil }
func (nonSyscallConn) Close() error                     { return nil }
func (nonSyscallConn) LocalAddr() net.Addr              { return nil }
func (nonSyscallConn) RemoteAddr() net.Addr             { return nil }
func (nonSyscallConn) SetDeadline(time.Time) error      { return nil }
func (nonSyscallConn) SetReadDeadline(time.Time) error  { return nil }
func (nonSyscallConn) SetWriteDeadline(time.Time) error { return nil }

// Positive control: TestGetConnFdTCP returns >=0 for a syscall-capable conn.
// Here a conn without SyscallConn must return -1 with no error (best-effort).
func TestGetConnFdNonSyscall(t *testing.T) {
	fd, err := getConnFd(nonSyscallConn{})
	if err != nil {
		t.Errorf("expected nil error for non-syscall conn, got %v", err)
	}
	if fd != -1 {
		t.Errorf("fd = %d, want -1 for conn without SyscallConn", fd)
	}
}

func TestProtectConnNoFdNoError(t *testing.T) {
	resetProtector(t)
	path, _ := fakeProtectServer(t, []byte{0}, false)
	globalProtector = &protector{path: path}
	// Non-syscall conn yields fd < 0, so ProtectConn returns nil without
	// contacting the protect socket.
	if err := ProtectConn(nonSyscallConn{}); err != nil {
		t.Errorf("ProtectConn with unprotectable conn should be nil, got %v", err)
	}
}

func TestProtectConnRealConnSuccess(t *testing.T) {
	resetProtector(t)
	path, gotFd := fakeProtectServer(t, []byte{0}, false)
	globalProtector = &protector{path: path}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := ProtectConn(conn); err != nil {
		t.Fatalf("ProtectConn on real conn: %v", err)
	}
	select {
	case <-gotFd:
	case <-time.After(time.Second):
		t.Fatal("protect socket never received an fd")
	}
}

func TestDialWithProtectNoProtector(t *testing.T) {
	resetProtector(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	conn, err := DialWithProtect("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialWithProtect: %v", err)
	}
	conn.Close()
}

func TestDialWithProtectDialFail(t *testing.T) {
	resetProtector(t)
	// Loopback port 1 is not listening: connection refused, fast and reliable.
	if _, err := DialWithProtect("tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("expected dial error to an unconnectable address")
	}
}

func TestProtectDialer(t *testing.T) {
	resetProtector(t)
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
			c.Close()
		}
	}()

	d := &ProtectDialer{}
	c1, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("ProtectDialer.Dial: %v", err)
	}
	c1.Close()

	c2, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("ProtectDialer.DialContext: %v", err)
	}
	c2.Close()
}

// When the protector is active but protect() fails, the dial helpers must
// close the freshly-dialed conn and return a "protect failed" error rather
// than hand back an unprotected connection.
func TestDialHelpersAbortOnProtectFailure(t *testing.T) {
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
			c.Close()
		}
	}()
	addr := ln.Addr().String()

	install := func() {
		path, _ := fakeProtectServer(t, []byte{1}, false) // reply 1 => protect fails
		globalProtector = &protector{path: path}
	}

	t.Run("DialWithProtect", func(t *testing.T) {
		resetProtector(t)
		install()
		if _, err := DialWithProtect("tcp", addr); err == nil {
			t.Fatal("expected protect-failure error from DialWithProtect")
		}
	})
	t.Run("ProtectDialer.Dial", func(t *testing.T) {
		resetProtector(t)
		install()
		d := &ProtectDialer{Dialer: &net.Dialer{}}
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected protect-failure error from ProtectDialer.Dial")
		}
	})
	t.Run("ProtectDialer.DialContext", func(t *testing.T) {
		resetProtector(t)
		install()
		d := &ProtectDialer{Dialer: &net.Dialer{}}
		if _, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Fatal("expected protect-failure error from ProtectDialer.DialContext")
		}
	})
}

func TestProtectDialerDialContextCancelled(t *testing.T) {
	resetProtector(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	d := &ProtectDialer{}
	if _, err := d.DialContext(ctx, "tcp", "192.0.2.1:80"); err == nil {
		t.Fatal("expected error dialing with a cancelled context")
	}
}
