//go:build android || linux

package protect

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// protector handles Android VpnService socket protection
type protector struct {
	path string
	conn net.Conn
	mu   sync.Mutex
}

var globalProtector *protector

// InitAndroidProtector initializes the socket protector for Android
// Must be called before any network connections if running under VpnService
func InitAndroidProtector(socketPath string) error {
	if socketPath == "" {
		return nil // No protection needed
	}

	p := &protector{
		path: socketPath,
	}

	// Test connection to protect socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to protect socket %s: %w", socketPath, err)
	}
	conn.Close()

	globalProtector = p
	log.Info("Android socket protector initialized (path=%s)", socketPath)
	return nil
}

// ProtectSocket calls VpnService.protect() for the given file descriptor
// This excludes the socket from VPN routing, preventing loops
// Uses simple 4-byte little-endian fd format (compatible with Android LocalSocket)
func ProtectSocket(fd int) error {
	if globalProtector == nil {
		return nil // No protector, running without VpnService
	}
	// Use raw fd format (4-byte little-endian) - simpler and more compatible with Android
	return ProtectRawFd(fd)
}

// protect sends the fd to VpnService for protection
func (p *protector) protect(fd int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Connect to protect socket
	conn, err := net.Dial("unix", p.path)
	if err != nil {
		return fmt.Errorf("protect socket connect failed: %w", err)
	}
	defer conn.Close()

	// Get underlying unix connection for fd passing
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	// Send fd via SCM_RIGHTS
	file := os.NewFile(uintptr(fd), "socket")
	if file == nil {
		return fmt.Errorf("invalid fd: %d", fd)
	}

	// Build ancillary message with fd
	rights := syscall.UnixRights(fd)

	// Send dummy byte with fd in ancillary data
	_, _, err = unixConn.WriteMsgUnix([]byte{0}, rights, nil)
	if err != nil {
		return fmt.Errorf("fd send failed: %w", err)
	}

	// Read response (Android sends single byte: 0=success, 1=failure)
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("protect response read failed: %w", err)
	}

	if n == 0 || buf[0] != 0 {
		return fmt.Errorf("protect failed (response=%d)", buf[0])
	}

	log.Debug("Socket fd=%d protected", fd)
	return nil
}

// ProtectConn protects a net.Conn's underlying socket
func ProtectConn(conn net.Conn) error {
	if globalProtector == nil {
		return nil
	}

	// Get file descriptor from connection
	fd, err := getConnFd(conn)
	if err != nil {
		return err
	}
	if fd < 0 {
		return nil // No fd to protect
	}

	return ProtectSocket(fd)
}

// getConnFd extracts the file descriptor from various connection types
func getConnFd(conn net.Conn) (int, error) {
	// Try to get SyscallConn interface
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}

	if sc, ok := conn.(syscallConner); ok {
		rawConn, err := sc.SyscallConn()
		if err != nil {
			return -1, err
		}

		var fd int
		var controlErr error
		err = rawConn.Control(func(fdRaw uintptr) {
			fd = int(fdRaw)
		})
		if err != nil {
			return -1, err
		}
		if controlErr != nil {
			return -1, controlErr
		}
		return fd, nil
	}

	return -1, nil // Can't get fd, but not an error
}

// DialWithProtect creates a TCP connection and protects it from VPN routing
func DialWithProtect(network, address string) (net.Conn, error) {
	// Create socket
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Protect socket if running under VpnService
	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// ProtectDialer wraps a dialer with socket protection
type ProtectDialer struct {
	Dialer *net.Dialer
}

// Dial implements net.Dialer.Dial with socket protection
func (d *ProtectDialer) Dial(network, address string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	conn, err := dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// DialContext implements context-aware dialing with protection
func (d *ProtectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// IsProtectorActive returns whether the Android protector is active
func IsProtectorActive() bool {
	return globalProtector != nil
}

// ProtectRawFd is a simpler version that just sends the fd number
// Some Android implementations expect just the fd number as 4 bytes
func ProtectRawFd(fd int) error {
	if globalProtector == nil {
		return nil
	}

	globalProtector.mu.Lock()
	defer globalProtector.mu.Unlock()

	// Connect to protect socket
	conn, err := net.Dial("unix", globalProtector.path)
	if err != nil {
		return fmt.Errorf("protect socket connect failed: %w", err)
	}
	defer conn.Close()

	// Send fd as 4-byte little-endian integer
	fdBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(fdBytes, uint32(fd))

	if _, err := conn.Write(fdBytes); err != nil {
		return fmt.Errorf("fd write failed: %w", err)
	}

	// Read response (Android sends single byte: 0=success, 1=failure)
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("protect response read failed: %w", err)
	}

	if n == 0 || buf[0] != 0 {
		return fmt.Errorf("protect failed (response=%d)", buf[0])
	}

	log.Debug("Socket fd=%d protected", fd)
	return nil
}
