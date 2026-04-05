//go:build android || linux

package tun

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// AndroidConfig holds Android VpnService specific configuration
type AndroidConfig struct {
	// TunFd is the file descriptor from VpnService.establish()
	// If > 0, use this fd instead of creating TUN device
	TunFd int

	// ProtectPath is the Unix socket path for protect() calls
	// VpnService listens on this socket to protect sockets from VPN routing
	ProtectPath string

	// MTU for the TUN device
	MTU int
}

// InitAndroidProtector delegates to protect package
func InitAndroidProtector(socketPath string) error {
	return protect.InitAndroidProtector(socketPath)
}

// ProtectSocket delegates to protect package
func ProtectSocket(fd int) error {
	return protect.ProtectSocket(fd)
}

// protect sends the fd to VpnService for protection
// ProtectConn delegates to protect package
func ProtectConn(conn net.Conn) error {
	return protect.ProtectConn(conn)
}

// CreateTUNFromFd creates a TUNDevice from an existing file descriptor
// This is used when running under Android VpnService
func CreateTUNFromFd(fd int, name string, mtu int) (*TUNDevice, error) {
	if fd <= 0 {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}

	if mtu == 0 {
		mtu = DefaultMTU
	}
	if name == "" {
		name = "tun0"
	}

	// Create file from fd
	file := os.NewFile(uintptr(fd), "tun")
	if file == nil {
		return nil, fmt.Errorf("failed to create file from fd %d", fd)
	}

	tun := &TUNDevice{
		name: name,
		file: file,
		mtu:  mtu,
	}

	log.Info("Created TUN device from fd: %d (name=%s, MTU=%d)", fd, name, mtu)
	return tun, nil
}

// ConfigureFromFd configures a TUN device that was created from an existing fd
// This skips the system configuration since VpnService already handles it
func (t *TUNDevice) ConfigureFromFd(localIP, remoteIP net.IP) error {
	t.localIP = localIP
	t.remoteIP = remoteIP

	log.Info("TUN device configured (from fd): local=%s, remote=%s", localIP, remoteIP)
	return nil
}

// DialWithProtect delegates to protect package
func DialWithProtect(network, address string) (net.Conn, error) {
	return protect.DialWithProtect(network, address)
}

// ProtectDialer is an alias for protect.ProtectDialer
type ProtectDialer = protect.ProtectDialer

// IsProtectorActive delegates to protect package
func IsProtectorActive() bool {
	return protect.IsProtectorActive()
}

// DialTCP creates a protected TCP connection
// This should be used by strategies when connecting to the VPN server
func DialTCP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	// Protect if running under VpnService
	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// DialUDP creates a protected UDP connection
// This should be used by QUIC strategies when connecting to the VPN server
func DialUDP(address string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.Dial("udp4", address)
	if err != nil {
		return nil, err
	}

	// Protect if running under VpnService
	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// ListenUDP creates a protected UDP listener (for QUIC client)
func ListenUDP(address string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}

	// Protect the listening socket
	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// ProtectRawFd delegates to protect package
func ProtectRawFd(fd int) error {
	return protect.ProtectRawFd(fd)
}
