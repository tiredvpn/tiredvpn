// +build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

const (
	tunDevice  = "/dev/net/tun"
	ifnamsiz   = 16
	iffTun     = 0x0001
	iffNoPi    = 0x1000
)

// ifReq is the Linux interface request structure
type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	pad   [24 - ifnamsiz - 2]byte
}

// TUNDevice represents a TUN network interface
type TUNDevice struct {
	name     string
	file     *os.File
	mtu      int
	localIP  net.IP
	remoteIP net.IP
	routes   []string // Store routes to re-add after IP changes
}

// CreateTUN creates a new TUN device
func CreateTUN(name string, mtu int) (*TUNDevice, error) {
	// Open TUN device
	fd, err := syscall.Open(tunDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	// Configure interface
	var req ifReq
	req.Flags = iffTun | iffNoPi
	copy(req.Name[:], name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	// Get actual name
	actualName := string(req.Name[:])
	for i, b := range req.Name {
		if b == 0 {
			actualName = string(req.Name[:i])
			break
		}
	}

	file := os.NewFile(uintptr(fd), tunDevice)
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to create file from fd")
	}

	tun := &TUNDevice{
		name: actualName,
		file: file,
		mtu:  mtu,
	}

	log.Info("Created TUN device: %s (MTU=%d)", tun.name, mtu)
	return tun, nil
}

// Name returns the device name
func (t *TUNDevice) Name() string {
	return t.name
}

// Read reads a packet from the TUN device
func (t *TUNDevice) Read(p []byte) (int, error) {
	return t.file.Read(p)
}

// Write writes a packet to the TUN device
func (t *TUNDevice) Write(p []byte) (int, error) {
	return t.file.Write(p)
}

// SetReadDeadline sets the read deadline on the TUN device
// This can be used to unblock goroutines waiting on Read()
func (t *TUNDevice) SetReadDeadline(deadline time.Time) error {
	return t.file.SetReadDeadline(deadline)
}

// Close closes the TUN device and removes the interface
func (t *TUNDevice) Close() error {
	// Clean up iptables MSS clamping rules before removing interface
	if t.name != "" && t.mtu > 40 {
		mssStr := fmt.Sprintf("%d", t.mtu-40)
		runIPTables("-t", "mangle", "-D", "FORWARD", "-o", t.name,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mssStr)
		runIPTables("-t", "mangle", "-D", "FORWARD", "-i", t.name,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mssStr)
	}

	// Set immediate deadline to unblock any goroutines blocked on Read()
	t.file.SetReadDeadline(time.Now())

	// Close the file descriptor
	err := t.file.Close()

	// Then explicitly delete the interface to ensure cleanup
	// This is needed because closing fd alone may not remove the interface
	// if there are goroutines blocked on Read()
	if t.name != "" {
		runIP("link", "delete", t.name)
	}

	return err
}

// File returns the underlying file descriptor
func (t *TUNDevice) File() *os.File {
	return t.file
}

// Configure sets up the TUN device with IP address and routes
func (t *TUNDevice) Configure(localIP, remoteIP net.IP, routes []string) error {
	// Save IP addresses and routes
	t.localIP = localIP
	t.remoteIP = remoteIP
	t.routes = routes

	// Use netlink or ip command to configure
	// For simplicity, we'll use the ip command

	// Disable IPv6 BEFORE bringing interface up
	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte("1"), 0644); err != nil {
		log.Warn("Failed to disable IPv6 on %s: %v", t.name, err)
	} else {
		log.Debug("Disabled IPv6 on %s (before up)", t.name)
	}

	// Set interface up with IP
	if err := runIP("link", "set", "dev", t.name, "up"); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// Set MTU
	if err := runIP("link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", t.mtu)); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Set IP address (point-to-point)
	addr := fmt.Sprintf("%s/32", localIP.String())
	if err := runIP("addr", "add", addr, "peer", remoteIP.String(), "dev", t.name); err != nil {
		// Try without peer for simpler setup
		if err2 := runIP("addr", "add", fmt.Sprintf("%s/24", localIP.String()), "dev", t.name); err2 != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	// Add routes
	for _, route := range routes {
		if err := runIP("route", "add", route, "dev", t.name); err != nil {
			log.Warn("Failed to add route %s: %v", route, err)
		}
	}

	// TCP MSS clamping: prevent TCP sessions from negotiating segments larger than tunnel MTU
	// MSS = MTU - 20 (IP header) - 20 (TCP header)
	mss := t.mtu - 40
	if mss > 0 {
		mssStr := fmt.Sprintf("%d", mss)
		if err := runIPTables("-t", "mangle", "-A", "FORWARD", "-o", t.name,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mssStr); err != nil {
			log.Warn("Failed to set MSS clamping (FORWARD out): %v", err)
		}
		if err := runIPTables("-t", "mangle", "-A", "FORWARD", "-i", t.name,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mssStr); err != nil {
			log.Warn("Failed to set MSS clamping (FORWARD in): %v", err)
		}
		log.Info("TCP MSS clamping set to %d on %s", mss, t.name)
	}

	log.Info("TUN device %s configured: local=%s, remote=%s", t.name, localIP, remoteIP)
	return nil
}

// ConfigureSubnet sets up the TUN device with subnet routing (not point-to-point)
// Used for shared TUN where multiple clients share one interface
func (t *TUNDevice) ConfigureSubnet(localIP net.IP, network *net.IPNet) error {
	t.localIP = localIP

	// Disable IPv6 BEFORE bringing interface up
	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte("1"), 0644); err != nil {
		log.Warn("Failed to disable IPv6 on %s: %v", t.name, err)
	}

	// Bring interface up
	if err := runIP("link", "set", "dev", t.name, "up"); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// Set MTU
	if err := runIP("link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", t.mtu)); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Set IP address with subnet mask (NOT point-to-point)
	// Example: ip addr add 10.9.0.1/24 dev tiredvpn0
	ones, _ := network.Mask.Size()
	addr := fmt.Sprintf("%s/%d", localIP.String(), ones)
	if err := runIP("addr", "add", addr, "dev", t.name); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	// TCP MSS clamping for server-side shared TUN
	mss := t.mtu - 40
	if mss > 0 {
		mssStr := fmt.Sprintf("%d", mss)
		if err := runIPTables("-t", "mangle", "-A", "FORWARD", "-o", t.name,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mssStr); err != nil {
			log.Warn("Failed to set MSS clamping (FORWARD out): %v", err)
		}
		if err := runIPTables("-t", "mangle", "-A", "FORWARD", "-i", t.name,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mssStr); err != nil {
			log.Warn("Failed to set MSS clamping (FORWARD in): %v", err)
		}
		log.Info("TCP MSS clamping set to %d on %s", mss, t.name)
	}

	log.Info("TUN device %s configured with subnet: %s", t.name, addr)
	return nil
}

// UpdatePeerIP updates the peer IP address of the TUN device
func (t *TUNDevice) UpdatePeerIP(newRemoteIP net.IP) error {
	if newRemoteIP.Equal(t.remoteIP) {
		return nil // No change needed
	}

	// Remove old address
	oldAddr := fmt.Sprintf("%s/32", t.localIP.String())
	runIP("addr", "del", oldAddr, "peer", t.remoteIP.String(), "dev", t.name)

	// Add new address with updated peer
	newAddr := fmt.Sprintf("%s/32", t.localIP.String())
	if err := runIP("addr", "add", newAddr, "peer", newRemoteIP.String(), "dev", t.name); err != nil {
		return fmt.Errorf("failed to update peer IP: %w", err)
	}

	t.remoteIP = newRemoteIP
	log.Info("TUN device %s peer IP updated to %s", t.name, newRemoteIP)

	// Re-add routes (Linux removes them when IP is deleted)
	for _, route := range t.routes {
		if err := runIP("route", "add", route, "dev", t.name); err != nil {
			log.Warn("Failed to re-add route %s: %v", route, err)
		} else {
			log.Debug("Re-added route %s after peer IP change", route)
		}
	}

	return nil
}

// UpdateLocalIP updates the local IP address of the TUN device
// This is used when server assigns a different IP than requested
func (t *TUNDevice) UpdateLocalIP(newLocalIP net.IP) error {
	if newLocalIP.Equal(t.localIP) {
		return nil // No change needed
	}

	// Remove old address
	oldAddr := fmt.Sprintf("%s/32", t.localIP.String())
	runIP("addr", "del", oldAddr, "peer", t.remoteIP.String(), "dev", t.name)

	// Add new address
	newAddr := fmt.Sprintf("%s/32", newLocalIP.String())
	if err := runIP("addr", "add", newAddr, "peer", t.remoteIP.String(), "dev", t.name); err != nil {
		return fmt.Errorf("failed to update local IP: %w", err)
	}

	t.localIP = newLocalIP
	log.Info("TUN device %s local IP updated to %s", t.name, newLocalIP)

	// Re-add routes (Linux removes them when IP is deleted)
	for _, route := range t.routes {
		if err := runIP("route", "add", route, "dev", t.name); err != nil {
			log.Warn("Failed to re-add route %s: %v", route, err)
		} else {
			log.Debug("Re-added route %s after IP change", route)
		}
	}

	return nil
}

// runIP executes the ip command
func runIP(args ...string) error {
	cmd := fmt.Sprintf("ip %s", args)
	log.Debug("Running: %s", cmd)

	// Use syscall.ForkExec for simplicity
	pid, err := syscall.ForkExec("/sbin/ip", append([]string{"ip"}, args...), &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		return err
	}

	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return err
	}

	if status.ExitStatus() != 0 {
		return fmt.Errorf("ip command failed with status %d", status.ExitStatus())
	}

	return nil
}

// runIPTables executes the iptables command
func runIPTables(args ...string) error {
	cmd := fmt.Sprintf("iptables %s", args)
	log.Debug("Running: %s", cmd)

	pid, err := syscall.ForkExec("/sbin/iptables", append([]string{"iptables"}, args...), &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		return err
	}

	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return err
	}

	if status.ExitStatus() != 0 {
		return fmt.Errorf("iptables command failed with status %d", status.ExitStatus())
	}

	return nil
}
