//go:build darwin
// +build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// macOS utun is exposed as a kernel control socket. Packets carry a 4-byte
// big-endian protocol family prefix (AF_INET=2, AF_INET6=30). The rest of the
// codebase deals with raw IP packets, so we strip the prefix on Read and add
// one on Write — same shape as Linux TUN with IFF_NO_PI.

const (
	// kernel control protocol family
	pfSystem = syscall.AF_SYSTEM
	// SYSPROTO_CONTROL is defined in <sys/sys_domain.h>; not exported by syscall pkg
	sysprotoControl = 2
	// kernel control name for utun
	utunControlName = "com.apple.net.utun_control"
	// ioctls — values from <sys/kern_control.h>
	ctliocginfo = 0xc0644e03
	// getsockopt level/option for utun interface name
	utunOptIfname = 2
	// AF_INET prefix used for outgoing IPv4 packets
	afInetPrefix uint32 = syscall.AF_INET
)

// ctlInfo mirrors struct ctl_info from <sys/kern_control.h>
type ctlInfo struct {
	ctlID   uint32
	ctlName [96]byte
}

// sockaddrCtl mirrors struct sockaddr_ctl from <sys/kern_control.h>
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// TUNDevice represents a macOS utun interface.
type TUNDevice struct {
	name string
	file *os.File
	// mtu is the construction-time MTU (configured cap), immutable afterwards.
	// The live MTU updated by SetMTU is held in atomicMTU and read via MTU().
	mtu       int
	atomicMTU int32
	localIP   net.IP
	remoteIP  net.IP
	routes    []string

	writeMu sync.Mutex
	readBuf []byte
}

// MTU returns the current effective interface MTU (atomic read).
func (t *TUNDevice) MTU() int {
	if m := int(atomic.LoadInt32(&t.atomicMTU)); m > 0 {
		return m
	}
	return t.mtu
}

// SetMTU changes the live interface MTU. On the utun-owned path it runs ifconfig;
// on the NetworkExtension fd path the host owns the link, so only the framing MTU
// is updated.
func (t *TUNDevice) SetMTU(mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("invalid MTU: %d", mtu)
	}
	if out, err := exec.Command("ifconfig", t.name, "mtu", fmt.Sprintf("%d", mtu)).CombinedOutput(); err != nil {
		log.Warn("SetMTU: ifconfig %s mtu %d failed: %v (%s)", t.name, mtu, err, string(out))
	}
	atomic.StoreInt32(&t.atomicMTU, int32(mtu))
	log.Info("TUN device %s MTU set to %d", t.name, mtu)
	return nil
}

// CreateTUN opens a new utun device. The `name` argument is advisory — macOS
// assigns utunN sequentially; if name is "utunN" we try that unit, otherwise
// we let the kernel pick the next free one.
func CreateTUN(name string, mtu int) (*TUNDevice, error) {
	fd, err := syscall.Socket(pfSystem, syscall.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("socket(PF_SYSTEM): %w", err)
	}

	var info ctlInfo
	copy(info.ctlName[:], utunControlName)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(ctliocginfo), uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO: %v", errno)
	}

	unit := uint32(0) // 0 = let kernel choose
	if n, ok := parseUtunUnit(name); ok {
		unit = n + 1 // kernel uses 1-based unit numbers
	}

	sc := sockaddrCtl{
		scLen:    uint8(unsafe.Sizeof(sockaddrCtl{})),
		scFamily: syscall.AF_SYSTEM,
		// SYSPROTO_CONTROL == AF_SYS_CONTROL == 2
		ssSysaddr: sysprotoControl,
		scID:      info.ctlID,
		scUnit:    unit,
	}

	// syscall.Connect wants RawSockaddr; we cast manually
	_, _, errno = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sc)), uintptr(sc.scLen))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect utun: %v", errno)
	}

	// Read back the actual interface name
	ifName, err := getUtunName(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("get utun name: %w", err)
	}

	// Non-blocking IO so SetReadDeadline works via os.File
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("set nonblock: %w", err)
	}

	file := os.NewFile(uintptr(fd), ifName)
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("os.NewFile failed for fd %d", fd)
	}

	t := &TUNDevice{
		name:      ifName,
		file:      file,
		mtu:       mtu,
		atomicMTU: int32(mtu),
		readBuf:   make([]byte, 65536+4),
	}
	log.Info("Created utun device: %s (MTU=%d)", ifName, mtu)
	return t, nil
}

// Name returns the kernel-assigned interface name (e.g. "utun3").
func (t *TUNDevice) Name() string { return t.name }

// Read reads one IP packet, stripping the 4-byte protocol family prefix.
func (t *TUNDevice) Read(p []byte) (int, error) {
	n, err := t.file.Read(t.readBuf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("short utun read: %d", n)
	}
	copied := copy(p, t.readBuf[4:n])
	return copied, nil
}

// Write writes one IP packet, prepending the AF_INET protocol family prefix.
// Caller passes the raw IP packet; we infer family from the version nibble.
func (t *TUNDevice) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	family := afInetPrefix
	if p[0]>>4 == 6 {
		family = syscall.AF_INET6
	}

	buf := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(buf[:4], family)
	copy(buf[4:], p)

	n, err := t.file.Write(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, nil
	}
	return n - 4, nil
}

// SetReadDeadline forwards to the underlying *os.File.
func (t *TUNDevice) SetReadDeadline(deadline time.Time) error {
	return t.file.SetReadDeadline(deadline)
}

// SetServerBypassIP is a no-op on macOS. Full-tunnel server bypass is not yet
// implemented for the utun/scutil path; provided so cross-platform callers
// (vpn.go) compile.
func (t *TUNDevice) SetServerBypassIP(net.IP) {}

// SetDeferRoutes is a no-op on macOS; route deferral is a Linux-only safeguard.
// Provided so cross-platform callers (vpn.go) compile.
func (t *TUNDevice) SetDeferRoutes(bool) {}

// InstallRoutes is a no-op on macOS; routes are installed by Configure (CLI) or
// by the host (NetworkExtension). Provided for cross-platform parity.
func (t *TUNDevice) InstallRoutes() {}

// Close closes the utun socket. macOS removes the interface automatically
// when the controlling socket is closed.
func (t *TUNDevice) Close() error {
	_ = t.file.SetReadDeadline(time.Now())
	return t.file.Close()
}

// File exposes the underlying *os.File (kept for parity with linux).
func (t *TUNDevice) File() *os.File { return t.file }

// Configure brings the interface up with point-to-point addressing and routes.
// In MacOSMode (NetworkExtension), this is a no-op because the host applies
// NEPacketTunnelNetworkSettings itself. Callers in CLI mode invoke this with
// elevated privileges so `ifconfig`/`route` succeed.
func (t *TUNDevice) Configure(localIP, remoteIP net.IP, routes []string) error {
	t.localIP = localIP
	t.remoteIP = remoteIP
	t.routes = routes

	if err := runIfconfig(t.name, "inet", localIP.String(), remoteIP.String(),
		"mtu", fmt.Sprintf("%d", t.mtu), "up"); err != nil {
		return fmt.Errorf("ifconfig: %w", err)
	}

	for _, r := range routes {
		if err := runRoute("add", "-net", r, "-interface", t.name); err != nil {
			log.Warn("route add %s failed: %v", r, err)
		}
	}

	log.Info("utun %s configured: local=%s remote=%s", t.name, localIP, remoteIP)
	return nil
}

// ConfigureSubnet — point-to-multipoint mode. Used by the server flow; the
// macOS client never runs as a server so we just refuse loudly to catch misuse.
func (t *TUNDevice) ConfigureSubnet(localIP net.IP, network *net.IPNet) error {
	return fmt.Errorf("ConfigureSubnet not supported on darwin (server-only API)")
}

// UpdatePeerIP changes the point-to-point peer address.
func (t *TUNDevice) UpdatePeerIP(newRemoteIP net.IP) error {
	if newRemoteIP.Equal(t.remoteIP) {
		return nil
	}
	if err := runIfconfig(t.name, "inet", t.localIP.String(), newRemoteIP.String(),
		"mtu", fmt.Sprintf("%d", t.mtu), "up"); err != nil {
		return fmt.Errorf("ifconfig (peer update): %w", err)
	}
	t.remoteIP = newRemoteIP
	for _, r := range t.routes {
		_ = runRoute("add", "-net", r, "-interface", t.name)
	}
	return nil
}

// UpdateLocalIP changes the local point-to-point address.
func (t *TUNDevice) UpdateLocalIP(newLocalIP net.IP) error {
	if newLocalIP.Equal(t.localIP) {
		return nil
	}
	if err := runIfconfig(t.name, "inet", newLocalIP.String(), t.remoteIP.String(),
		"mtu", fmt.Sprintf("%d", t.mtu), "up"); err != nil {
		return fmt.Errorf("ifconfig (local update): %w", err)
	}
	t.localIP = newLocalIP
	for _, r := range t.routes {
		_ = runRoute("add", "-net", r, "-interface", t.name)
	}
	return nil
}

// getUtunName reads the kernel-assigned interface name via getsockopt.
func getUtunName(fd int) (string, error) {
	const sysprotoLevel = sysprotoControl
	var buf [16]byte
	bufLen := uint32(len(buf))
	// getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &buf, &bufLen)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(sysprotoLevel), uintptr(utunOptIfname),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)), 0)
	if errno != 0 {
		return "", fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %v", errno)
	}
	end := int(bufLen)
	if end > 0 && buf[end-1] == 0 {
		end--
	}
	return string(buf[:end]), nil
}

// parseUtunUnit extracts N from a name like "utun5". Returns ok=false otherwise.
func parseUtunUnit(name string) (uint32, bool) {
	const prefix = "utun"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return 0, false
	}
	var n uint32
	for _, c := range name[len(prefix):] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint32(c-'0')
	}
	return n, true
}

// runIfconfig wraps /sbin/ifconfig.
func runIfconfig(args ...string) error {
	log.Debug("ifconfig %v", args)
	return exec.Command("/sbin/ifconfig", args...).Run()
}

// runRoute wraps /sbin/route.
func runRoute(args ...string) error {
	log.Debug("route %v", args)
	return exec.Command("/sbin/route", args...).Run()
}

// CreateTUNFromFd wraps an existing file descriptor (passed by the
// NetworkExtension host) into a TUNDevice. The caller owns route/DNS setup.
func CreateTUNFromFd(fd int, name string, mtu int) (*TUNDevice, error) {
	if fd <= 0 {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if name == "" {
		name = "utun0"
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		return nil, fmt.Errorf("os.NewFile failed for fd %d", fd)
	}
	t := &TUNDevice{
		name:      name,
		file:      file,
		mtu:       mtu,
		atomicMTU: int32(mtu),
		readBuf:   make([]byte, 65536+4),
	}
	log.Info("Created TUN device from fd=%d (name=%s, MTU=%d)", fd, name, mtu)
	return t, nil
}

// ConfigureFromFd records the assigned IPs on a TUN device obtained via CreateTUNFromFd.
// Route/DNS setup is handled by the NetworkExtension host, not by Go.
func (t *TUNDevice) ConfigureFromFd(localIP, remoteIP net.IP) error {
	t.localIP = localIP
	t.remoteIP = remoteIP
	return nil
}

// InitAndroidProtector is a no-op on macOS; socket protection is not needed
// outside the Android VpnService model.
func InitAndroidProtector(_ string) error { return nil }
