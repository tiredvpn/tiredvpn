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

	// Dual-stack state: dualStack is the client's intent (SetIPv6Policy);
	// v6Enabled/localIP6/remoteIP6 are set once EnableDualStack installed the
	// negotiated v6 address and half-default routes.
	dualStack bool
	v6Enabled bool
	localIP6  net.IP
	remoteIP6 net.IP

	// ipv6Policy is the full -tun-ipv6 policy. Its blocking half is not
	// implemented on macOS (see ApplyIPv6LeakBlock); v6BlockWarned keeps that
	// gap to one warning per session instead of one per reconnect.
	ipv6Policy    IPv6Policy
	v6BlockWarned bool

	writeMu sync.Mutex
	readBuf []byte
}

// SetIPv6Policy records the -tun-ipv6 policy for this tunnel. On macOS there
// is no disable_ipv6 sysctl to flip in Configure, so the dual-stack half only
// gates the post-handshake EnableDualStack; the blocking half is not
// implemented at all (ApplyIPv6LeakBlock).
func (t *TUNDevice) SetIPv6Policy(p IPv6Policy) {
	t.ipv6Policy = p
	t.dualStack = p.NegotiatesDualStack()
}

// SetIPv6BlockAllow is a no-op on macOS: there is no leak block to punch holes
// in. Present so the platform-independent caller in vpn.go needs no build tag.
func (t *TUNDevice) SetIPv6BlockAllow([]net.IP) {}

// ApplyIPv6LeakBlock is not implemented on macOS. The Linux block is an
// nftables chain, which has no counterpart here — the equivalent would be a
// pf anchor, which means owning /etc/pf.conf state that the OS and other VPN
// software also write to. Until that exists the gap is reported rather than
// hidden: on a dual-stack Mac whose exit cannot carry IPv6, applications keep
// reaching the internet over IPv6 outside the tunnel.
func (t *TUNDevice) ApplyIPv6LeakBlock() {
	if !t.ipv6Policy.BlocksLeakedIPv6() || t.v6BlockWarned {
		return
	}
	t.v6BlockWarned = true
	log.Warn("IPv6 leak block (-tun-ipv6=%s) is not implemented on macOS: the tunnel is not "+
		"carrying IPv6 and outbound IPv6 is NOT blocked, so applications with a working IPv6 "+
		"default route will reach the internet outside the VPN. Disable IPv6 on the active "+
		"network service (System Settings > Network > Details > TCP/IP > Configure IPv6: Off) "+
		"to close it by hand.", t.ipv6Policy)
}

// RemoveIPv6LeakBlock is a no-op on macOS: nothing was installed.
func (t *TUNDevice) RemoveIPv6LeakBlock() {
	t.v6BlockWarned = false
}

// EnableDualStack assigns the negotiated v6 point-to-point address and
// installs the two v6 half-default routes (::/1, 8000::/1) into the utun.
// The split default outranks RA-learned ::/0 on prefix length without
// touching the host's real default route. Mirrors the v4
// `ifconfig inet local remote` + `route add -net` pattern in Configure.
//
// Idempotent: the utun outlives a reconnect, so the routes are usually
// already installed and `route add` fails with EEXIST ("File exists"). That
// used to surface as an EnableDualStack error, whose caller responds with
// DisableIPv6 — every reconnect tore down a perfectly good IPv6 and the next
// one brought it back. `route change` refreshes an existing route in place,
// with no window in which the route is missing (the v4 path solves the same
// problem by ignoring route errors outright, and Linux by using RouteReplace).
func (t *TUNDevice) EnableDualStack(clientIP6, serverIP6 net.IP) error {
	if _, _, _, err := dualStackAddrPlan(clientIP6, serverIP6); err != nil {
		return err
	}
	if err := runIfconfig(t.name, "inet6", clientIP6.String(), serverIP6.String(),
		"prefixlen", "128"); err != nil {
		return fmt.Errorf("ifconfig inet6: %w", err)
	}

	// Publish the state as soon as the address is on the link and before the
	// routes go in. Everything below can fail, and the caller's fallback is
	// DisableIPv6, whose guard is v6Enabled: recording late left a failed
	// second route install with the address and the first half-default
	// stranded on the interface.
	t.localIP6 = clientIP6
	t.remoteIP6 = serverIP6
	t.v6Enabled = true

	for _, r := range dualStackRouteCIDRs {
		if err := runRoute("add", "-inet6", r, "-iface", t.name); err == nil {
			continue
		}
		if err := runRoute("change", "-inet6", r, "-iface", t.name); err != nil {
			return fmt.Errorf("route add/change -inet6 %s: %w", r, err)
		}
	}

	log.Info("utun %s dual-stack enabled: local=%s, peer=%s, routes=%v",
		t.name, clientIP6, serverIP6, dualStackRouteCIDRs)
	return nil
}

// DisableIPv6 undoes EnableDualStack (v6 routes and address) when the exit
// declined dual-stack. macOS has no per-interface disable_ipv6 sysctl; a utun
// without an inet6 address carries no IPv6, so removing what we added is
// sufficient.
func (t *TUNDevice) DisableIPv6() {
	// Warn about the missing leak block on every path that leaves the tunnel
	// without IPv6, including the one that returns right below.
	t.ApplyIPv6LeakBlock()
	if !t.v6Enabled {
		return
	}
	for _, r := range dualStackRouteCIDRs {
		if err := runRoute("delete", "-inet6", r, "-iface", t.name); err != nil {
			log.Debug("route delete -inet6 %s failed: %v", r, err)
		}
	}
	if t.localIP6 != nil {
		if err := runIfconfig(t.name, "inet6", t.localIP6.String(), "-alias"); err != nil {
			log.Debug("ifconfig inet6 -alias failed: %v", err)
		}
	}
	t.localIP6 = nil
	t.remoteIP6 = nil
	t.v6Enabled = false
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

// SetServerBypassIP6 is a no-op on macOS, for the same reason as
// SetServerBypassIP. Note the exposure this leaves: with -prefer-ipv6 and a
// negotiated dual-stack tunnel, the ::/1 + 8000::/1 half-defaults installed by
// EnableDualStack also cover the client's own IPv6 transport socket, so the
// CLI/utun path on macOS loops its server traffic into the tunnel. Fixing it
// needs the scutil/route bypass the v4 side does not have either, so both
// families stay unimplemented together rather than half-done. The
// NetworkExtension path is unaffected: the host owns routing there and
// excludes the tunnel's own socket.
func (t *TUNDevice) SetServerBypassIP6(net.IP) {}

// EnsureServerBypass is a no-op on macOS; see SetServerBypassIP.
func (t *TUNDevice) EnsureServerBypass() {}

// WatchServerBypass is a no-op on macOS; see SetServerBypassIP.
func (t *TUNDevice) WatchServerBypass(<-chan struct{}) {}

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
func (t *TUNDevice) ConfigureSubnet(localIP net.IP, network *net.IPNet, serverIP6 *net.IPNet) error {
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
