//go:build linux
// +build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tunDevice = "/dev/net/tun"
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPi   = 0x1000

	// bypassWatchInterval is how often the server bypass route is verified. The
	// healthy check is a single RouteGet, so polling this often is free, and it
	// bounds how long a link flap can keep the client dialling into its own
	// tunnel (previously: forever, until the unit was restarted by hand).
	bypassWatchInterval = 5 * time.Second
)

type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	pad   [24 - ifnamsiz - 2]byte
}

type TUNDevice struct {
	name string
	file *os.File
	// mtu is the MTU set at construction (the configured cap). It is immutable
	// after construction; the live MTU (which auto-MTU may lower/raise on the fly)
	// is held in atomicMTU and read via MTU().
	mtu int
	// atomicMTU is the current effective interface MTU, updated atomically by
	// SetMTU so the hot data-path goroutines can read it without a lock while a
	// background probe adjusts it.
	atomicMTU int32
	localIP   net.IP
	remoteIP  net.IP
	routes    []string

	// addedRoutes records the destinations actually installed on this link so
	// teardown can remove exactly its own routes (netlink.RouteDel) instead of
	// relying on the kernel's cascade delete from LinkDel. On a multi-tunnel
	// host that cascade is fine, but explicit scoped deletion keeps cleanup
	// from ever touching the main table / default route or another tunnel.
	addedRoutes []*net.IPNet

	// serverBypassIP is the VPN server's public IP. When the installed route set
	// covers this IP (a default route, or the 0.0.0.0/1 + 128.0.0.0/1 pair), a
	// /32 (or /128) host route to it is pinned through the current physical
	// gateway so server traffic does not loop back into the tunnel. Set via
	// SetServerBypassIP before Configure.
	serverBypassIP net.IP
	// bypassRoute is the host route installed for serverBypassIP, kept so
	// teardown removes exactly it (it lives on the physical link, not the TUN,
	// so delRoutes does not cover it). Guarded by bypassMu: the watcher
	// goroutine re-pins it while Close may be tearing it down.
	bypassRoute *netlink.Route
	bypassMu    sync.Mutex

	// deferRoutes, when true, makes Configure bring the interface up and assign
	// the tunnel address but NOT install the route set (notably a 0.0.0.0/0
	// default route). Routes are installed later via InstallRoutes once a real
	// connection + handshake to the server succeeds. This prevents the client
	// from hijacking the default route into a dead tunnel and taking the whole
	// machine offline when the server is unreachable.
	deferRoutes bool
	// routesInstalled guards InstallRoutes so it is idempotent across the
	// initial connect and subsequent reconnects.
	routesInstalled bool
}

// SetDeferRoutes requests that Configure NOT install routes immediately, leaving
// them for an explicit InstallRoutes call after the tunnel is actually usable.
// Must be set before Configure. Linux only.
func (t *TUNDevice) SetDeferRoutes(defer_ bool) {
	t.deferRoutes = defer_
}

// SetServerBypassIP records the VPN server's public IP so that, when a default
// route is installed, traffic to the server keeps leaving via the physical
// interface instead of looping through the tunnel. Linux only; on Android the
// server socket is protected via VpnService.protect() instead.
func (t *TUNDevice) SetServerBypassIP(ip net.IP) {
	t.bypassMu.Lock()
	t.serverBypassIP = ip
	t.bypassMu.Unlock()
}

// bypassIP returns the server IP to keep off the tunnel, or nil once the device
// is torn down. Read under the lock because the watcher goroutine races Close.
func (t *TUNDevice) bypassIP() net.IP {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	return t.serverBypassIP
}

// mssTableName returns the per-interface nftables table name for MSS clamping.
// It is scoped to the interface so tearing down one tunnel never deletes the
// clamping table of another tunnel sharing the same host.
func mssTableName(ifName string) string {
	return nftablesTableName + "-" + ifName
}

// The device is opened without IFF_VNET_HDR on purpose. A tun fd is a character
// device, not a socket: one read(2) or readv(2) always yields exactly one frame
// (readv only scatters that single frame across iovecs), so no syscall-batching
// is available at this layer. The only way to move more bytes per syscall is
// IFF_VNET_HDR + TUNSETOFFLOAD, which hands back GSO super-frames of up to 64 KB
// prefixed by a virtio_net_hdr. That would break the [len:4][pkt:N] wire framing
// (peers reject frames above 65535 and size them against the negotiated MTU),
// invalidate the plain-IP assumptions in ClampTCPMSS and pmtu.go, and require
// software segmentation plus a capability negotiation with already-deployed
// peers. Not worth it for this datapath.
func CreateTUN(name string, mtu int) (*TUNDevice, error) {
	fd, err := syscall.Open(tunDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	var req ifReq
	req.Flags = iffTun | iffNoPi
	copy(req.Name[:], name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

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
		name:      actualName,
		file:      file,
		mtu:       mtu,
		atomicMTU: int32(mtu),
	}

	log.Info("Created TUN device: %s (MTU=%d)", tun.name, mtu)
	return tun, nil
}

func (t *TUNDevice) Name() string {
	return t.name
}

func (t *TUNDevice) Read(p []byte) (int, error) {
	return t.file.Read(p)
}

func (t *TUNDevice) Write(p []byte) (int, error) {
	return t.file.Write(p)
}

func (t *TUNDevice) SetReadDeadline(deadline time.Time) error {
	return t.file.SetReadDeadline(deadline)
}

func (t *TUNDevice) Close() error {
	if t.name != "" && t.mtu > 40 {
		if err := removeMSSClamping(t.name); err != nil {
			log.Warn("Failed to remove MSS clamping rules: %v", err)
		}
	}

	// Remove only the routes this device installed, before deleting the link.
	// This avoids relying on LinkDel's cascade delete and guarantees teardown
	// never disturbs the main table / default route or another tunnel.
	if t.name != "" && len(t.addedRoutes) > 0 {
		t.delRoutes()
	}

	// Remove the server bypass host route (it lives on the physical link, not
	// the TUN, so delRoutes does not cover it).
	t.bypassMu.Lock()
	if t.bypassRoute != nil {
		if err := netlink.RouteDel(t.bypassRoute); err != nil {
			log.Debug("Failed to delete server bypass route: %v", err)
		}
		t.bypassRoute = nil
	}
	// Stop the watcher from re-pinning a route we just tore down.
	t.serverBypassIP = nil
	t.bypassMu.Unlock()

	t.file.SetReadDeadline(time.Now())

	err := t.file.Close()

	if t.name != "" {
		link, lerr := netlink.LinkByName(t.name)
		if lerr == nil {
			if derr := netlink.LinkDel(link); derr != nil {
				log.Warn("Failed to delete link %s: %v", t.name, derr)
			}
		}
	}

	return err
}

// delRoutes removes the routes recorded in t.addedRoutes from this link. Only
// destinations scoped to this interface's index are deleted, so cleanup cannot
// touch routes owned by the host or by other tunnels.
func (t *TUNDevice) delRoutes() {
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		log.Warn("Cannot delete routes, link %s lookup failed: %v", t.name, err)
		return
	}
	idx := link.Attrs().Index
	for _, dst := range t.addedRoutes {
		if err := netlink.RouteDel(&netlink.Route{LinkIndex: idx, Dst: dst}); err != nil {
			log.Debug("Failed to delete route %s on %s: %v", dst, t.name, err)
		}
	}
	t.addedRoutes = nil
}

func (t *TUNDevice) File() *os.File {
	return t.file
}

// MTU returns the current effective interface MTU. It reads the value updated by
// SetMTU atomically so the hot data-path may consult it without a lock.
func (t *TUNDevice) MTU() int {
	if m := int(atomic.LoadInt32(&t.atomicMTU)); m > 0 {
		return m
	}
	return t.mtu
}

// SetMTU changes the live interface MTU (auto-MTU result). It updates the kernel
// link MTU and the atomic value read by the data path. The construction-time
// t.mtu (the cap) is left untouched so read buffers sized at the cap stay valid.
// Lowering is always safe; raising never exceeds the cap the buffers were sized
// for. On the fd-supplied (Android) path the kernel link is owned by the host, so
// only the framing MTU is updated.
func (t *TUNDevice) SetMTU(mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("invalid MTU: %d", mtu)
	}
	if link, err := netlink.LinkByName(t.name); err == nil {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			log.Warn("SetMTU: failed to set kernel MTU on %s to %d: %v", t.name, mtu, err)
		}
	} else {
		log.Debug("SetMTU: link %s not found (fd mode?), updating framing MTU only: %v", t.name, err)
	}
	atomic.StoreInt32(&t.atomicMTU, int32(mtu))
	log.Info("TUN device %s MTU set to %d", t.name, mtu)
	return nil
}

func (t *TUNDevice) Configure(localIP, remoteIP net.IP, routes []string) error {
	t.localIP = localIP
	t.remoteIP = remoteIP
	t.routes = routes

	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte("1"), 0644); err != nil {
		log.Warn("Failed to disable IPv6 on %s: %v", t.name, err)
	} else {
		log.Debug("Disabled IPv6 on %s (before up)", t.name)
	}

	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %w", t.name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	if err := netlink.LinkSetMTU(link, t.mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	nlAddr := &netlink.Addr{
		IPNet: &net.IPNet{IP: localIP, Mask: net.CIDRMask(32, 32)},
		Peer:  &net.IPNet{IP: remoteIP, Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.AddrAdd(link, nlAddr); err != nil {
		_, ipNet, perr := net.ParseCIDR(fmt.Sprintf("%s/24", localIP.String()))
		if perr != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
		if err2 := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err2 != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	// When routes are deferred, the interface is up and addressed but no route
	// (especially a default route) is installed yet. This keeps the host's
	// normal routing intact until InstallRoutes is called after a successful
	// connect, so an unreachable server can never strand the machine offline.
	if t.deferRoutes {
		log.Info("TUN %s up, routes deferred until server connection is established", t.name)
	} else {
		t.addRoutes(link, routes)
	}

	mss := t.mtu - 40
	if mss > 0 {
		if err := addMSSClamping(t.name, t.mtu); err != nil {
			log.Warn("Failed to set MSS clamping: %v", err)
		} else {
			log.Info("TCP MSS clamping set to %d on %s", mss, t.name)
		}
	}

	log.Info("TUN device %s configured: local=%s, remote=%s", t.name, localIP, remoteIP)
	return nil
}

// addRoutes installs the given routes on the link, normalizing bare IPs to
// host CIDRs (/32, /128). Invalid routes are skipped rather than aborting the
// whole tunnel, but their count is reported at ERROR level so a misconfigured
// -tun-routes does not fail silently and leak traffic outside the tunnel.
// routesCoverIP reports whether the route set would pull traffic to ip into the
// tunnel. Checking coverage rather than a literal 0.0.0.0/0 matters because a
// full tunnel is commonly expressed as the two half-defaults 0.0.0.0/1 +
// 128.0.0.0/1 (they outrank the host's real default without replacing it), and
// those need the very same server bypass a 0.0.0.0/0 route does.
func routesCoverIP(routes []string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, route := range routes {
		cidr, err := normalizeRoute(route)
		if err != nil {
			continue
		}
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if dst.Contains(ip) {
			return true
		}
	}
	return false
}

// physicalRouteTo finds the most specific route to ip that does NOT go through
// our own TUN, i.e. the path the server traffic must keep taking. It reads the
// main table directly instead of using RouteGet because once the tunnel routes
// are installed RouteGet answers with the TUN itself — which is exactly the
// looped state the bypass exists to prevent.
func (t *TUNDevice) physicalRouteTo(ip net.IP) (*netlink.Route, error) {
	family := netlink.FAMILY_V4
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
	}
	tunIdx := -1
	if link, err := netlink.LinkByName(t.name); err == nil {
		tunIdx = link.Attrs().Index
	}
	routes, err := netlink.RouteListFiltered(family,
		&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("route list failed: %w", err)
	}

	var best *netlink.Route
	bestOnes := -1
	for i := range routes {
		r := &routes[i]
		if r.LinkIndex == tunIdx || r.LinkIndex <= 0 {
			continue
		}
		ones := 0
		if r.Dst != nil {
			if !r.Dst.Contains(ip) {
				continue
			}
			ones, _ = r.Dst.Mask.Size()
		} else if r.Gw == nil {
			// Default route without a gateway and without a destination is not
			// something we can pin through.
			continue
		}
		if ones > bestOnes || (ones == bestOnes && best != nil && r.Priority < best.Priority) {
			best = r
			bestOnes = ones
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no physical route to %s", ip)
	}
	return best, nil
}

// addServerBypass pins a host route to the VPN server through the current
// physical gateway. Without it, a full-tunnel client loops its own server
// traffic (handshake, keepalive, reconnect) back into the tunnel and wedges
// until the process is restarted. Safe to call at any time: it looks the
// gateway up in the main table, ignoring our own TUN, so it also repairs a
// bypass that was wiped out from under us (e.g. a Wi-Fi reassociation takes the
// link down and the kernel drops every route attached to it). No-op if no
// server IP was set.
func (t *TUNDevice) addServerBypass() {
	ip := t.bypassIP()
	if ip == nil {
		return
	}
	r, err := t.physicalRouteTo(ip)
	if err != nil {
		log.Warn("Server bypass: cannot resolve physical route to %s: %v", ip, err)
		return
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	bypass := &netlink.Route{
		LinkIndex: r.LinkIndex,
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)},
		Gw:        r.Gw,
		Src:       r.Src,
	}
	if err := netlink.RouteReplace(bypass); err != nil {
		log.Warn("Server bypass: failed to pin host route to %s: %v", ip, err)
		return
	}
	t.bypassMu.Lock()
	// Close raced us and tore the device down: undo the pin instead of leaking it.
	closed := t.serverBypassIP == nil
	if !closed {
		t.bypassRoute = bypass
	}
	t.bypassMu.Unlock()
	if closed {
		netlink.RouteDel(bypass)
		return
	}
	log.Info("Server bypass route pinned: %s/%d via %v (linkIndex %d)", ip, bits, r.Gw, r.LinkIndex)
}

// EnsureServerBypass re-pins the server bypass if traffic to the server would
// currently go through the tunnel. Cheap enough to poll: the healthy path costs
// one RouteGet and touches nothing.
func (t *TUNDevice) EnsureServerBypass() {
	ip := t.bypassIP()
	if ip == nil {
		return
	}
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return
	}
	resolved, err := netlink.RouteGet(ip)
	if err == nil && len(resolved) > 0 && resolved[0].LinkIndex != link.Attrs().Index {
		return // still leaving through a physical link, nothing to do
	}
	if err != nil {
		log.Debug("Server bypass: route lookup for %s failed: %v, re-pinning", ip, err)
	} else {
		log.Warn("Server bypass: traffic to %s now routes via %s, re-pinning", ip, t.name)
	}
	t.addServerBypass()
}

// WatchServerBypass polls the bypass route and restores it when the host drops
// it. The trigger in practice is a link flap (Wi-Fi roam/reassociation, dock,
// suspend/resume): the kernel deletes every route attached to the interface
// that went down, the bypass among them, after which the client's own
// full-tunnel routes swallow the traffic to the server and every reconnect
// attempt dials into the dead tunnel. Returns when stop is closed.
func (t *TUNDevice) WatchServerBypass(stop <-chan struct{}) {
	if t.bypassIP() == nil {
		return
	}
	ticker := time.NewTicker(bypassWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.EnsureServerBypass()
		}
	}
}

func (t *TUNDevice) addRoutes(link netlink.Link, routes []string) {
	// Pin the server bypass before any tunnel route that covers the server lands.
	if routesCoverIP(routes, t.bypassIP()) {
		t.addServerBypass()
	}
	var invalid []string
	for _, route := range routes {
		cidr, err := normalizeRoute(route)
		if err != nil {
			invalid = append(invalid, route)
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			invalid = append(invalid, route)
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		t.trackRoute(dst)
		// RouteReplace is idempotent: it installs the route if absent and is a
		// no-op (no EEXIST) if it already exists. addRoutes runs on the initial
		// install and again on every reconnect, so RouteAdd here used to spam
		// "file exists" warnings once the route was already present.
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
			log.Warn("Failed to add route %s: %v", route, err)
		}
	}
	if len(invalid) > 0 {
		log.Error("%d of %d routes invalid, not added to %s: %v",
			len(invalid), len(routes), t.name, invalid)
	}
}

// InstallRoutes installs the deferred route set onto the tunnel. It is called
// only after a real connection + handshake with the server succeeds, so the
// default route is never pointed at a dead tunnel. Idempotent: safe to call on
// every (re)connect; the route adds themselves use RouteReplace. No-op when
// routes were not deferred (e.g. Android, where VpnService owns routing).
func (t *TUNDevice) InstallRoutes() {
	if !t.deferRoutes {
		return
	}
	if t.routesInstalled {
		// Already installed; refresh idempotently in case a reconnect dropped
		// the link's routes, but skip the "deferred" log noise.
		link, err := netlink.LinkByName(t.name)
		if err != nil {
			log.Warn("InstallRoutes: cannot find link %s: %v", t.name, err)
			return
		}
		t.reAddRoutes(link, "reconnect")
		return
	}
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		log.Warn("InstallRoutes: cannot find link %s: %v", t.name, err)
		return
	}
	t.addRoutes(link, t.routes)
	t.routesInstalled = true
	log.Info("Routes installed on %s after successful server connection", t.name)
}

// trackRoute records dst in t.addedRoutes for scoped teardown, deduping so
// reconnect re-adds do not grow the list unbounded.
func (t *TUNDevice) trackRoute(dst *net.IPNet) {
	for _, existing := range t.addedRoutes {
		if existing.String() == dst.String() {
			return
		}
	}
	t.addedRoutes = append(t.addedRoutes, dst)
}

// reAddRoutes re-installs t.routes after an address change, normalizing bare
// IPs the same way addRoutes does. It logs at debug level since this runs on
// every reconnect/IP update; hard failures are already surfaced by addRoutes
// at configure time.
func (t *TUNDevice) reAddRoutes(link netlink.Link, reason string) {
	// A reconnect often follows the very event that wiped the bypass (link flap,
	// gateway change), so verify it before re-asserting the tunnel routes.
	if routesCoverIP(t.routes, t.bypassIP()) {
		t.EnsureServerBypass()
	}
	for _, route := range t.routes {
		cidr, err := normalizeRoute(route)
		if err != nil {
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		t.trackRoute(dst)
		// RouteReplace keeps re-adds idempotent across reconnects / IP changes:
		// an already-present route is refreshed rather than failing with EEXIST.
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
			log.Warn("Failed to re-add route %s: %v", route, err)
		} else {
			log.Debug("Re-added route %s after %s", route, reason)
		}
	}
}

// ConfigureSubnet sets up the server-side TUN with subnet routing. serverIP6,
// when non-nil, enables dual-stack on the link: IPv6 stays enabled (instead
// of the historical disable_ipv6=1) and the server's tunnel v6 address is
// assigned with the full pool prefix so the kernel routes the whole ULA
// prefix back into the TUN. A nil serverIP6 keeps the exact IPv4-only
// behavior, including disable_ipv6=1.
func (t *TUNDevice) ConfigureSubnet(localIP net.IP, network *net.IPNet, serverIP6 *net.IPNet) error {
	t.localIP = localIP

	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	disableV6 := "1"
	if serverIP6 != nil {
		disableV6 = "0"
	}
	if err := os.WriteFile(sysctlPath, []byte(disableV6), 0644); err != nil {
		log.Warn("Failed to set disable_ipv6=%s on %s: %v", disableV6, t.name, err)
	}

	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %w", t.name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	if err := netlink.LinkSetMTU(link, t.mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	ones, _ := network.Mask.Size()
	_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", localIP.String(), ones))
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}
	addr := fmt.Sprintf("%s/%d", localIP.String(), ones)
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	// Dual-stack: assign the server's tunnel v6 address with the full pool
	// prefix (e.g. fd00:10:8::1/64). The connected route this installs is what
	// makes the kernel hand replies for any client v6 address in the prefix
	// back to the TUN for the dispatcher to route.
	if serverIP6 != nil {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: serverIP6}); err != nil {
			return fmt.Errorf("failed to set IPv6 address: %w", err)
		}
		log.Info("TUN device %s dual-stack enabled: %s", t.name, serverIP6)
	}

	mss := t.mtu - 40
	if mss > 0 {
		if err := addMSSClamping(t.name, t.mtu); err != nil {
			log.Warn("Failed to set MSS clamping: %v", err)
		} else {
			log.Info("TCP MSS clamping set to %d on %s", mss, t.name)
		}
	}

	log.Info("TUN device %s configured with subnet: %s", t.name, addr)
	return nil
}

func (t *TUNDevice) UpdatePeerIP(newRemoteIP net.IP) error {
	if newRemoteIP.Equal(t.remoteIP) {
		return nil
	}

	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %w", t.name, err)
	}

	oldAddr := &netlink.Addr{
		IPNet: &net.IPNet{IP: t.localIP, Mask: net.CIDRMask(32, 32)},
		Peer:  &net.IPNet{IP: t.remoteIP, Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.AddrDel(link, oldAddr); err != nil {
		log.Warn("Failed to delete old peer addr: %v", err)
	}

	newAddr := &netlink.Addr{
		IPNet: &net.IPNet{IP: t.localIP, Mask: net.CIDRMask(32, 32)},
		Peer:  &net.IPNet{IP: newRemoteIP, Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.AddrAdd(link, newAddr); err != nil {
		return fmt.Errorf("failed to update peer IP: %w", err)
	}

	t.remoteIP = newRemoteIP
	log.Info("TUN device %s peer IP updated to %s", t.name, newRemoteIP)

	t.reAddRoutes(link, "peer IP change")

	return nil
}

func (t *TUNDevice) UpdateLocalIP(newLocalIP net.IP) error {
	if newLocalIP.Equal(t.localIP) {
		return nil
	}

	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %w", t.name, err)
	}

	// Compare against the address the interface ACTUALLY carries, not just the
	// cached t.localIP. If the kernel already has newLocalIP on the link (struct
	// drift, or the sticky server handed back the same IP), skip the AddrDel +
	// AddrAdd entirely — that del/add is what flushes the link's routes and makes
	// the L3 path flap on every reconnect.
	if t.linkHasAddr(link, newLocalIP) {
		t.localIP = newLocalIP
		log.Debug("TUN device %s already carries %s, skipping addr swap", t.name, newLocalIP)
		t.reAddRoutes(link, "IP sync")
		return nil
	}

	oldAddr := &netlink.Addr{
		IPNet: &net.IPNet{IP: t.localIP, Mask: net.CIDRMask(32, 32)},
		Peer:  &net.IPNet{IP: t.remoteIP, Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.AddrDel(link, oldAddr); err != nil {
		log.Warn("Failed to delete old local addr: %v", err)
	}

	newAddr := &netlink.Addr{
		IPNet: &net.IPNet{IP: newLocalIP, Mask: net.CIDRMask(32, 32)},
		Peer:  &net.IPNet{IP: t.remoteIP, Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.AddrAdd(link, newAddr); err != nil {
		return fmt.Errorf("failed to update local IP: %w", err)
	}

	t.localIP = newLocalIP
	log.Info("TUN device %s local IP updated to %s", t.name, newLocalIP)

	// AddrDel above flushes every route bound to the old source/link, so re-add
	// the tracked route set idempotently (RouteReplace, same as 27109a3) to
	// restore the default route and any split-tunnel routes. The server-bypass
	// host route lives on the physical link, so it is unaffected by this swap.
	t.reAddRoutes(link, "IP change")

	return nil
}

// linkHasAddr reports whether the link already carries ip as an IPv4 address.
func (t *TUNDevice) linkHasAddr(link netlink.Link, ip net.IP) bool {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.IPNet != nil && a.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// nftablesTableName is the prefix for the per-interface nftables tables created
// for MSS clamping rules. The actual table name is derived per interface via
// mssTableName (e.g. "tiredvpn-tiredvpn0") so tearing down one tunnel never
// deletes the clamping table of another tunnel on the same host.
const nftablesTableName = "tiredvpn"

// ifnamePad pads an interface name to 16 bytes (IFNAMSIZ) as required by nftables.
func ifnamePad(name string) []byte {
	b := make([]byte, 16)
	copy(b, name+"\x00")
	return b
}

// mssRule builds the nftables expressions for a single MSS clamping rule.
// It matches: oifname == ifName AND tcp AND tcp flags SYN (SYN|RST mask) AND sets MSS.
func mssRule(ifName string, mtu int) []expr.Any {
	mss := uint16(mtu - 40)
	mssBE := make([]byte, 2)
	binary.BigEndian.PutUint16(mssBE, mss)

	return []expr.Any{
		// oifname == ifName
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifnamePad(ifName),
		},

		// ip protocol == tcp
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},

		// tcp flags byte (offset 13 of transport header)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},
		// mask: flags & (SYN|RST) == SYN  =>  & 0x06, compare == 0x02
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            1,
			Mask:           []byte{0x06}, // SYN=0x02 | RST=0x04
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0x02}, // SYN only
		},

		// load fixed MSS value into reg 1 (network byte order)
		&expr.Immediate{
			Register: 1,
			Data:     mssBE,
		},

		// write reg 1 into TCP MSS option field: tcpopt 2b @ type=2 offset=2
		&expr.Exthdr{
			SourceRegister: 1,
			Type:           2, // TCP option kind: MSS
			Offset:         2,
			Len:            2,
			Op:             expr.ExthdrOpTcpopt,
		},
	}
}

// addMSSClamping installs nftables rules for TCP MSS clamping on ifName.
// Creates a per-interface table mssTableName(ifName) (IPv4, filter/forward/
// mangle priority) with two rules: one matching outbound (oifname) and one
// matching inbound (iifname) on ifName.
// Non-fatal: logs a warning and returns nil if nftables is unavailable.
func addMSSClamping(ifName string, mtu int) error {
	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables unavailable, skipping MSS clamping: %v", err)
		return nil
	}

	tbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   mssTableName(ifName),
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     "mssclamping",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
		Policy:   chainPolicyAcceptPtr(),
	})

	// outbound: oifname == ifName
	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: chain,
		Exprs: mssRule(ifName, mtu),
	})

	// inbound: iifname == ifName
	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: chain,
		Exprs: mssRuleIIF(ifName, mtu),
	})

	if err := conn.Flush(); err != nil {
		log.Warn("Failed to flush nftables MSS clamping rules: %v", err)
		return nil
	}

	log.Debug("nftables MSS clamping installed for %s (MSS=%d)", ifName, mtu-40)
	return nil
}

// mssRuleIIF is like mssRule but matches iifname (inbound).
func mssRuleIIF(ifName string, mtu int) []expr.Any {
	mss := uint16(mtu - 40)
	mssBE := make([]byte, 2)
	binary.BigEndian.PutUint16(mssBE, mss)

	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifnamePad(ifName),
		},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            1,
			Mask:           []byte{0x06},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0x02},
		},
		&expr.Immediate{
			Register: 1,
			Data:     mssBE,
		},
		&expr.Exthdr{
			SourceRegister: 1,
			Type:           2,
			Offset:         2,
			Len:            2,
			Op:             expr.ExthdrOpTcpopt,
		},
	}
}

// chainPolicyAcceptPtr returns a pointer to ChainPolicyAccept, as required by the nftables API.
func chainPolicyAcceptPtr() *nftables.ChainPolicy {
	p := nftables.ChainPolicyAccept
	return &p
}

// removeMSSClamping deletes this interface's per-interface nftables table
// (mssTableName(ifName)), removing only its own MSS clamping rules and leaving
// other tunnels' tables untouched.
// Non-fatal: logs a warning and returns nil if the operation fails.
func removeMSSClamping(ifName string) error {
	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables unavailable, cannot remove MSS clamping: %v", err)
		return nil
	}

	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   mssTableName(ifName),
	})

	if err := conn.Flush(); err != nil {
		log.Warn("Failed to remove nftables MSS clamping table: %v", err)
		return nil
	}

	log.Debug("nftables MSS clamping table %q removed", mssTableName(ifName))
	return nil
}
