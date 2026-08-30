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

	// addedRoutes records the routes actually installed on this link so
	// teardown can remove exactly its own routes (netlink.RouteDel) instead of
	// relying on the kernel's cascade delete from LinkDel. On a multi-tunnel
	// host that cascade is fine, but explicit scoped deletion keeps cleanup
	// from ever touching the main table / default route or another tunnel.
	//
	// The metric is part of the record, not just the destination, because that
	// is what the kernel keys an entry on: the same destination at two metrics
	// is two routes. Teardown then deletes exactly what install created rather
	// than relying on the matcher to fill the metric in for it.
	addedRoutes []trackedRoute

	// serverBypassIPs are every server transport address this client may dial.
	// When the installed route set covers one of them (a default route, or the
	// 0.0.0.0/1 + 128.0.0.0/1 pair), a /32 (or /128) host route to it is pinned
	// through the current physical gateway so server traffic does not loop back
	// into the tunnel.
	//
	// It is a set, not one address per family, because the client walks a list
	// of servers: with a full tunnel up, dialling the SECOND server without a
	// pin of its own routes that dial into the tunnel and it dies there. Every
	// endpoint is therefore pinned at startup rather than at the moment of the
	// switch - which also removes the race where the client has moved on but
	// the route has not. Set via SetServerBypassIPs before Configure.
	serverBypassIPs []net.IP
	// bypassRoutes maps a bypass address to the host route installed for it,
	// kept so teardown removes exactly those (they live on the physical link,
	// not the TUN, so delRoutes does not cover them). Guarded by bypassMu: the
	// watcher goroutine re-pins them while Close may be tearing them down.
	bypassRoutes map[string]*netlink.Route
	// bypassPreexisted records, per address, that a host route to it was
	// already in the table before we pinned ours. Such a route belongs to the
	// operator (NetworkManager profile, a boot script, a hand-typed
	// `ip route add`), and on a host with no default route for that family it
	// is the only way the server is reachable at all. Deleting it on teardown
	// left the next client start with no path to the server, so teardown skips
	// it.
	bypassPreexisted map[string]bool
	// v6BlockAllow are the IPv6 addresses punched through the leak block (the
	// server's own transport addresses). Guarded by bypassMu, like the bypass
	// state it mirrors.
	v6BlockAllow []net.IP
	// v6BlockAllowList are the operator's -tun-ipv6-allow exceptions: host
	// interfaces and destination prefixes the block must leave alone. Same
	// lock, same lifetime; set from VPNConfig before Configure.
	v6BlockAllowList IPv6AllowList
	bypassMu         sync.Mutex

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

	// dualStack records that the client wants IPv6 inside the tunnel
	// (handshake v0x04). It only relaxes the historical disable_ipv6=1 in
	// Configure; the v6 address/routes are installed by EnableDualStack once
	// the exit has actually negotiated dual-stack. Derived from the policy by
	// SetIPv6Policy, which must be called before Configure.
	dualStack bool
	// ipv6Policy is the full -tun-ipv6 policy. Beyond dualStack it decides
	// whether outbound IPv6 that did not make it into the tunnel is rejected;
	// see ipv6block_linux.go. Left at IPv6PolicyOff on host-owned interfaces
	// (Android), where filtering belongs to VpnService.
	ipv6Policy IPv6Policy
	// v6BlockInstalled reports that the leak-block table exists, so teardown
	// removes exactly what it created and re-installs are logged as such.
	v6BlockInstalled bool
	// v6Enabled reports that EnableDualStack ran to completion: the link
	// carries localIP6/remoteIP6, the v6 half-default routes in routes6 are
	// installed, and the ip6 MSS clamp table exists. Drives v6-aware teardown
	// in Close/DisableIPv6 and route re-installs in reAddRoutes.
	v6Enabled bool
	localIP6  net.IP
	remoteIP6 net.IP
	routes6   []*net.IPNet
	// v6PeerForm records which address form actually landed on the link:
	// true for the point-to-point clientIP6/128 with peer serverIP6/128,
	// false for the /64 fallback used on kernels that reject a v6 peer.
	// Every later address operation has to use the same form — netlink
	// matches on the whole address, so deleting the wrong form fails and
	// leaves the stale address behind.
	v6PeerForm bool
}

// trackedRoute is one route this device installed: its destination and the
// metric it went in with. Both are needed to delete it again.
type trackedRoute struct {
	dst      *net.IPNet
	priority int
}

// sameAs reports whether two records name the same kernel routing entry.
func (r trackedRoute) sameAs(other trackedRoute) bool {
	return r.priority == other.priority && r.dst.String() == other.dst.String()
}

func (r trackedRoute) String() string {
	if r.priority == 0 {
		return r.dst.String()
	}
	return fmt.Sprintf("%s metric %d", r.dst, r.priority)
}

// tunRoute builds an install request for a route pointed at the tunnel. The
// metric is left at 0 (the kernel picks its default) — deliberately, for the
// IPv4 side: the tunnel's v4 default is expected to beat a DHCP-installed one
// with metric 600, and moving our v4 metrics up would break that comparison.
func tunRoute(linkIndex int, dst *net.IPNet) *netlink.Route {
	return &netlink.Route{LinkIndex: linkIndex, Dst: dst}
}

// v6HalfDefaultRoute builds the request for one of the IPv6 half-defaults on
// this tunnel. Install and delete both go through it, so the metric that makes
// two tunnels coexist (see v6HalfDefaultPriority) cannot be present on one side
// and missing on the other.
func v6HalfDefaultRoute(linkIndex int, dst *net.IPNet) *netlink.Route {
	return &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       dst,
		Priority:  v6HalfDefaultPriority(linkIndex),
	}
}

// SetDeferRoutes requests that Configure NOT install routes immediately, leaving
// them for an explicit InstallRoutes call after the tunnel is actually usable.
// Must be set before Configure. Linux only.
func (t *TUNDevice) SetDeferRoutes(defer_ bool) {
	t.deferRoutes = defer_
}

// SetServerBypassIPs records every server transport address that must keep
// leaving via the physical interface instead of looping through the tunnel.
// Nil and duplicate addresses are dropped. Replaces the whole set, so it is the
// one call a caller with a server list needs. Linux only; on Android the server
// socket is protected via VpnService.protect() instead.
func (t *TUNDevice) SetServerBypassIPs(ips []net.IP) {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil || containsIP(out, ip) {
			continue
		}
		out = append(out, ip)
	}
	t.bypassMu.Lock()
	t.serverBypassIPs = out
	t.bypassMu.Unlock()
}

// SetServerBypassIP records the VPN server's public IPv4, replacing whatever
// IPv4 addresses were in the bypass set. A wrapper over SetServerBypassIPs kept
// for the single-server callers (macOS, tests, benchmarks).
func (t *TUNDevice) SetServerBypassIP(ip net.IP) {
	t.replaceBypassFamily(ip, false)
}

// SetServerBypassIP6 is the IPv6 twin of SetServerBypassIP. It matters only for
// a dual-stack tunnel: the ::/1 + 8000::/1 half-defaults installed by
// EnableDualStack cover every IPv6 destination, so a client using the IPv6
// transport would route its own transport socket into the tunnel.
func (t *TUNDevice) SetServerBypassIP6(ip net.IP) {
	if ip != nil && ip.To4() != nil {
		return // not an IPv6 address; the v4 bypass covers it
	}
	t.replaceBypassFamily(ip, true)
}

// replaceBypassFamily swaps out every address of one family, leaving the other
// family's entries alone. That is what makes the two legacy setters composable:
// calling both leaves one address of each, exactly as the old pair of fields
// held.
func (t *TUNDevice) replaceBypassFamily(ip net.IP, v6 bool) {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	kept := make([]net.IP, 0, len(t.serverBypassIPs)+1)
	for _, existing := range t.serverBypassIPs {
		if isV6(existing) == v6 {
			continue
		}
		kept = append(kept, existing)
	}
	if ip != nil && !containsIP(kept, ip) {
		kept = append(kept, ip)
	}
	t.serverBypassIPs = kept
}

// bypassIPs returns every address to keep off the tunnel, empty once the device
// is torn down. Read under the lock because the watcher goroutine races Close.
func (t *TUNDevice) bypassIPs() []net.IP {
	t.bypassMu.Lock()
	defer t.bypassMu.Unlock()
	return append([]net.IP(nil), t.serverBypassIPs...)
}

// bypassIPsFamily returns the bypass addresses of one family.
func (t *TUNDevice) bypassIPsFamily(v6 bool) []net.IP {
	out := make([]net.IP, 0, 2)
	for _, ip := range t.bypassIPs() {
		if isV6(ip) == v6 {
			out = append(out, ip)
		}
	}
	return out
}

// isV6 reports whether ip is an IPv6 address (v4-mapped forms count as IPv4,
// matching what physicalRouteTo and pinBypass decide the family from).
func isV6(ip net.IP) bool { return ip != nil && ip.To4() == nil }

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
		if t.v6Enabled {
			if err := removeMSSClampingV6(t.name); err != nil {
				log.Warn("Failed to remove IPv6 MSS clamping rules: %v", err)
			}
		}
	}

	// The leak block outlives the interface unless it is taken down here: it
	// is keyed on the interface name, not its index, so a stale table would
	// keep rejecting the host's IPv6 long after the tunnel is gone.
	t.RemoveIPv6LeakBlock()

	// Remove only the routes this device installed, before deleting the link.
	// This avoids relying on LinkDel's cascade delete and guarantees teardown
	// never disturbs the main table / default route or another tunnel.
	if t.name != "" && len(t.addedRoutes) > 0 {
		t.delRoutes()
	}

	// Remove the server bypass host route (it lives on the physical link, not
	// the TUN, so delRoutes does not cover it).
	t.bypassMu.Lock()
	for _, route := range bypassRoutesToDelete(t.bypassRoutes, t.bypassPreexisted) {
		if err := netlink.RouteDel(route); err != nil {
			log.Debug("Failed to delete server bypass route: %v", err)
		}
	}
	t.bypassRoutes = nil
	t.bypassPreexisted = nil
	// Stop the watcher from re-pinning routes we just tore down.
	t.serverBypassIPs = nil
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
	for _, route := range t.routeDelSpecs(link.Attrs().Index) {
		if err := netlink.RouteDel(route); err != nil {
			log.Debug("Failed to delete route %s on %s: %v", route.Dst, t.name, err)
		}
	}
	t.addedRoutes = nil
}

// routeDelSpecs turns the tracked set into deletion requests scoped to
// linkIndex, each carrying the metric its route was installed with.
//
// Measured, not assumed (see TestRootRouteDelMetricSemantics): given the
// destination and the interface, the kernel deletes the entry whatever metric
// the request names, so omitting it would work today. The metric is included
// anyway — reproducing the install exactly is an invariant that holds no
// matter how lenient the matcher is, and it is the tracked set, not the
// kernel, that decides what teardown touches.
func (t *TUNDevice) routeDelSpecs(linkIndex int) []*netlink.Route {
	specs := make([]*netlink.Route, 0, len(t.addedRoutes))
	for _, r := range t.addedRoutes {
		specs = append(specs, &netlink.Route{
			LinkIndex: linkIndex,
			Dst:       r.dst,
			Priority:  r.priority,
		})
	}
	return specs
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

	// Dual-stack intent keeps IPv6 enabled on the link (mirroring the
	// server-side ConfigureSubnet) so EnableDualStack can assign the
	// negotiated v6 address after the handshake. When dual-stack is off — or
	// was requested but the exit declined it (DisableIPv6) — the historical
	// disable_ipv6=1 stands, byte-identical to before.
	disableV6 := "1"
	if t.dualStack {
		disableV6 = "0"
	}
	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte(disableV6), 0644); err != nil {
		log.Warn("Failed to set disable_ipv6=%s on %s: %v", disableV6, t.name, err)
	} else {
		log.Debug("Set disable_ipv6=%s on %s (before up)", disableV6, t.name)
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

// EnableDualStack brings up the IPv6 side of the tunnel after the exit
// negotiated dual-stack (handshake v0x04 with the dual-stack flag). It
// installs the negotiated v6 address and the two v6 half-default routes
// (::/1, 8000::/1) into the TUN together, so there is no intermediate state
// with a v6 address but routes to nowhere (or vice versa). The split default
// outranks RA-learned ::/0 routes on prefix length without touching the
// host's real default route or its RA machinery.
//
// Idempotent: safe to call on every (re)connect. Address replacement mirrors
// the v4 UpdateLocalIP/UpdatePeerIP behavior and route installs use
// RouteReplace.
func (t *TUNDevice) EnableDualStack(clientIP6, serverIP6 net.IP) error {
	p2pLocal, p2pPeer, fallback, err := dualStackAddrPlan(clientIP6, serverIP6)
	if err != nil {
		return err
	}
	routes6, err := dualStackRouteNets()
	if err != nil {
		return err
	}

	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %w", t.name, err)
	}

	// The interface must accept IPv6 before the address can be assigned.
	// Configure already wrote 0 when dual-stack intent was set; rewrite it
	// here so the call is self-contained (e.g. after a fallback DisableIPv6).
	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte("0"), 0644); err != nil {
		return fmt.Errorf("failed to enable IPv6 on %s: %w", t.name, err)
	}

	// Address: same shape as the v4 point-to-point setup — clientIP6/128 with
	// peer serverIP6/128, falling back to the /64 pool prefix when the kernel
	// rejects a v6 peer address.
	if t.v6Enabled && !t.localIP6.Equal(clientIP6) {
		// Reconnect assigned a new v6 (follows the v4 assignment): drop the
		// stale address before adding the new one, in whichever form it was
		// installed as.
		if err := t.delV6Addr(link, t.localIP6); err != nil {
			log.Debug("Failed to delete old v6 addr %s on %s: %v", t.localIP6, t.name, err)
		}
	}
	peerForm := true
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: p2pLocal, Peer: p2pPeer}); err != nil {
		if err2 := netlink.AddrReplace(link, &netlink.Addr{IPNet: fallback}); err2 != nil {
			return fmt.Errorf("failed to set IPv6 address: %w", err)
		}
		peerForm = false
		log.Info("TUN device %s: v6 peer address unsupported, using %s", t.name, fallback)
	}

	// Publish the state as soon as the address is on the link and before the
	// routes go in: everything below can fail, and the caller's fallback is
	// DisableIPv6, whose guard is v6Enabled. Recording late used to make a
	// failed route install leave the address (and possibly one half-default)
	// stranded on the interface.
	t.localIP6 = p2pLocal.IP
	t.remoteIP6 = p2pPeer.IP
	t.v6PeerForm = peerForm
	t.routes6 = routes6
	t.v6Enabled = true

	// The tunnel's own IPv6 transport socket must keep leaving through the
	// physical link. Pinned before the half-defaults below, which otherwise
	// swallow it on the very next packet.
	t.addServerBypass6()

	// Routes: installed together with the address, idempotently. Tracking
	// them in addedRoutes makes Close remove exactly these. The per-link metric
	// keeps a second dual-stack tunnel on this host from replacing our entries
	// with its own (same Dst plus same metric is one entry, not two).
	for _, dst := range routes6 {
		route := v6HalfDefaultRoute(link.Attrs().Index, dst)
		t.trackRoute(route)
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", dst, err)
		}
	}

	// MSS clamp for the ip6 family, mirroring the v4 table. The v6 base
	// header is 40 bytes (vs 20 for v4), so the clamp is mtu-60 against the
	// v4 mtu-40 — same "MTU minus L3+L4 headers" logic.
	if mss := t.mtu - 60; mss > 0 {
		if err := addMSSClampingV6(t.name, t.mtu); err != nil {
			log.Warn("Failed to set IPv6 MSS clamping: %v", err)
		} else {
			log.Info("TCP MSS clamping (IPv6) set to %d on %s", mss, t.name)
		}
	}

	// IPv6 is now inside the tunnel, so the leak block has nothing left to
	// protect against. Relevant on a reconnect that lands on a dual-stack exit
	// after a previous one declined: leaving the block up would reject the
	// tunnel's own v6 the moment it started working.
	t.RemoveIPv6LeakBlock()

	log.Info("TUN device %s dual-stack enabled: local=%s, peer=%s, routes=%v",
		t.name, clientIP6, serverIP6, dualStackRouteCIDRs)
	return nil
}

// v6AddrForms returns the link address for ip in the form currently installed
// (v6PeerForm) first and the other form second. Address operations retry
// against the second form because netlink matches the whole address: a
// mismatched delete does not fail loudly, it just leaves the stale address on
// the interface, and the replacement add then collides with it.
func (t *TUNDevice) v6AddrForms(ip net.IP) []*netlink.Addr {
	peer := &netlink.Addr{
		IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)},
		Peer:  &net.IPNet{IP: t.remoteIP6, Mask: net.CIDRMask(128, 128)},
	}
	fallback := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}}
	if t.v6PeerForm {
		return []*netlink.Addr{peer, fallback}
	}
	return []*netlink.Addr{fallback, peer}
}

// delV6Addr removes ip from the link, trying the recorded form first.
func (t *TUNDevice) delV6Addr(link netlink.Link, ip net.IP) error {
	if ip == nil {
		return nil
	}
	var lastErr error
	for _, addr := range t.v6AddrForms(ip) {
		err := netlink.AddrDel(link, addr)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// setV6Addr assigns ip to the link, trying the recorded form first and the
// other one as a fallback. Returns the form that stuck so the caller can
// update v6PeerForm.
func (t *TUNDevice) setV6Addr(link netlink.Link, ip net.IP) (peerForm bool, err error) {
	forms := t.v6AddrForms(ip)
	for i, addr := range forms {
		if err = netlink.AddrReplace(link, addr); err == nil {
			if i == 0 {
				return t.v6PeerForm, nil
			}
			return !t.v6PeerForm, nil
		}
	}
	return t.v6PeerForm, err
}

// DisableIPv6 pins the interface back to the exact v4-only state: any v6
// address/routes/clamp installed by EnableDualStack are removed and
// disable_ipv6=1 is restored. Called when dual-stack was requested but the
// exit did not negotiate it, so a declined negotiation never leaves a
// half-configured v6 path behind.
//
// The tunnel not carrying IPv6 is precisely the condition the leak block
// exists for, so it goes in here — including on the mid-session path where a
// live dual-stack tunnel loses its v6 address (updateLocalIP6). Under
// -tun-ipv6=off the policy declines and this stays a pure v4-only restore.
func (t *TUNDevice) DisableIPv6() {
	if t.name == "" {
		return
	}

	if t.v6Enabled {
		if link, err := netlink.LinkByName(t.name); err == nil {
			for _, dst := range t.routes6 {
				// Built by the same helper as the install, so the deletion
				// carries the metric netlink needs to match the entry.
				route := v6HalfDefaultRoute(link.Attrs().Index, dst)
				if err := netlink.RouteDel(route); err != nil {
					log.Debug("Failed to delete v6 route %s on %s: %v", dst, t.name, err)
				}
				t.untrackRoute(route)
			}
			if err := t.delV6Addr(link, t.localIP6); err != nil {
				log.Debug("Failed to delete v6 addr %s on %s: %v", t.localIP6, t.name, err)
			}
		}
		if err := removeMSSClampingV6(t.name); err != nil {
			log.Warn("Failed to remove IPv6 MSS clamping rules: %v", err)
		}
		t.v6Enabled = false
		t.localIP6 = nil
		t.remoteIP6 = nil
		t.routes6 = nil
		t.v6PeerForm = false
	}

	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte("1"), 0644); err != nil {
		log.Warn("Failed to disable IPv6 on %s: %v", t.name, err)
	}

	t.ApplyIPv6LeakBlock()
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

// routesCoverAnyIP is routesCoverIP over a whole bypass set. One covered
// address is enough to need the bypass machinery, and pinning is per-address
// anyway, so there is nothing to gain from knowing which ones matched.
func routesCoverAnyIP(routes []string, ips []net.IP) bool {
	for _, ip := range ips {
		if routesCoverIP(routes, ip) {
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
func (t *TUNDevice) addServerBypass() { t.pinBypassAll(t.bypassIPsFamily(false)) }

// addServerBypass6 pins the same host routes for the IPv6 transport addresses.
// Called by EnableDualStack before the ::/1 + 8000::/1 half-defaults land, so
// a client dialling its server over IPv6 never routes that socket into its own
// tunnel. No-op when no v6 server address was configured.
func (t *TUNDevice) addServerBypass6() { t.pinBypassAll(t.bypassIPsFamily(true)) }

// pinBypassAll pins one host route per address. A failure on one address is
// logged and skipped rather than aborting: the remaining endpoints are still
// worth pinning, and the client can reach the server through any of them.
func (t *TUNDevice) pinBypassAll(ips []net.IP) {
	for _, ip := range ips {
		t.pinBypass(ip)
	}
}

// hostRouteExists reports whether the routing table already holds a route for
// exactly dst. Used to tell an operator-installed host route to the server
// apart from one we pinned ourselves, so teardown does not delete somebody
// else's. A listing failure answers false: re-pinning and removing our own
// route is the pre-existing behaviour and the safer default.
func hostRouteExists(dst *net.IPNet, v6 bool) bool {
	family := netlink.FAMILY_V4
	if v6 {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteListFiltered(family,
		&netlink.Route{Dst: dst}, netlink.RT_FILTER_DST)
	if err != nil {
		log.Debug("Server bypass: cannot list routes for %s: %v", dst, err)
		return false
	}
	return len(routes) > 0
}

// bypassRoutesToDelete picks the bypass routes teardown owns, i.e. the ones it
// pinned itself.
//
// A route that was already in the table before we pinned ours belongs to the
// operator (NetworkManager profile, boot script, hand-typed `ip route add`),
// and on a host with no default route for that family it is the only way the
// server is reachable at all: deleting it strands the next client start. With a
// server list this is a per-address decision - one endpoint being operator-owned
// says nothing about the others - which is why it is a map lookup and not a
// pair of booleans.
//
// Split out of Close so the decision is testable without root: installing a
// real route to compare against needs CAP_NET_ADMIN, the rule does not.
func bypassRoutesToDelete(routes map[string]*netlink.Route, preexisted map[string]bool) []*netlink.Route {
	out := make([]*netlink.Route, 0, len(routes))
	for key, route := range routes {
		if route == nil {
			continue
		}
		if preexisted[key] {
			log.Debug("Server bypass: leaving pre-existing route to %s in place", route.Dst)
			continue
		}
		out = append(out, route)
	}
	return out
}

// pinBypass installs the /32 (v4) or /128 (v6) host route to ip through the
// current physical gateway and records it for teardown. Shared by the v4 and
// v6 paths; physicalRouteTo already selects the right address family.
func (t *TUNDevice) pinBypass(ip net.IP) {
	if ip == nil {
		return
	}
	r, err := t.physicalRouteTo(ip)
	if err != nil {
		log.Warn("Server bypass: cannot resolve physical route to %s: %v", ip, err)
		return
	}
	v6 := ip.To4() == nil
	bits := 32
	if v6 {
		bits = 128
	}
	dst := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	preexisting := hostRouteExists(dst, v6)
	bypass := &netlink.Route{
		LinkIndex: r.LinkIndex,
		Dst:       dst,
		Gw:        r.Gw,
		Src:       r.Src,
	}
	if err := netlink.RouteReplace(bypass); err != nil {
		log.Warn("Server bypass: failed to pin host route to %s: %v", ip, err)
		return
	}
	key := ip.String()
	t.bypassMu.Lock()
	// Close raced us and dropped this address: undo the pin instead of leaking
	// a route nothing will ever tear down. Checking the address itself rather
	// than "any address of this family" is what keeps one endpoint's teardown
	// from silently orphaning another's route.
	dropped := !containsIP(t.serverBypassIPs, ip)
	if !dropped {
		if t.bypassRoutes == nil {
			t.bypassRoutes = make(map[string]*netlink.Route, len(t.serverBypassIPs))
			t.bypassPreexisted = make(map[string]bool, len(t.serverBypassIPs))
		}
		t.bypassRoutes[key] = bypass
		t.bypassPreexisted[key] = t.bypassPreexisted[key] || preexisting
	}
	t.bypassMu.Unlock()
	if dropped {
		netlink.RouteDel(bypass)
		return
	}
	log.Info("Server bypass route pinned: %s/%d via %v (linkIndex %d)", ip, bits, r.Gw, r.LinkIndex)
}

// EnsureServerBypass re-pins the server bypasses if traffic to any of them
// would currently go through the tunnel. Cheap enough to poll: the healthy path
// costs one RouteGet per configured address and touches nothing.
func (t *TUNDevice) EnsureServerBypass() {
	for _, ip := range t.bypassIPs() {
		t.ensureBypass(ip)
	}
}

func (t *TUNDevice) ensureBypass(ip net.IP) {
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
	t.pinBypass(ip)
}

// WatchServerBypass polls the bypass route and restores it when the host drops
// it. The trigger in practice is a link flap (Wi-Fi roam/reassociation, dock,
// suspend/resume): the kernel deletes every route attached to the interface
// that went down, the bypass among them, after which the client's own
// full-tunnel routes swallow the traffic to the server and every reconnect
// attempt dials into the dead tunnel. Returns when stop is closed.
func (t *TUNDevice) WatchServerBypass(stop <-chan struct{}) {
	if len(t.bypassIPs()) == 0 {
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
	// Pin the server bypasses before any tunnel route that covers a server
	// lands. All of them, at once: the client walks its endpoint list without
	// telling this layer, so pinning only the one it happens to be using now
	// would leave the next dial to route itself into the tunnel.
	if routesCoverAnyIP(routes, t.bypassIPsFamily(false)) {
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
		r := tunRoute(link.Attrs().Index, dst)
		t.trackRoute(r)
		// RouteReplace is idempotent: it installs the route if absent and is a
		// no-op (no EEXIST) if it already exists. addRoutes runs on the initial
		// install and again on every reconnect, so RouteAdd here used to spam
		// "file exists" warnings once the route was already present.
		if err := netlink.RouteReplace(r); err != nil {
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

// trackRoute records an installed route in t.addedRoutes for scoped teardown,
// deduping so reconnect re-adds do not grow the list unbounded. It takes the
// very route that was handed to netlink, so what teardown deletes cannot drift
// from what install created.
//
// The dedup key is the (destination, metric) pair, because that pair is what
// the kernel keys a routing entry on: two entries differing only in metric are
// two routes and both need deleting.
func (t *TUNDevice) trackRoute(route *netlink.Route) {
	entry := trackedRoute{dst: route.Dst, priority: route.Priority}
	for _, existing := range t.addedRoutes {
		if existing.sameAs(entry) {
			return
		}
	}
	t.addedRoutes = append(t.addedRoutes, entry)
}

// untrackRoute drops a route from t.addedRoutes (used when it is removed ahead
// of teardown, e.g. DisableIPv6 tearing down the v6 half-defaults). It takes
// the same route the deletion was built from, metric included.
func (t *TUNDevice) untrackRoute(route *netlink.Route) {
	entry := trackedRoute{dst: route.Dst, priority: route.Priority}
	for i, existing := range t.addedRoutes {
		if existing.sameAs(entry) {
			t.addedRoutes = append(t.addedRoutes[:i], t.addedRoutes[i+1:]...)
			return
		}
	}
}

// reAddRoutes re-installs t.routes after an address change, normalizing bare
// IPs the same way addRoutes does. It logs at debug level since this runs on
// every reconnect/IP update; hard failures are already surfaced by addRoutes
// at configure time.
func (t *TUNDevice) reAddRoutes(link netlink.Link, reason string) {
	// A reconnect often follows the very event that wiped the bypass (link flap,
	// gateway change), so verify it before re-asserting the tunnel routes.
	if routesCoverAnyIP(t.routes, t.bypassIPs()) {
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
		r := tunRoute(link.Attrs().Index, dst)
		t.trackRoute(r)
		// RouteReplace keeps re-adds idempotent across reconnects / IP changes:
		// an already-present route is refreshed rather than failing with EEXIST.
		if err := netlink.RouteReplace(r); err != nil {
			log.Warn("Failed to re-add route %s: %v", route, err)
		} else {
			log.Debug("Re-added route %s after %s", route, reason)
		}
	}
	// The v6 half-defaults are not part of t.routes (they are implied by the
	// negotiated dual-stack, not user-supplied), so re-assert them separately
	// with the same idempotent RouteReplace — and the same per-link metric they
	// were installed with, or the replace would land on a second entry instead
	// of refreshing ours.
	if t.v6Enabled {
		for _, dst := range t.routes6 {
			r := v6HalfDefaultRoute(link.Attrs().Index, dst)
			t.trackRoute(r)
			if err := netlink.RouteReplace(r); err != nil {
				log.Warn("Failed to re-add v6 route %s: %v", dst, err)
			}
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
		t.updateLocalIP6(link)
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

	// The client v6 follows the v4 assignment (pool-prefix | v4-uint32), so a
	// v4 reassignment implies a v6 one when dual-stack is live.
	t.updateLocalIP6(link)

	// AddrDel above flushes every route bound to the old source/link, so re-add
	// the tracked route set idempotently (RouteReplace, same as 27109a3) to
	// restore the default route and any split-tunnel routes. The server-bypass
	// host route lives on the physical link, so it is unaffected by this swap.
	t.reAddRoutes(link, "IP change")

	return nil
}

// updateLocalIP6 swaps the tunnel v6 address after the v4 local IP changed.
// The exit assigns client v6 as pool-prefix | client-v4-uint32, so the new v6
// is derived from the previous v6 address and the new v4 (deriveClientIP6).
// No-op when dual-stack is not live or the derived address is unchanged.
//
// Both the delete and the add go through the recorded address form
// (v6PeerForm) with the other form as a retry: on a kernel that rejected the
// v6 peer, EnableDualStack installed the /64 fallback, and a peer-form delete
// silently matches nothing — the stale address then survives the lease change
// and the fresh add collides with it.
func (t *TUNDevice) updateLocalIP6(link netlink.Link) {
	if !t.v6Enabled {
		return
	}
	newIP6 := deriveClientIP6(t.localIP6, t.localIP)
	if newIP6 == nil || newIP6.Equal(t.localIP6) {
		return
	}
	if err := t.delV6Addr(link, t.localIP6); err != nil {
		log.Debug("Failed to delete old v6 addr %s: %v", t.localIP6, err)
	}
	peerForm, err := t.setV6Addr(link, newIP6)
	if err != nil {
		// Neither address form was accepted. The v6 half-defaults still point
		// into the TUN, so leaving them up black-holes every IPv6 flow behind
		// an interface with no usable address. Tear the v6 side down and keep
		// the session IPv4-only instead.
		log.Warn("Failed to update v6 local IP to %s: %v, disabling IPv6 on %s", newIP6, err, t.name)
		t.DisableIPv6()
		return
	}
	t.v6PeerForm = peerForm
	t.localIP6 = newIP6
	log.Info("TUN device %s local IPv6 updated to %s", t.name, newIP6)
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

// mssRuleExprs builds the nftables expressions for a single MSS clamping rule.
// It matches: ifKey (oifname/iifname) == ifName AND tcp AND tcp flags SYN
// (SYN|RST mask) AND sets MSS. The same expressions work in an ip (v4) or ip6
// family table; only the clamped value differs (v6 base header is 40 bytes).
func mssRuleExprs(ifKey expr.MetaKey, ifName string, mss uint16) []expr.Any {
	mssBE := make([]byte, 2)
	binary.BigEndian.PutUint16(mssBE, mss)

	return []expr.Any{
		// oifname/iifname == ifName
		&expr.Meta{Key: ifKey, Register: 1},
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

// mssRule builds the nftables expressions for a single MSS clamping rule.
// It matches: oifname == ifName AND tcp AND tcp flags SYN (SYN|RST mask) AND sets MSS.
func mssRule(ifName string, mtu int) []expr.Any {
	return mssRuleExprs(expr.MetaKeyOIFNAME, ifName, uint16(mtu-40))
}

// mssRuleIIF is like mssRule but matches iifname (inbound).
func mssRuleIIF(ifName string, mtu int) []expr.Any {
	return mssRuleExprs(expr.MetaKeyIIFNAME, ifName, uint16(mtu-40))
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

// addMSSClampingV6 is the ip6-family counterpart of addMSSClamping, installed
// only when dual-stack is negotiated (EnableDualStack). Same table name and
// chain structure as the v4 clamp — nftables tables are namespaced per
// family, so the two coexist and are torn down independently. The clamped
// value is mtu-60: the v6 base header is 40 bytes (vs 20 for v4), keeping the
// same "MTU minus L3+L4 headers" logic as the v4 mtu-40.
// Non-fatal: logs a warning and returns nil if nftables is unavailable.
func addMSSClampingV6(ifName string, mtu int) error {
	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables unavailable, skipping IPv6 MSS clamping: %v", err)
		return nil
	}

	tbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
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

	mss := uint16(mtu - 60)

	// outbound: oifname == ifName
	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: chain,
		Exprs: mssRuleExprs(expr.MetaKeyOIFNAME, ifName, mss),
	})

	// inbound: iifname == ifName
	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: chain,
		Exprs: mssRuleExprs(expr.MetaKeyIIFNAME, ifName, mss),
	})

	if err := conn.Flush(); err != nil {
		log.Warn("Failed to flush nftables IPv6 MSS clamping rules: %v", err)
		return nil
	}

	log.Debug("nftables IPv6 MSS clamping installed for %s (MSS=%d)", ifName, mtu-60)
	return nil
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

// removeMSSClampingV6 deletes this interface's ip6-family MSS clamping table.
// Called only when the table was installed (v6Enabled), so the v4-only path
// never issues a delete for a table that cannot exist.
// Non-fatal: logs a warning and returns nil if the operation fails.
func removeMSSClampingV6(ifName string) error {
	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables unavailable, cannot remove IPv6 MSS clamping: %v", err)
		return nil
	}

	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   mssTableName(ifName),
	})

	if err := conn.Flush(); err != nil {
		log.Warn("Failed to remove nftables IPv6 MSS clamping table: %v", err)
		return nil
	}

	log.Debug("nftables IPv6 MSS clamping table %q removed", mssTableName(ifName))
	return nil
}
