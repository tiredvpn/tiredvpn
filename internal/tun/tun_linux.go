//go:build linux
// +build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
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
)

type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	pad   [24 - ifnamsiz - 2]byte
}

type TUNDevice struct {
	name     string
	file     *os.File
	mtu      int
	localIP  net.IP
	remoteIP net.IP
	routes   []string
}

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
		name: actualName,
		file: file,
		mtu:  mtu,
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

func (t *TUNDevice) File() *os.File {
	return t.file
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

	for _, route := range routes {
		_, dst, err := net.ParseCIDR(route)
		if err != nil {
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
			log.Warn("Failed to add route %s: %v", route, err)
		}
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

func (t *TUNDevice) ConfigureSubnet(localIP net.IP, network *net.IPNet) error {
	t.localIP = localIP

	sysctlPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", t.name)
	if err := os.WriteFile(sysctlPath, []byte("1"), 0644); err != nil {
		log.Warn("Failed to disable IPv6 on %s: %v", t.name, err)
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

	for _, route := range t.routes {
		_, dst, err := net.ParseCIDR(route)
		if err != nil {
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
			log.Warn("Failed to re-add route %s: %v", route, err)
		} else {
			log.Debug("Re-added route %s after peer IP change", route)
		}
	}

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

	for _, route := range t.routes {
		_, dst, err := net.ParseCIDR(route)
		if err != nil {
			log.Warn("Failed to parse route %s: %v", route, err)
			continue
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
			log.Warn("Failed to re-add route %s: %v", route, err)
		} else {
			log.Debug("Re-added route %s after IP change", route)
		}
	}

	return nil
}

// nftablesTableName is the nftables table created for MSS clamping rules.
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
// Creates table "tiredvpn" (IPv4, filter/forward/mangle priority) with two rules:
// one matching outbound (oifname) and one matching inbound (iifname) on ifName.
// Non-fatal: logs a warning and returns nil if nftables is unavailable.
func addMSSClamping(ifName string, mtu int) error {
	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables unavailable, skipping MSS clamping: %v", err)
		return nil
	}

	tbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftablesTableName,
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

// removeMSSClamping deletes the "tiredvpn" nftables table, removing all MSS clamping rules.
// Non-fatal: logs a warning and returns nil if the operation fails.
func removeMSSClamping(ifName string) error {
	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables unavailable, cannot remove MSS clamping: %v", err)
		return nil
	}

	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftablesTableName,
	})

	if err := conn.Flush(); err != nil {
		log.Warn("Failed to remove nftables MSS clamping table: %v", err)
		return nil
	}

	log.Debug("nftables MSS clamping table %q removed", nftablesTableName)
	return nil
}
