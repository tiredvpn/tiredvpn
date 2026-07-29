//go:build linux
// +build linux

package tun

import (
	"fmt"
	"net"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/vishvananda/netlink"
)

// natTableName is the nftables table used for the server's TUN-mode NAT
// bootstrap (MASQUERADE + FORWARD accept for the client IP pool). Kept
// separate from the per-interface MSS clamping tables (nftablesTableName)
// so the two subsystems never collide.
const natTableName = "tiredvpn-nat"

// SetupServerNAT installs IPv4 forwarding, MASQUERADE and FORWARD-accept
// rules for pool egressing via the WAN interface, replacing the iptables
// rules the Docker entrypoint and packaging/tiredvpn-nat.sh used to install
// by shelling out to `sysctl`/`ip`/`iptables`. wanOverride, if non-empty,
// skips autodetection (mirrors the old TIREDVPN_WAN_IFACE env override).
//
// A no-op if pool is empty (proxy-only mode). Every other failure is
// returned rather than logged directly, so the caller can decide how loud to
// be - the old shell scripts warned and continued rather than failing
// startup, and callers should do the same here.
func SetupServerNAT(pool string, wanOverride string) error {
	if pool == "" {
		return nil
	}

	if err := enableIPForward(); err != nil {
		log.Warn("could not enable net.ipv4.ip_forward: %v", err)
	}

	wan := wanOverride
	if wan == "" {
		var err error
		wan, err = detectWANInterface()
		if err != nil {
			return fmt.Errorf("detect WAN interface (set TIREDVPN_WAN_IFACE to override): %w", err)
		}
	}
	log.Info("NAT: using WAN interface %s for pool %s", wan, pool)

	_, ipnet, err := net.ParseCIDR(pool)
	if err != nil {
		return fmt.Errorf("invalid pool %q: %w", pool, err)
	}

	if err := installNATRules(ipnet, wan); err != nil {
		return fmt.Errorf("install nftables NAT rules: %w", err)
	}

	log.Info("NAT: installed MASQUERADE %s -> %s and FORWARD accept via nftables", pool, wan)
	return nil
}

// enableIPForward turns on IPv4 forwarding by writing directly to the proc
// sysctl, replacing the `sysctl -w net.ipv4.ip_forward=1` shell-out.
func enableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

// detectWANInterface returns the name of the interface the kernel would use
// to reach the public internet, mirroring `ip route get 1.1.1.1 | ... dev`.
func detectWANInterface() (string, error) {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil {
		return "", fmt.Errorf("route lookup: %w", err)
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return "", fmt.Errorf("no route to 1.1.1.1")
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", fmt.Errorf("resolve link %d: %w", routes[0].LinkIndex, err)
	}
	return link.Attrs().Name, nil
}

// installNATRules creates the tiredvpn-nat table with a postrouting chain
// (MASQUERADE for pool traffic leaving wan) and a forward chain (accept
// traffic to/from pool). Re-running replaces the table's rules wholesale, so
// this is safe to call again after a config change without leaving stale
// duplicate rules behind - the same idempotency the old scripts got from
// their `iptables -C ... || iptables -A ...` check-then-append pattern.
func installNATRules(pool *net.IPNet, wan string) error {
	// nftables commits a Flush() as one atomic batch: if any message in it
	// fails, the kernel rolls back the whole batch. Deleting a stale table
	// from a previous run has to happen in its own flush, separate from the
	// create-and-populate one below, because DelTable on a table that
	// doesn't exist yet (first run) would otherwise abort that batch too.
	// Best-effort: ignore the error either way.
	if delConn, err := nftables.New(); err == nil {
		delConn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: natTableName})
		_ = delConn.Flush()
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables unavailable: %w", err)
	}

	natTbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   natTableName,
	})

	postrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    natTbl,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   chainPolicyAcceptPtr(),
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: postrouting,
		Exprs: masqRule(pool, wan),
	})

	forward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    natTbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicyAcceptPtr(),
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: forward,
		Exprs: poolMatchAcceptRule(pool, true), // saddr in pool
	})
	conn.AddRule(&nftables.Rule{
		Table: natTbl,
		Chain: forward,
		Exprs: poolMatchAcceptRule(pool, false), // daddr in pool
	})

	return conn.Flush()
}

// masqRule matches packets leaving via wan whose source address is in pool,
// then masquerades them (equivalent to
// `iptables -t nat -A POSTROUTING -s pool -o wan -j MASQUERADE`).
func masqRule(pool *net.IPNet, wan string) []expr.Any {
	exprs := []expr.Any{
		// oifname == wan
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnamePad(wan)},
	}
	exprs = append(exprs, ipInPoolExprs(pool, 12)...) // ip saddr in pool
	return append(exprs, &expr.Masq{})
}

// poolMatchAcceptRule matches ip saddr (src=true) or daddr (src=false)
// against pool with a plain ACCEPT verdict (equivalent to
// `iptables -A FORWARD -s/-d pool -j ACCEPT`).
func poolMatchAcceptRule(pool *net.IPNet, src bool) []expr.Any {
	offset := uint32(16) // daddr
	if src {
		offset = 12 // saddr
	}
	exprs := ipInPoolExprs(pool, offset)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

// ipInPoolExprs loads the 4-byte IPv4 address at the given network-header
// offset (12=saddr, 16=daddr) and compares it, masked by pool's netmask,
// against pool's network address.
func ipInPoolExprs(pool *net.IPNet, offset uint32) []expr.Any {
	network := pool.IP.To4()
	mask := net.IP(pool.Mask).To4()

	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
		&expr.Bitwise{DestRegister: 1, SourceRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
	}
}
