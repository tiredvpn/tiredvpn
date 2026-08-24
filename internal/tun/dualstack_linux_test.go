//go:build linux
// +build linux

package tun

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/nftables/expr"
)

// clampedMSS extracts the MSS value carried by the Immediate expression of a
// clamp rule, so tests can assert the exact on-wire clamp.
func clampedMSS(t *testing.T, exprs []expr.Any) uint16 {
	t.Helper()
	for _, e := range exprs {
		if imm, ok := e.(*expr.Immediate); ok {
			return binary.BigEndian.Uint16(imm.Data)
		}
	}
	t.Fatal("no Immediate expression in rule")
	return 0
}

// TestMSSClampFamilies pins the clamp values per family: v4 keeps the
// historical mtu-40 (20B IPv4 + 20B TCP), v6 clamps at mtu-60 (40B IPv6 +
// 20B TCP) — the same "MTU minus L3+L4 headers" logic.
func TestMSSClampFamilies(t *testing.T) {
	const mtu = 1280

	if got := clampedMSS(t, mssRule("tun0", mtu)); got != mtu-40 {
		t.Errorf("v4 oif clamp = %d, want %d", got, mtu-40)
	}
	if got := clampedMSS(t, mssRuleIIF("tun0", mtu)); got != mtu-40 {
		t.Errorf("v4 iif clamp = %d, want %d", got, mtu-40)
	}

	v6 := uint16(mtu - 60)
	if got := clampedMSS(t, mssRuleExprs(expr.MetaKeyOIFNAME, "tun0", v6)); got != v6 {
		t.Errorf("v6 oif clamp = %d, want %d", got, v6)
	}
	if got := clampedMSS(t, mssRuleExprs(expr.MetaKeyIIFNAME, "tun0", v6)); got != v6 {
		t.Errorf("v6 iif clamp = %d, want %d", got, v6)
	}
}

// TestMSSRuleExprsUnchanged verifies the refactor into mssRuleExprs did not
// alter the v4 rule shape: same expression count, same ifname key.
func TestMSSRuleExprsUnchanged(t *testing.T) {
	out := mssRule("tun0", 1280)
	in := mssRuleIIF("tun0", 1280)
	if len(out) != len(in) {
		t.Fatalf("oif/iif expr count mismatch: %d vs %d", len(out), len(in))
	}
	if meta, ok := out[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyOIFNAME {
		t.Errorf("oif rule first expr = %#v, want Meta OIFNAME", out[0])
	}
	if meta, ok := in[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Errorf("iif rule first expr = %#v, want Meta IIFNAME", in[0])
	}
}

// TestV6AddrForms pins which address form later operations use. Nothing used
// to record whether EnableDualStack landed the point-to-point peer form or the
// /64 fallback, and every consumer assumed the peer form: on a kernel that
// took the fallback, the delete matched nothing, the stale address survived a
// lease change and the replacement add collided with it.
func TestV6AddrForms(t *testing.T) {
	client6 := net.ParseIP("fd00:10:8::a08:2")
	server6 := net.ParseIP("fd00:10:8::1")

	t.Run("peer form first", func(t *testing.T) {
		td := &TUNDevice{remoteIP6: server6, v6PeerForm: true}
		forms := td.v6AddrForms(client6)
		if len(forms) != 2 {
			t.Fatalf("got %d forms, want 2", len(forms))
		}
		if ones, _ := forms[0].Mask.Size(); ones != 128 || forms[0].Peer == nil {
			t.Errorf("first form = %v (peer=%v), want /128 with a peer", forms[0].IPNet, forms[0].Peer)
		}
		if !forms[0].Peer.IP.Equal(server6) {
			t.Errorf("peer = %s, want %s", forms[0].Peer.IP, server6)
		}
		if ones, _ := forms[1].Mask.Size(); ones != 64 || forms[1].Peer != nil {
			t.Errorf("fallback form = %v (peer=%v), want /64 with no peer", forms[1].IPNet, forms[1].Peer)
		}
	})

	t.Run("fallback form first", func(t *testing.T) {
		td := &TUNDevice{remoteIP6: server6, v6PeerForm: false}
		forms := td.v6AddrForms(client6)
		if ones, _ := forms[0].Mask.Size(); ones != 64 || forms[0].Peer != nil {
			t.Errorf("first form = %v (peer=%v), want the /64 fallback", forms[0].IPNet, forms[0].Peer)
		}
		if ones, _ := forms[1].Mask.Size(); ones != 128 || forms[1].Peer == nil {
			t.Errorf("second form = %v, want the peer form as retry", forms[1].IPNet)
		}
	})

	t.Run("both forms carry the address", func(t *testing.T) {
		td := &TUNDevice{remoteIP6: server6, v6PeerForm: true}
		for i, a := range td.v6AddrForms(client6) {
			if !a.IP.Equal(client6) {
				t.Errorf("form %d address = %s, want %s", i, a.IP, client6)
			}
		}
	})
}

// TestEnsureIPv6AcceptRA covers the sysctl nudge that keeps an RA-learned IPv6
// default route alive once forwarding is on: only 1 is rewritten (0 means RAs
// are off by policy, 2 is already correct), and an unreadable path is a
// warning rather than a failure.
func TestEnsureIPv6AcceptRA(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  string
		want string
	}{
		{"raises 1 to 2", "1\n", "2\n"},
		{"leaves 2 alone", "2\n", "2\n"},
		{"leaves 0 alone (RAs disabled by policy)", "0\n", "0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "accept_ra")
			if err := os.WriteFile(path, []byte(tc.cur), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ensureIPv6AcceptRAAt(path, "eth0")
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("accept_ra = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("missing sysctl does not panic", func(t *testing.T) {
		ensureIPv6AcceptRAAt(filepath.Join(t.TempDir(), "absent"), "eth0")
	})
}
