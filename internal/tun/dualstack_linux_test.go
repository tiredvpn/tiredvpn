//go:build linux
// +build linux

package tun

import (
	"encoding/binary"
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
