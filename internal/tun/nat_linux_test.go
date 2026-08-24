//go:build linux
// +build linux

package tun

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/nftables/expr"
)

func mustParsePool6(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	return n
}

// The ip6 pool-match expression must load 16 bytes at the given header offset
// and compare against the masked network address.
func TestIP6InPoolExprs(t *testing.T) {
	pool := mustParsePool6(t, "fd00:10:8::/64")
	exprs := ip6InPoolExprs(pool, 8)
	if len(exprs) != 3 {
		t.Fatalf("ip6InPoolExprs returned %d exprs, want 3", len(exprs))
	}

	payload, ok := exprs[0].(*expr.Payload)
	if !ok {
		t.Fatalf("expr[0] = %T, want *expr.Payload", exprs[0])
	}
	if payload.Offset != 8 || payload.Len != 16 {
		t.Errorf("payload offset/len = %d/%d, want 8/16", payload.Offset, payload.Len)
	}

	bitwise, ok := exprs[1].(*expr.Bitwise)
	if !ok {
		t.Fatalf("expr[1] = %T, want *expr.Bitwise", exprs[1])
	}
	if bitwise.Len != 16 {
		t.Errorf("bitwise len = %d, want 16", bitwise.Len)
	}
	if !bytes.Equal(bitwise.Mask, net.IP(pool.Mask)) {
		t.Errorf("bitwise mask = %x, want %x", bitwise.Mask, net.IP(pool.Mask))
	}
	if !bytes.Equal(bitwise.Xor, make([]byte, 16)) {
		t.Errorf("bitwise xor = %x, want zeroed", bitwise.Xor)
	}

	cmp, ok := exprs[2].(*expr.Cmp)
	if !ok {
		t.Fatalf("expr[2] = %T, want *expr.Cmp", exprs[2])
	}
	if !bytes.Equal(cmp.Data, pool.IP.To16()) {
		t.Errorf("cmp data = %x, want %x", cmp.Data, pool.IP.To16())
	}
}

// The NAT66 masquerade rule must match the output interface, the pool source
// (offset 8 in the v6 header) and end in Masq.
func TestMasqRule6(t *testing.T) {
	pool := mustParsePool6(t, "fd00:10:8::/64")
	exprs := masqRule6(pool, "eth0")
	if len(exprs) != 6 {
		t.Fatalf("masqRule6 returned %d exprs, want 6", len(exprs))
	}
	if meta, ok := exprs[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyOIFNAME {
		t.Fatalf("expr[0] = %+v, want Meta OIFNAME", exprs[0])
	}
	if payload, ok := exprs[2].(*expr.Payload); !ok || payload.Offset != 8 {
		t.Fatalf("expr[2] = %+v, want Payload offset 8 (ip6 saddr)", exprs[2])
	}
	if _, ok := exprs[5].(*expr.Masq); !ok {
		t.Fatalf("expr[5] = %T, want *expr.Masq", exprs[5])
	}
}

// Forward-accept rules: saddr variant matches offset 8, daddr offset 24, both
// terminating in ACCEPT.
func TestPoolMatchAcceptRule6(t *testing.T) {
	pool := mustParsePool6(t, "fd00:10:8::/64")

	src := poolMatchAcceptRule6(pool, true)
	if p, ok := src[0].(*expr.Payload); !ok || p.Offset != 8 {
		t.Errorf("saddr rule offset = %+v, want Payload offset 8", src[0])
	}
	if v, ok := src[3].(*expr.Verdict); !ok || v.Kind != expr.VerdictAccept {
		t.Errorf("saddr rule verdict = %+v, want ACCEPT", src[3])
	}

	dst := poolMatchAcceptRule6(pool, false)
	if p, ok := dst[0].(*expr.Payload); !ok || p.Offset != 24 {
		t.Errorf("daddr rule offset = %+v, want Payload offset 24", dst[0])
	}
	if v, ok := dst[3].(*expr.Verdict); !ok || v.Kind != expr.VerdictAccept {
		t.Errorf("daddr rule verdict = %+v, want ACCEPT", dst[3])
	}
}

// SetupServerNAT6 guards: empty pool is a no-op, garbage and v4 CIDRs are
// rejected before any nftables work.
func TestSetupServerNAT6ArgValidation(t *testing.T) {
	if err := SetupServerNAT6("", ""); err != nil {
		t.Errorf("empty pool should be a no-op, got %v", err)
	}
	if err := SetupServerNAT6("not-a-cidr", "eth0"); err == nil {
		t.Error("garbage pool should fail")
	}
	if err := SetupServerNAT6("10.8.0.0/24", "eth0"); err == nil {
		t.Error("IPv4 pool should fail")
	}
}

// The v4 twins must be untouched by the v6 additions (offsets 12/16, 4-byte).
func TestIP4ExprsUnchanged(t *testing.T) {
	_, pool, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	src := poolMatchAcceptRule(pool, true)
	if p, ok := src[0].(*expr.Payload); !ok || p.Offset != 12 || p.Len != 4 {
		t.Errorf("v4 saddr rule = %+v, want Payload offset 12 len 4", src[0])
	}
	dst := poolMatchAcceptRule(pool, false)
	if p, ok := dst[0].(*expr.Payload); !ok || p.Offset != 16 || p.Len != 4 {
		t.Errorf("v4 daddr rule = %+v, want Payload offset 16 len 4", dst[0])
	}
}
