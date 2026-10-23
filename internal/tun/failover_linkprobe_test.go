package tun

import (
	"net"
	"slices"
	"testing"
	"time"
)

// TestLocalLinkUpAsksTheFallbackProbes is the Android half of P2-4 of the
// round-3 review of PR #126: with no gateway found (per-network tables,
// restricted netlink) localLinkUp said "cannot tell" every time, so dead
// sessions and storms never charged an endpoint on a phone. On Android it
// asks a public resolver over the underlying network instead.
func TestLocalLinkUpAsksTheFallbackProbes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	oldGw, oldProbes := gatewayAddrs, linkFallbackProbes
	t.Cleanup(func() { gatewayAddrs, linkFallbackProbes = oldGw, oldProbes })
	gatewayAddrs = func() []string { return nil }

	linkFallbackProbes = nil
	if localLinkUp() {
		t.Fatal("no gateway and no fallback probes, yet the link reads as up")
	}
	linkFallbackProbes = []string{ln.Addr().String()}
	if !localLinkUp() {
		t.Fatal("a fallback probe answered and the link still cannot be confirmed")
	}
}

// TestDefaultGatewayAddrs: only default routes with a gateway on a link
// qualify, once each; link-local gateways carry their zone.
func TestDefaultGatewayAddrs(t *testing.T) {
	got := defaultGatewayAddrs([]ribRoute{
		{gw: net.ParseIP("192.168.1.1"), link: 7},
		{gw: net.ParseIP("192.168.1.1"), link: 7}, // same route in two tables
		{gw: nil, link: 9},                        // the tunnel's own default
		{gw: net.ParseIP("0.0.0.0"), link: 3},
		{gw: net.ParseIP("fe80::1"), link: 7},
		{gw: net.ParseIP("10.0.0.1"), link: 0},
	})
	want := []string{"192.168.1.1:53", "[fe80::1%7]:53"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestBSDDefaultRoute is the macOS half of P2-4: the gateway comes from the
// routing socket. The tunnel claims 0/1 and 128/1 with a gateway of its own;
// those must not read as the default.
func TestBSDDefaultRoute(t *testing.T) {
	v4 := func(s string) *ribAddr { return &ribAddr{ip: net.ParseIP(s).To4()} }
	v6 := func(s string, zone int) *ribAddr { return &ribAddr{ip: net.ParseIP(s), zone: zone} }
	cases := []struct {
		name          string
		dst, mask, gw *ribAddr
		ifscope       bool
		want          string // dial address, "" for not a default
	}{
		{"default, mask absent", v4("0.0.0.0"), nil, v4("192.168.1.1"), false, "192.168.1.1:53"},
		{"interface-scoped default", v4("0.0.0.0"), nil, v4("192.168.1.1"), true, ""},
		{"scoped v6 default on the utun", v6("::", 0), nil, v6("fe80::1", 12), true, ""},
		{"default, zero mask", v4("0.0.0.0"), v4("0.0.0.0"), v4("192.168.1.1"), false, "192.168.1.1:53"},
		{"tunnel 0/1", v4("0.0.0.0"), v4("128.0.0.0"), v4("10.8.0.1"), false, ""},
		{"tunnel 128/1", v4("128.0.0.0"), v4("128.0.0.0"), v4("10.8.0.1"), false, ""},
		{"lan prefix", v4("192.168.1.0"), v4("255.255.255.0"), v4("192.168.1.1"), false, ""},
		{"link-layer gateway", v4("0.0.0.0"), nil, nil, false, ""},
		{"v6 default, scoped gateway", v6("::", 0), nil, v6("fe80::1", 4), false, "[fe80::1%4]:53"},
		{"v6 tunnel ::/1", v6("::", 0), v6("8000::", 0), v6("fd00::1", 0), false, ""},
	}
	for _, tc := range cases {
		r, ok := bsdDefaultRoute(tc.dst, tc.mask, tc.gw, 9, tc.ifscope)
		got := ""
		if ok {
			if addrs := defaultGatewayAddrs([]ribRoute{r}); len(addrs) == 1 {
				got = addrs[0]
			}
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestLocalLinkUpDoesNotQueueBehindSilentGateways is P3-10/P3-11 of the
// round-4 review: gateways and fallback probes were dialled one after
// another, so each silent one (an interface-scoped default, a dead family)
// added a full timeout before the answer. Two silent addresses ahead of one
// that answers: the answer comes in well under one timeout.
func TestLocalLinkUpDoesNotQueueBehindSilentGateways(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	silentA, silentB := silentTCPAddr(t), silentTCPAddr(t)
	oldGw := gatewayAddrs
	t.Cleanup(func() { gatewayAddrs = oldGw })
	gatewayAddrs = func() []string { return []string{silentA, silentB, ln.Addr().String()} }
	start := time.Now()
	if !localLinkUp() {
		t.Fatal("a gateway answered and the link reads as down")
	}
	if took := time.Since(start); took > networkCheckTimeout/2 {
		t.Fatalf("took %v: the answering gateway waited behind the silent ones", took)
	}
}
