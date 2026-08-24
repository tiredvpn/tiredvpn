package tun

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// TestParseIPv6Policy pins the -tun-ipv6 flag surface: exactly {off, dual}
// today, everything else an error. The accepted set is a closed list so a
// future "block" value slots in without changing the flag's shape.
func TestParseIPv6Policy(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    IPv6Policy
		wantErr bool
	}{
		{"off", IPv6PolicyOff, false},
		{"dual", IPv6PolicyDual, false},
		{"", IPv6PolicyOff, true},
		{"block", IPv6PolicyOff, true}, // reserved for the leak-block branch, not yet valid
		{"on", IPv6PolicyOff, true},
		{"DUAL", IPv6PolicyOff, true},
		{" dual", IPv6PolicyOff, true},
	} {
		got, err := ParseIPv6Policy(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseIPv6Policy(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseIPv6Policy(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseIPv6Policy(%q) = %v, want %v", tc.in, got, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("IPv6Policy.String() = %q, want %q", got.String(), tc.in)
		}
	}
}

// TestDualStackRouteNets pins the v6 route set installed into the tunnel: the
// two half-defaults ::/1 and 8000::/1, never a blanket ::/0 (which would
// replace RA-learned defaults instead of outranking them).
func TestDualStackRouteNets(t *testing.T) {
	nets, err := dualStackRouteNets()
	if err != nil {
		t.Fatalf("dualStackRouteNets: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d routes, want 2: %v", len(nets), nets)
	}
	if nets[0].String() != "::/1" || nets[1].String() != "8000::/1" {
		t.Errorf("routes = %v, want [::/1 8000::/1]", nets)
	}
	for _, dst := range nets {
		if ones, bits := dst.Mask.Size(); bits != 128 || ones != 1 {
			t.Errorf("route %s is not a v6 /1", dst)
		}
	}
}

// TestDualStackAddrPlan pins the address shapes installed on the link: a
// point-to-point /128 pair mirroring the v4 setup, with a /64 fallback
// carrying the pool prefix.
func TestDualStackAddrPlan(t *testing.T) {
	client6 := net.ParseIP("fd00:10:8::a08:2")
	server6 := net.ParseIP("fd00:10:8::1")

	p2pLocal, p2pPeer, fallback, err := dualStackAddrPlan(client6, server6)
	if err != nil {
		t.Fatalf("dualStackAddrPlan: %v", err)
	}
	if p2pLocal.String() != "fd00:10:8::a08:2/128" {
		t.Errorf("p2p local = %s, want fd00:10:8::a08:2/128", p2pLocal)
	}
	if p2pPeer.String() != "fd00:10:8::1/128" {
		t.Errorf("p2p peer = %s, want fd00:10:8::1/128", p2pPeer)
	}
	if fallback.String() != "fd00:10:8::a08:2/64" {
		t.Errorf("fallback = %s, want fd00:10:8::a08:2/64", fallback)
	}

	for _, tc := range []struct {
		name           string
		client, server net.IP
	}{
		{"nil client", nil, server6},
		{"nil server", client6, nil},
		{"v4 client", net.ParseIP("10.8.0.2"), server6},
		{"v4 server", client6, net.ParseIP("10.8.0.1")},
	} {
		if _, _, _, err := dualStackAddrPlan(tc.client, tc.server); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

// TestDeriveClientIP6 pins the v6-follows-v4 reassignment rule: the exit
// assigns client v6 as pool-prefix | client-v4-uint32, so a new v4 keeps the
// old v6 prefix and swaps the last 4 bytes.
func TestDeriveClientIP6(t *testing.T) {
	old6 := net.ParseIP("fd00:10:8::a08:2") // ...|10.8.0.2
	got := deriveClientIP6(old6, net.ParseIP("10.8.0.9"))
	if want := net.ParseIP("fd00:10:8::a08:9"); !got.Equal(want) {
		t.Errorf("deriveClientIP6 = %s, want %s", got, want)
	}

	if got := deriveClientIP6(nil, net.ParseIP("10.8.0.9")); got != nil {
		t.Errorf("nil old v6: got %s, want nil", got)
	}
	if got := deriveClientIP6(old6, nil); got != nil {
		t.Errorf("nil v4: got %s, want nil", got)
	}
	if got := deriveClientIP6(net.ParseIP("10.8.0.2"), net.ParseIP("10.8.0.9")); got != nil {
		t.Errorf("v4 old addr: got %s, want nil", got)
	}
}

// TestControlResponseIPv6JSON covers the additive JSON contract: v6 fields
// appear when dual-stack was negotiated and are absent (omitempty) on a plain
// v4 session, so old consumers see an unchanged payload.
func TestControlResponseIPv6JSON(t *testing.T) {
	dual := ControlResponse{
		Status:    "waiting_fd",
		IP:        "10.8.0.2",
		ServerIP:  "10.8.0.1",
		IP6:       "fd00:10:8::a08:2",
		ServerIP6: "fd00:10:8::1",
		MTU:       1280,
	}
	data, err := json.Marshal(dual)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ControlResponse
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != dual {
		t.Errorf("round-trip = %+v, want %+v", back, dual)
	}

	v4 := ControlResponse{Status: "waiting_fd", IP: "10.8.0.2", ServerIP: "10.8.0.1", MTU: 1280}
	data, err = json.Marshal(v4)
	if err != nil {
		t.Fatalf("marshal v4: %v", err)
	}
	if strings.Contains(string(data), "ip6") {
		t.Errorf("v4-only response must not contain ip6 keys: %s", data)
	}
}

// TestPerformTUNHandshakeDualStack drives the control-socket handshake against
// a scripted server: the version byte on the wire follows the DualStack knob,
// and the negotiated v6 addresses land on the ControlServer only when the
// exit actually advertises them.
func TestPerformTUNHandshakeDualStack(t *testing.T) {
	block, server6, client6 := dualBlock()
	baseResp := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}

	newCS := func(dual bool, serverResp []byte) (*ControlServer, *scriptedConn) {
		conn := &scriptedConn{chunks: [][]byte{serverResp}}
		cs := &ControlServer{
			serverConn: conn,
			mtu:        1280,
			config:     &ControlConfig{DualStack: dual},
		}
		return cs, conn
	}

	t.Run("dual off keeps v3 and ignores v6", func(t *testing.T) {
		cs, conn := newCS(false, baseResp)
		if _, _, err := cs.performTUNHandshake(); err != nil {
			t.Fatalf("performTUNHandshake: %v", err)
		}
		if conn.written[7] != tunHandshakeVersion {
			t.Errorf("version byte = 0x%02x, want 0x%02x", conn.written[7], tunHandshakeVersion)
		}
		if cs.assignedIP6 != nil || cs.serverIP6 != nil {
			t.Errorf("v6 state = %s/%s, want nil", cs.assignedIP6, cs.serverIP6)
		}
	})

	t.Run("dual on, dual server", func(t *testing.T) {
		resp := append(append([]byte{}, baseResp...), tunFlagDualStack)
		resp = append(resp, block...)
		cs, conn := newCS(true, resp)
		assigned, server, err := cs.performTUNHandshake()
		if err != nil {
			t.Fatalf("performTUNHandshake: %v", err)
		}
		if conn.written[7] != tunHandshakeVersionDualStack {
			t.Errorf("version byte = 0x%02x, want 0x%02x", conn.written[7], tunHandshakeVersionDualStack)
		}
		if !assigned.Equal(net.IPv4(10, 8, 0, 2)) || !server.Equal(net.IPv4(10, 8, 0, 1)) {
			t.Errorf("v4 addrs = %s/%s", assigned, server)
		}
		if !cs.assignedIP6.Equal(client6) || !cs.serverIP6.Equal(server6) {
			t.Errorf("v6 state = %s/%s, want %s/%s", cs.assignedIP6, cs.serverIP6, client6, server6)
		}
	})

	t.Run("dual on, non-dual server falls back to v4-only", func(t *testing.T) {
		cs, conn := newCS(true, baseResp)
		if _, _, err := cs.performTUNHandshake(); err != nil {
			t.Fatalf("performTUNHandshake: %v", err)
		}
		if conn.written[7] != tunHandshakeVersionDualStack {
			t.Errorf("version byte = 0x%02x, want 0x%02x", conn.written[7], tunHandshakeVersionDualStack)
		}
		if cs.assignedIP6 != nil || cs.serverIP6 != nil {
			t.Errorf("declined dual-stack must leave v6 state nil, got %s/%s", cs.assignedIP6, cs.serverIP6)
		}
	})
}

// TestHandshakeFallbackNonDualServer is the client-side regression for a
// dual-requested client against a non-dual exit: the v3 response parses to a
// clean v4-only capability set, so no v6 configuration is emitted anywhere
// downstream.
func TestHandshakeFallbackNonDualServer(t *testing.T) {
	// Legacy 9-byte response (pre-flags server).
	conn := &scriptedConn{chunks: [][]byte{{0x00, 10, 8, 0, 1, 10, 8, 0, 2}}}
	v := &VPNClient{tun: &TUNDevice{mtu: 1280}, dualStack: true}
	resp, n, err := v.doHandshake(conn, net.IPv4zero)
	if err != nil {
		t.Fatalf("doHandshake: %v", err)
	}
	caps, hasCaps := parseServerCapabilities(resp, n)
	if hasCaps || caps.DualStackEnabled || caps.ServerIP6 != nil || caps.ClientIP6 != nil {
		t.Errorf("legacy server response must yield no caps and no v6: %+v hasCaps=%v", caps, hasCaps)
	}
	if conn.written[7] != tunHandshakeVersionDualStack {
		t.Errorf("dual client must still send 0x%02x, sent 0x%02x", tunHandshakeVersionDualStack, conn.written[7])
	}
}
