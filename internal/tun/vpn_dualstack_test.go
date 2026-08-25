package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// dualPolicy maps the "is this the dual-stack case" boolean the older table
// tests are written around onto the policy the client now carries.
func dualPolicy(dual bool) IPv6Policy {
	if dual {
		return IPv6PolicyDual
	}
	return IPv6PolicyOff
}

// TestHandshakeVersionSelection pins the version knob: only the dual policy
// sends 0x04. off keeps 0x03, and so does block — it wants the host's IPv6
// stopped, not carried, so it has nothing to ask the exit for and stays
// byte-identical to a v4-only client on the wire.
func TestHandshakeVersionSelection(t *testing.T) {
	for _, tc := range []struct {
		policy IPv6Policy
		want   byte
	}{
		{IPv6PolicyOff, tunHandshakeVersion},
		{IPv6PolicyBlock, tunHandshakeVersion},
		{IPv6PolicyDual, tunHandshakeVersionDualStack},
	} {
		if got := (&VPNClient{ipv6Policy: tc.policy}).handshakeVersion(); got != tc.want {
			t.Errorf("handshake version for %s = 0x%02x, want 0x%02x", tc.policy, got, tc.want)
		}
	}
	if got := (&VPNClient{}).handshakeVersion(); got != tunHandshakeVersion {
		t.Errorf("zero-value handshake version = 0x%02x, want 0x%02x", got, tunHandshakeVersion)
	}
}

// scriptedConn feeds Read from a fixed sequence of chunks; a read past the
// end of the script is an error, which lets tests prove no extra read
// happens. Chunks larger than the read buffer are truncated to it.
type scriptedConn struct {
	chunks  [][]byte
	idx     int
	written []byte
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.chunks) {
		return 0, errors.New("unexpected extra read")
	}
	n := copy(p, c.chunks[c.idx])
	c.idx++
	return n, nil
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

// dualBlock returns a deterministic 32-byte [serverIP6:16][clientIP6:16]
// block for the parse tests.
func dualBlock() (block []byte, server6, client6 net.IP) {
	server6 = net.ParseIP("fd00:10:8::1")
	client6 = net.ParseIP("fd00:10:8::a08:2")
	block = make([]byte, 32)
	copy(block[0:16], server6.To16())
	copy(block[16:32], client6.To16())
	return block, server6, client6
}

// TestParseServerCapabilitiesDualStack covers the client side of the v0x04
// negotiation across the version-dependent base layouts.
func TestParseServerCapabilitiesDualStack(t *testing.T) {
	block, server6, client6 := dualBlock()
	base := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}

	mk := func(flags byte, mid []byte) []byte {
		resp := append(append([]byte{}, base...), flags)
		resp = append(resp, mid...)
		return append(resp, block...)
	}

	t.Run("flags-only base (10B) with dual block", func(t *testing.T) {
		resp := mk(tunFlagMTUProbe|tunFlagDualStack, nil)
		caps, ok := parseServerCapabilities(resp, len(resp))
		if !ok || !caps.DualStackEnabled {
			t.Fatalf("dual-stack not detected: %+v ok=%v", caps, ok)
		}
		if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
			t.Errorf("v6 addrs = %s/%s, want %s/%s", caps.ServerIP6, caps.ClientIP6, server6, client6)
		}
		if caps.PortHoppingEnabled {
			t.Error("port hopping should be off")
		}
	})

	t.Run("v2 base (20B, no seed) with dual block", func(t *testing.T) {
		mid := []byte{0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x01, 0x00}
		resp := mk(tunFlagPortHopping|tunFlagMTUProbe|tunFlagDualStack, mid)
		caps, ok := parseServerCapabilities(resp, len(resp))
		if !ok || !caps.DualStackEnabled || !caps.PortHoppingEnabled {
			t.Fatalf("caps wrong: %+v ok=%v", caps, ok)
		}
		if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
			t.Errorf("v6 addrs = %s/%s, want %s/%s", caps.ServerIP6, caps.ClientIP6, server6, client6)
		}
		if caps.PortRangeStart != 47000 || caps.PortRangeEnd != 47100 || caps.HopStrategy != "sequential" {
			t.Errorf("port-hop caps wrong: %+v", caps)
		}
	})

	t.Run("v2 base with seed shifts the dual block", func(t *testing.T) {
		mid := []byte{0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x00, 0x04, 's', 'e', 'e', 'd'}
		resp := mk(tunFlagPortHopping|tunFlagDualStack, mid)
		caps, ok := parseServerCapabilities(resp, len(resp))
		if !ok || !caps.DualStackEnabled {
			t.Fatalf("dual-stack not detected: %+v ok=%v", caps, ok)
		}
		if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
			t.Errorf("v6 addrs = %s/%s, want %s/%s", caps.ServerIP6, caps.ClientIP6, server6, client6)
		}
		if !bytes.Equal(caps.HopSeed, []byte("seed")) {
			t.Errorf("seed = %q, want %q", caps.HopSeed, "seed")
		}
	})

	t.Run("v3 response without dual flag stays v4-only", func(t *testing.T) {
		resp := append(append([]byte{}, base...), tunFlagMTUProbe)
		caps, ok := parseServerCapabilities(resp, len(resp))
		if !ok || !caps.MTUProbeSupported {
			t.Fatalf("probe cap lost: %+v ok=%v", caps, ok)
		}
		if caps.DualStackEnabled || caps.ServerIP6 != nil || caps.ClientIP6 != nil {
			t.Errorf("v3 response must not yield v6 addrs: %+v", caps)
		}
	})

	t.Run("dual flag with truncated block degrades to v4-only", func(t *testing.T) {
		resp := append(append([]byte{}, base...), tunFlagDualStack)
		resp = append(resp, block[:10]...) // only 10 of 32 bytes
		caps, _ := parseServerCapabilities(resp, len(resp))
		if caps.DualStackEnabled {
			t.Errorf("truncated block must not enable dual-stack: %+v", caps)
		}
	})
}

// TestReadDualStackBlock verifies the stream stays frame-aligned: the extra
// 32 bytes are consumed exactly when the flag is set, and never otherwise.
func TestReadDualStackBlock(t *testing.T) {
	block, _, _ := dualBlock()

	t.Run("no flag: no extra read", func(t *testing.T) {
		legacy := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}
		conn := &scriptedConn{} // any read fails
		n, err := readResponseTail(conn, legacy, len(legacy), tunHandshakeVersionDualStack)
		if err != nil || n != len(legacy) {
			t.Errorf("legacy: n=%d err=%v", n, err)
		}

		probe := append(append([]byte{}, legacy...), tunFlagMTUProbe)
		n, err = readResponseTail(conn, probe, len(probe), tunHandshakeVersionDualStack)
		if err != nil || n != len(probe) {
			t.Errorf("v3 probe-only: n=%d err=%v", n, err)
		}
	})

	t.Run("flag set, whole response in one read", func(t *testing.T) {
		resp := make([]byte, handshakeRespBufSize)
		full := append([]byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2, tunFlagDualStack}, block...)
		copy(resp, full)
		conn := &scriptedConn{} // must not be read again
		n, err := readResponseTail(conn, resp, len(full), tunHandshakeVersionDualStack)
		if err != nil || n != len(full) {
			t.Errorf("n=%d err=%v, want n=%d", n, err, len(full))
		}
	})

	t.Run("flag set, block arrives split across reads", func(t *testing.T) {
		resp := make([]byte, handshakeRespBufSize)
		head := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2, tunFlagMTUProbe | tunFlagDualStack}
		copy(resp, head)
		conn := &scriptedConn{chunks: [][]byte{block[:13], block[13:]}}
		n, err := readResponseTail(conn, resp, len(head), tunHandshakeVersionDualStack)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if n != len(head)+32 {
			t.Errorf("n=%d, want %d", n, len(head)+32)
		}
		if !bytes.Equal(resp[len(head):n], block) {
			t.Errorf("block = %x, want %x", resp[len(head):n], block)
		}
	})

	t.Run("flag set, block never arrives", func(t *testing.T) {
		resp := make([]byte, handshakeRespBufSize)
		head := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2, tunFlagDualStack}
		copy(resp, head)
		conn := &scriptedConn{} // read fails immediately
		if _, err := readResponseTail(conn, resp, len(head), tunHandshakeVersionDualStack); err == nil {
			t.Error("expected an error when the advertised block is missing")
		}
	})
}

// TestHandshakeResponseBaseLen pins the base-layout sizing used to locate the
// trailing dual-stack block.
func TestHandshakeResponseBaseLen(t *testing.T) {
	resp := make([]byte, 96)
	resp[9] = tunFlagPortHopping
	resp[19] = 7 // seedLen

	if got := handshakeResponseBaseLen(resp, 9); got != 9 {
		t.Errorf("legacy: %d, want 9", got)
	}
	resp[9] = tunFlagMTUProbe
	if got := handshakeResponseBaseLen(resp, 10); got != 10 {
		t.Errorf("flags-only: %d, want 10", got)
	}
	resp[9] = tunFlagPortHopping
	if got := handshakeResponseBaseLen(resp, 14); got != 14 {
		t.Errorf("v1: %d, want 14", got)
	}
	if got := handshakeResponseBaseLen(resp, 27); got != 27 {
		t.Errorf("v2 with seedLen 7: %d, want 27", got)
	}
	resp[19] = 0
	if got := handshakeResponseBaseLen(resp, 20); got != 20 {
		t.Errorf("v2 no seed: %d, want 20", got)
	}
}

// TestDoHandshakeEndToEndDualStack drives doHandshake against a scripted
// server to prove the version byte on the wire and the full response parse.
func TestDoHandshakeEndToEndDualStack(t *testing.T) {
	block, server6, client6 := dualBlock()

	for _, dual := range []bool{false, true} {
		t.Run(map[bool]string{false: "v3", true: "v4"}[dual], func(t *testing.T) {
			serverResp := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2, tunFlagMTUProbe}
			if dual {
				serverResp[9] |= tunFlagDualStack
				serverResp = append(serverResp, block...)
			}
			conn := &scriptedConn{chunks: [][]byte{serverResp}}

			v := &VPNClient{tun: &TUNDevice{mtu: 1280}, ipv6Policy: dualPolicy(dual)}
			resp, n, err := v.doHandshake(conn, net.IPv4zero)
			if err != nil {
				t.Fatalf("doHandshake: %v", err)
			}
			if n != len(serverResp) {
				t.Errorf("n=%d, want %d", n, len(serverResp))
			}

			caps, _ := parseServerCapabilities(resp, n)
			if caps.DualStackEnabled != dual {
				t.Errorf("DualStackEnabled=%v, want %v", caps.DualStackEnabled, dual)
			}
			if dual && (!caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6)) {
				t.Errorf("v6 addrs = %s/%s", caps.ServerIP6, caps.ClientIP6)
			}
		})
	}
}

// dripConn serves data one byte per Read, the worst case a TCP segment / TLS
// record / stego frame boundary can produce. Reads past the end block until
// the test's deadline, exactly like a server that has stopped talking.
func dripConn(t *testing.T, payload []byte) net.Conn {
	t.Helper()
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		for i := range payload {
			if _, err := srv.Write(payload[i : i+1]); err != nil {
				return
			}
		}
	}()
	return cli
}

// TestReadHandshakeResponseFragmented is the regression for a response split
// across reads. The old code took whatever the first Read returned: a
// dual-stack response split at the 9-byte boundary lost its flags byte, the
// v6 block stayed in the stream, and the packet loop that follows parsed it as
// [len:4][pkt:N] — a dead session. A legacy server must still not be waited on.
func TestReadHandshakeResponseFragmented(t *testing.T) {
	block, server6, client6 := dualBlock()
	base := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}

	t.Run("legacy 9-byte response, dual requested", func(t *testing.T) {
		// Nothing follows the 9 bytes: the read must complete on the grace
		// rather than block until the connect deadline.
		conn := dripConn(t, base)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		resp, n, err := readHandshakeResponse(conn, tunHandshakeVersionDualStack)
		if err != nil {
			t.Fatalf("readHandshakeResponse: %v", err)
		}
		if n != 9 {
			t.Fatalf("n = %d, want 9", n)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("legacy response took %v, want a bounded peek", elapsed)
		}
		if caps, ok := parseServerCapabilities(resp, n); ok || caps.DualStackEnabled {
			t.Errorf("legacy response must yield no caps: %+v ok=%v", caps, ok)
		}
	})

	t.Run("flags-only dual-stack response", func(t *testing.T) {
		full := append(append(append([]byte{}, base...), tunFlagMTUProbe|tunFlagDualStack), block...)
		conn := dripConn(t, full)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, n, err := readHandshakeResponse(conn, tunHandshakeVersionDualStack)
		if err != nil {
			t.Fatalf("readHandshakeResponse: %v", err)
		}
		if n != len(full) {
			t.Fatalf("n = %d, want %d", n, len(full))
		}
		caps, ok := parseServerCapabilities(resp, n)
		if !ok || !caps.DualStackEnabled {
			t.Fatalf("dual-stack not detected: %+v ok=%v", caps, ok)
		}
		if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
			t.Errorf("v6 addrs = %s/%s, want %s/%s", caps.ServerIP6, caps.ClientIP6, server6, client6)
		}
	})

	t.Run("port-hop v2 base with seed, then the dual block", func(t *testing.T) {
		// The seed length lives at resp[19], so the base has to be completed
		// before the block's offset is even knowable.
		mid := []byte{0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x01, 0x04, 's', 'e', 'e', 'd'}
		full := append(append(append(append([]byte{}, base...),
			tunFlagPortHopping|tunFlagMTUProbe|tunFlagDualStack), mid...), block...)
		conn := dripConn(t, full)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, n, err := readHandshakeResponse(conn, tunHandshakeVersionDualStack)
		if err != nil {
			t.Fatalf("readHandshakeResponse: %v", err)
		}
		if n != len(full) {
			t.Fatalf("n = %d, want %d", n, len(full))
		}
		caps, ok := parseServerCapabilities(resp, n)
		if !ok || !caps.DualStackEnabled || !caps.PortHoppingEnabled {
			t.Fatalf("caps wrong: %+v ok=%v", caps, ok)
		}
		if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
			t.Errorf("v6 addrs = %s/%s, want %s/%s", caps.ServerIP6, caps.ClientIP6, server6, client6)
		}
		if !bytes.Equal(caps.HopSeed, []byte("seed")) {
			t.Errorf("seed = %q, want %q", caps.HopSeed, "seed")
		}
		if caps.PortRangeStart != 47000 || caps.PortRangeEnd != 47100 {
			t.Errorf("port range = %d-%d, want 47000-47100", caps.PortRangeStart, caps.PortRangeEnd)
		}
	})

	t.Run("prefix split below 9 bytes still completes", func(t *testing.T) {
		conn := dripConn(t, base)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, n, err := readHandshakeResponse(conn, tunHandshakeVersion)
		if err != nil {
			t.Fatalf("readHandshakeResponse: %v", err)
		}
		if n != 9 {
			t.Errorf("n = %d, want 9 (the fixed prefix is always waited for)", n)
		}
	})

	t.Run("truncated prefix is an error, not a short read", func(t *testing.T) {
		conn := dripConn(t, base[:5])
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, n, err := readHandshakeResponse(conn, tunHandshakeVersion); err == nil {
			t.Errorf("expected an error for a 5-byte response, got n=%d", n)
		}
	})
}

// TestReadHandshakeResponseNoPeekWithoutDual pins the compatibility guarantee:
// a v0x03 client cannot be sent the dual-stack flag, so its read path must not
// grow an extra round trip. The scripted conn errors on any read past the
// first one, which is what proves it.
func TestReadHandshakeResponseNoPeekWithoutDual(t *testing.T) {
	conn := &scriptedConn{chunks: [][]byte{{0x00, 10, 8, 0, 1, 10, 8, 0, 2}}}
	_, n, err := readHandshakeResponse(conn, tunHandshakeVersion)
	if err != nil {
		t.Fatalf("readHandshakeResponse: %v", err)
	}
	if n != 9 {
		t.Errorf("n = %d, want 9", n)
	}
}

// TestResolveServerBypassIP6 covers the address the v6 bypass route is pinned
// for: only a literal IPv6 (with or without a port) qualifies, and an IPv4
// server address must not produce one — the v4 bypass already covers it.
func TestResolveServerBypassIP6(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want string
	}{
		{"", ""},
		{"[2001:db8::1]:995", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"1.2.3.4:995", ""},
		{"1.2.3.4", ""},
	} {
		got := resolveServerBypassIP6(tc.addr)
		if tc.want == "" {
			if got != nil {
				t.Errorf("resolveServerBypassIP6(%q) = %s, want nil", tc.addr, got)
			}
			continue
		}
		if got == nil || !got.Equal(net.ParseIP(tc.want)) {
			t.Errorf("resolveServerBypassIP6(%q) = %s, want %s", tc.addr, got, tc.want)
		}
	}
}

// TestServerBypassIP6Source pins which config field the v6 bypass is taken
// from. -server-v6 wins, but a v6 literal in -server has to work on its own:
// that is how an exit reachable only over IPv6 is configured in practice, and
// before this the bypass was silently skipped for it.
func TestServerBypassIP6Source(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    VPNConfig
		want   string
		wantIs bool
	}{
		{"v6 only in -server", VPNConfig{ServerAddr: "[2001:db8::1]:997"}, "2001:db8::1", true},
		{"v6 only in -server-v6", VPNConfig{ServerAddrV6: "[2001:db8::2]:995"}, "2001:db8::2", true},
		{"both set, -server-v6 wins", VPNConfig{
			ServerAddr:   "[2001:db8::1]:997",
			ServerAddrV6: "[2001:db8::2]:995",
		}, "2001:db8::2", true},
		{"v4 server, no v6 anywhere", VPNConfig{ServerAddr: "1.2.3.4:995"}, "", false},
		{"nothing configured", VPNConfig{}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := serverBypassIP6(tc.cfg)
			if !tc.wantIs {
				if got != nil {
					t.Fatalf("serverBypassIP6 = %s, want nil", got)
				}
				return
			}
			if got == nil || !got.Equal(net.ParseIP(tc.want)) {
				t.Fatalf("serverBypassIP6 = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestHandshakeRequestVersionByte checks the request bytes written by
// doHandshake: still 8 bytes, only the version byte changes.
func TestHandshakeRequestVersionByte(t *testing.T) {
	for _, dual := range []bool{false, true} {
		conn := &scriptedConn{chunks: [][]byte{{0x00, 10, 8, 0, 1, 10, 8, 0, 2}}}
		v := &VPNClient{tun: &TUNDevice{mtu: 1280}, ipv6Policy: dualPolicy(dual)}
		if _, _, err := v.doHandshake(conn, net.IPv4(10, 8, 0, 2)); err != nil {
			t.Fatalf("doHandshake: %v", err)
		}
		want := byte(tunHandshakeVersion)
		if dual {
			want = tunHandshakeVersionDualStack
		}
		if len(conn.written) != 8 {
			t.Fatalf("dual=%v: wrote %d handshake bytes, want 8", dual, len(conn.written))
		}
		if conn.written[0] != 0x02 || conn.written[7] != want {
			t.Errorf("dual=%v: handshake = %x, want mode=0x02 version=0x%02x", dual, conn.written, want)
		}
		if got := binary.BigEndian.Uint16(conn.written[5:7]); got != 1280 {
			t.Errorf("mtu field = %d, want 1280", got)
		}
	}
}
