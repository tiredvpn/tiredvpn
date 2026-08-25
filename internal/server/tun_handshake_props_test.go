package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// TestBuildTUNHandshakeResponseSeedTruncation pins the 32-byte ceiling on the
// port-hop seed. The seed length is announced in a single byte (resp[19]) and
// the client reads exactly that many bytes, so a seed longer than 32 must be
// truncated here rather than announced in full: an over-long seed would either
// overflow the length byte or leave the client reading seed bytes as tunnel
// traffic.
func TestBuildTUNHandshakeResponseSeedTruncation(t *testing.T) {
	tests := []struct {
		name       string
		seed       []byte
		wantSeed   []byte
		wantRespLn int
	}{
		{"no seed", nil, []byte{}, 20},
		{"short seed", []byte("abc"), []byte("abc"), 23},
		{"seed exactly 32", bytes.Repeat([]byte{0xAA}, 32), bytes.Repeat([]byte{0xAA}, 32), 52},
		{"seed 33 truncated to 32", bytes.Repeat([]byte{0xBB}, 33), bytes.Repeat([]byte{0xBB}, 32), 52},
		{"seed 200 truncated to 32", bytes.Repeat([]byte{0xCC}, 200), bytes.Repeat([]byte{0xCC}, 32), 52},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := portHopCaps()
			caps.hopSeed = tt.seed
			got := buildTUNHandshakeResponse(0x02, hsServerIP, hsClientIP, caps, nil)

			if len(got) != tt.wantRespLn {
				t.Fatalf("len = %d, want %d (%x)", len(got), tt.wantRespLn, got)
			}
			if int(got[19]) != len(tt.wantSeed) {
				t.Errorf("announced seedLen = %d, want %d", got[19], len(tt.wantSeed))
			}
			if !bytes.Equal(got[20:], tt.wantSeed) {
				t.Errorf("seed = %x, want %x", got[20:], tt.wantSeed)
			}
			// The announced length must match what actually follows, or the
			// client desyncs on the first tunnel packet.
			if 20+int(got[19]) != len(got) {
				t.Errorf("announced seedLen %d does not account for the %d trailing bytes", got[19], len(got)-20)
			}
		})
	}

	// A caller's slice must not be aliased or mutated by the truncation.
	seed := bytes.Repeat([]byte{0xDD}, 40)
	caps := portHopCaps()
	caps.hopSeed = seed
	buildTUNHandshakeResponse(0x02, hsServerIP, hsClientIP, caps, nil)
	if len(seed) != 40 {
		t.Errorf("caller seed was resized to %d bytes", len(seed))
	}
}

// TestBuildTUNHandshakeResponseHopIntervalDefault pins the 60-second fallback.
// A zero or negative interval on the wire would make the client hop
// continuously (or never), so an unset config value must be normalised here.
func TestBuildTUNHandshakeResponseHopIntervalDefault(t *testing.T) {
	tests := []struct {
		name     string
		interval int
		want     uint32
	}{
		{"zero defaults to 60", 0, 60},
		{"negative defaults to 60", -1, 60},
		{"large negative defaults to 60", -86400, 60},
		{"one is honored", 1, 1},
		{"explicit 60", 60, 60},
		{"explicit 3600", 3600, 3600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := portHopCaps()
			caps.hopInterval = tt.interval
			got := buildTUNHandshakeResponse(0x02, hsServerIP, hsClientIP, caps, nil)
			if len(got) < 18 {
				t.Fatalf("response too short for the interval field: %x", got)
			}
			if iv := binary.BigEndian.Uint32(got[14:18]); iv != tt.want {
				t.Errorf("hopInterval on the wire = %d, want %d", iv, tt.want)
			}
		})
	}
}

// TestBuildTUNHandshakeResponseHopStrategyByte checks that every strategy byte
// reaches the wire verbatim, including values this server does not produce: the
// field is a passthrough, and silently rewriting it would make a future
// strategy undeployable without a server release.
func TestBuildTUNHandshakeResponseHopStrategyByte(t *testing.T) {
	for _, strategy := range []byte{0x00, 0x01, 0x02, 0x03, 0xff} {
		caps := portHopCaps()
		caps.hopStrategy = strategy
		got := buildTUNHandshakeResponse(0x02, hsServerIP, hsClientIP, caps, nil)
		if len(got) < 19 {
			t.Fatalf("strategy 0x%02x: response too short: %x", strategy, got)
		}
		if got[18] != strategy {
			t.Errorf("strategy on the wire = 0x%02x, want 0x%02x", got[18], strategy)
		}
	}
}

// TestPortHopStrategyByte pins the name -> wire-byte mapping. The client keys
// its hop schedule off this byte, so a rename on either side desynchronises the
// two ends onto different port sequences.
func TestPortHopStrategyByte(t *testing.T) {
	tests := []struct {
		name string
		want byte
	}{
		{"sequential", 0x01},
		{"fibonacci", 0x02},
		{"random", 0x00},
		{"", 0x00},        // unset config -> random
		{"Random", 0x00},  // matching is case-sensitive; anything unknown is random
		{"bogus", 0x00},   // unknown name must not pick a real strategy
		{"SEQUENTIAL", 0}, // ditto, uppercase is not the configured spelling
	}

	for _, tt := range tests {
		t.Run("strategy="+tt.name, func(t *testing.T) {
			if got := portHopStrategyByte(tt.name); got != tt.want {
				t.Errorf("portHopStrategyByte(%q) = 0x%02x, want 0x%02x", tt.name, got, tt.want)
			}
		})
	}
}

// TestBuildTUNHandshakeResponseCapsMatrix walks every capability combination on
// every client version and pins the exact response length and flags byte. It is
// the compact form of the golden test: a change to the layout rules for any one
// cell shows up here as a length or flag mismatch.
func TestBuildTUNHandshakeResponseCapsMatrix(t *testing.T) {
	capsCases := []struct {
		name string
		caps tunHandshakeCaps
	}{
		{"none", tunHandshakeCaps{}},
		{"probe", tunHandshakeCaps{mtuProbe: true}},
		{"hop", tunHandshakeCaps{portHopping: true, portStart: 47000, portEnd: 47100, hopInterval: 60}},
		{"hop+probe", portHopCaps()},
	}

	// wantLen/wantFlags indexed by [capsCase][version 0x00..0x04].
	wantLen := map[string][5]int{
		"none":      {9, 9, 9, 9, 10},
		"probe":     {9, 9, 9, 10, 10},
		"hop":       {9, 14, 20, 20, 20},
		"hop+probe": {9, 14, 20, 20, 20},
	}
	wantFlags := map[string][5]byte{
		"none":      {0, 0, 0, 0, 0x00},
		"probe":     {0, 0, 0, 0x02, 0x02},
		"hop":       {0, 0x01, 0x01, 0x01, 0x01},
		"hop+probe": {0, 0x01, 0x01, 0x03, 0x03},
	}

	for _, cc := range capsCases {
		for version := byte(0x00); version <= 0x04; version++ {
			t.Run(cc.name+"/v"+string(rune('0'+version)), func(t *testing.T) {
				got := buildTUNHandshakeResponse(version, hsServerIP, hsClientIP, cc.caps, nil)
				if len(got) != wantLen[cc.name][version] {
					t.Fatalf("len = %d, want %d (%x)", len(got), wantLen[cc.name][version], got)
				}
				if len(got) >= 10 && got[9] != wantFlags[cc.name][version] {
					t.Errorf("flags = 0x%02x, want 0x%02x", got[9], wantFlags[cc.name][version])
				}
				// The 9-byte prefix is invariant across every cell.
				if !bytes.Equal(got[:9], []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}) {
					t.Errorf("base prefix = %x, want the unchanged 9-byte form", got[:9])
				}
			})
		}
	}
}

// TestBuildTUNHandshakeResponseWireStableBelowV4 is the wire-compatibility
// property: for every client below version 0x04, and across the whole caps
// matrix, whether the server has an IPv6 pool configured must not change a
// single byte of the response. Deployed clients parse fixed offsets off these
// bytes; one extra flag bit or trailing byte and they read tunnel traffic as
// handshake, so this is the check that lets a dual-stack server be rolled out
// under an unchanged client fleet.
func TestBuildTUNHandshakeResponseWireStableBelowV4(t *testing.T) {
	dual := dualTestAddrs()

	capsMatrix := []tunHandshakeCaps{
		{},
		{mtuProbe: true},
		{portHopping: true, portStart: 47000, portEnd: 47100},
		{portHopping: true, portStart: 1, portEnd: 65535, hopInterval: -5, hopStrategy: 0xff},
		portHopCaps(),
		func() tunHandshakeCaps {
			c := portHopCaps()
			c.hopSeed = bytes.Repeat([]byte{0x5A}, 40)
			return c
		}(),
		func() tunHandshakeCaps {
			c := portHopCaps()
			c.hopStrategy = 0x02
			c.hopInterval = 7
			c.hopSeed = []byte("seed")
			return c
		}(),
	}

	// Several distinct pools, including the /96 edge, so the property does not
	// accidentally hold only for one prefix shape.
	pools := []*dualStackAddrs{
		dual,
		{ServerIP6: net.ParseIP("fc00::1"), ClientIP6: net.ParseIP("fc00::a08:2")},
		{ServerIP6: net.ParseIP("fdff:ffff:ffff:ffff::1"), ClientIP6: net.ParseIP("fdff:ffff:ffff:ffff::a08:2")},
	}

	for version := byte(0x00); version < tunClientVersionDualStack; version++ {
		for i, caps := range capsMatrix {
			without := buildTUNHandshakeResponse(version, hsServerIP, hsClientIP, caps, nil)
			for j, pool := range pools {
				with := buildTUNHandshakeResponse(version, hsServerIP, hsClientIP, caps, pool)
				if !bytes.Equal(with, without) {
					t.Fatalf("version 0x%02x caps[%d] pool[%d]: dual-stack pool changed the wire bytes: %x vs %x",
						version, i, j, with, without)
				}
				// Belt and braces: no flag bit and no trailing block can appear.
				if len(with) >= 10 && with[9]&0x04 != 0 {
					t.Fatalf("version 0x%02x caps[%d]: dual-stack flag leaked to a pre-v4 client: 0x%02x",
						version, i, with[9])
				}
			}
		}
	}
}

// TestDeriveDualStackAddrsDegradesToV4Only covers the seam's failure modes: any
// pool it cannot use must yield nil (session stays IPv4-only) instead of
// panicking or handing out an address from the wrong space.
func TestDeriveDualStackAddrsDegradesToV4Only(t *testing.T) {
	tests := []struct {
		name     string
		pool     string
		clientIP net.IP
	}{
		{"empty pool", "", hsClientIP},
		{"whitespace pool", " ", hsClientIP},
		{"missing prefix length", "fd00:10:8::", hsClientIP},
		{"prefix length /97 leaves <32 host bits", "fd00:10:8::/97", hsClientIP},
		{"prefix length /128", "fd00:10:8::1/128", hsClientIP},
		{"out-of-range prefix length", "fd00:10:8::/129", hsClientIP},
		{"IPv4 CIDR", "10.8.0.0/24", hsClientIP},
		{"IPv4-mapped CIDR", "::ffff:10.8.0.0/120", hsClientIP},
		{"garbage", "\x00\xff not a cidr", hsClientIP},
		{"nil client IP", "fd00:10:8::/64", nil},
		{"empty client IP", "fd00:10:8::/64", net.IP{}},
		{"IPv6 client lease", "fd00:10:8::/64", net.ParseIP("fd00:10:8::5")},
		{"reserved lease 0.0.0.0", "fd00:10:8::/64", net.IPv4zero},
		{"reserved lease 0.0.0.1", "fd00:10:8::/64", net.IPv4(0, 0, 0, 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("deriveDualStackAddrs panicked: %v", r)
				}
			}()
			if d := deriveDualStackAddrs(tt.pool, tt.clientIP); d != nil {
				t.Errorf("got %+v, want nil (session must degrade to IPv4-only)", d)
			}
		})
	}

	// The /96 edge is the shortest prefix that still fits a 32-bit host part,
	// so it must derive rather than degrade.
	if d := deriveDualStackAddrs("fd00:10:8:1:2:3::/96", hsClientIP); d == nil {
		t.Error("/96 pool should derive addresses, got nil")
	} else if got, want := d.ClientIP6.String(), "fd00:10:8:1:2:3:a08:2"; got != want {
		t.Errorf("/96 ClientIP6 = %s, want %s", got, want)
	}
}

// TestValidateIPPoolV6 covers the flag-parsing wrapper cmd calls. An empty
// value means "no dual-stack" and must not be an error, and every rejection has
// to name its reason: this message is the only thing an operator sees when the
// server refuses to boot.
func TestValidateIPPoolV6(t *testing.T) {
	if err := ValidateIPPoolV6(""); err != nil {
		t.Errorf("empty -ip-pool-v6 must be valid (means no dual-stack), got %v", err)
	}
	for _, ok := range []string{"fd00:10:8::/64", "fc00::/7", "fdff:ffff::/32", "fd00:10:8:1:2:3::/96"} {
		if err := ValidateIPPoolV6(ok); err != nil {
			t.Errorf("ValidateIPPoolV6(%q) = %v, want nil", ok, err)
		}
	}

	tests := []struct {
		cidr       string
		wantReason string
	}{
		{"fd00:10:8::/97", "host bits"},
		{"fd00:10:8::/128", "host bits"},
		{"2001:db8::/64", "Unique Local Address"},
		{"fe80::/64", "Unique Local Address"},
		{"ff00::/8", "Unique Local Address"},
		{"::/64", "Unique Local Address"},
		{"10.8.0.0/24", "not an IPv6 CIDR"},
		{"not-a-cidr", "invalid IPv6 pool"},
		{"fd00:10:8::", "invalid IPv6 pool"},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			err := ValidateIPPoolV6(tt.cidr)
			if err == nil {
				t.Fatalf("ValidateIPPoolV6(%q) = nil, want an error", tt.cidr)
			}
			if !strings.Contains(err.Error(), tt.wantReason) {
				t.Errorf("error %q does not state the reason %q", err, tt.wantReason)
			}
			// The offending value has to appear, or the operator cannot tell
			// which flag was rejected.
			if !strings.Contains(err.Error(), tt.cidr) {
				t.Errorf("error %q does not quote the rejected value %q", err, tt.cidr)
			}
		})
	}
}

// TestDownstreamDualStackAddrsPartialRelayBlock covers a relay whose exit set
// the dual-stack flag but delivered only half the address block. Answering the
// downstream client with a half-filled pair would put it on an address the exit
// never assigned, so the relay must fall back to IPv4-only — and must not
// substitute its own pool, which routes nowhere from the exit.
func TestDownstreamDualStackAddrsPartialRelayBlock(t *testing.T) {
	tests := []struct {
		name string
		sink *relayTUNSink
	}{
		{"neither address", &relayTUNSink{}},
		{"server address only", &relayTUNSink{serverIP6: exitServerIP6}},
		{"client address only", &relayTUNSink{clientIP6: exitClientIP6}},
		{"empty (non-nil) addresses", &relayTUNSink{serverIP6: net.IP{}, clientIP6: net.IP{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := downstreamDualStackAddrs(tt.sink, "fd00:10:8::/64", hsClientIP); d != nil {
				t.Errorf("got %+v, want nil (relay must never answer from its own pool)", d)
			}
		})
	}
}

// TestFrameConfusionTUNResponseLengthPrefix pins the confusion framing across
// every payload size the builder can produce: the length prefix must always
// describe exactly the bytes that follow, since the client slices the frame by
// that number before parsing the handshake.
func TestFrameConfusionTUNResponseLengthPrefix(t *testing.T) {
	payloads := [][]byte{
		nil,
		{},
		buildTUNHandshakeResponse(0x00, hsServerIP, hsClientIP, tunHandshakeCaps{}, nil),
		buildTUNHandshakeResponse(0x04, hsServerIP, hsClientIP, tunHandshakeCaps{}, nil),
		buildTUNHandshakeResponse(0x04, hsServerIP, hsClientIP, portHopCaps(), dualTestAddrs()),
	}

	for i, payload := range payloads {
		frame := frameConfusionTUNResponse(payload)
		if len(frame) != 4+len(payload) {
			t.Errorf("payload %d: frame = %d bytes, want %d", i, len(frame), 4+len(payload))
		}
		if n := binary.BigEndian.Uint32(frame[:4]); int(n) != len(payload) {
			t.Errorf("payload %d: length prefix = %d, want %d", i, n, len(payload))
		}
		if !bytes.Equal(frame[4:], payload) {
			t.Errorf("payload %d: body = %x, want %x", i, frame[4:], payload)
		}
	}
}
