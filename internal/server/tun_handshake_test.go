package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

var (
	hsServerIP = net.IPv4(10, 8, 0, 1)
	hsClientIP = net.IPv4(10, 8, 0, 2)
)

// portHopCaps returns the caps handleTUNModeCore derives from a typical
// port-hopping config: range 47000-47100, default interval, random strategy.
func portHopCaps() tunHandshakeCaps {
	return tunHandshakeCaps{
		portHopping: true,
		portStart:   47000,
		portEnd:     47100,
		hopInterval: 60,
		hopStrategy: 0x00,
		mtuProbe:    true,
	}
}

// TestBuildTUNHandshakeResponseGolden pins the exact response bytes the
// pre-refactor inline code emitted for every version variant. These
// expectations were characterized from the old handleTUNModeCore /
// handleMorphTUNMode / handleConfusionTUNMode / setupH2TUNTunnel /
// runPollingTUNMode response builders; the refactor into
// buildTUNHandshakeResponse must not change a single byte for version < 0x04
// or when dual-stack is not configured.
func TestBuildTUNHandshakeResponseGolden(t *testing.T) {
	base := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2} // [status][serverIP][clientIP]

	tests := []struct {
		name    string
		version byte
		caps    tunHandshakeCaps
		want    []byte
	}{
		{
			name:    "legacy v0 client, caps configured",
			version: 0x00,
			caps:    portHopCaps(),
			want:    base,
		},
		{
			name:    "v1 client with port hopping",
			version: 0x01,
			caps:    portHopCaps(),
			want: append(append([]byte{}, base...),
				0x01,       // flags: port hopping (no probe bit for v1)
				0xb7, 0x98, // portStart = 47000
				0xb7, 0xfc, // portEnd = 47100
			),
		},
		{
			name:    "v2 client with port hopping",
			version: 0x02,
			caps:    portHopCaps(),
			want: append(append([]byte{}, base...),
				0x01, // flags: port hopping (no probe bit for v2)
				0xb7, 0x98, 0xb7, 0xfc,
				0x00, 0x00, 0x00, 0x3c, // hopInterval = 60
				0x00, // strategy = random
				0x00, // seedLen = 0
			),
		},
		{
			name:    "v2 client with port hopping and seed",
			version: 0x02,
			caps: func() tunHandshakeCaps {
				c := portHopCaps()
				c.hopSeed = []byte("abc")
				return c
			}(),
			want: append(append([]byte{}, base...),
				0x01,
				0xb7, 0x98, 0xb7, 0xfc,
				0x00, 0x00, 0x00, 0x3c,
				0x00,
				0x03, 'a', 'b', 'c', // seedLen=3 + seed
			),
		},
		{
			name:    "v3 client with port hopping",
			version: 0x03,
			caps:    portHopCaps(),
			want: append(append([]byte{}, base...),
				0x03, // flags: port hopping | MTU probe
				0xb7, 0x98, 0xb7, 0xfc,
				0x00, 0x00, 0x00, 0x3c,
				0x00,
				0x00,
			),
		},
		{
			name:    "v3 client, no port hopping (flags-only 10-byte form)",
			version: 0x03,
			caps:    tunHandshakeCaps{mtuProbe: true},
			want:    append(append([]byte{}, base...), 0x02),
		},
		{
			name:    "v2 client, no port hopping (probe not advertised below v3)",
			version: 0x02,
			caps:    tunHandshakeCaps{mtuProbe: true},
			want:    base,
		},
		{
			name:    "v3 client, morph/h2/polling shape (no caps passed)",
			version: 0x03,
			caps:    tunHandshakeCaps{},
			want:    base,
		},
		{
			// Compatibility (b): a v0x04 client talking to a server without
			// dual-stack configured gets exactly what the old code emitted for
			// version >= 0x03 (treated as v3): probe flag only, no dual bit.
			name:    "v4 client, dual-stack NOT configured",
			version: 0x04,
			caps:    tunHandshakeCaps{mtuProbe: true},
			want:    append(append([]byte{}, base...), 0x02),
		},
		{
			name:    "v4 client, port hopping, dual-stack NOT configured",
			version: 0x04,
			caps:    portHopCaps(),
			want: append(append([]byte{}, base...),
				0x03,
				0xb7, 0x98, 0xb7, 0xfc,
				0x00, 0x00, 0x00, 0x3c,
				0x00,
				0x00,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTUNHandshakeResponse(tt.version, hsServerIP, hsClientIP, tt.caps, nil)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("buildTUNHandshakeResponse(0x%02x) = %x, want %x", tt.version, got, tt.want)
			}
		})
	}
}

// dualTestAddrs returns deterministic v6 addresses for the round-trip tests.
func dualTestAddrs() *dualStackAddrs {
	return &dualStackAddrs{
		ServerIP6: net.ParseIP("fd00:10:8::1"),
		ClientIP6: net.ParseIP("fd00:10:8::a08:2"),
	}
}

// TestBuildTUNHandshakeResponseDualStack covers the v0x04 negotiation: flag
// bit plus the trailing 32-byte [serverIP6:16][clientIP6:16] block, on every
// payload shape the six transports emit.
func TestBuildTUNHandshakeResponseDualStack(t *testing.T) {
	dual := dualTestAddrs()
	wantBlock := make([]byte, 32)
	copy(wantBlock[0:16], dual.ServerIP6.To16())
	copy(wantBlock[16:32], dual.ClientIP6.To16())

	tests := []struct {
		name     string
		version  byte
		caps     tunHandshakeCaps
		wantLen  int
		wantFlag byte
	}{
		// morph / h2 / polling / confusion payload shape: no caps, so a v4
		// client gets the 10-byte flags-only form + 32-byte block.
		{"transport payload (morph/h2/polling/confusion)", 0x04, tunHandshakeCaps{}, 42, 0x04},
		// raw TLS / QUIC (handleTUNModeCore), no port hopping: probe + dual.
		{"core, no port hopping", 0x04, tunHandshakeCaps{mtuProbe: true}, 42, 0x06},
		// raw TLS / QUIC with port hopping: v2 form (20+seed) + block.
		{"core, port hopping", 0x04, portHopCaps(), 52, 0x07},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTUNHandshakeResponse(tt.version, hsServerIP, hsClientIP, tt.caps, dual)
			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d (%x)", len(got), tt.wantLen, got)
			}
			if got[0] != 0x00 {
				t.Errorf("status = 0x%02x, want 0x00", got[0])
			}
			if !bytes.Equal(got[1:5], hsServerIP.To4()) || !bytes.Equal(got[5:9], hsClientIP.To4()) {
				t.Errorf("v4 addresses wrong: %x", got[1:9])
			}
			if got[9] != tt.wantFlag {
				t.Errorf("flags = 0x%02x, want 0x%02x", got[9], tt.wantFlag)
			}
			if !bytes.Equal(got[tt.wantLen-32:], wantBlock) {
				t.Errorf("v6 block = %x, want %x", got[tt.wantLen-32:], wantBlock)
			}
		})
	}

	// Dual configured but client below v0x04: byte-identical to the golden
	// non-dual output (no flag, no block).
	for _, version := range []byte{0x00, 0x01, 0x02, 0x03} {
		withDual := buildTUNHandshakeResponse(version, hsServerIP, hsClientIP, portHopCaps(), dual)
		without := buildTUNHandshakeResponse(version, hsServerIP, hsClientIP, portHopCaps(), nil)
		if !bytes.Equal(withDual, without) {
			t.Errorf("version 0x%02x: dual-configured server must not alter the response: %x vs %x",
				version, withDual, without)
		}
	}
}

// TestBuildTUNHandshakeResponseV4AlwaysHasFlags pins the rule the client's
// fixed 10-byte prefix read depends on: a v0x04 client always gets the flags
// byte, even on a server with no IPv6 pool and no other capability, so the
// client never has to stop at 9 bytes and wait to see whether a tenth arrives.
// Clients below 0x04 keep the bare 9-byte form.
func TestBuildTUNHandshakeResponseV4AlwaysHasFlags(t *testing.T) {
	got := buildTUNHandshakeResponse(0x04, hsServerIP, hsClientIP, tunHandshakeCaps{}, nil)
	if len(got) != 10 {
		t.Fatalf("v0x04 with no caps and no pool: len = %d, want 10 (%x)", len(got), got)
	}
	if got[9] != 0x00 {
		t.Errorf("flags = 0x%02x, want 0x00", got[9])
	}
	if !bytes.Equal(got[:9], []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}) {
		t.Errorf("base = %x, want the unchanged 9-byte prefix", got[:9])
	}

	for _, version := range []byte{0x00, 0x01, 0x02, 0x03} {
		bare := buildTUNHandshakeResponse(version, hsServerIP, hsClientIP, tunHandshakeCaps{}, nil)
		if len(bare) != 9 {
			t.Errorf("version 0x%02x: len = %d, want 9 (%x)", version, len(bare), bare)
		}
	}
}

// TestDeriveDualStackAddrs covers the Phase-1 placeholder address derivation
// from the -ip-pool-v6 prefix.
func TestDeriveDualStackAddrs(t *testing.T) {
	d := deriveDualStackAddrs("fd00:10:8::/64", hsClientIP)
	if d == nil {
		t.Fatal("expected addresses for a valid v6 pool")
	}
	if got := d.ServerIP6.String(); got != "fd00:10:8::1" {
		t.Errorf("ServerIP6 = %s, want fd00:10:8::1", got)
	}
	if got := d.ClientIP6.String(); got != "fd00:10:8::a08:2" {
		t.Errorf("ClientIP6 = %s, want fd00:10:8::a08:2 (prefix | client v4)", got)
	}

	if d := deriveDualStackAddrs("", hsClientIP); d != nil {
		t.Errorf("empty pool should yield nil, got %+v", d)
	}
	if d := deriveDualStackAddrs("not-a-cidr", hsClientIP); d != nil {
		t.Errorf("invalid CIDR should yield nil, got %+v", d)
	}
	if d := deriveDualStackAddrs("10.8.0.0/24", hsClientIP); d != nil {
		t.Errorf("IPv4 CIDR should yield nil, got %+v", d)
	}

	// Non-ULA prefixes are rejected by the pool parser, so the handshake seam
	// must degrade the session to IPv4-only rather than advertise addresses
	// out of somebody else's space.
	for _, bad := range []string{"2001:db8:1::/64", "fe80::/64", "ff00::/8", "::/64"} {
		if d := deriveDualStackAddrs(bad, hsClientIP); d != nil {
			t.Errorf("non-ULA pool %q should yield nil, got %+v", bad, d)
		}
	}

	// A lease whose derivation is reserved (prefix::1 is the server's own
	// address) yields no block either: better IPv4-only than two peers on one
	// address.
	if d := deriveDualStackAddrs("fd00:10:8::/64", net.IPv4(0, 0, 0, 1)); d != nil {
		t.Errorf("reserved derivation should yield nil, got %+v", d)
	}
	if d := deriveDualStackAddrs("fd00:10:8::/64", nil); d != nil {
		t.Errorf("nil lease should yield nil, got %+v", d)
	}
}

// TestFrameConfusionTUNResponse pins the confusion transport's shifted
// framing: [len:4][payload], historically a 13-byte frame for the legacy
// 9-byte payload with serverIP@5:9 and clientIP@9:13.
func TestFrameConfusionTUNResponse(t *testing.T) {
	// Legacy payload -> 13-byte frame with the historical offsets.
	legacy := buildTUNHandshakeResponse(0x03, hsServerIP, hsClientIP, tunHandshakeCaps{}, nil)
	frame := frameConfusionTUNResponse(legacy)
	if len(frame) != 13 {
		t.Fatalf("legacy confusion frame = %d bytes, want 13", len(frame))
	}
	if binary.BigEndian.Uint32(frame[0:4]) != 9 {
		t.Errorf("frame length prefix = %d, want 9", binary.BigEndian.Uint32(frame[0:4]))
	}
	if frame[4] != 0x00 {
		t.Errorf("status = 0x%02x, want 0x00", frame[4])
	}
	if !bytes.Equal(frame[5:9], hsServerIP.To4()) {
		t.Errorf("serverIP@5:9 = %x, want %x", frame[5:9], hsServerIP.To4())
	}
	if !bytes.Equal(frame[9:13], hsClientIP.To4()) {
		t.Errorf("clientIP@9:13 = %x, want %x", frame[9:13], hsClientIP.To4())
	}

	// v0x04 dual payload -> 46-byte frame, length prefix tracks the payload.
	dualFrame := frameConfusionTUNResponse(
		buildTUNHandshakeResponse(0x04, hsServerIP, hsClientIP, tunHandshakeCaps{}, dualTestAddrs()))
	if len(dualFrame) != 46 {
		t.Fatalf("dual confusion frame = %d bytes, want 46", len(dualFrame))
	}
	if binary.BigEndian.Uint32(dualFrame[0:4]) != 42 {
		t.Errorf("frame length prefix = %d, want 42", binary.BigEndian.Uint32(dualFrame[0:4]))
	}
	if dualFrame[13]&0x04 == 0 {
		t.Errorf("dual-stack flag missing at payload flags byte (frame[13]): 0x%02x", dualFrame[13])
	}
}
