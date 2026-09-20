package geneva

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// testOverlapNonceLen is the nonce prefix length used by the test markers,
// matching the production layout ([nonce:8][HMAC:24]).
const testOverlapNonceLen = 8

var testOverlapSalt = []byte("test-overlap-salt")

// testMarkerFromNonce derives a self-describing [nonce||HMAC(secret,salt||nonce)]
// marker, the same layout the client uses. Shared by the minter and the verifier
// so the two agree.
func testMarkerFromNonce(secret, nonce []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(testOverlapSalt)
	mac.Write(nonce)
	tag := mac.Sum(nil)
	out := make([]byte, 0, OverlapMarkerLen)
	out = append(out, nonce...)
	out = append(out, tag[:OverlapMarkerLen-testOverlapNonceLen]...)
	return out
}

// testMintFn returns a minter that produces a fresh per-call marker under secret.
func testMintFn(secret []byte) func() []byte {
	return func() []byte {
		nonce := make([]byte, testOverlapNonceLen)
		_, _ = cryptorand.Read(nonce)
		return testMarkerFromNonce(secret, nonce)
	}
}

// createClientHelloPacketPort is createClientHelloPacket with a configurable
// source port, so distinct connections (distinct 4-tuples) can be built.
func createClientHelloPacketPort(seq uint32, payloadLen int, srcPort uint16) []byte {
	packet := createClientHelloPacket(seq, payloadLen)
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	recalculateIPChecksum(packet)
	recalculateTCPChecksum(packet)
	return packet
}

// createClientHelloPacket builds a TCP data segment whose payload looks like a
// TLS ClientHello record, for exercising OverlapPrimitive.
func createClientHelloPacket(seq uint32, payloadLen int) []byte {
	const hdr = 40 // 20 IP + 20 TCP
	packet := make([]byte, hdr+payloadLen)

	// IP header
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64 // TTL
	packet[9] = 6  // TCP
	packet[12], packet[13], packet[14], packet[15] = 10, 0, 0, 1
	packet[16], packet[17], packet[18], packet[19] = 10, 0, 0, 2

	// TCP header
	binary.BigEndian.PutUint16(packet[20:22], 40000) // src port
	binary.BigEndian.PutUint16(packet[22:24], 995)   // dst port
	binary.BigEndian.PutUint32(packet[24:28], seq)
	packet[32] = 0x50 // data offset 5
	packet[33] = TCPFlagPSH | TCPFlagACK
	binary.BigEndian.PutUint16(packet[34:36], 65535)

	// Payload: TLS handshake record header (0x16 0x03 0x03 ...) then filler.
	if payloadLen >= 3 {
		packet[40] = 0x16
		packet[41] = 0x03
		packet[42] = 0x03
	}
	for i := 43; i < len(packet); i++ {
		packet[i] = byte(i)
	}

	recalculateIPChecksum(packet)
	recalculateTCPChecksum(packet)
	return packet
}

// ipChecksumValid reports whether the IPv4 header checksum verifies to 0xFFFF.
func ipChecksumValid(packet []byte) bool {
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	var sum uint32
	for i := 0; i < ipHeaderLen; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return sum == 0xFFFF
}

// tcpChecksumValid reports whether the TCP checksum verifies to 0xFFFF.
func tcpChecksumValid(packet []byte) bool {
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	tcpStart := ipHeaderLen
	tcpLen := len(packet) - tcpStart

	var sum uint32
	for i := 12; i < 20; i += 2 { // pseudo-header addresses
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	sum += 6 // proto
	sum += uint32(tcpLen)
	for i := tcpStart; i+1 < len(packet); i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if (len(packet)-tcpStart)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return sum == 0xFFFF
}

func TestOverlapPrimitiveGeometry(t *testing.T) {
	marker := bytes.Repeat([]byte{0xAB}, OverlapMarkerLen)
	const realSeq = uint32(100000)

	tests := []struct {
		name       string
		overlapLen int
		fakeLen    int
		junk       byte
	}{
		{"safe_equal", 64, 64, 0x00},
		{"safe_min", OverlapMarkerLen, OverlapMarkerLen, 0x5A},
		{"aggressive_larger", 48, 120, 0xFF},
		{"default_fakelen", 80, 0, 0x11}, // FakeLen 0 => defaults to OverlapLen
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prim := &OverlapPrimitive{
				OverlapLen: tt.overlapLen,
				FakeLen:    tt.fakeLen,
				Marker:     marker,
				JunkByte:   tt.junk,
			}
			packet := createClientHelloPacket(realSeq, 300)

			out, err := prim.Apply(packet)
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			if len(out) != 2 {
				t.Fatalf("Apply() returned %d packets, want 2 (fake, real)", len(out))
			}
			fake, realOut := out[0], out[1]

			// Fake must precede the real segment: check ordering by seq.
			wantFakeSeq := realSeq - uint32(tt.overlapLen)
			gotFakeSeq := binary.BigEndian.Uint32(fake[24:28])
			if gotFakeSeq != wantFakeSeq {
				t.Errorf("fake seq = %d, want %d (real %d backed up by %d)",
					gotFakeSeq, wantFakeSeq, realSeq, tt.overlapLen)
			}

			// Real segment must be unchanged.
			if !bytes.Equal(realOut, packet) {
				t.Errorf("real segment was modified")
			}
			if got := binary.BigEndian.Uint32(realOut[24:28]); got != realSeq {
				t.Errorf("real seq = %d, want %d", got, realSeq)
			}

			// Fake payload length and IP total length.
			wantFakeLen := tt.fakeLen
			if wantFakeLen <= 0 {
				wantFakeLen = tt.overlapLen
			}
			if wantFakeLen < len(marker) {
				wantFakeLen = len(marker)
			}
			if got := len(fake) - 40; got != wantFakeLen {
				t.Errorf("fake payload len = %d, want %d", got, wantFakeLen)
			}
			if got := int(binary.BigEndian.Uint16(fake[2:4])); got != len(fake) {
				t.Errorf("fake IP total length = %d, want %d", got, len(fake))
			}

			// Checksums must verify.
			if !ipChecksumValid(fake) {
				t.Errorf("fake IP checksum invalid")
			}
			if !tcpChecksumValid(fake) {
				t.Errorf("fake TCP checksum invalid")
			}

			// Marker present at payload start; junk fills the remainder.
			fakePayload := fake[40:]
			if !OverlapPayloadHasMarker(fakePayload, marker) {
				t.Errorf("fake payload does not carry the marker")
			}
			for i := len(marker); i < len(fakePayload); i++ {
				if fakePayload[i] != tt.junk {
					t.Errorf("junk byte at %d = 0x%02x, want 0x%02x", i, fakePayload[i], tt.junk)
					break
				}
			}
		})
	}
}

func TestOverlapPrimitiveOnce(t *testing.T) {
	marker := bytes.Repeat([]byte{0xCD}, OverlapMarkerLen)
	prim := &OverlapPrimitive{OverlapLen: 64, Marker: marker, Once: true}

	first, err := prim.Apply(createClientHelloPacket(5000, 200))
	if err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first Apply() returned %d packets, want 2", len(first))
	}

	second, err := prim.Apply(createClientHelloPacket(5200, 200))
	if err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if len(second) != 1 {
		t.Errorf("second Apply() returned %d packets, want 1 (passthrough after Once)", len(second))
	}
}

func TestOverlapPrimitiveNoPayload(t *testing.T) {
	// Pure ACK: 20 IP + 20 TCP, no payload.
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 64
	packet[9] = 6
	packet[32] = 0x50
	packet[33] = TCPFlagACK
	recalculateIPChecksum(packet)
	recalculateTCPChecksum(packet)

	prim := &OverlapPrimitive{OverlapLen: 64, Marker: bytes.Repeat([]byte{1}, OverlapMarkerLen), Once: true}
	out, err := prim.Apply(packet)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(out) != 1 {
		t.Errorf("Apply() on no-payload segment returned %d packets, want 1", len(out))
	}
}

func TestOverlapPayloadHasMarker(t *testing.T) {
	marker := bytes.Repeat([]byte{0x42}, OverlapMarkerLen)

	if !OverlapPayloadHasMarker(append(append([]byte{}, marker...), 0, 0, 0), marker) {
		t.Errorf("expected marker to be recognised")
	}
	// A real ClientHello payload must NOT be mistaken for a fake.
	realCH := []byte{0x16, 0x03, 0x03, 0x01, 0x00}
	if OverlapPayloadHasMarker(realCH, marker) {
		t.Errorf("real ClientHello falsely detected as fake")
	}
	// Too-short payload.
	if OverlapPayloadHasMarker([]byte{0x42}, marker) {
		t.Errorf("short payload falsely detected")
	}
}

func TestNewOverlapPrimitiveDefaults(t *testing.T) {
	marker := bytes.Repeat([]byte{0x7E}, OverlapMarkerLen)
	prim := NewOverlapPrimitive(marker)

	if prim.OverlapLen < OverlapMarkerLen {
		t.Errorf("OverlapLen = %d, must be >= marker len %d", prim.OverlapLen, OverlapMarkerLen)
	}
	if prim.FakeLen != prim.OverlapLen {
		t.Errorf("default FakeLen = %d, want == OverlapLen %d (safe geometry)", prim.FakeLen, prim.OverlapLen)
	}
	if !prim.Once {
		t.Errorf("default primitive should be Once=true")
	}

	strat := NewOverlapStrategy(prim)
	if strat.Trigger.Protocol != "TCP" {
		t.Errorf("overlap strategy trigger protocol = %q, want TCP", strat.Trigger.Protocol)
	}
}

// markerOf extracts the OverlapMarkerLen-byte marker from a fake segment.
func markerOf(t *testing.T, fake []byte) []byte {
	t.Helper()
	if len(fake) < 40+OverlapMarkerLen {
		t.Fatalf("fake too short (%d) to hold a marker", len(fake))
	}
	return append([]byte(nil), fake[40:40+OverlapMarkerLen]...)
}

// TestOverlapPrimitivePerConnectionNonce is the per-connection guarantee: two
// distinct connections (distinct 4-tuples) must get DIFFERENT fake markers when
// the primitive mints per connection. The broken-code control below shows a
// single static marker (the pre-fix per-injector nonce) makes them IDENTICAL, so
// this test would go red on that regression.
func TestOverlapPrimitivePerConnectionNonce(t *testing.T) {
	secret := []byte("per-conn-secret")

	// Two connections differ only by source port.
	pkt1 := createClientHelloPacketPort(100000, 300, 40001)
	pkt2 := createClientHelloPacketPort(100000, 300, 40002)

	t.Run("minted_per_connection_differs", func(t *testing.T) {
		prim := NewOverlapPrimitiveMinted(testMintFn(secret))

		out1, err := prim.Apply(pkt1)
		if err != nil || len(out1) != 2 {
			t.Fatalf("conn1 Apply: out=%d err=%v", len(out1), err)
		}
		out2, err := prim.Apply(pkt2)
		if err != nil || len(out2) != 2 {
			t.Fatalf("conn2 Apply: out=%d err=%v", len(out2), err)
		}

		m1, m2 := markerOf(t, out1[0]), markerOf(t, out2[0])
		if bytes.Equal(m1, m2) {
			t.Fatal("two connections carry the SAME packet marker; per-connection nonce is not applied")
		}

		// Positive control: both markers must verify under the matching verifier.
		v := OverlapMarkerVerifier{NonceLen: testOverlapNonceLen, Mint: func(n []byte) []byte {
			return testMarkerFromNonce(secret, n)
		}}
		if !v.Matches(m1) || !v.Matches(m2) {
			t.Fatal("minted markers do not verify under the matching verifier")
		}
	})

	// Broken-code control (rule 1): a single static marker shared across
	// connections - exactly what a per-injector (not per-connection) nonce would
	// produce - makes the two markers identical. Flipping the production path back
	// to a static marker turns the assertion above red; this proves it discriminates.
	t.Run("static_marker_is_identical", func(t *testing.T) {
		static := testMarkerFromNonce(secret, bytes.Repeat([]byte{0x11}, testOverlapNonceLen))
		prim := &OverlapPrimitive{OverlapLen: 64, Marker: static, Once: true}

		out1, _ := prim.Apply(createClientHelloPacketPort(100000, 300, 41001))
		out2, _ := prim.Apply(createClientHelloPacketPort(100000, 300, 41002))
		if len(out1) != 2 || len(out2) != 2 {
			t.Fatalf("expected a fake per connection, got %d and %d", len(out1), len(out2))
		}
		if !bytes.Equal(markerOf(t, out1[0]), markerOf(t, out2[0])) {
			t.Fatal("static marker unexpectedly differed across connections")
		}
	})
}

// TestOverlapServerDropperClassify is the server-side packet verification: the
// dropper's decision function must DROP a fake carrying a valid marker and ACCEPT
// everything else. Negative controls (rule 2): a corrupted MAC and a marker under
// the wrong secret must NOT be dropped.
func TestOverlapServerDropperClassify(t *testing.T) {
	secret := []byte("dropper-secret")
	verify := AnyOverlapVerifier(OverlapMarkerVerifier{
		NonceLen: testOverlapNonceLen,
		Mint:     func(n []byte) []byte { return testMarkerFromNonce(secret, n) },
	})

	// Build a fake segment via the primitive (same path the client emits).
	prim := NewOverlapPrimitiveMinted(testMintFn(secret))
	out, err := prim.Apply(createClientHelloPacketPort(200000, 300, 42001))
	if err != nil || len(out) != 2 {
		t.Fatalf("Apply: out=%d err=%v", len(out), err)
	}
	fake, real := out[0], out[1]

	// Positive control: the fake is recognised and dropped.
	if !overlapPacketIsFake(fake, verify) {
		t.Fatal("valid fake segment was not recognised (would not be dropped)")
	}
	// The real ClientHello must pass through (not dropped).
	if overlapPacketIsFake(real, verify) {
		t.Fatal("real segment falsely recognised as a fake (would be dropped)")
	}

	// Negative control 1: corrupt the MAC portion of the marker -> must not drop.
	corrupt := append([]byte(nil), fake...)
	corrupt[40+OverlapMarkerLen-1] ^= 0xFF // last MAC byte
	if overlapPacketIsFake(corrupt, verify) {
		t.Fatal("fake with corrupted MAC was recognised (must not be)")
	}

	// Negative control 2: a marker minted under a DIFFERENT secret must not verify.
	wrongPrim := NewOverlapPrimitiveMinted(testMintFn([]byte("other-secret")))
	wrongOut, _ := wrongPrim.Apply(createClientHelloPacketPort(200000, 300, 42002))
	if overlapPacketIsFake(wrongOut[0], verify) {
		t.Fatal("fake under a different secret was recognised (must not be)")
	}

	// A non-TCP / no-payload packet is never a fake.
	ack := make([]byte, 40)
	ack[0] = 0x45
	binary.BigEndian.PutUint16(ack[2:4], 40)
	ack[9] = 6
	ack[32] = 0x50
	if overlapPacketIsFake(ack, verify) {
		t.Fatal("empty ACK recognised as a fake")
	}
}

func BenchmarkOverlapPrimitive(b *testing.B) {
	marker := bytes.Repeat([]byte{0x33}, OverlapMarkerLen)
	packet := createClientHelloPacket(1000, 300)
	for b.Loop() {
		prim := &OverlapPrimitive{OverlapLen: 64, Marker: marker}
		prim.Apply(packet)
	}
}
