package tun

import (
	"context"
	"sync"
	"testing"
	"time"
)

// --- codec ---

func TestEncodeDecodeProbeRoundtrip(t *testing.T) {
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, size := range []int{probeHeaderLen, 100, 1280, 1400, 1500, 9000, 65535} {
		p := encodeProbeFrame(probeTypeRequest, 42, size, nonce)
		if len(p) != size {
			t.Fatalf("size %d: encoded len = %d", size, len(p))
		}
		f, ok := decodeProbeFrame(p)
		if !ok {
			t.Fatalf("size %d: decode failed", size)
		}
		if f.typ != probeTypeRequest || f.seq != 42 || int(f.size) != size || f.nonce != nonce {
			t.Fatalf("size %d: decoded %+v", size, f)
		}
	}
}

func TestProbeMarkerNoCollision(t *testing.T) {
	// Real IPv4 header (version nibble 0x4) must not look like a probe.
	ipv4 := make([]byte, 1400)
	ipv4[0] = 0x45
	if IsProbeFrame(ipv4) {
		t.Fatal("IPv4 packet misdetected as probe frame")
	}
	// Real IPv6 header (version nibble 0x6).
	ipv6 := make([]byte, 1400)
	ipv6[0] = 0x60
	if IsProbeFrame(ipv6) {
		t.Fatal("IPv6 packet misdetected as probe frame")
	}
	// Keepalive is a zero-length payload.
	if IsProbeFrame(nil) || IsProbeFrame([]byte{}) {
		t.Fatal("empty/keepalive payload misdetected as probe frame")
	}
	// A real probe frame is detected.
	if !IsProbeFrame(encodeProbeFrame(probeTypeRequest, 1, 1280, [8]byte{})) {
		t.Fatal("valid probe frame not detected")
	}
}

func TestDecodeProbeRejects(t *testing.T) {
	// Too short.
	if _, ok := decodeProbeFrame([]byte{probeMarker, 'M', 'T'}); ok {
		t.Fatal("short payload accepted")
	}
	// Wrong marker.
	bad := encodeProbeFrame(probeTypeRequest, 1, 1280, [8]byte{})
	bad[0] = 0x45
	if _, ok := decodeProbeFrame(bad); ok {
		t.Fatal("wrong marker accepted")
	}
	// Declared size != actual length (truncated relay/reassembly artifact).
	frame := encodeProbeFrame(probeTypeRequest, 1, 1280, [8]byte{})
	if _, ok := decodeProbeFrame(frame[:1000]); ok {
		t.Fatal("size mismatch accepted")
	}
	// Unknown type.
	frame[3] = 0x09
	if _, ok := decodeProbeFrame(frame); ok {
		t.Fatal("unknown type accepted")
	}
}

func TestMakeProbeReply(t *testing.T) {
	nonce := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	req := encodeProbeFrame(probeTypeRequest, 77, 1400, nonce)
	reply := MakeProbeReply(req)
	if reply == nil {
		t.Fatal("reply nil for valid request")
	}
	if len(reply) != len(req) {
		t.Fatalf("reply size %d != request size %d (anti-amplification)", len(reply), len(req))
	}
	f, ok := decodeProbeFrame(reply)
	if !ok || f.typ != probeTypeReply || f.seq != 77 || int(f.size) != 1400 || f.nonce != nonce {
		t.Fatalf("bad reply: %+v ok=%v", f, ok)
	}
	// A reply is not itself a valid request to echo.
	if MakeProbeReply(reply) != nil {
		t.Fatal("reply should not be echoed as a request")
	}
}

// --- engine ---

// mockExit emulates an exit echoing probes, gated by a per-size decision so tests
// can model blackholes and loss. The reply is delivered synchronously inside send
// because probeOnce registers the pending channel before calling send.
type mockExit struct {
	prober   *Prober
	mu       sync.Mutex
	attempts map[int]int
	decide   func(size, attempt int) bool // attempt is 1-based
}

func (m *mockExit) send(payload []byte) error {
	f, ok := decodeProbeFrame(payload)
	if !ok {
		return nil
	}
	m.mu.Lock()
	m.attempts[int(f.size)]++
	n := m.attempts[int(f.size)]
	m.mu.Unlock()
	if m.decide(int(f.size), n) {
		m.prober.HandleReply(MakeProbeReply(payload))
	}
	return nil
}

func newMockProber(cfg ProbeConfig, decide func(size, attempt int) bool) (*Prober, *mockExit) {
	m := &mockExit{attempts: make(map[int]int), decide: decide}
	p := NewProber(cfg, m.send)
	m.prober = p
	return p, m
}

func fastCfg(cap int) ProbeConfig {
	return ProbeConfig{Floor: MTUFloor, Cap: cap, Step: defaultProbeStep, Timeout: 20 * time.Millisecond, Retries: defaultProbeRetries}
}

func TestRunHappyPathCapEchoes(t *testing.T) {
	// Everything up to cap echoes -> one optimistic jump answers cap.
	p, _ := newMockProber(fastCfg(1500), func(size, _ int) bool { return size <= 1500 })
	res := p.Run(context.Background())
	if res.AppliedMTU != 1500 || res.Source != "cap" {
		t.Fatalf("expected cap=1500, got %+v", res)
	}
	if res.Probes != 2 { // anchor floor + jump cap
		t.Fatalf("expected 2 probes on happy path, got %d", res.Probes)
	}
}

func TestRunBinarySearchOnBlackhole(t *testing.T) {
	// Node silently drops anything above 1352 -> search must converge just under it.
	const boundary = 1352
	p, _ := newMockProber(fastCfg(1500), func(size, _ int) bool { return size <= boundary })
	res := p.Run(context.Background())
	if res.Source != "probed" {
		t.Fatalf("expected source=probed, got %+v", res)
	}
	if res.AppliedMTU > boundary {
		t.Fatalf("false-high: applied %d > boundary %d", res.AppliedMTU, boundary)
	}
	if boundary-res.AppliedMTU > 2*defaultProbeStep {
		t.Fatalf("converged too low: applied %d, boundary %d", res.AppliedMTU, boundary)
	}
}

func TestRunFloorTimeoutFallback(t *testing.T) {
	// Exit never echoes -> anchor fails -> fall back to floor.
	p, _ := newMockProber(fastCfg(1500), func(_, _ int) bool { return false })
	res := p.Run(context.Background())
	if res.AppliedMTU != MTUFloor || res.Source != "floor" || res.FallbackReason != "floor-timeout" {
		t.Fatalf("expected floor-timeout fallback, got %+v", res)
	}
}

func TestProbeSizeRetriesTolerateLoss(t *testing.T) {
	// Size 1400 drops the first two attempts, echoes on the third. With retries=2
	// (3 attempts total) it must still be judged passable - loss != MTU drop.
	p, _ := newMockProber(fastCfg(1500), func(size, attempt int) bool {
		return size == 1400 && attempt >= 3
	})
	if !p.probeSize(context.Background(), 1400) {
		t.Fatal("probeSize should pass when an attempt within retries echoes")
	}
	// A size that always drops yields a too-big verdict (all attempts fail).
	if p.probeSize(context.Background(), 1408) {
		t.Fatal("probeSize should fail when every attempt drops")
	}
}

func TestFastProbeSuccessAndFailure(t *testing.T) {
	p, _ := newMockProber(fastCfg(1500), func(size, _ int) bool { return size <= 1500 })
	if !p.FastProbe(context.Background(), 200*time.Millisecond) {
		t.Fatal("FastProbe should succeed when cap echoes")
	}
	p2, _ := newMockProber(fastCfg(1500), func(_, _ int) bool { return false })
	if p2.FastProbe(context.Background(), 60*time.Millisecond) {
		t.Fatal("FastProbe should fail when nothing echoes")
	}
}

func TestParseServerCapabilitiesProbeFlag(t *testing.T) {
	mk := func(flags byte, n int) []byte {
		b := make([]byte, n)
		b[0] = 0x00
		if n >= 10 {
			b[9] = flags
		}
		return b
	}

	// Legacy 9-byte response: no flags byte, no caps.
	if _, ok := parseServerCapabilities(mk(0, 9), 9); ok {
		t.Fatal("9-byte legacy response should yield no caps")
	}

	// 10-byte probe-only response.
	caps, ok := parseServerCapabilities(mk(tunFlagMTUProbe, 10), 10)
	if !ok || !caps.MTUProbeSupported || caps.PortHoppingEnabled {
		t.Fatalf("probe-only response: ok=%v caps=%+v", ok, caps)
	}

	// 14-byte port-hop + probe response.
	resp := mk(tunFlagPortHopping|tunFlagMTUProbe, 14)
	resp[10], resp[11] = 0xB7, 0x60 // portStart 47000
	resp[12], resp[13] = 0xFF, 0xFF // portEnd 65535
	caps, ok = parseServerCapabilities(resp, 14)
	if !ok || !caps.MTUProbeSupported || !caps.PortHoppingEnabled {
		t.Fatalf("combined response: ok=%v caps=%+v", ok, caps)
	}

	// Port-hop only, no probe bit.
	resp = mk(tunFlagPortHopping, 14)
	resp[10], resp[11] = 0xB7, 0x60
	resp[12], resp[13] = 0xFF, 0xFF
	caps, ok = parseServerCapabilities(resp, 14)
	if !ok || caps.MTUProbeSupported || !caps.PortHoppingEnabled {
		t.Fatalf("porthop-only response: ok=%v caps=%+v", ok, caps)
	}
}

func TestRunCapEqualsFloor(t *testing.T) {
	// When the configured cap is the floor there is nothing above to measure.
	p, _ := newMockProber(fastCfg(MTUFloor), func(size, _ int) bool { return size <= MTUFloor })
	res := p.Run(context.Background())
	if res.AppliedMTU != MTUFloor {
		t.Fatalf("expected floor, got %+v", res)
	}
}
