package presets

import (
	"bytes"
	"errors"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

func TestList_NotEmpty(t *testing.T) {
	names := List()
	if len(names) < 4 {
		t.Fatalf("expected >=4 presets, got %v", names)
	}
	want := map[string]bool{
		PresetChromeBrowsing:   false,
		PresetYouTubeStreaming: false,
		PresetBitTorrentIdle:   false,
		PresetRandomPerSession: false,
	}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("missing preset %q", n)
		}
	}
}

func TestByName_Unknown(t *testing.T) {
	_, err := ByName("does_not_exist", 1)
	if !errors.Is(err, ErrUnknownPreset) {
		t.Fatalf("want ErrUnknownPreset, got %v", err)
	}
}

func TestByName_AllPresets_Determinism(t *testing.T) {
	for _, name := range List() {
		t.Run(name, func(t *testing.T) {
			a, err := ByName(name, 42)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ByName(name, 42)
			if err != nil {
				t.Fatal(err)
			}
			const N = 1000
			for i := range N {
				sa := a.NextPacketSize(shaper.DirectionUp)
				sb := b.NextPacketSize(shaper.DirectionUp)
				if sa != sb {
					t.Fatalf("step %d size mismatch: %d != %d", i, sa, sb)
				}
				da := a.NextDelay(shaper.DirectionDown)
				db := b.NextDelay(shaper.DirectionDown)
				if da != db {
					t.Fatalf("step %d delay mismatch: %v != %v", i, da, db)
				}
			}
		})
	}
}

// TestByName_DifferentPresetsDiffer compares mean packet size of chrome and
// youtube. youtube must dominate (preferentially full-MTU).
func TestByName_DifferentPresetsDiffer(t *testing.T) {
	chrome, err := ByName(PresetChromeBrowsing, 7)
	if err != nil {
		t.Fatal(err)
	}
	yt, err := ByName(PresetYouTubeStreaming, 7)
	if err != nil {
		t.Fatal(err)
	}
	const N = 5000
	var chromeMean, ytMean float64
	for range N {
		chromeMean += float64(chrome.NextPacketSize(shaper.DirectionDown))
		ytMean += float64(yt.NextPacketSize(shaper.DirectionDown))
	}
	chromeMean /= N
	ytMean /= N
	if ytMean-chromeMean < 200 {
		t.Fatalf("expected youtube mean ≫ chrome mean, got chrome=%v youtube=%v", chromeMean, ytMean)
	}
	t.Logf("chrome mean=%.1f youtube mean=%.1f delta=%.1f", chromeMean, ytMean, ytMean-chromeMean)
}

func TestRandomPerSession_Variation(t *testing.T) {
	const N = 2000
	signature := func(seed int64) (mean float64) {
		s, err := ByName(PresetRandomPerSession, seed)
		if err != nil {
			t.Fatal(err)
		}
		var sum float64
		for range N {
			sum += float64(s.NextPacketSize(shaper.DirectionDown))
		}
		return sum / N
	}
	// Try several seeds; at least two should differ noticeably.
	means := make([]float64, 8)
	for i := range means {
		means[i] = signature(int64(i + 1))
	}
	maxDelta := 0.0
	for i := range means {
		for j := i + 1; j < len(means); j++ {
			d := math.Abs(means[i] - means[j])
			if d > maxDelta {
				maxDelta = d
			}
		}
	}
	if maxDelta < 50 {
		t.Fatalf("random_per_session shows insufficient cross-seed variation: maxDelta=%.1f means=%v", maxDelta, means)
	}
}

func TestFromConfig_PresetAndCustomMutuallyExclusive(t *testing.T) {
	cfg := toml.ShaperConfig{
		Preset: PresetChromeBrowsing,
		Custom: &toml.ShaperCustom{},
	}
	if _, err := FromConfig(cfg); err == nil {
		t.Fatal("expected error for both preset and custom set")
	}
	cfg = toml.ShaperConfig{}
	if _, err := FromConfig(cfg); err == nil {
		t.Fatal("expected error for neither preset nor custom set")
	}
}

func TestFromConfig_Preset_WithRandomization(t *testing.T) {
	rr := 0.3
	cfg := toml.ShaperConfig{
		Preset:             PresetChromeBrowsing,
		RandomizationRange: rr,
		Seed:               int64Ptr(123),
	}
	s, err := FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Just ensure it works and returns sensible values.
	for range 100 {
		n := s.NextPacketSize(shaper.DirectionUp)
		if n < 1 || n > defaultMTU {
			t.Fatalf("size %d out of range", n)
		}
	}
}

func TestFromConfig_Custom_Histogram(t *testing.T) {
	cfg := toml.ShaperConfig{
		Custom: &toml.ShaperCustom{
			PacketSize: &toml.DistConfig{
				Type: toml.DistHistogram,
				Histogram: &toml.HistogramDist{
					Bins: []toml.HistogramBin{
						{Value: 100, Weight: 1},
						{Value: 1400, Weight: 1},
					},
				},
			},
			InterArrival: &toml.DistConfig{
				Type:      toml.DistLogNormal,
				LogNormal: &toml.LogNormalDist{Mu: -5, Sigma: 0.5},
			},
		},
		Seed: int64Ptr(99),
	}
	s, err := FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		n := s.NextPacketSize(shaper.DirectionUp)
		if n != 100 && n != 1400 {
			t.Fatalf("unexpected size %d, want 100 or 1400", n)
		}
		if d := s.NextDelay(shaper.DirectionUp); d < 0 {
			t.Fatalf("negative delay: %v", d)
		}
	}
}

func TestFromConfig_Custom_BadDist(t *testing.T) {
	cfg := toml.ShaperConfig{
		Custom: &toml.ShaperCustom{
			PacketSize: &toml.DistConfig{Type: "weird"},
		},
		Seed: int64Ptr(1),
	}
	if _, err := FromConfig(cfg); err == nil {
		t.Fatal("expected error for unknown distribution type")
	}
}

func TestFromConfig_NilSeed_Works(t *testing.T) {
	cfg := toml.ShaperConfig{Preset: PresetChromeBrowsing}
	s, err := FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.NextPacketSize(shaper.DirectionUp) <= 0 {
		t.Fatal("expected positive packet size")
	}
}

func TestDistShaper_WrapUnwrap_Roundtrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{0, 1, 100, 1500, 4096, 65536} {
		s, err := ByName(PresetChromeBrowsing, 1)
		if err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(rng.UintN(256))
		}
		frames := s.Wrap(payload)
		out := s.Unwrap(frames)
		if !bytes.Equal(out, payload) {
			t.Fatalf("size=%d: roundtrip mismatch (got %d bytes, want %d)", size, len(out), len(payload))
		}
	}
}

func TestDistShaper_NextPacketSize_RespectsMTU(t *testing.T) {
	for _, name := range []string{
		PresetChromeBrowsing, PresetYouTubeStreaming,
		PresetBitTorrentIdle, PresetRandomPerSession,
	} {
		s, err := ByName(name, 5)
		if err != nil {
			t.Fatal(err)
		}
		for range 5000 {
			n := s.NextPacketSize(shaper.DirectionDown)
			if n < 1 || n > defaultMTU {
				t.Fatalf("%s: size %d out of [1, %d]", name, n, defaultMTU)
			}
		}
	}
}

func TestDistShaper_NextDelay_NonNegative(t *testing.T) {
	for _, name := range List() {
		s, err := ByName(name, 11)
		if err != nil {
			t.Fatal(err)
		}
		for range 1000 {
			if d := s.NextDelay(shaper.DirectionUp); d < 0 {
				t.Fatalf("%s: negative delay %v", name, d)
			}
		}
	}
}

func TestNoopWrapEmpty(t *testing.T) {
	s, err := ByName(PresetChromeBrowsing, 1)
	if err != nil {
		t.Fatal(err)
	}
	out := s.Unwrap(nil)
	if out != nil {
		t.Fatalf("nil unwrap got %v", out)
	}
}

func int64Ptr(v int64) *int64 { return &v }

func TestConstDist(t *testing.T) {
	c := constDist(42)
	if c.Next() != 42 {
		t.Fatalf("constDist.Next mismatch")
	}
	c.Reset() // no-op, must not panic
}

func TestFromConfig_Custom_Empty(t *testing.T) {
	cfg := toml.ShaperConfig{
		Custom: &toml.ShaperCustom{},
		Seed:   int64Ptr(1),
	}
	s, err := FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.NextPacketSize(shaper.DirectionUp) != defaultPacketSize {
		t.Fatalf("expected default packet size %d", defaultPacketSize)
	}
	if s.NextDelay(shaper.DirectionUp) != 0 {
		t.Fatalf("expected zero default delay")
	}
}

func TestFromConfig_Custom_AllDistTypes(t *testing.T) {
	tests := []struct {
		name string
		d    *toml.DistConfig
	}{
		{"pareto", &toml.DistConfig{Type: toml.DistPareto, Pareto: &toml.ParetoDist{Xm: 1, Alpha: 1.5}}},
		{"markov", &toml.DistConfig{Type: toml.DistMarkov, Markov: &toml.MarkovDist{
			States:      []toml.MarkovState{{Name: "a", Value: 100}, {Name: "b", Value: 1400}},
			Transitions: [][]float64{{0.5, 0.5}, {0.3, 0.7}},
		}}},
		{"histogram", &toml.DistConfig{Type: toml.DistHistogram, Histogram: &toml.HistogramDist{
			Bins: []toml.HistogramBin{{Value: 200, Weight: 1}},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := toml.ShaperConfig{
				Custom: &toml.ShaperCustom{
					PacketSize: tt.d,
					Burst:      tt.d,
				},
				Seed:               int64Ptr(7),
				RandomizationRange: 0.1,
			}
			s, err := FromConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if n := s.NextPacketSize(shaper.DirectionDown); n < 1 {
				t.Fatalf("bad size %d", n)
			}
		})
	}
}

func TestFromConfig_Custom_BadHistogram(t *testing.T) {
	cfg := toml.ShaperConfig{
		Custom: &toml.ShaperCustom{
			InterArrival: &toml.DistConfig{
				Type:      toml.DistHistogram,
				Histogram: &toml.HistogramDist{Bins: []toml.HistogramBin{{Value: 1, Weight: 0}}},
			},
		},
		Seed: int64Ptr(1),
	}
	if _, err := FromConfig(cfg); err == nil {
		t.Fatal("expected error for zero-weight histogram")
	}
}

func TestFromConfig_Custom_BadBurst(t *testing.T) {
	cfg := toml.ShaperConfig{
		Custom: &toml.ShaperCustom{
			Burst: &toml.DistConfig{Type: "weird"},
		},
		Seed: int64Ptr(1),
	}
	if _, err := FromConfig(cfg); err == nil {
		t.Fatal("expected error for bad burst dist")
	}
}

func TestFromConfig_Custom_BadInterArrival(t *testing.T) {
	cfg := toml.ShaperConfig{
		Custom: &toml.ShaperCustom{
			InterArrival: &toml.DistConfig{Type: "weird"},
		},
		Seed: int64Ptr(1),
	}
	if _, err := FromConfig(cfg); err == nil {
		t.Fatal("expected error for bad inter_arrival dist")
	}
}

func TestUnwrap_TruncatedFrame(t *testing.T) {
	// Build a valid frame, then truncate it to test the bounds-check branch.
	s, err := ByName(PresetChromeBrowsing, 1)
	if err != nil {
		t.Fatal(err)
	}
	frames := s.Wrap([]byte("hello world"))
	// Short frame (< header).
	frames = append(frames, []byte{0x01, 0x02})
	// Frame with header claiming more bytes than present.
	bad := make([]byte, frameHeaderLen+2)
	bad[0] = 0xFF // claim huge length
	bad[1] = 0xFF
	bad[2] = 0xFF
	bad[3] = 0xFF
	bad[4] = 'X'
	bad[5] = 'Y'
	frames = append(frames, bad)
	out := s.Unwrap(frames)
	// Original payload should still be at the front; trailing garbage is XY.
	if len(out) < len("hello world") || string(out[:len("hello world")]) != "hello world" {
		t.Fatalf("expected hello world prefix, got %q", string(out))
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate register")
		}
	}()
	register(PresetChromeBrowsing, buildChromeBrowsing)
}

func BenchmarkChromeBrowsing_Next(b *testing.B) {
	s, err := ByName(PresetChromeBrowsing, 1)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		_ = s.NextPacketSize(shaper.DirectionUp)
		_ = s.NextDelay(shaper.DirectionUp)
	}
}
