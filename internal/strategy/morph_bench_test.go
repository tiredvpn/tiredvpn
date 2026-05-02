package strategy_test

import (
	"io"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// payload size shared by all shaper benchmarks. 64 KiB is large enough that
// per-Write fixed overhead is amortized but small enough to run thousands of
// iterations within the default benchmark budget.
const benchPayloadBytes = 64 * 1024

func benchPayload() []byte {
	p := make([]byte, benchPayloadBytes)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

func benchProfile() *strategy.TrafficProfile {
	return &strategy.TrafficProfile{
		Name:            "Bench",
		PacketSizes:     []int{1200},
		PacketSizeProbs: []float64{1.0},
	}
}

func mustPresetShaper(b *testing.B, name string) shaper.Shaper {
	b.Helper()
	seed := int64(1)
	sh, err := strategy.ShaperFromConfig(&toml.ShaperConfig{Preset: name, Seed: &seed})
	if err != nil {
		b.Fatal(err)
	}
	return sh
}

// runShaperBench measures Write throughput for a shaper-driven MorphedConn
// pair. Server side does pure reads to drain the pipe. The benchmark reports
// bytes/op derived from payload size so go test --benchstat can compare
// throughput across preset variants directly.
func runShaperBench(b *testing.B, clientShaper, serverShaper shaper.Shaper) {
	profile := benchProfile()
	payload := benchPayload()
	client, server, cleanup := strategy.NewTestMorphedConnPair(profile, clientShaper, serverShaper)
	defer cleanup()

	// Drain the server side continuously so the pipe doesn't block.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		for {
			if _, err := server.Read(buf); err != nil {
				close(done)
				return
			}
		}
	}()

	b.SetBytes(int64(benchPayloadBytes))
	b.ResetTimer()
	for b.Loop() {
		if _, err := client.Write(payload); err != nil {
			if err == io.EOF {
				break
			}
			b.Fatal(err)
		}
	}
	b.StopTimer()
	cleanup()
	<-done
}

func BenchmarkMorphedConn_NoopShaper(b *testing.B) {
	runShaperBench(b, shaper.NoopShaper{}, shaper.NoopShaper{})
}

func BenchmarkMorphedConn_ChromeShaper(b *testing.B) {
	runShaperBench(b, mustPresetShaper(b, presets.PresetChromeBrowsing), mustPresetShaper(b, presets.PresetChromeBrowsing))
}

func BenchmarkMorphedConn_YoutubeShaper(b *testing.B) {
	runShaperBench(b, mustPresetShaper(b, presets.PresetYouTubeStreaming), mustPresetShaper(b, presets.PresetYouTubeStreaming))
}
