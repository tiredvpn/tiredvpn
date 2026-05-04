package strategy_test

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// realistic_bench_test exercises the shaped Write path over a real loopback
// TCP socket instead of net.Pipe. Rationale (see adr-shaper-perf.md §8):
// net.Pipe is synchronous; the kernel TCP buffer on 127.0.0.1 absorbs bursts
// and lets the async pacer goroutine make progress while the producer keeps
// enqueuing. The realistic numbers — and thus the issue #18 acceptance bar —
// must be measured here, not on net.Pipe.

const realisticPayloadBytes = 16 * 1024 * 1024 // 16 MiB

func realisticProfile() *strategy.TrafficProfile {
	return &strategy.TrafficProfile{
		Name:            "Bench",
		PacketSizes:     []int{1200},
		PacketSizeProbs: []float64{1.0},
	}
}

func mustRealisticPresetShaper(b *testing.B, name string) shaper.Shaper {
	b.Helper()
	seed := int64(1)
	sh, err := strategy.ShaperFromConfig(&toml.ShaperConfig{Preset: name, Seed: &seed})
	if err != nil {
		b.Fatal(err)
	}
	return sh
}

// runRealisticBench writes a single 16 MiB payload through a shaped
// MorphedConn pair connected via loopback TCP, while a server-side goroutine
// drains continuously. Each b.Loop() iteration covers one full payload, which
// means we measure steady-state throughput rather than per-Write fixed costs.
func runRealisticBench(b *testing.B, clientShaper, serverShaper shaper.Shaper) {
	b.Helper()
	profile := realisticProfile()
	payload := make([]byte, realisticPayloadBytes)
	for i := range payload {
		payload[i] = byte(i)
	}

	// One TCP pair per benchmark invocation; b.Loop iterates payloads over
	// the same socket so each iteration includes a full Write + drain to the
	// kernel buffer, but we don't pay listener/dial cost per iteration.
	client, server, cleanup, err := strategy.NewTestMorphedConnPairTCP(profile, clientShaper, serverShaper)
	if err != nil {
		b.Fatalf("pair: %v", err)
	}
	defer cleanup()

	// Counter the server-side reader hands back so the producer can wait
	// for "this iteration's bytes have been drained" before declaring the
	// iteration complete. Without that, all the work might still be sitting
	// in the kernel send buffer when the timer stops.
	var drained atomic.Int64
	readDone := make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(readDone)
		buf := make([]byte, 64*1024)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				drained.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(realisticPayloadBytes))
	b.ReportAllocs()
	b.ResetTimer()
	var written int64
	for b.Loop() {
		if _, err := client.Write(payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				break
			}
			b.Fatalf("write: %v", err)
		}
		written += int64(realisticPayloadBytes)
		// Wait until the server has drained at least everything we've
		// written so far. This is what turns "producer enqueue MB/s" into
		// "end-to-end MB/s".
		deadline := time.Now().Add(60 * time.Second)
		for drained.Load() < written {
			if time.Now().After(deadline) {
				b.Fatal("drain timeout")
			}
			time.Sleep(100 * time.Microsecond)
		}
	}
	b.StopTimer()
	_ = client.Close()
	<-readDone
	wg.Wait()
}

// BenchmarkRealistic_Noop is the loopback-TCP baseline. With NoopShaper this
// is just framed Conn.Write into the kernel buffer; the resulting MB/s is the
// upper bound any other preset must compare against.
func BenchmarkRealistic_Noop(b *testing.B) {
	runRealisticBench(b, shaper.NoopShaper{}, shaper.NoopShaper{})
}

// BenchmarkRealistic_Chrome_Async exercises chrome_browsing through the async
// pacer over loopback TCP. This is the headline number for issue #18: target
// is ≤ 30 % overhead vs Noop.
func BenchmarkRealistic_Chrome_Async(b *testing.B) {
	runRealisticBench(b,
		mustRealisticPresetShaper(b, presets.PresetChromeBrowsing),
		mustRealisticPresetShaper(b, presets.PresetChromeBrowsing),
	)
}

// BenchmarkRealistic_Youtube_Async is the youtube_streaming counterpart.
// Pareto-tail delays are clamped to 50 ms in the pacer (ADR §7) and the
// up-direction packet sizes are tiny (~120 B), so this is the worst-case
// preset for throughput; it's expected to underperform chrome.
func BenchmarkRealistic_Youtube_Async(b *testing.B) {
	runRealisticBench(b,
		mustRealisticPresetShaper(b, presets.PresetYouTubeStreaming),
		mustRealisticPresetShaper(b, presets.PresetYouTubeStreaming),
	)
}

// BenchmarkRealistic_RandomPerSession sanity-checks the third data-plane-safe
// preset; numbers should sit between chrome and youtube depending on which
// candidate the seed selects.
func BenchmarkRealistic_RandomPerSession(b *testing.B) {
	runRealisticBench(b,
		mustRealisticPresetShaper(b, presets.PresetRandomPerSession),
		mustRealisticPresetShaper(b, presets.PresetRandomPerSession),
	)
}
