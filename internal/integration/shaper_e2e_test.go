// Package integration_test holds end-to-end tests that exercise multiple
// internal packages together. The shaper E2E suite drives a real MorphedConn
// pair over net.Pipe with preset-derived shapers on both sides and verifies
// that arbitrary payloads survive a full Wrap → wire → Unwrap roundtrip.
package integration_test

import (
	"bytes"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// newPresetShaper resolves a preset name through ShaperFromConfig the same
// way production code will once the CLI migration lands. This guarantees the
// test exercises the real wiring path, not just the presets package.
func newPresetShaper(t *testing.T, name string, seed int64) shaper.Shaper {
	t.Helper()
	sh, err := strategy.ShaperFromConfig(&toml.ShaperConfig{
		Preset: name,
		Seed:   &seed,
	})
	if err != nil {
		t.Fatalf("ShaperFromConfig(%q): %v", name, err)
	}
	return sh
}

// pairedMorphedConns builds two MorphedConn endpoints that talk over
// net.Pipe with their own per-side shapers and a shared profile. We bypass
// NewMorphedConnWithShaper because that constructor performs a synchronous
// Write of the Morph handshake; on net.Pipe (unbuffered) this would deadlock
// without a peer reader.
func pairedMorphedConns(t *testing.T, clientShaper, serverShaper shaper.Shaper) (*strategy.MorphedConn, *strategy.MorphedConn, func()) {
	t.Helper()
	profile := &strategy.TrafficProfile{
		Name:            "T",
		PacketSizes:     []int{1200},
		PacketSizeProbs: []float64{1.0},
	}
	client, server, cleanup := strategy.NewTestMorphedConnPair(profile, clientShaper, serverShaper)
	return client, server, cleanup
}

// TestShaperE2E_ChromePreset_RoundTrip drives 1 MiB of random data through a
// chrome_browsing-shaped MorphedConn pair and asserts byte-perfect recovery.
// Same preset on both sides; sizes/delays are independent RNG streams (each
// side seeds itself), but Unwrap relies only on the per-frame length prefix.
func TestShaperE2E_ChromePreset_RoundTrip(t *testing.T) {
	t.Parallel()
	clientShaper := newPresetShaper(t, presets.PresetChromeBrowsing, 1)
	serverShaper := newPresetShaper(t, presets.PresetChromeBrowsing, 2)
	client, server, cleanup := pairedMorphedConns(t, clientShaper, serverShaper)
	defer cleanup()

	const N = 1 << 20 // 1 MiB
	rng := rand.New(rand.NewPCG(0xDEADBEEF, 0xCAFEBABE))
	want := make([]byte, N)
	for i := range want {
		want[i] = byte(rng.UintN(256))
	}

	var (
		writeErr error
		wg       sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, writeErr = client.Write(want)
		_ = client.Close()
	}()

	got, readErr := readAll(server, N, 30*time.Second)
	wg.Wait()
	if writeErr != nil {
		t.Fatalf("client write: %v", writeErr)
	}
	if readErr != nil && readErr != io.EOF {
		t.Fatalf("server read: %v", readErr)
	}
	if !bytes.Equal(got[:N], want) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

// TestShaperE2E_DifferentPresetsCantTalk_DocumentBehavior pins down the
// shaper contract: changing the preset on one side does NOT corrupt the
// payload, because Wrap/Unwrap are independent — each side decides its own
// on-wire shape (sizes, delays, fragmentation), but the embedded length
// prefix lets the peer reassemble the original bytes regardless of what
// shape was used.
//
// The visible asymmetry is timing/sizes; the application-layer bytes are
// untouched. Future fingerprinting should therefore look at this aspect, but
// transport-layer correctness is unaffected.
func TestShaperE2E_DifferentPresetsCantTalk_DocumentBehavior(t *testing.T) {
	t.Parallel()
	clientShaper := newPresetShaper(t, presets.PresetChromeBrowsing, 7)
	// Server uses a different preset on purpose. We pick youtube_streaming
	// (large packets, fast delays) so the test stays under a few seconds.
	serverShaper := newPresetShaper(t, presets.PresetYouTubeStreaming, 7)
	client, server, cleanup := pairedMorphedConns(t, clientShaper, serverShaper)
	defer cleanup()

	const N = 64 * 1024
	rng := rand.New(rand.NewPCG(1, 2))
	want := make([]byte, N)
	for i := range want {
		want[i] = byte(rng.UintN(256))
	}

	var writeErr error
	go func() {
		_, writeErr = client.Write(want)
		_ = client.Close()
	}()

	got, readErr := readAll(server, N, 10*time.Second)
	if writeErr != nil {
		t.Fatalf("client write: %v", writeErr)
	}
	if readErr != nil && readErr != io.EOF {
		t.Fatalf("server read: %v", readErr)
	}
	if !bytes.Equal(got[:N], want) {
		t.Fatalf("cross-preset roundtrip mismatch: got %d bytes, want %d", len(got), N)
	}
	t.Log("cross-preset roundtrip succeeded; shaper changes affect on-wire shape, not application semantics")
}

func readAll(r io.Reader, n int, timeout time.Duration) ([]byte, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for len(out) < n {
		if time.Now().After(deadline) {
			return out, io.ErrUnexpectedEOF
		}
		k, err := r.Read(buf)
		if k > 0 {
			out = append(out, buf[:k]...)
		}
		if err != nil {
			if len(out) >= n {
				return out, nil
			}
			return out, err
		}
	}
	return out, nil
}
