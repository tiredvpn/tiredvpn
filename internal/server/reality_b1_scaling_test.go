//go:build !race

package server

// The race detector instruments every map access, which is exactly the
// operation this measures, and inflates it by an order of magnitude with
// enough variance to make a 20% comparison meaningless. The property being
// checked is about the algorithm, not about the build, so it is measured in a
// normal build and skipped under -race rather than loosened until it stops
// catching anything.

import (
	"sort"
	"testing"
	"time"
)

// TestB1GateCostIsFlatInClientCount guards the reason the index exists. The
// legacy path runs one HMAC per registered client per connection, so a server
// with a thousand customers pays a hundred times what a server with ten pays,
// on every connection, including the ones an attacker opens.
func TestB1GateCostIsFlatInClientCount(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement, skipped under -short")
	}

	measure := func(clients int) time.Duration {
		f := newB1Fixture(t, clients)
		now := time.Now()
		hello := f.buildB1Hello(t, f.payload(t, now))

		const runs = 300
		samples := make([]time.Duration, 0, runs)
		for range runs {
			// A fresh cache each time so the replay check never short-circuits
			// the measurement into a different branch.
			f.gate.replay = newReplayCache(replayTTLFor(300))
			start := time.Now()
			if _, err := f.gate.evaluate(f.srvCtx, hello, now); err != nil {
				t.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		return samples[len(samples)/2]
	}

	small := measure(10)
	large := measure(1000)
	t.Logf("10 clients: %v, 1000 clients: %v", small, large)

	ratio := float64(large) / float64(small)
	if ratio > 1.2 || ratio < 0.8 {
		t.Fatalf("per-connection cost moved by %.2fx between 10 and 1000 clients; "+
			"the lookup is not O(1)", ratio)
	}
}
