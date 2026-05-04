// shaper-dump samples a preset Shaper and writes a CSV trace of packet
// sizes and inter-packet delays for visual inspection / Jupyter analysis.
//
// Usage:
//
//	shaper-dump --preset chrome_browsing --samples 10000 --seed 42 --out /tmp/dump.csv
//
// Output schema: idx,direction,size,delay_ms.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
)

func main() {
	preset := flag.String("preset", "chrome_browsing", "preset name (see internal/shaper/presets)")
	samples := flag.Int("samples", 10000, "number of samples per direction")
	seed := flag.Int64("seed", 42, "preset seed (deterministic for reproducibility)")
	out := flag.String("out", "", "output CSV path; empty = stdout")
	flag.Parse()

	// Inspection tool — allow any preset so cover-traffic profiles can be
	// dumped for analysis, not just data-plane-safe ones.
	sh, err := presets.ByNameAllowAny(*preset, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unknown preset %q: %v\n", *preset, err)
		fmt.Fprintf(os.Stderr, "available: %v\n", presets.List())
		os.Exit(2)
	}

	w, closer, err := openOutput(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer closer()

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"idx", "direction", "size", "delay_ms"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	upStats := newRunningStats()
	downStats := newRunningStats()

	for i := range *samples {
		sUp := sh.NextPacketSize(shaper.DirectionUp)
		dUp := sh.NextDelay(shaper.DirectionUp).Seconds() * 1000
		_ = cw.Write([]string{strconv.Itoa(i), "up", strconv.Itoa(sUp), strconv.FormatFloat(dUp, 'f', 4, 64)})
		upStats.add(float64(sUp), dUp)

		sDown := sh.NextPacketSize(shaper.DirectionDown)
		dDown := sh.NextDelay(shaper.DirectionDown).Seconds() * 1000
		_ = cw.Write([]string{strconv.Itoa(i), "down", strconv.Itoa(sDown), strconv.FormatFloat(dDown, 'f', 4, 64)})
		downStats.add(float64(sDown), dDown)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "preset=%s seed=%d samples=%d\n", *preset, *seed, *samples)
	fmt.Fprintf(os.Stderr, "  up:   %s\n", upStats.summary())
	fmt.Fprintf(os.Stderr, "  down: %s\n", downStats.summary())
}

func openOutput(path string) (*os.File, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

type runningStats struct {
	sizes  []float64
	delays []float64
}

func newRunningStats() *runningStats { return &runningStats{} }

func (r *runningStats) add(size, delay float64) {
	r.sizes = append(r.sizes, size)
	r.delays = append(r.delays, delay)
}

func (r *runningStats) summary() string {
	sortedSizes := append([]float64(nil), r.sizes...)
	sort.Float64s(sortedSizes)
	sortedDelays := append([]float64(nil), r.delays...)
	sort.Float64s(sortedDelays)
	return fmt.Sprintf(
		"size mean=%.1f median=%.0f p95=%.0f | delay_ms mean=%.4f median=%.4f p95=%.4f",
		mean(r.sizes), percentile(sortedSizes, 0.5), percentile(sortedSizes, 0.95),
		mean(r.delays), percentile(sortedDelays, 0.5), percentile(sortedDelays, 0.95),
	)
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, v := range xs {
		s += v
	}
	return s / float64(len(xs))
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}
