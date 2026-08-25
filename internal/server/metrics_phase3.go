package server

// Metrics and config plumbing for burst reshaping (phase 3). The mechanism
// itself lives in internal/strategy/burst_reshape.go; this file only translates
// the server Config into it and exposes its counters.

import (
	"fmt"
	"io"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// BurstReshapeOff and BurstReshapeOn are the accepted values of
// Config.BurstReshape. Anything else is treated as off: an unrecognised value
// must not silently enable a mode that corrupts streams when only one end has
// it.
const (
	BurstReshapeOff = "off"
	BurstReshapeOn  = "on"
)

// burstReshapeConfig maps the server Config onto the strategy layer's settings.
func burstReshapeConfig(cfg *Config) strategy.BurstReshapeConfig {
	if cfg == nil {
		return strategy.BurstReshapeConfig{}
	}
	return strategy.BurstReshapeConfig{
		Enabled:   cfg.BurstReshape == BurstReshapeOn,
		PadFlight: cfg.BurstReshapePadFlight,
	}
}

// writePhase3Metrics appends the reshaping counters in Prometheus text format.
//
// hold_bytes and hold_streams are gauges and are the ones to watch: holding the
// upstream reply is the shape that has caused OOM before, so a hold_bytes that
// does not return to zero, or a hold_streams pinned at the ceiling, means the
// exchange is not completing and streams are sitting in the timeout path.
func writePhase3Metrics(w io.Writer) {
	st := strategy.ReadBurstReshapeStats()

	fmt.Fprintf(w, "# HELP tiredvpn_phase3_hold_bytes Upstream reply bytes currently held for the nudge/ack exchange\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_phase3_hold_bytes gauge\n")
	fmt.Fprintf(w, "tiredvpn_phase3_hold_bytes %d\n", st.HoldBytes)

	fmt.Fprintf(w, "# HELP tiredvpn_phase3_hold_streams Streams currently waiting for a burst-reshape ack\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_phase3_hold_streams gauge\n")
	fmt.Fprintf(w, "tiredvpn_phase3_hold_streams %d\n", st.HoldStreams)

	fmt.Fprintf(w, "# HELP tiredvpn_phase3_reshaped_total Streams where the nudge/ack exchange completed\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_phase3_reshaped_total counter\n")
	fmt.Fprintf(w, "tiredvpn_phase3_reshaped_total %d\n", st.ReshapedTotal)

	fmt.Fprintf(w, "# HELP tiredvpn_phase3_skipped_total Streams served without reshaping (cap, ceiling or ack timeout)\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_phase3_skipped_total counter\n")
	fmt.Fprintf(w, "tiredvpn_phase3_skipped_total %d\n", st.SkippedTotal)
}
