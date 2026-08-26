package client

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// renderClientMetrics runs the /metrics handler and returns its body. The
// assertions go through the real handler because that is what Prometheus
// scrapes; an exporter that is correct in isolation but never wired up would
// still leave the dashboard empty.
func renderClientMetrics(t *testing.T, m *ClientMetrics) string {
	t.Helper()

	rec := httptest.NewRecorder()
	m.Handler()(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("/metrics returned %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// seriesBounds returns the le labels of metricName's buckets, keeping only the
// lines that also carry labelFilter (pass "" to take every line).
func seriesBounds(t *testing.T, body, metricName, labelFilter string) []string {
	t.Helper()

	var out []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, metricName+"_bucket{") {
			continue
		}
		if labelFilter != "" && !strings.Contains(line, labelFilter) {
			continue
		}
		i := strings.Index(line, `le="`)
		if i < 0 {
			t.Fatalf("bucket line without le label: %q", line)
		}
		rest := line[i+len(`le="`):]
		j := strings.Index(rest, `"`)
		out = append(out, rest[:j])
	}
	if len(out) == 0 {
		t.Fatalf("no %s_bucket lines matching %q in exposition", metricName, labelFilter)
	}
	return out
}

func wantBounds(t *testing.T, got, want []string, what string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s: le labels = %v (%d), want %v (%d)", what, got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: le[%d] = %q, want %q", what, i, got[i], want[i])
		}
	}
}

// TestClientDurationHistogramsAreSeconds checks all three client-side
// histograms whose name ends in _seconds. Each one was observed with
// duration.Milliseconds() against millisecond bucket boundaries, so every
// PromQL quantile over them came out 1000x too large. Each subtest is
// independent: a fix applied to only one of the three still fails the other two.
func TestClientDurationHistogramsAreSeconds(t *testing.T) {
	const observed = 250 * time.Millisecond
	const wantSum = "0.25" // 250ms expressed in the unit the metric name promises

	t.Run("tls_handshake", func(t *testing.T) {
		m := NewClientMetrics(nil, nil)
		m.strategyMetrics.RecordTLSHandshake("reality", observed)
		body := renderClientMetrics(t, m)

		const name = "tiredvpn_local_tls_handshake_duration_seconds"
		wantBounds(t, seriesBounds(t, body, name, ""),
			[]string{"0.01", "0.05", "0.1", "0.2", "0.5", "1", "2", "5", "+Inf"}, name)
		mustHaveSum(t, body, name+"_sum "+wantSum)
	})

	t.Run("dns_resolution", func(t *testing.T) {
		m := NewClientMetrics(nil, nil)
		m.performanceMetrics.RecordDNSResolution(observed)
		body := renderClientMetrics(t, m)

		const name = "tiredvpn_local_dns_resolution_duration_seconds"
		wantBounds(t, seriesBounds(t, body, name, ""),
			[]string{"0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "+Inf"}, name)
		mustHaveSum(t, body, name+"_sum "+wantSum)
	})

	// The phase histogram is exported once per phase label, and each phase has
	// its own Histogram instance. Checking a single phase would pass on a
	// partial fix, so every phase is asserted.
	for _, phase := range []string{"dns", "tcp", "tls", "app"} {
		t.Run("connect_phase_"+phase, func(t *testing.T) {
			m := NewClientMetrics(nil, nil)
			m.strategyMetrics.RecordPhaseDuration(phase, observed)
			body := renderClientMetrics(t, m)

			const name = "tiredvpn_local_connect_phases_duration_seconds"
			filter := `phase="` + phase + `"`
			wantBounds(t, seriesBounds(t, body, name, filter),
				[]string{"0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "+Inf"}, name+" "+filter)
			mustHaveSum(t, body, name+"_sum{"+filter+"} "+wantSum)
		})
	}
}

func mustHaveSum(t *testing.T, body, want string) {
	t.Helper()

	if !strings.Contains(body, want+"\n") {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, strings.SplitN(want, " ", 2)[0]) {
				t.Fatalf("_sum line = %q, want %q", line, want)
			}
		}
		t.Fatalf("no line %q in exposition", want)
	}
}
