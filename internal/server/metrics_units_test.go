package server

import (
	"strings"
	"testing"
	"time"
)

// serverSeriesBounds returns the le labels of metricName's buckets.
func serverSeriesBounds(t *testing.T, body, metricName string) []string {
	t.Helper()

	var out []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, metricName+"_bucket{") {
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
		t.Fatalf("no %s_bucket lines in exposition", metricName)
	}
	return out
}

func wantServerBounds(t *testing.T, got, want []string, what string) {
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

// TestServerTLSHandshakeHistogramIsSeconds is the server half of the unit fix.
// The metric promised seconds while the recorder took a millisecond float and
// the buckets ran 1…1000 ms, so a 250 ms handshake landed in the +Inf bucket
// and read as "over 1000 seconds".
func TestServerTLSHandshakeHistogramIsSeconds(t *testing.T) {
	m := NewMetrics(nil)
	m.protocolMetrics.RecordTLSHandshake(250 * time.Millisecond)
	body := renderMetrics(t, m)

	const name = "tiredvpn_tls_handshake_duration_seconds"
	wantServerBounds(t, serverSeriesBounds(t, body, name),
		[]string{"0.001", "0.005", "0.01", "0.05", "0.1", "0.2", "0.5", "1", "+Inf"}, name)

	if !strings.Contains(body, name+"_sum 0.25\n") {
		t.Errorf("%s_sum is not 0.25 for a 250ms handshake", name)
	}
	// 0.25s belongs above le=0.2 and at or below le=0.5. Under the old
	// millisecond boundaries the same handshake was recorded as 250 and fell
	// past le=1000 into +Inf, which read as "longer than 1000 seconds".
	for _, want := range []string{
		name + `_bucket{le="0.2"} 0`,
		name + `_bucket{le="0.5"} 1`,
		name + `_bucket{le="1"} 1`,
		name + `_bucket{le="+Inf"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s: missing bucket line %q", name, want)
		}
	}
}

// TestServerConnectionDurationStaysSeconds is the positive control. This
// histogram was already honest about its unit; the fix must leave it alone.
// Without it, a blanket "divide everything by 1000" would pass unnoticed.
func TestServerConnectionDurationStaysSeconds(t *testing.T) {
	m := NewMetrics(nil)
	m.qualityMetrics.RecordConnectionDuration(90 * time.Second)
	body := renderMetrics(t, m)

	const name = "tiredvpn_connection_duration_seconds"
	wantServerBounds(t, serverSeriesBounds(t, body, name),
		[]string{"1", "10", "30", "60", "300", "600", "1800", "3600", "7200", "+Inf"}, name)

	if !strings.Contains(body, name+"_sum 90\n") {
		t.Errorf("%s_sum is not 90 for a 90s connection", name)
	}
}

// TestServerRTTHistogramStaysMilliseconds is the second positive control: this
// series is named _milliseconds and must keep millisecond boundaries.
func TestServerRTTHistogramStaysMilliseconds(t *testing.T) {
	m := NewMetrics(nil)
	m.qualityMetrics.RecordRTT(25 * time.Millisecond)
	body := renderMetrics(t, m)

	const name = "tiredvpn_rtt_milliseconds"
	wantServerBounds(t, serverSeriesBounds(t, body, name),
		[]string{"1", "2", "5", "10", "20", "50", "100", "200", "500", "1000", "+Inf"}, name)

	if !strings.Contains(body, name+"_sum 25\n") {
		t.Errorf("%s_sum is not 25 for a 25ms RTT", name)
	}
}

// TestProtocolConfusionBucketsAreDistinct is the exposition half of the le fix
// seen through a real metric: its boundaries are 0.0…1.0 and used to collapse
// onto two duplicated series.
func TestProtocolConfusionBucketsAreDistinct(t *testing.T) {
	m := NewMetrics(nil)
	m.dpiMetrics.RecordProtocolConfusion("ssh", true)
	m.dpiMetrics.RecordProtocolConfusion("ssh", false)
	body := renderMetrics(t, m)

	const name = "tiredvpn_protocol_confusion_success_rate"
	wantServerBounds(t, serverSeriesBounds(t, body, name),
		[]string{"0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1", "+Inf"}, name)

	if !strings.Contains(body, name+`_bucket{type="ssh",le="0.5"} 1`) {
		t.Errorf("%s: the failed observation is not visible below le=0.5", name)
	}
	if !strings.Contains(body, name+`_bucket{type="ssh",le="1"} 2`) {
		t.Errorf("%s: the successful observation is not visible at le=1", name)
	}
}
