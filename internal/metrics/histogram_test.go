package metrics

import (
	"strings"
	"testing"
)

// leLabels returns the le label values of every _bucket line of metricName, in
// the order they were exported.
func leLabels(t *testing.T, exposition, metricName string) []string {
	t.Helper()

	var out []string
	for _, line := range strings.Split(exposition, "\n") {
		if !strings.HasPrefix(line, metricName+"_bucket{") {
			continue
		}
		i := strings.Index(line, `le="`)
		if i < 0 {
			t.Fatalf("bucket line without le label: %q", line)
		}
		rest := line[i+len(`le="`):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			t.Fatalf("unterminated le label: %q", line)
		}
		out = append(out, rest[:j])
	}
	return out
}

func assertLabels(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("le labels = %v (%d), want %v (%d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("le[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFormatPrometheusFractionalBuckets pins the fractional case. Rendering the
// boundary with %.0f made every bucket of a 0.0-1.0 histogram collapse onto
// le="0" or le="1": Prometheus keeps the last sample of a duplicated series, so
// the histogram silently lost all but two buckets.
func TestFormatPrometheusFractionalBuckets(t *testing.T) {
	h := NewHistogram([]float64{0.0, 0.1, 0.25, 0.5, 0.75, 1.0})
	h.Observe(0.3)

	out := h.FormatPrometheus("test_fraction", nil)
	assertLabels(t, leLabels(t, out, "test_fraction"),
		[]string{"0", "0.1", "0.25", "0.5", "0.75", "1", "+Inf"})

	// Cumulative counts must still line up with the boundaries they are printed
	// against; a formatting fix that shifted them would be worse than the bug.
	for _, want := range []string{
		`test_fraction_bucket{le="0.25"} 0`,
		`test_fraction_bucket{le="0.5"} 1`,
		`test_fraction_bucket{le="+Inf"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestFormatPrometheusFractionalBucketsWithLabels covers the second, separate
// formatting site: the branch that splices le into an existing label set. It
// carried its own copy of the %.0f verb, so fixing only the unlabelled branch
// would have left tiredvpn_protocol_confusion_success_rate broken.
func TestFormatPrometheusFractionalBucketsWithLabels(t *testing.T) {
	h := NewHistogram([]float64{0.0, 0.1, 0.25, 0.5, 0.75, 1.0})
	h.Observe(0.3)

	out := h.FormatPrometheus("test_fraction", map[string]string{"type": "ssh"})
	assertLabels(t, leLabels(t, out, "test_fraction"),
		[]string{"0", "0.1", "0.25", "0.5", "0.75", "1", "+Inf"})

	if !strings.Contains(out, `test_fraction_bucket{type="ssh",le="0.5"} 1`) {
		t.Errorf("labelled bucket line malformed in:\n%s", out)
	}
	if !strings.Contains(out, `test_fraction_sum{type="ssh"}`) {
		t.Errorf("labelled _sum line malformed in:\n%s", out)
	}
}

// TestFormatPrometheusIntegerBucketsStayPlain guards the other direction: a
// switch to exponent notation would turn le="1000" into le="1e+03". Prometheus
// parses both, but every dashboard and recording rule that matches on the
// literal label text would break.
func TestFormatPrometheusIntegerBucketsStayPlain(t *testing.T) {
	h := NewHistogram([]float64{1, 5, 100, 1000, 5000, 7200})
	h.Observe(3)

	out := h.FormatPrometheus("test_integer", nil)
	assertLabels(t, leLabels(t, out, "test_integer"),
		[]string{"1", "5", "100", "1000", "5000", "7200", "+Inf"})

	if strings.Contains(out, "e+") {
		t.Errorf("exponent notation leaked into exposition:\n%s", out)
	}
}

// TestFormatPrometheusSumKeepsPrecision pins the _sum verb. Once the duration
// histograms report seconds, a fixed two-decimal sum quantises every average to
// 10 ms and rounds sub-10 ms totals to zero.
func TestFormatPrometheusSumKeepsPrecision(t *testing.T) {
	h := NewHistogram([]float64{0.001, 0.005, 0.01})
	h.Observe(0.0125)

	out := h.FormatPrometheus("test_sum", nil)
	if !strings.Contains(out, "test_sum_sum 0.0125\n") {
		t.Errorf("_sum lost precision, want 0.0125, got:\n%s", out)
	}
	if !strings.Contains(out, "test_sum_count 1\n") {
		t.Errorf("_count malformed in:\n%s", out)
	}
}
