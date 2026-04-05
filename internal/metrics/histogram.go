package metrics

import (
	"fmt"
	"math"
	"sort"
	"sync"
)

// Histogram is a simple histogram implementation for tracking value distributions
// Thread-safe for concurrent use
type Histogram struct {
	mu      sync.RWMutex
	buckets []float64      // Bucket boundaries
	counts  []uint64       // Counts per bucket
	sum     float64        // Sum of all observed values
	count   uint64         // Total number of observations
	min     float64        // Minimum observed value
	max     float64        // Maximum observed value
}

// NewHistogram creates a new histogram with predefined buckets
// buckets should be sorted in ascending order
func NewHistogram(buckets []float64) *Histogram {
	if len(buckets) == 0 {
		// Default buckets for latency (ms): 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000
		buckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}
	}

	sortedBuckets := make([]float64, len(buckets))
	copy(sortedBuckets, buckets)
	sort.Float64s(sortedBuckets)

	return &Histogram{
		buckets: sortedBuckets,
		counts:  make([]uint64, len(sortedBuckets)+1), // +1 for infinity bucket
		min:     math.MaxFloat64,
		max:     -math.MaxFloat64,
	}
}

// Observe records a new value
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update sum and count
	h.sum += value
	h.count++

	// Update min/max
	if value < h.min {
		h.min = value
	}
	if value > h.max {
		h.max = value
	}

	// Find bucket
	bucketIdx := len(h.buckets) // Default to infinity bucket
	for i, boundary := range h.buckets {
		if value <= boundary {
			bucketIdx = i
			break
		}
	}
	h.counts[bucketIdx]++
}

// Snapshot returns current histogram state
type HistogramSnapshot struct {
	Buckets []float64
	Counts  []uint64
	Sum     float64
	Count   uint64
	Min     float64
	Max     float64
}

// GetSnapshot returns a snapshot of current histogram state
func (h *Histogram) GetSnapshot() HistogramSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	counts := make([]uint64, len(h.counts))
	copy(counts, h.counts)

	return HistogramSnapshot{
		Buckets: h.buckets,
		Counts:  counts,
		Sum:     h.sum,
		Count:   h.count,
		Min:     h.min,
		Max:     h.max,
	}
}

// Mean returns the average value
func (h *Histogram) Mean() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.count == 0 {
		return 0
	}
	return h.sum / float64(h.count)
}

// Percentile calculates approximate percentile (0.0-1.0)
// Uses linear interpolation within buckets
func (h *Histogram) Percentile(p float64) float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.count == 0 {
		return 0
	}

	targetCount := uint64(float64(h.count) * p)
	cumulative := uint64(0)

	for i, count := range h.counts {
		cumulative += count
		if cumulative >= targetCount {
			if i == 0 {
				return h.buckets[0]
			}
			if i >= len(h.buckets) {
				return h.max
			}
			return h.buckets[i]
		}
	}

	return h.max
}

// Reset clears all histogram data
func (h *Histogram) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range h.counts {
		h.counts[i] = 0
	}
	h.sum = 0
	h.count = 0
	h.min = math.MaxFloat64
	h.max = -math.MaxFloat64
}

// FormatPrometheus formats histogram for Prometheus exposition
// metricName should NOT include _bucket/_sum/_count suffix
func (h *Histogram) FormatPrometheus(metricName string, labels map[string]string) string {
	snapshot := h.GetSnapshot()

	var result string
	labelStr := ""
	if len(labels) > 0 {
		labelStr = "{"
		first := true
		for k, v := range labels {
			if !first {
				labelStr += ","
			}
			labelStr += fmt.Sprintf("%s=\"%s\"", k, v)
			first = false
		}
		labelStr += "}"
	}

	// Buckets
	cumulative := uint64(0)
	for i, boundary := range snapshot.Buckets {
		cumulative += snapshot.Counts[i]
		bucketLabel := labelStr
		if bucketLabel == "" {
			bucketLabel = fmt.Sprintf("{le=\"%.0f\"}", boundary)
		} else {
			// Insert le label
			bucketLabel = bucketLabel[:len(bucketLabel)-1] + fmt.Sprintf(",le=\"%.0f\"}", boundary)
		}
		result += fmt.Sprintf("%s_bucket%s %d\n", metricName, bucketLabel, cumulative)
	}

	// +Inf bucket
	cumulative += snapshot.Counts[len(snapshot.Counts)-1]
	infLabel := labelStr
	if infLabel == "" {
		infLabel = "{le=\"+Inf\"}"
	} else {
		infLabel = infLabel[:len(infLabel)-1] + ",le=\"+Inf\"}"
	}
	result += fmt.Sprintf("%s_bucket%s %d\n", metricName, infLabel, cumulative)

	// Sum
	result += fmt.Sprintf("%s_sum%s %.2f\n", metricName, labelStr, snapshot.Sum)

	// Count
	result += fmt.Sprintf("%s_count%s %d\n", metricName, labelStr, snapshot.Count)

	return result
}
