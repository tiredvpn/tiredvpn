package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Collector is a generic metrics collector with labels
type Collector struct {
	mu      sync.RWMutex
	metrics map[string]*MetricValue
}

// MetricValue holds a metric value with metadata
type MetricValue struct {
	Value     float64
	Labels    map[string]string
	Timestamp time.Time
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		metrics: make(map[string]*MetricValue),
	}
}

// Set sets a metric value with labels
func (c *Collector) Set(name string, value float64, labels map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.buildKey(name, labels)
	c.metrics[key] = &MetricValue{
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
}

// Get retrieves a metric value
func (c *Collector) Get(name string, labels map[string]string) (float64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.buildKey(name, labels)
	mv, ok := c.metrics[key]
	if !ok {
		return 0, false
	}
	return mv.Value, true
}

// GetAll returns all metrics with a given name
func (c *Collector) GetAll(name string) map[string]*MetricValue {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*MetricValue)
	for key, mv := range c.metrics {
		// Simple prefix match (could be improved)
		if len(key) >= len(name) && key[:len(name)] == name {
			result[key] = mv
		}
	}
	return result
}

// Delete removes a metric
func (c *Collector) Delete(name string, labels map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.buildKey(name, labels)
	delete(c.metrics, key)
}

// Clear removes all metrics
func (c *Collector) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.metrics = make(map[string]*MetricValue)
}

func (c *Collector) buildKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	// Sort label names so the key is stable across calls. Go map range order
	// is randomised per call, so an unsorted concatenation produced a different
	// key for the same labels between Set and Get - the value was stored under
	// one key and looked up under another.
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := name
	for _, k := range keys {
		key += ";" + k + "=" + labels[k]
	}
	return key
}

// CounterVec is a vector of counters with labels
type CounterVec struct {
	mu       sync.Mutex
	counters map[string]*uint64
}

// NewCounterVec creates a new counter vector
func NewCounterVec() *CounterVec {
	return &CounterVec{
		counters: make(map[string]*uint64),
	}
}

// Inc increments a counter
func (cv *CounterVec) Inc(labels map[string]string) {
	cv.Add(labels, 1)
}

// Add adds to a counter
func (cv *CounterVec) Add(labels map[string]string, delta uint64) {
	key := buildLabelsKey(labels)

	cv.mu.Lock()
	counter, ok := cv.counters[key]
	if !ok {
		var val uint64
		cv.counters[key] = &val
		counter = &val
	}
	cv.mu.Unlock()

	// Atomic increment: the map slot is guarded by mu, but the counter itself
	// is mutated after the lock is released, so concurrent Adds to the same key
	// race and lose updates without this. (The pointer stored in the map is
	// stable once created, so atomic access to *counter is safe post-unlock.)
	atomic.AddUint64(counter, delta)
}

// Get retrieves counter value
func (cv *CounterVec) Get(labels map[string]string) uint64 {
	key := buildLabelsKey(labels)

	cv.mu.Lock()
	counter, ok := cv.counters[key]
	cv.mu.Unlock()

	if !ok {
		return 0
	}
	return atomic.LoadUint64(counter)
}

func buildLabelsKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	// Sort for a stable key (see buildKey): without this, Inc and Get computed
	// different keys for the same label set and concurrent Incs split one
	// logical counter across several map entries.
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := ""
	for _, k := range keys {
		if key != "" {
			key += ";"
		}
		key += k + "=" + labels[k]
	}
	return key
}
