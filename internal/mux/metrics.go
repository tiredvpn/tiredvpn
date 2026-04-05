package mux

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks mux layer statistics
type Metrics struct {
	// Stream statistics
	StreamsOpened uint64 // Total streams opened
	StreamsClosed uint64 // Total streams closed
	StreamsActive int64  // Currently active streams (can go negative temporarily during race)
	StreamsFailed uint64 // Failed stream open attempts

	// Data transfer statistics
	BytesSent     uint64 // Total bytes sent across all streams
	BytesReceived uint64 // Total bytes received across all streams

	// Frame statistics
	FramesSent     uint64 // Total frames sent
	FramesReceived uint64 // Total frames received

	// Session statistics
	SessionsCreated  uint64    // Total sessions created
	SessionsClosed   uint64    // Total sessions closed
	SessionsActive   int64     // Currently active sessions
	SessionsFailed   uint64    // Failed session creation attempts
	LastSessionStart time.Time // When the last session was created

	// Error statistics
	ReadErrors  uint64 // Read errors encountered
	WriteErrors uint64 // Write errors encountered

	// Timing statistics
	mu              sync.RWMutex
	streamLatencies []time.Duration // Recent stream open latencies (ring buffer)
	latencyIdx      int             // Current position in ring buffer
	latencySize     int             // Size of ring buffer
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		streamLatencies: make([]time.Duration, 100), // Keep last 100 latencies
		latencySize:     100,
	}
}

// RecordStreamOpen records a stream being opened
func (m *Metrics) RecordStreamOpen(latency time.Duration) {
	atomic.AddUint64(&m.StreamsOpened, 1)
	atomic.AddInt64(&m.StreamsActive, 1)

	m.mu.Lock()
	m.streamLatencies[m.latencyIdx] = latency
	m.latencyIdx = (m.latencyIdx + 1) % m.latencySize
	m.mu.Unlock()
}

// RecordStreamClose records a stream being closed
func (m *Metrics) RecordStreamClose() {
	atomic.AddUint64(&m.StreamsClosed, 1)
	atomic.AddInt64(&m.StreamsActive, -1)
}

// RecordStreamFailed records a failed stream open
func (m *Metrics) RecordStreamFailed() {
	atomic.AddUint64(&m.StreamsFailed, 1)
}

// RecordBytesSent adds to the bytes sent counter
func (m *Metrics) RecordBytesSent(n uint64) {
	atomic.AddUint64(&m.BytesSent, n)
}

// RecordBytesReceived adds to the bytes received counter
func (m *Metrics) RecordBytesReceived(n uint64) {
	atomic.AddUint64(&m.BytesReceived, n)
}

// RecordFrameSent increments the frames sent counter
func (m *Metrics) RecordFrameSent() {
	atomic.AddUint64(&m.FramesSent, 1)
}

// RecordFrameReceived increments the frames received counter
func (m *Metrics) RecordFrameReceived() {
	atomic.AddUint64(&m.FramesReceived, 1)
}

// RecordSessionCreate records a new session being created
func (m *Metrics) RecordSessionCreate() {
	atomic.AddUint64(&m.SessionsCreated, 1)
	atomic.AddInt64(&m.SessionsActive, 1)
	m.mu.Lock()
	m.LastSessionStart = time.Now()
	m.mu.Unlock()
}

// RecordSessionClose records a session being closed
func (m *Metrics) RecordSessionClose() {
	atomic.AddUint64(&m.SessionsClosed, 1)
	atomic.AddInt64(&m.SessionsActive, -1)
}

// RecordSessionFailed records a failed session creation
func (m *Metrics) RecordSessionFailed() {
	atomic.AddUint64(&m.SessionsFailed, 1)
}

// RecordReadError records a read error
func (m *Metrics) RecordReadError() {
	atomic.AddUint64(&m.ReadErrors, 1)
}

// RecordWriteError records a write error
func (m *Metrics) RecordWriteError() {
	atomic.AddUint64(&m.WriteErrors, 1)
}

// GetActiveStreams returns the number of active streams
func (m *Metrics) GetActiveStreams() int64 {
	return atomic.LoadInt64(&m.StreamsActive)
}

// GetActiveSessions returns the number of active sessions
func (m *Metrics) GetActiveSessions() int64 {
	return atomic.LoadInt64(&m.SessionsActive)
}

// GetTotalBytes returns total bytes transferred
func (m *Metrics) GetTotalBytes() (sent, received uint64) {
	return atomic.LoadUint64(&m.BytesSent), atomic.LoadUint64(&m.BytesReceived)
}

// GetAverageStreamLatency returns the average stream open latency
func (m *Metrics) GetAverageStreamLatency() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var total time.Duration
	var count int
	for _, lat := range m.streamLatencies {
		if lat > 0 {
			total += lat
			count++
		}
	}

	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

// Snapshot returns a copy of current metrics
type MetricsSnapshot struct {
	StreamsOpened   uint64
	StreamsClosed   uint64
	StreamsActive   int64
	StreamsFailed   uint64
	BytesSent       uint64
	BytesReceived   uint64
	FramesSent      uint64
	FramesReceived  uint64
	SessionsCreated uint64
	SessionsClosed  uint64
	SessionsActive  int64
	SessionsFailed  uint64
	ReadErrors      uint64
	WriteErrors     uint64
	AvgLatency      time.Duration
	Timestamp       time.Time
}

// Snapshot returns a point-in-time copy of metrics
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		StreamsOpened:   atomic.LoadUint64(&m.StreamsOpened),
		StreamsClosed:   atomic.LoadUint64(&m.StreamsClosed),
		StreamsActive:   atomic.LoadInt64(&m.StreamsActive),
		StreamsFailed:   atomic.LoadUint64(&m.StreamsFailed),
		BytesSent:       atomic.LoadUint64(&m.BytesSent),
		BytesReceived:   atomic.LoadUint64(&m.BytesReceived),
		FramesSent:      atomic.LoadUint64(&m.FramesSent),
		FramesReceived:  atomic.LoadUint64(&m.FramesReceived),
		SessionsCreated: atomic.LoadUint64(&m.SessionsCreated),
		SessionsClosed:  atomic.LoadUint64(&m.SessionsClosed),
		SessionsActive:  atomic.LoadInt64(&m.SessionsActive),
		SessionsFailed:  atomic.LoadUint64(&m.SessionsFailed),
		ReadErrors:      atomic.LoadUint64(&m.ReadErrors),
		WriteErrors:     atomic.LoadUint64(&m.WriteErrors),
		AvgLatency:      m.GetAverageStreamLatency(),
		Timestamp:       time.Now(),
	}
}

// Reset clears all metrics
func (m *Metrics) Reset() {
	atomic.StoreUint64(&m.StreamsOpened, 0)
	atomic.StoreUint64(&m.StreamsClosed, 0)
	atomic.StoreInt64(&m.StreamsActive, 0)
	atomic.StoreUint64(&m.StreamsFailed, 0)
	atomic.StoreUint64(&m.BytesSent, 0)
	atomic.StoreUint64(&m.BytesReceived, 0)
	atomic.StoreUint64(&m.FramesSent, 0)
	atomic.StoreUint64(&m.FramesReceived, 0)
	atomic.StoreUint64(&m.SessionsCreated, 0)
	atomic.StoreUint64(&m.SessionsClosed, 0)
	atomic.StoreInt64(&m.SessionsActive, 0)
	atomic.StoreUint64(&m.SessionsFailed, 0)
	atomic.StoreUint64(&m.ReadErrors, 0)
	atomic.StoreUint64(&m.WriteErrors, 0)

	m.mu.Lock()
	m.streamLatencies = make([]time.Duration, m.latencySize)
	m.latencyIdx = 0
	m.mu.Unlock()
}

// Global metrics instance
var globalMetrics = NewMetrics()

// GetGlobalMetrics returns the global metrics instance
func GetGlobalMetrics() *Metrics {
	return globalMetrics
}
