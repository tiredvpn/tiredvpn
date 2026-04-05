package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// RTTTracker tracks Round-Trip Time measurements
type RTTTracker struct {
	histogram *Histogram

	// Recent window for jitter calculation
	mu         sync.Mutex
	recentRTTs []float64
	maxRecent  int

	// Running statistics
	count uint64
	sum   uint64 // microseconds
	min   uint64 // microseconds
	max   uint64 // microseconds
}

// NewRTTTracker creates a new RTT tracker
func NewRTTTracker() *RTTTracker {
	// RTT buckets in milliseconds: 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000
	buckets := []float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000}

	return &RTTTracker{
		histogram:  NewHistogram(buckets),
		recentRTTs: make([]float64, 0, 100),
		maxRecent:  100,
		min:        ^uint64(0), // max uint64
	}
}

// Observe records a new RTT measurement
func (r *RTTTracker) Observe(rtt time.Duration) {
	microseconds := uint64(rtt.Microseconds())
	milliseconds := float64(rtt.Microseconds()) / 1000.0

	// Update histogram
	r.histogram.Observe(milliseconds)

	// Update running stats
	atomic.AddUint64(&r.count, 1)
	atomic.AddUint64(&r.sum, microseconds)

	// Update min
	for {
		oldMin := atomic.LoadUint64(&r.min)
		if microseconds >= oldMin {
			break
		}
		if atomic.CompareAndSwapUint64(&r.min, oldMin, microseconds) {
			break
		}
	}

	// Update max
	for {
		oldMax := atomic.LoadUint64(&r.max)
		if microseconds <= oldMax {
			break
		}
		if atomic.CompareAndSwapUint64(&r.max, oldMax, microseconds) {
			break
		}
	}

	// Update recent window for jitter
	r.mu.Lock()
	r.recentRTTs = append(r.recentRTTs, milliseconds)
	if len(r.recentRTTs) > r.maxRecent {
		r.recentRTTs = r.recentRTTs[1:]
	}
	r.mu.Unlock()
}

// GetHistogram returns the underlying histogram
func (r *RTTTracker) GetHistogram() *Histogram {
	return r.histogram
}

// GetMean returns average RTT in milliseconds
func (r *RTTTracker) GetMean() float64 {
	count := atomic.LoadUint64(&r.count)
	if count == 0 {
		return 0
	}
	sum := atomic.LoadUint64(&r.sum)
	return float64(sum) / float64(count) / 1000.0
}

// GetMin returns minimum RTT in milliseconds
func (r *RTTTracker) GetMin() float64 {
	min := atomic.LoadUint64(&r.min)
	if min == ^uint64(0) {
		return 0
	}
	return float64(min) / 1000.0
}

// GetMax returns maximum RTT in milliseconds
func (r *RTTTracker) GetMax() float64 {
	return float64(atomic.LoadUint64(&r.max)) / 1000.0
}

// GetJitter calculates jitter (variance in RTT) from recent samples
func (r *RTTTracker) GetJitter() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.recentRTTs) < 2 {
		return 0
	}

	// Calculate variance
	mean := 0.0
	for _, rtt := range r.recentRTTs {
		mean += rtt
	}
	mean /= float64(len(r.recentRTTs))

	variance := 0.0
	for _, rtt := range r.recentRTTs {
		diff := rtt - mean
		variance += diff * diff
	}
	variance /= float64(len(r.recentRTTs))

	// Return standard deviation as jitter
	return variance // Could use math.Sqrt(variance) for std dev
}

// BandwidthTracker tracks bandwidth utilization
type BandwidthTracker struct {
	mu             sync.Mutex
	windowStart    time.Time
	windowBytes    uint64
	windowDuration time.Duration

	// Peak tracking
	peakBps    uint64
	currentBps uint64
}

// NewBandwidthTracker creates a new bandwidth tracker
func NewBandwidthTracker(windowDuration time.Duration) *BandwidthTracker {
	return &BandwidthTracker{
		windowStart:    time.Now(),
		windowDuration: windowDuration,
	}
}

// Observe records bytes transferred
func (b *BandwidthTracker) Observe(bytes uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.windowStart)

	b.windowBytes += bytes

	// Update window if needed
	if elapsed >= b.windowDuration {
		// Calculate current bandwidth
		bps := uint64(float64(b.windowBytes) / elapsed.Seconds())
		atomic.StoreUint64(&b.currentBps, bps)

		// Update peak
		if bps > atomic.LoadUint64(&b.peakBps) {
			atomic.StoreUint64(&b.peakBps, bps)
		}

		// Reset window
		b.windowStart = now
		b.windowBytes = 0
	}
}

// GetCurrentBps returns current bandwidth in bytes per second
func (b *BandwidthTracker) GetCurrentBps() uint64 {
	return atomic.LoadUint64(&b.currentBps)
}

// GetPeakBps returns peak bandwidth in bytes per second
func (b *BandwidthTracker) GetPeakBps() uint64 {
	return atomic.LoadUint64(&b.peakBps)
}

// GetCurrentMbps returns current bandwidth in megabits per second
func (b *BandwidthTracker) GetCurrentMbps() float64 {
	return float64(atomic.LoadUint64(&b.currentBps)) * 8 / 1000000
}

// PacketLossEstimator estimates packet loss from retransmissions
type PacketLossEstimator struct {
	totalPackets uint64
	lostPackets  uint64
	retransmits  uint64
}

// ObservePackets records packet counts
func (p *PacketLossEstimator) ObservePackets(sent, lost uint64) {
	atomic.AddUint64(&p.totalPackets, sent)
	atomic.AddUint64(&p.lostPackets, lost)
}

// ObserveRetransmit records a retransmission
func (p *PacketLossEstimator) ObserveRetransmit() {
	atomic.AddUint64(&p.retransmits, 1)
}

// GetLossRate returns packet loss rate (0.0-1.0)
func (p *PacketLossEstimator) GetLossRate() float64 {
	total := atomic.LoadUint64(&p.totalPackets)
	if total == 0 {
		return 0
	}
	lost := atomic.LoadUint64(&p.lostPackets)
	return float64(lost) / float64(total)
}

// GetLossPercent returns packet loss percentage
func (p *PacketLossEstimator) GetLossPercent() float64 {
	return p.GetLossRate() * 100.0
}
