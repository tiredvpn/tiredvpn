package strategy

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Handshake discipline constants.
//
// Russian TSPU applies a per-SNI heuristic on TLS handshake bursts: more than
// three concurrent handshakes to the same SNI, arriving 20-50 ms apart, within a
// 60 s window, freezes that SNI for 120 s. Changing the client's TLS fingerprint
// after such a freeze escalates it to a 600 s block of all TLS from the source
// address — which is why REALITYStrategy.fingerprint is fixed for the lifetime
// of the strategy and never rotated per connection.
//
// We break the heuristic on both of its conjuncts we can afford to break:
//
//   - Concurrency: at most two handshakes to one SNI are in flight at once,
//     one below the threshold.
//   - Spacing: consecutive handshake starts to one SNI are at least 250 ms
//     apart plus up to 250 ms of jitter, putting every inter-arrival an order of
//     magnitude outside the 20-50 ms band the rule keys on.
//
// We deliberately do NOT cap the count per 60 s window. Every CONNECT currently
// costs a fresh REALITY handshake (the connection pool's put() is dead), and the
// donor pool is four domains wide, so a hard 3-per-60 s cap would throttle the
// client to a dozen requests a minute. Breaking the interval half of the rule is
// what buys safety; capping the count would only buy unusability.
const (
	// maxConcurrentHandshakesPerSNI is one below the threshold that trips the
	// per-SNI freeze.
	maxConcurrentHandshakesPerSNI = 2

	// minHandshakeSpacing is the floor on the gap between two handshake starts
	// to the same SNI.
	minHandshakeSpacing = 250 * time.Millisecond

	// handshakeSpacingJitter is added on top of minHandshakeSpacing, uniformly
	// at random, so the spacing itself does not become a fixed-period signal.
	handshakeSpacingJitter = 250 * time.Millisecond
)

// handshakeGate throttles TLS handshake starts per donor SNI.
//
// It is safe for concurrent use: the TUN tunnel, the proxy pool and the health
// checker all dial through the same strategy instance.
type handshakeGate struct {
	maxConcurrent int
	minSpacing    time.Duration
	jitter        time.Duration

	// rnd is only used for jitter, never for anything security-relevant, so a
	// math/rand source guarded by its own mutex is fine.
	rndMu sync.Mutex
	rnd   *rand.Rand

	mu   sync.Mutex
	lane map[string]*sniLane
}

// sniLane holds the per-SNI state: an occupancy semaphore and the earliest
// instant at which the next handshake to this SNI may start.
type sniLane struct {
	slots chan struct{}

	mu          sync.Mutex
	nextAllowed time.Time
}

func newHandshakeGate() *handshakeGate {
	return newHandshakeGateWith(maxConcurrentHandshakesPerSNI, minHandshakeSpacing, handshakeSpacingJitter)
}

// newHandshakeGateWith builds a gate with explicit limits. Tests use it to run
// the same logic on millisecond timescales.
func newHandshakeGateWith(maxConcurrent int, minSpacing, jitter time.Duration) *handshakeGate {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &handshakeGate{
		maxConcurrent: maxConcurrent,
		minSpacing:    minSpacing,
		jitter:        jitter,
		rnd:           rand.New(rand.NewSource(time.Now().UnixNano())),
		lane:          make(map[string]*sniLane),
	}
}

func (g *handshakeGate) laneFor(sni string) *sniLane {
	g.mu.Lock()
	defer g.mu.Unlock()
	l, ok := g.lane[sni]
	if !ok {
		l = &sniLane{slots: make(chan struct{}, g.maxConcurrent)}
		g.lane[sni] = l
	}
	return l
}

func (g *handshakeGate) spacing() time.Duration {
	if g.jitter <= 0 {
		return g.minSpacing
	}
	g.rndMu.Lock()
	defer g.rndMu.Unlock()
	return g.minSpacing + time.Duration(g.rnd.Int63n(int64(g.jitter)))
}

// acquire blocks until a handshake to sni may start, and returns the function
// that releases the slot. The returned release is nil when the error is
// non-nil; callers must call it exactly once (defer) once they have it.
//
// Cancellation of ctx aborts the wait. The caller's dial deadline therefore
// bounds the total time spent queued, and a queued dial dies with the request
// that asked for it rather than outliving it.
func (g *handshakeGate) acquire(ctx context.Context, sni string) (func(), error) {
	lane := g.laneFor(sni)

	select {
	case lane.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	release := func() { <-lane.slots }

	wait := lane.reserve(time.Now(), g.spacing())
	if wait <= 0 {
		return release, nil
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return release, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

// reserve claims the next handshake slot on the timeline and reports how long
// the caller must wait before starting. It advances nextAllowed by spacing from
// whichever is later: now, or the previously reserved instant. Reserving under
// the lock (rather than sleeping under it) is what makes concurrent callers
// queue up behind each other instead of all waking at the same moment.
func (l *sniLane) reserve(now time.Time, spacing time.Duration) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	start := now
	if l.nextAllowed.After(start) {
		start = l.nextAllowed
	}
	l.nextAllowed = start.Add(spacing)
	return start.Sub(now)
}
