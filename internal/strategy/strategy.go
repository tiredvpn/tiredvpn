package strategy

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/mux"
	"github.com/tiredvpn/tiredvpn/internal/porthopping"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// clientSocketBufferBytes is the SO_RCVBUF/SO_SNDBUF size applied to client TCP
// sockets in optimizeTCPConn. On high-RTT censored links (150-300ms) the BDP far
// exceeds the old 64KB default, which capped the TCP window and throughput. This
// matches the 4MB the server already uses (server/upstream.go, server/server.go).
const clientSocketBufferBytes = 4 * 1024 * 1024

// Strategy defines interface for DPI evasion techniques
type Strategy interface {
	// Name returns human-readable strategy name
	Name() string

	// ID returns unique strategy identifier
	ID() string

	// Priority returns execution priority (lower = try first)
	Priority() int

	// Probe tests if this strategy works in current network conditions
	// Returns nil if strategy is likely to work
	Probe(ctx context.Context, target string) error

	// Connect establishes connection using this strategy
	Connect(ctx context.Context, target string) (net.Conn, error)

	// RequiresServer returns true if strategy needs special server support
	RequiresServer() bool

	// Description returns detailed description
	Description() string
}

// Result holds strategy execution result with extended statistics
type Result struct {
	Strategy   Strategy
	Success    bool
	Latency    time.Duration
	Error      error
	TestedAt   time.Time
	Confidence float64 // 0.0 - 1.0, based on historical success

	// Extended statistics for adaptive scoring
	SuccessCount    int64
	FailureCount    int64
	ConsecutiveFail int
	LastSuccess     time.Time
	LastFailure     time.Time
	AvgLatency      time.Duration
	LatencySum      time.Duration // for calculating average
	LatencyCount    int64
}

// Manager manages multiple strategies and performs auto-fallback
type Manager struct {
	strategies []Strategy
	results    map[string]*Result
	mu         sync.RWMutex

	// Config
	probeTimeout   time.Duration
	connectTimeout time.Duration
	maxRetries     int
	parallelProbes int
	adaptiveOrder  bool // Reorder strategies based on success rate

	// burstReshape configures the nudge/ack exchange that splits the inner
	// handshake. Off unless the operator turns it on, and it must be on at both
	// ends - see internal/strategy/burst_reshape.go.
	burstReshape BurstReshapeConfig

	// Circuit breaker
	circuitBreakers *CircuitBreakerManager

	// Storm detector: catches strategies that connect successfully but whose
	// sessions are repeatedly torn down (e.g. DPI killing a REALITY pattern
	// after a few seconds). The circuit breaker cannot see this because every
	// connect() succeeds.
	stormDetector *StormDetector

	// forced is true when ForceStrategy() was called (user passed -strategy X).
	// In forced mode storms are logged loudly but never trigger a switch.
	forced bool

	// Periodic re-probe. There is deliberately no cached target here: the
	// reprobe must follow whichever candidate is pinned right now, and a copy
	// written once at start-up cannot. All four consumers call GetServerAddr.
	reprobeInterval time.Duration
	stopReprobe     chan struct{}
	reprobeRunning  bool
	reprobeHeld     atomic.Bool // see HoldReprobe

	// Emergency re-probe (for network recovery)
	emergencyReprobeRunning bool
	emergencyReprobeStop    chan struct{}
	lastEmergencyReprobe    time.Time
	emergencyInterval       time.Duration // mean pause between emergency reprobes

	// Manager lifecycle. Background goroutines the manager spawns on its own
	// (e.g. the emergency reprobe fired from a failed scan) hang off lifeCtx so
	// Close cancels them instead of leaving them to run out their own budget
	// after the manager is discarded. Set once in NewManager, never mutated.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	// RTT Masking
	rttMaskingEnabled bool
	rttProfile        *RTTProfile

	// Mux configuration
	muxEnabled          bool
	muxConfig           *mux.Config
	muxClient           *mux.Client
	muxConn             net.Conn   // underlying connection for mux
	muxStrategy         Strategy   // strategy that established the live mux carrier (under muxMu)
	muxMu               sync.Mutex // separate mutex for mux operations
	recyclingInProgress bool       // true while budget recycling goroutine is running (under muxMu)

	// Last successful strategy for fast reconnect
	lastSuccessfulStrategy Strategy
	lastSuccessfulTime     time.Time // When the last successful connection was made

	// Fast-reconnect loop guard. connectWithRTT re-uses lastSuccessfulStrategy on
	// a "fast reconnect" path while it is not parked. A strategy that connects
	// fine but whose tunnel dies seconds later (meek under DPI) can ride that path
	// in a tight loop without the storm detector ever parking it (the storm
	// detector keys on session lifetime; these sessions can outlive the short
	// threshold). These fields count consecutive fast reconnects of one strategy
	// inside fastReconnectWindow; past the limit the fast path is skipped so a
	// full scan gives other strategies (and the detector) a turn. Guarded by m.mu.
	fastReconnectStrategy string
	fastReconnectCount    int
	fastReconnectFirst    time.Time
	fastReconnectLast     time.Time // when the previous counted attempt happened

	// swallowed is, per server (swallowKey), the run of reconnect cycles that
	// ended with no verdict because a connected handshake heard nothing (see
	// swallowCycle). Guarded by m.mu.
	swallowed map[string]*swallowRecord

	// unansweredHS is, per server (swallowKey), the run of session
	// handshakes that went unanswered after their transport had connected
	// (HandshakeUnanswered). Guarded by m.mu.
	unansweredHS map[string]*handshakeRun

	// Connectivity checker for pre-flight checks
	connectivityChecker  *ConnectivityChecker
	excludeUDPStrategies bool // Temporarily exclude UDP-based strategies if UDP is blocked
	// udpGatePending marks an exclusion set by udpGateDeferQUIC rather than by
	// a verdict: the next scan replaces it with the verdict once it has landed.
	udpGatePending bool
	// udpGateRefreshHook, when set, runs in udpGateRefresh between reading the
	// verdict and taking the lock to apply it. Tests only.
	udpGateRefreshHook func()

	// routeReachable, when set, reports whether the host has a physical route
	// (off the tunnel) to a candidate address's family, and whether that answer
	// is known. Injected from the TUN layer; nil in tests and on platforms
	// without a route table. The family preflight uses it to drop no-route
	// families - an IPv6 endpoint on a host with no IPv6 - before the strategy
	// scan, instead of letting each dial time out into the tunnel. Guarded by
	// m.mu.
	routeReachable func(addr string) (routable, known bool)

	// consecutiveConnectFailures counts back-to-back failed Connect() calls. The
	// blocking pre-flight connectivity check is skipped on the hot reconnect path
	// (a brief server-side RST/EOF should not cost a full check) and only re-armed
	// after this many failures in a row, which is the real "network is down"
	// signal rather than a one-off reset. Reset on any successful connect.
	// Guarded by m.mu.
	consecutiveConnectFailures int

	// preflightArmed makes the next Connect run the pre-flight gate even on
	// the hot reconnect path. Set by NoteServerSilent when the tunnel died of
	// silence; cleared by the gate run it causes. Guarded by m.mu.
	preflightArmed bool

	// lastDeath is the last verdict a session or a cycle gave a server (see
	// routeDeath); server -1 when a useful session has ended since. Guarded by
	// m.mu.
	lastDeath deathMark

	// routeParked holds, per server (endpoint index), the transports a
	// route verdict set aside there and until when (routeDeath). Guarded by
	// m.mu.
	routeParked map[int]map[string]time.Time

	// Strategy upgrade (see offerUpgrade). upgradeCallback receives the
	// candidates a periodic reprobe found working; upgradeFails counts each
	// strategy's consecutive failed upgrade dials and upgradeSkip how many more
	// reprobes it sits out. Guarded by m.mu.
	upgradeCallback func([]Strategy)
	upgradeFails    map[string]int
	upgradeSkip     map[string]int

	// Android mode - deprioritize QUIC/UDP strategies
	androidMode bool

	// Android adaptive strategy selection
	consecutiveTCPTimeouts int // Count of consecutive TCP strategy timeouts
	tcpFailuresBeforeQUIC  int // Threshold before fast-switching to QUIC (default: 3)

	// Last connection info (for Android UI and metrics)
	lastConnectionLatency    time.Duration
	lastConnectionAttempts   int
	lastConnectionStrategy   string
	lastConnectionStrategyID string

	// Port hopping for DPI evasion
	portHopper        *porthopping.PortHopper
	portHopperStop    chan struct{}
	portHopperMu      sync.Mutex
	portHopCallback   func(oldPort, newPort int) // External callback for port hop events (e.g., VPN reconnect)
	portHopCallbackMu sync.Mutex

	// Endpoint selection: which server, on which address family, we currently
	// dial. Replaces the old serverAddrV4/serverAddrV6 pair together with the
	// one-shot ipv6CheckedOnce verdict, which was decided once per process and
	// never revisited outside the Android control socket. Guarded by m.mu; the
	// selector itself is safe for concurrent use.
	endpoints *endpoint.Selector

	// secret is the process-wide shared secret: -secret / TIREDVPN_SECRET, or
	// the one value a config file gave every server. It is the fallback for
	// endpoints that do not carry a secret of their own - see secret.go for how
	// the secret in force reaches a strategy. Guarded by m.mu.
	secret []byte

	// Shared TLS client session cache for resumption across reconnects.
	// The adaptive manager reconnects frequently (fallback, reprobe); without a
	// shared cache every stdlib-TLS strategy does a full handshake each time,
	// costing 1-2 extra RTTs. tls.ClientSessionCache is safe for concurrent use,
	// and resumption is keyed by ServerName, so strategies with different SNI
	// never collide. Set once at construction, never mutated => race-free.
	tlsSessionCache tls.ClientSessionCache
}

// Fast-reconnect loop-guard tuning. See Manager.fastReconnectStrategy.
const (
	fastReconnectLimit  = 3                // fast reconnects of one strategy allowed before forcing a full scan
	fastReconnectWindow = 5 * time.Minute  // window over which fast reconnects are counted
	fastReconnectGap    = 30 * time.Second // max pause between counted reconnects; a longer one means the session held
)

// errStrategyScanFailed marks the one failure mode that says something about
// the ENDPOINT rather than about a strategy: every eligible transport was tried
// against this address and every one of them died. dialEndpoints keys its
// candidate switch on it, so it must not be attached to "context cancelled" or
// "nothing was eligible", which say nothing about the address.
var errStrategyScanFailed = errors.New("all strategies failed")

// errAddrRefused is the verdict that the address's port is closed: a TCP
// strategy's dial to it came back with ECONNREFUSED, and kept doing so through
// refusalRetries. Every TCP transport rides that one port, so the next strategy
// in the list cannot do better, and the failure says nothing about the strategy
// that met it. A server being restarted refuses for half a second; walking the
// list through that half second used to land the client on whichever strategy
// happened to be dialling when the port reopened - HTTP Polling, on the stand
// and in production.
//
// Errors carrying it also carry errStrategyScanFailed: a port that stays
// closed is an endpoint verdict, and the walk moves on to the next candidate.
var errAddrRefused = errors.New("address refused the connection")

// refusalRetries is how long a refused strategy waits before dialling the same
// address again, one entry per retry. 1.75 s in all: a restart (0.4-0.6 s on
// the stand) is over within it, a stopped server is not.
var refusalRetries = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second}

// connectThroughRefusal dials s with an attempt limit, and when the address
// refuses, waits and dials it again per refusalRetries. refused reports that
// the last answer was still a refusal.
//
// dialLimit, when shorter than limit, is how long the attempt may wait for its
// TCP connect. An attempt whose connect is up by then runs on to limit: its
// handshake is under way, and cutting it is how a REALITY handshake that needs
// 7-9 s (a slow path, a server reaching its cover domain) lost the cycle to
// HTTP Polling. Only dials through protect.ProtectDialer report the connect;
// a strategy dialling on its own is held to dialLimit as a whole.
func (m *Manager) connectThroughRefusal(ctx context.Context, s Strategy, target string, limit, dialLimit time.Duration, scan *scanState) (conn net.Conn, latency time.Duration, refused bool, err error) {
	_, reporter := s.(connectReporter)
	if !reporter && dialLimit > 0 {
		limit, dialLimit = attemptLimit(s, limit, dialLimit), 0
	}
	for i := 0; ; i++ {
		connectCtx, cancel := context.WithTimeout(ctx, limit)
		phase := watchConnect(connectCtx, cancel, limit, dialLimit, reporter)
		start := time.Now()
		conn, err = s.Connect(phase.ctx, target)
		latency = time.Since(start)
		phase.stop()
		cancel()
		switch {
		case err == nil:
		case phase.wasCut():
			err = fmt.Errorf("%w: %w", errTCPConnectCut, err)
		case phase.neverDialled():
			err = fmt.Errorf("%w: %w", errNotDialled, err)
		}
		// How long the attempt had to hear an answer: since its TCP connect
		// when that is known, else its whole run.
		scan.allowance = latency
		if at := phase.connectedAt.Load(); at != 0 {
			scan.allowance = time.Since(time.Unix(0, at))
		}
		if err != nil && phase.extended() && phase.connected() && heardNothing(err, latency, limit) &&
			m.swallowEvidence(s, scan.allowance) {
			scan.connectedSilent = append(scan.connectedSilent, s.ID())
		}
		if err == nil || isUDPBasedStrategy(s) || !refusedByAddr(err, target, m.GetServerAddr(ctx)) {
			return conn, latency, false, err
		}
		if i >= len(refusalRetries) {
			return nil, latency, true, err
		}
		if i == 0 {
			log.Info("%s: %s refused the connection - waiting for the port instead of trying other transports on it", s.Name(), target)
		}
		select {
		case <-ctx.Done():
			return nil, latency, true, err
		case <-time.After(refusalRetries[i]):
		}
	}
}

// attemptLimit is how long connectThroughRefusal lets one attempt of s run:
// limit, or dialLimit as a whole for a strategy that does not report its TCP
// connect. Its silence is read against the same figure: read against limit,
// an attempt cut at half of it never burned "nearly all of its budget", and a
// cut that came back as "use of closed network connection" counted as an
// answer.
func attemptLimit(s Strategy, limit, dialLimit time.Duration) time.Duration {
	if _, ok := s.(connectReporter); ok || dialLimit <= 0 {
		return limit
	}
	return min(limit, dialLimit)
}

// connectReporter marks a strategy whose Connect dials the server only through
// protect.ProtectDialer, so the manager hears when its TCP connect is up (see
// connectThroughRefusal). A strategy without it gives no such signal, and a cut
// at the dial limit could land in the middle of its handshake.
type connectReporter interface{ reportsTCPConnect() }

func (*REALITYStrategy) reportsTCPConnect()     {}
func (*SeqovlStrategy) reportsTCPConnect()      {}
func (*HTTP2StegoStrategy) reportsTCPConnect()  {}
func (*HTTPPollingStrategy) reportsTCPConnect() {}

// Connect phases of one attempt, see watchConnect.
const (
	phaseLocal     int32 = iota // no TCP dial out yet: a local wait, a handshake gate
	phaseDialling               // the TCP dial is out
	phaseConnected              // the TCP connect is up, the handshake under way
	phaseCut                    // cut at the dial limit while dialling
	phaseCutLocal               // cut at the dial limit before any dial went out
)

// connectPhase follows one attempt through its TCP connect.
type connectPhase struct {
	ctx         context.Context
	state       atomic.Int32
	timer       *time.Timer
	split       bool
	tracked     bool         // the strategy reports its dial, so state is known
	connectedAt atomic.Int64 // UnixNano of the TCP connect, 0 before
}

// dialCutTimer arms an attempt's dialLimit cut. A var so a test can fire the
// cut itself rather than race a wall-clock budget under load.
var dialCutTimer = time.AfterFunc

// watchConnect follows an attempt on ctx, whose cancel is cancel, through its
// TCP dial when the strategy reports it (hooked), and arms the dialLimit cut
// of connectThroughRefusal. Without a split (dialLimit zero or not shorter
// than limit) the attempt simply runs to limit.
func watchConnect(ctx context.Context, cancel context.CancelFunc, limit, dialLimit time.Duration, hooked bool) *connectPhase {
	p := &connectPhase{ctx: ctx}
	if !hooked {
		return p
	}
	p.tracked = true
	p.ctx = protect.WithDialHooks(ctx,
		func() {
			// A dial after a connect - Stego's second try without ECH - is
			// a TCP connect still to come, and the dial limit bounds it too.
			if !p.state.CompareAndSwap(phaseLocal, phaseDialling) {
				p.state.CompareAndSwap(phaseConnected, phaseDialling)
			}
		},
		func() {
			p.connectedAt.Store(time.Now().UnixNano())
			p.state.CompareAndSwap(phaseLocal, phaseConnected)
			p.state.CompareAndSwap(phaseDialling, phaseConnected)
		})
	if dialLimit <= 0 || dialLimit >= limit {
		return p
	}
	p.split = true
	p.timer = dialCutTimer(dialLimit, func() {
		if p.state.CompareAndSwap(phaseDialling, phaseCut) || p.state.CompareAndSwap(phaseLocal, phaseCutLocal) {
			cancel()
		}
	})
	return p
}

func (p *connectPhase) stop() {
	if p.timer != nil {
		p.timer.Stop()
	}
}

// extended reports an attempt allowed past dialLimit once connected.
func (p *connectPhase) extended() bool { return p.split }

func (p *connectPhase) connected() bool { return p.state.Load() == phaseConnected }

// wasCut reports an attempt stopped at dialLimit with its TCP dial out and no
// connect.
func (p *connectPhase) wasCut() bool { return p.state.Load() == phaseCut }

// neverDialled reports an attempt of a strategy that reports its dial which
// ended - cut at dialLimit, out of time, or failed - before its TCP dial went
// out at all.
func (p *connectPhase) neverDialled() bool {
	st := p.state.Load()
	return p.tracked && (st == phaseLocal || st == phaseCutLocal)
}

// errNotDialled marks an attempt that ended while it was still waiting on the
// client - REALITY queued at its per-SNI handshake gate - with no packet sent.
// It says nothing about the address.
var errNotDialled = errors.New("cut before any TCP dial went out")

// errTCPConnectCut marks an attempt cut at its dial limit before its TCP
// connect completed: a dial timeout, whatever the strategy made of the
// cancellation.
var errTCPConnectCut = tcpConnectCut{}

type tcpConnectCut struct{}

func (tcpConnectCut) Error() string   { return "no TCP connect within the attempt's dial limit" }
func (tcpConnectCut) Timeout() bool   { return true }
func (tcpConnectCut) Temporary() bool { return true }

// refusedScan is the error a scan ends with when the address kept refusing.
func refusedScan(target string, err error) error {
	log.Warn("Address %s refused every connection for %v - port closed", target, sumDurations(refusalRetries))
	return fmt.Errorf("%w: %w: %w", errAddrRefused, errStrategyScanFailed, err)
}

func sumDurations(ds []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	return total
}

// refusedByAddr reports whether err is a refused dial to one of addrs. The
// address check keeps a refusal from somewhere else - a relay, another port -
// from being read as a verdict about the server. A name instead of an IP in
// addrs (a single-server client configured by hostname) matches on the port.
func refusedByAddr(err error, addrs ...string) bool {
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	opErr, ok := errors.AsType[*net.OpError](err)
	if !ok || opErr.Op != "dial" || opErr.Addr == nil {
		return false
	}
	gotHost, gotPort, err := net.SplitHostPort(opErr.Addr.String())
	if err != nil {
		return false
	}
	gotIP := net.ParseIP(gotHost)
	for _, a := range addrs {
		host, port, err := net.SplitHostPort(a)
		if err != nil || port != gotPort {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.Equal(gotIP) {
			return true
		}
	}
	return false
}

// ErrNoServerAnswered is the pre-flight gate's verdict that it walked every
// address it was given and not one completed a TCP handshake. It is about the
// path to the whole pool, not about any strategy or any one endpoint: the
// caller decides whether that means "no network" or "servers unreachable from
// this network", and in neither case does backing off longer help it notice
// the moment one of them answers again.
var ErrNoServerAnswered = errors.New("no connectivity to server")

// ErrAddrSilent is errAddrSilent for callers outside the package: the cycle
// ended because an address answered no transport.
var ErrAddrSilent = errAddrSilent

// ErrCycleUnanswered marks a connect cycle that ended with no verdict on the
// address while the transports it dialled heard nothing back: a swallowed
// handshake that used up the cycle, a cut attempt. Not silence yet (one cycle
// is never a verdict), but nothing a longer backoff helps with either: the
// reconnect loop caps its backoff as it does for silence.
var ErrCycleUnanswered = errors.New("connect cycle heard nothing back")

// errAddrSilent narrows errStrategyScanFailed: the scan was abandoned because
// the address accepted connections and then answered nothing, on one transport
// after another. Every failure was a timeout at connectTimeout - no refusal, no
// reset, no protocol error - which is what a blackholed address looks like and
// what no application-layer disguise can talk its way out of.
//
// Errors carrying it also carry errStrategyScanFailed, so dialEndpoints still
// treats it as an endpoint verdict; the extra sentinel only says the verdict is
// strong enough to act on at once.
var errAddrSilent = errors.New("address answered no transport")

// androidSilentScanAbort is how many consecutive non-UDP strategies must die on
// the connect timeout before an Android scan gives up on the address.
//
// Two rather than the desktop three because the VPN service abandons a connect
// after ~26s and rebuilds the client: with connectTimeout at 10s, a verdict
// reached at 30s is a verdict nobody is left to hear.
const androidSilentScanAbort = 2

// silenceLatency is the share of the connect timeout an attempt has to burn
// before it counts as having heard nothing back, whatever its error says.
//
// Not the full timeout: the deadline fires a hair before the caller measures,
// and a strategy that gives up a moment early on its own inner deadline heard
// just as little. Not much less either - a transport that got an answer and
// disliked it comes back in milliseconds, nowhere near this line.
func silenceLatency(connectTimeout time.Duration) time.Duration {
	return connectTimeout - connectTimeout/10
}

// attemptBudget is how long a strategy attempt started now can really run: the
// connect timeout, unless the caller's context runs out first. The reconnect
// loop gives a whole cycle 15 seconds and a single attempt is allowed 30, so
// measuring silence against the 30 never fired - the deadline cut the attempt
// at 15 and the scan read that as an answer.
func (m *Manager) attemptBudget(ctx context.Context) time.Duration {
	budget := m.connectTimeout
	if dl, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(dl))
	}
	return budget
}

// addrUnreachable reports a dial that went out and found no host: nothing came
// back from the server, and every transport aimed at the same address meets
// the same wall. On a shared segment a dead host shows up exactly like this,
// after the kernel's neighbour discovery gives up, rather than as a timeout.
//
// ENETUNREACH is not in it: that is the local stack with no route at all, the
// client's network rather than the server, and charging the address for it
// parked live servers whenever the link was down (the selector already reads
// it as local, see ProbeCurrent).
func addrUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH)
}

// heardNothing reports whether a failed attempt is evidence of silence: a
// timeout, an attempt that burned (nearly) its whole budget whatever its error
// says, or a dial that could not reach the address.
func heardNothing(err error, latency, budget time.Duration) bool {
	return isTimeoutError(err) || latency >= silenceLatency(budget) || addrUnreachable(err)
}

// attemptSilence is what one failed attempt says about the address.
type attemptSilence int

const (
	attemptAnswered     attemptSilence = iota // a refusal, a reset, a rejected handshake
	attemptSilent                             // heard nothing: counts toward the silence verdict
	attemptInconclusive                       // cut short by a shortened budget after TCP connected
	attemptNotDialled                         // cut while still waiting locally: nothing went out
)

// classifyAttempt reads a failed attempt. heardNothing is the base; an attempt
// whose budget was shortened below connectTimeout (half of a short cycle) is
// silence only if the TCP connect itself never completed - a dial timeout or
// an unreachable host. A handshake still waiting when the shortened budget ran
// out heard nothing in less time than a server is given to answer, so it is
// no verdict either way: counting it parked live servers whose Polling
// handshake simply needed a couple of seconds.
func (m *Manager) classifyAttempt(err error, latency, budget time.Duration) attemptSilence {
	if errors.Is(err, errNotDialled) {
		return attemptNotDialled
	}
	if !heardNothing(err, latency, budget) {
		return attemptAnswered
	}
	if budget < m.connectTimeout && !dialNeverConnected(err) {
		return attemptInconclusive
	}
	return attemptSilent
}

// dialNeverConnected reports a failure in the TCP connect itself: a dial that
// timed out, or a host that could not be reached.
func dialNeverConnected(err error) bool {
	if addrUnreachable(err) || errors.Is(err, errTCPConnectCut) {
		return true
	}
	opErr, ok := errors.AsType[*net.OpError](err)
	return ok && opErr.Op == "dial" && opErr.Timeout()
}

// scanOutOfTime ends a scan whose context ran out.
//
// Two silent transports at least: one swallowed handshake is a property of that
// transport (a censor that resets or eats only REALITY's), not of the address.
//
// A deadline that fell while the address had answered nothing is the silence
// verdict, reached the slow way: the caller's budget ran out before
// tcpFailuresBeforeQUIC transports could each time out. Reporting it as a plain
// context error left the address unpunished, so the next cycle dialled the same
// silent server with the same result.
func scanOutOfTime(ctx context.Context, target string, scan *scanState, lastErr error) error {
	err := ctxErr(ctx)
	if errors.Is(err, context.DeadlineExceeded) && !scan.answered && scan.timeouts >= 2 {
		log.Info("Address %s answered nothing on %d transports before the connect budget ran out",
			target, scan.timeouts)
		if lastErr == nil {
			lastErr = err
		}
		return fmt.Errorf("%w: %w, last error: %w", errAddrSilent, errStrategyScanFailed, lastErr)
	}
	log.Warn("Connection cancelled by context")
	return err
}

// ctxErr is ctx.Err(), except that a deadline already behind us reads as
// context.DeadlineExceeded even before the context's own timer has fired.
//
// That timer runs on its own and can be late. A dial bounded by the same
// deadline comes back with "i/o timeout" from the netpoller first, and under
// load the scan then found ctx.Err() still nil: the last transport's silence
// read as an ordinary failure, the endpoint walk moved to the next server on a
// context about to expire, and the cycle ended with no verdict at all.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return nil
}

// preflightFailThreshold is how many consecutive failed connects must pile up
// before Connect re-arms the blocking pre-flight connectivity check. See
// Manager.consecutiveConnectFailures.
const preflightFailThreshold = 2

// hasUDPStrategies reports whether any registered strategy rides UDP - the
// only reason to spend a UDP probe on the gate.
func (m *Manager) hasUDPStrategies() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.ContainsFunc(m.strategies, isUDPBasedStrategy)
}

// NoteServerSilent tells the manager the tunnel died because the server went
// quiet - a read deadline, not a reset or an EOF.
//
// The hot reconnect path skips the pre-flight gate on the theory that a server
// which just reset us is back in a moment and the real connect reaches it
// first. Silence is the opposite case: the address may be gone, and every
// strategy dialled at it burns the reconnect budget on a SYN nobody answers.
// The gate walks the whole pool for the price of a few TCP handshakes and pins
// whatever answers, so the next Connect runs it instead of waiting for
// preflightFailThreshold failed cycles - on the stand that was 42 seconds of
// outage spent before the gate was allowed to look.
func (m *Manager) NoteServerSilent() {
	m.mu.Lock()
	m.preflightArmed = true
	m.mu.Unlock()
}

// PreflightArmed reports whether the next Connect runs the pre-flight gate
// regardless of the hot-path rule (see NoteServerSilent).
func (m *Manager) PreflightArmed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.preflightArmed
}

// recordConnectResult tracks the consecutive-failure streak that gates the
// pre-flight connectivity check on reconnect.
func (m *Manager) recordConnectResult(success bool) {
	m.mu.Lock()
	if success {
		m.consecutiveConnectFailures = 0
	} else {
		m.consecutiveConnectFailures++
	}
	m.mu.Unlock()
}

// applyUDPGate flips QUIC/UDP strategy exclusion based on a fresh UDP probe.
func (m *Manager) applyUDPGate(udpOK bool) {
	m.mu.Lock()
	m.applyUDPGateLocked(udpOK)
	m.mu.Unlock()
}

// applyUDPGateLocked is applyUDPGate for a caller that holds m.mu.
func (m *Manager) applyUDPGateLocked(udpOK bool) {
	m.udpGatePending = false
	if !udpOK {
		if !m.excludeUDPStrategies {
			log.Info("UDP not working, temporarily excluding QUIC strategies")
		}
		m.excludeUDPStrategies = true
	} else {
		if m.excludeUDPStrategies {
			log.Info("UDP connectivity restored, QUIC strategies enabled")
		}
		m.excludeUDPStrategies = false
	}
}

// udpGateDeferQUIC handles a pre-flight that ended before the UDP probe did.
//
// Forced mode keeps QUIC: the user asked for it and there is nothing else to
// try. Auto mode lets it sit out this scan instead, exactly as it did before
// verdicts were tracked, and on purpose now: the probe cannot see a silent
// drop (its "UDP works" is just its read timeout), so the pending verdict
// adds nothing, while a QUIC dial into a dropped path costs ~10s of handshake
// timeout ahead of every TCP strategy. The verdict lands in the checker's
// cache, and udpGateRefresh applies it at the start of the next scan.
func (m *Manager) udpGateDeferQUIC() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.forced {
		return
	}
	if !m.excludeUDPStrategies {
		log.Debug("UDP verdict not in yet, QUIC strategies sit out this scan")
	}
	m.udpGateDeferQUICLocked()
}

// udpGateDeferQUICLocked is the auto-mode half of udpGateDeferQUIC, for a
// caller that holds m.mu and has already ruled out forced mode.
func (m *Manager) udpGateDeferQUICLocked() {
	m.excludeUDPStrategies = true
	m.udpGatePending = true
}

// quicGateRTT is the path RTT the connectivity gate measured to host (the
// minimum TCP connect time to it), 0 when there is none. Nil-safe: strategies
// built without a manager in tests ask too.
func (m *Manager) quicGateRTT(host string) time.Duration {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	c := m.connectivityChecker
	m.mu.RUnlock()
	if c == nil {
		return 0
	}
	return c.pathRTT(host)
}

// udpGateRefresh replaces a deferral with the verdict that has landed since.
// Without it the deferral stood until the next pre-flight, which a connected
// client only runs after preflightFailThreshold failed connects in a row, so
// one cold start kept QUIC out of every later scan.
func (m *Manager) udpGateRefresh() {
	m.mu.RLock()
	pending, checker := m.udpGatePending, m.connectivityChecker
	m.mu.RUnlock()
	if !pending || checker == nil {
		return
	}
	// The verdict about the address the gate stands on now, not LastResult's:
	// after an endpoint switch that is the previous server's, and applying it
	// kept QUIC off a working server for the rest of the session.
	udpOK, known := checker.currentUDPVerdict()
	if !known {
		return
	}
	if m.udpGateRefreshHook != nil {
		m.udpGateRefreshHook()
	}
	// Re-checked under the lock: a pre-flight running alongside may have
	// applied a fresher verdict since pending was read, and the cached one
	// must not undo it.
	m.mu.Lock()
	if m.udpGatePending {
		m.applyUDPGateLocked(udpOK)
	}
	m.mu.Unlock()
}

// shouldSkipFastReconnect records a fast-reconnect attempt for strategyID and
// reports whether the fast path should be skipped in favor of a full scan. A
// strategy that fast-reconnects more than fastReconnectLimit times inside
// fastReconnectWindow is looping on a tunnel that connects but will not hold;
// the full scan then gives the storm detector and other strategies a chance.
// A different strategy, an expired window, or a pause of fastReconnectGap or
// more since the previous counted attempt (the previous session held - not a
// loop) restarts the count. The gap clause matters because long-lived traffic
// rides the same fast path: every proxied CONNECT re-enters connectWithRTT,
// and counting those trips as looping flagged ordinary traffic as a storm.
// Caller must hold m.mu.
func (m *Manager) shouldSkipFastReconnect(strategyID string, now time.Time) bool {
	if m.fastReconnectStrategy != strategyID ||
		now.Sub(m.fastReconnectFirst) > fastReconnectWindow ||
		!m.fastReconnectLast.IsZero() && now.Sub(m.fastReconnectLast) >= fastReconnectGap {
		m.fastReconnectStrategy = strategyID
		m.fastReconnectCount = 0
		m.fastReconnectFirst = now
	}
	m.fastReconnectLast = now
	m.fastReconnectCount++
	return m.fastReconnectCount > fastReconnectLimit
}

// NewManager creates a new strategy manager
func NewManager() *Manager {
	m := &Manager{
		strategies:            make([]Strategy, 0),
		results:               make(map[string]*Result),
		probeTimeout:          10 * time.Second,
		connectTimeout:        30 * time.Second,
		maxRetries:            2,
		parallelProbes:        3,
		adaptiveOrder:         true,
		circuitBreakers:       NewCircuitBreakerManager(DefaultCircuitBreakerConfig()),
		stormDetector:         NewStormDetector(StormConfig{}),
		reprobeInterval:       5 * time.Minute,
		emergencyInterval:     30 * time.Second,
		stopReprobe:           make(chan struct{}),
		tcpFailuresBeforeQUIC: 3, // Switch to QUIC after 3 TCP timeouts
		tlsSessionCache:       tls.NewLRUClientSessionCache(64),
		lastDeath:             deathMark{server: -1},
	}
	m.lifeCtx, m.lifeCancel = context.WithCancel(context.Background())
	log.Debug("Strategy Manager created (probeTimeout=%v, connectTimeout=%v, maxRetries=%d)",
		m.probeTimeout, m.connectTimeout, m.maxRetries)
	return m
}

// Close tears the manager's background goroutines down: it cancels the
// lifecycle context (stopping any manager-spawned emergency reprobe) and stops
// the periodic reprobe and port-hop checker. Safe to call more than once.
func (m *Manager) Close() {
	if m.lifeCancel != nil {
		m.lifeCancel()
	}
	m.StopEmergencyReprobe()
	m.StopPeriodicReprobe()
	m.StopPortHopChecker()
}

// Register adds a strategy to the manager
func (m *Manager) Register(s Strategy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.strategies = append(m.strategies, s)
	m.results[s.ID()] = &Result{
		Strategy:   s,
		Confidence: 0.5, // Initial neutral confidence
	}

	log.Debug("Registered strategy: %s (id=%s, priority=%d, requiresServer=%v)",
		s.Name(), s.ID(), s.Priority(), s.RequiresServer())

	// Sort by priority
	m.sortStrategies()
}

// ConnectivityChecker returns the pre-flight gate, or nil when none was set.
//
// Exported so the reconnect loop asks the same question the same way the
// connect path does, against the addresses the selector pinned - instead of
// inventing its own probe and, in the process, its own observable signature.
func (m *Manager) ConnectivityChecker() *ConnectivityChecker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connectivityChecker
}

// SetConnectivityChecker sets the connectivity checker for pre-flight checks
func (m *Manager) SetConnectivityChecker(checker *ConnectivityChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectivityChecker = checker
	if checker != nil {
		log.Debug("Connectivity checker set for server: %s", checker.ServerAddr())
		for _, s := range m.strategies {
			if q, ok := s.(*QUICStrategy); ok {
				checker.setUDPProbePort(q.port)
				break
			}
		}
	}
}

// SetRouteReachable injects the physical-route probe the family preflight
// consults. addr is a "host:port" candidate address; the probe reports whether
// the host can reach that family off the tunnel and whether it knows. Nil
// disables the preflight (the pre-existing behaviour). Safe to call before
// endpoints are configured.
func (m *Manager) SetRouteReachable(fn func(addr string) (routable, known bool)) {
	m.mu.Lock()
	m.routeReachable = fn
	m.mu.Unlock()
}

// SetEndpointReachableIP marks every candidate whose host matches ip as
// reachable or not, without a network probe of its own. It is the path the TUN
// bypass watcher uses to report that a family lost (or regained) its physical
// route mid-session, so the next reconnect skips a dead family instead of
// dialling it into the tunnel. A no-op when no selector or no matching
// candidate exists.
func (m *Manager) SetEndpointReachableIP(ip net.IP, reachable bool) {
	sel := m.selector()
	if sel == nil || ip == nil {
		return
	}
	host := ip.String()
	for _, c := range sel.Candidates() {
		h, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			h = c.Addr
		}
		if h != host {
			continue
		}
		if sel.SetReachable(c.Addr, reachable) {
			log.Info("Endpoint %s marked reachable=%v by the bypass watcher", c, reachable)
		}
	}
}

// familyReachabilityPreflight runs before the strategy scan: it asks the
// injected route probe about every candidate and marks the ones whose family
// has no physical route unreachable, so the selector walk skips them instead of
// timing out on each. It sends no packets - the probe reads the local routing
// table only - so it adds no scanner-like traffic to the pool (verification
// rule 8). A candidate whose route came back is re-admitted here too.
func (m *Manager) familyReachabilityPreflight(sel *endpoint.Selector) {
	m.mu.RLock()
	probe := m.routeReachable
	m.mu.RUnlock()
	if probe == nil {
		return
	}
	for _, c := range sel.Candidates() {
		routable, known := probe(c.Addr)
		if !known {
			continue
		}
		if !sel.SetReachable(c.Addr, routable) {
			continue
		}
		if routable {
			log.Info("Family preflight: %s has a physical route again, re-admitting", c)
		} else {
			log.Warn("Family preflight: no physical route to %s, excluding it from the scan", c)
		}
	}
}

// isTimeoutError checks if an error is a timeout
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// net.Error with Timeout()
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// String checks for QUIC and other protocols
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "no recent network activity") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "i/o timeout")
}

// isUDPBasedStrategy checks if a strategy uses UDP (like QUIC)
func isUDPBasedStrategy(s Strategy) bool {
	id := s.ID()
	return strings.HasPrefix(id, "quic") ||
		strings.Contains(id, "quic") ||
		strings.Contains(strings.ToLower(s.Name()), "quic")
}

// confidenceWeight is how many priority points the whole confidence range is
// worth in the scan order.
//
// It was 10, and one failure costs about 0.33 confidence, so a single failed
// attempt moved a strategy three priority points down: REALITY (5) fell behind
// HTTP Polling (6), H2 Stego and seqovl (7) and WebSocket Padded (8) after one
// bad reconnect, and the next full scan picked one of them. At 2 one failure
// moves a strategy less than one priority point and never past its neighbour;
// two in a row do, and the circuit breaker and storm parking still take a
// strategy that keeps failing out of the scan altogether.
const confidenceWeight = 2.0

// sortStrategies sorts by priority and confidence
func (m *Manager) sortStrategies() {
	// Simple bubble sort (small list)
	for i := 0; i < len(m.strategies)-1; i++ {
		for j := 0; j < len(m.strategies)-i-1; j++ {
			s1, s2 := m.strategies[j], m.strategies[j+1]
			r1, r2 := m.results[s1.ID()], m.results[s2.ID()]

			// Compare by adjusted priority (priority - confidence bonus)
			score1 := float64(s1.Priority()) - r1.Confidence*confidenceWeight
			score2 := float64(s2.Priority()) - r2.Confidence*confidenceWeight

			// Android mode: adaptive penalty for UDP/QUIC strategies
			// Base penalty is 50, but decreases with each TCP timeout
			// After tcpFailuresBeforeQUIC TCP timeouts, penalty becomes 0
			if m.androidMode {
				// Calculate adaptive penalty: starts at 10, decreases by 5 per TCP timeout
				// 0 timeouts: +10, 1: +5, 2+: 0
				// Reduced from 50 to avoid 4x TCP timeout delay (~20s) before trying QUIC
				basePenalty := 10.0
				penaltyReduction := float64(m.consecutiveTCPTimeouts) * 5.0
				adaptivePenalty := basePenalty - penaltyReduction
				if adaptivePenalty < 0 {
					adaptivePenalty = 0
				}

				if isUDPBasedStrategy(s1) {
					score1 += adaptivePenalty
				}
				if isUDPBasedStrategy(s2) {
					score2 += adaptivePenalty
				}
			}

			if score1 > score2 {
				m.strategies[j], m.strategies[j+1] = m.strategies[j+1], m.strategies[j]
			}
		}
	}
}

// ForceStrategy keeps only matching strategy (by ID prefix)
func (m *Manager) ForceStrategy(idPrefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if q := quicPlainForForce(idPrefix, m.strategies); q != nil {
		log.Warn("Plain QUIC forced without -quic-sni-frag: it only reaches a server running " +
			"-quic-sni-reassembly; a default server speaks Salamander (-strategy quic_salamander)")
		m.strategies = append(m.strategies, q)
		m.results[q.ID()] = &Result{Strategy: q, Confidence: 0.5}
	}

	var matched []Strategy
	for _, s := range m.strategies {
		// Match by prefix (e.g., "morph" matches "morph_YouTube 1080p")
		if len(s.ID()) >= len(idPrefix) && s.ID()[:len(idPrefix)] == idPrefix {
			matched = append(matched, s)
		}
		// Also match by full ID
		if s.ID() == idPrefix {
			matched = []Strategy{s}
			break
		}
	}

	if len(matched) == 0 {
		return fmt.Errorf("no strategy matching: %s", idPrefix)
	}

	m.strategies = matched
	m.forced = true
	log.Info("Forced %d strategies matching '%s'", len(matched), idPrefix)
	return nil
}

// IsForced reports whether a strategy was explicitly forced via ForceStrategy.
// In forced mode the manager never auto-switches away from a storming strategy.
func (m *Manager) IsForced() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.forced
}

// ListStrategyIDs returns comma-separated list of all strategy IDs
func (m *Manager) ListStrategyIDs() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect unique base IDs (without variant suffixes)
	seen := make(map[string]bool)
	var ids []string
	for _, s := range m.strategies {
		id := s.ID()
		// Extract base ID (e.g., "morph" from "morph_YouTube 1080p")
		baseID := id
		if idx := strings.Index(id, "_"); idx > 0 {
			// Keep full ID for strategies like geneva_russia
			if !strings.HasPrefix(id, "geneva") && !strings.HasPrefix(id, "quic") {
				baseID = id[:idx]
			}
		}
		if !seen[baseID] {
			seen[baseID] = true
			ids = append(ids, baseID)
		}
	}
	return strings.Join(ids, ", ")
}

// ProbeAll tests all strategies in parallel
func (m *Manager) ProbeAll(ctx context.Context, target string) []Result {
	// Probe the pinned candidate and only the pinned candidate. Sweeping every
	// configured endpoint on a timer would multiply this client's traffic by the
	// size of its server list and hand an observer a periodic fan-out pattern
	// that nothing else on the wire produces.
	//
	// Same endpoint, same key: the address and the secret come from one read of
	// the pin, and travel on the context to every probe.
	ctx = m.ensureDialSecret(ctx)
	if addr := m.GetServerAddr(ctx); addr != "" {
		target = addr
		log.Debug("Probing with effective server address: %s", target)
	}

	m.mu.RLock()
	// Filter out disabled strategies (priority <= 0)
	var strategies []Strategy
	for _, s := range m.strategies {
		if s.Priority() > 0 {
			strategies = append(strategies, s)
		} else {
			log.Debug("Skipping probe for disabled strategy: %s (priority=%d)", s.Name(), s.Priority())
		}
	}
	m.mu.RUnlock()

	log.Info("Probing %d strategies for target: %s", len(strategies), target)

	results := make([]Result, len(strategies))
	var wg sync.WaitGroup

	// Limit parallel probes
	sem := make(chan struct{}, m.parallelProbes)

	for i, s := range strategies {
		wg.Add(1)
		go func(idx int, strat Strategy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			log.Debug("Probing strategy: %s", strat.Name())
			start := time.Now()
			probeCtx, cancel := context.WithTimeout(ctx, m.probeTimeout)
			defer cancel()

			err := strat.Probe(probeCtx, target)
			latency := time.Since(start)

			result := Result{
				Strategy: strat,
				Success:  err == nil,
				Latency:  latency,
				Error:    err,
				TestedAt: time.Now(),
			}

			if err == nil {
				log.Debug("Probe SUCCESS: %s (latency=%v)", strat.Name(), latency)
			} else {
				log.Debug("Probe FAILED: %s (error=%v, latency=%v)", strat.Name(), err, latency)
			}

			results[idx] = result

			if errors.Is(err, errProbeUnknown) {
				// Nothing learned, nothing recorded.
				return
			}

			// Update stored results. A probe is (almost always) a bare TCP
			// connect - it says the address is reachable, not that the strategy's
			// handshake survives DPI. Feed it into the reachability/confidence
			// stats (which influence ordering) but NOT into the circuit breaker:
			// a censor that keeps 443 open while killing the handshake would
			// otherwise let every probe "recover" a strategy the real Connect
			// cannot use. Only Connect records success/failure in the breaker.
			m.mu.Lock()
			m.updateConfidenceStats(strat.ID(), err == nil, latency)
			m.mu.Unlock()
		}(i, s)
	}

	wg.Wait()

	// Re-sort based on new confidence scores
	if m.adaptiveOrder {
		m.mu.Lock()
		m.sortStrategies()
		m.mu.Unlock()
	}

	// Log summary
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	log.Info("Probe complete: %d/%d strategies available", successCount, len(results))

	return results
}

// updateConfidence adjusts confidence based on result with adaptive scoring
func (m *Manager) updateConfidence(id string, success bool) {
	m.updateConfidenceWithLatency(id, success, 0)
}

// updateConfidenceWithLatency updates the confidence stats/EMA and records the
// outcome in the circuit breaker exactly once.
func (m *Manager) updateConfidenceWithLatency(id string, success bool, latency time.Duration) {
	m.updateConfidenceStats(id, success, latency)
	if success {
		// Record success in circuit breaker (with RTT for adaptive thresholds)
		if latency > 0 {
			m.circuitBreakers.RecordSuccessWithRTT(id, latency)
		} else {
			m.circuitBreakers.RecordSuccess(id)
		}
	} else {
		m.circuitBreakers.RecordFailure(id)
	}
}

// updateConfidenceStats updates the confidence EMA and per-strategy statistics
// WITHOUT recording anything in the circuit breaker. Callers that record the
// circuit-breaker outcome themselves (e.g. the connect retry loop, which counts
// one logical strategy failure once) use this to avoid double-counting.
func (m *Manager) updateConfidenceStats(id string, success bool, latency time.Duration) {
	r, ok := m.results[id]
	if !ok {
		return
	}

	now := time.Now()

	// Update statistics
	if success {
		r.SuccessCount++
		r.ConsecutiveFail = 0
		r.LastSuccess = now
		if latency > 0 {
			r.LatencySum += latency
			r.LatencyCount++
			r.AvgLatency = r.LatencySum / time.Duration(r.LatencyCount)
		}
	} else {
		r.FailureCount++
		r.ConsecutiveFail++
		r.LastFailure = now
	}

	// Base: Exponential moving average
	alpha := 0.3
	baseConfidence := r.Confidence
	if success {
		baseConfidence = baseConfidence*(1-alpha) + 1.0*alpha
	} else {
		baseConfidence = baseConfidence*(1-alpha) + 0.0*alpha
	}

	// Bonus: +0.1 if successful in last 5 minutes
	bonus := 0.0
	if !r.LastSuccess.IsZero() && time.Since(r.LastSuccess) < 5*time.Minute {
		bonus = 0.1
	}

	// Penalty: -0.15 for each consecutive failure (up to 3)
	penalty := 0.0
	if r.ConsecutiveFail > 0 {
		penalty = float64(min(r.ConsecutiveFail, 3)) * 0.15
	}

	// Recovery: if unused for 10+ minutes and was failing, give small boost
	recovery := 0.0
	if r.ConsecutiveFail > 0 && !r.LastFailure.IsZero() && time.Since(r.LastFailure) > 10*time.Minute {
		recovery = 0.1
	}

	// Calculate final confidence
	r.Confidence = baseConfidence + bonus - penalty + recovery

	// Clamp to 0.05-0.95 to never completely exclude
	if r.Confidence < 0.05 {
		r.Confidence = 0.05
	}
	if r.Confidence > 0.95 {
		r.Confidence = 0.95
	}

	log.Debug("Strategy %s confidence updated: %.2f (base=%.2f, bonus=%.2f, penalty=%.2f, recovery=%.2f, consecutive_fail=%d)",
		id, r.Confidence, baseConfidence, bonus, penalty, recovery, r.ConsecutiveFail)
}

// UpdateStrategyConfidence updates a strategy's confidence (public wrapper)
func (m *Manager) UpdateStrategyConfidence(id string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateConfidence(id, success)
	m.sortStrategies()
}

// RecordSessionStart marks the moment a tunnel session became usable for the
// given strategy. Pair it with RecordSessionEnd to let the storm detector
// measure how long the session survived.
func (m *Manager) RecordSessionStart(strategyID string) {
	m.stormDetector.SessionOpened(strategyID)
}

// SessionOpenedAt reports when the storm detector's clock for strategyID's
// open session started, for logs and tests.
func (m *Manager) SessionOpenedAt(strategyID string) (time.Time, bool) {
	return m.stormDetector.SessionOpenedAt(strategyID)
}

// RecordSessionEnd reports that the session for strategyID has ended and
// returns whether the strategy is now storming (repeatedly short-lived
// sessions). On a storm in auto-mode the strategy is parked and excluded from
// selection for the cooldown; the caller should drop the cached fast-reconnect
// strategy so the next Connect picks a fresh one. In forced mode the verdict is
// still returned (for loud logging) but the strategy stays in use.
func (m *Manager) RecordSessionEnd(strategyID string) (storming bool) {
	storming = m.stormDetector.SessionClosed(strategyID)
	if !storming {
		return false
	}

	if m.IsForced() {
		log.Error("STORM on forced strategy %s: sessions keep dying within %v of connecting. "+
			"DPI is likely tearing down this pattern. Consider switching strategy (-strategy ...) "+
			"or running in auto mode.", strategyID, stormShortSession)
		return true
	}

	log.Warn("STORM detected on %s: repeated short-lived sessions, parking for %v and failing over to next strategy",
		strategyID, stormCooldown)

	// Drop the cached fast-reconnect strategy if it is the storming one, so the
	// next reconnect does not immediately retry it.
	m.mu.Lock()
	if m.lastSuccessfulStrategy != nil && m.lastSuccessfulStrategy.ID() == strategyID {
		m.lastSuccessfulStrategy = nil
	}
	m.mu.Unlock()
	return true
}

// SessionEnd describes a tunnel session that has just ended.
type SessionEnd struct {
	// Strategy is the ID of the strategy that carried the session.
	Strategy string

	// Endpoint is the candidate the session rode, as ConnectSession returned
	// it; HasEndpoint is false when there is none (no selector, mux stream).
	Endpoint    endpoint.Candidate
	HasEndpoint bool

	// Useful says the session carried downlink for a meaningful time. Only a
	// session that did not is evidence against the strategy: a tunnel that ran
	// for fifteen minutes and then lost its server to a restart, or its network
	// to a dead link, says nothing about the transport, and charging it for that
	// dropped REALITY below HTTP Polling after a single server restart.
	Useful bool

	// Replaced says the session did not die: the client moved the tunnel
	// off it on purpose (an upgrade swap, a port hop). A useful one ends like
	// any useful session. A young one is no evidence about anything - not a
	// short session for the storm detector, not a failure of its strategy -
	// and it clears nothing either: a fallback a few seconds old said nothing
	// about the endpoint's dead-session streak.
	Replaced bool

	// UpgradeFailed says the session was a pending strategy upgrade that died
	// before proving itself. UpgradeOutcome has already charged the strategy,
	// so it is not charged a second time here.
	UpgradeFailed bool

	// LocalNetworkUp, when set, is asked before the endpoint is charged for
	// a dead session or a storm: a link that dropped on the client's side
	// kills sessions just the same, and parking a server for it is D7 over
	// again. It reports false when it cannot tell. Nil means "up".
	LocalNetworkUp func() bool

	// Dead says the session ended in silence with its downlink dead almost from
	// the start, while the local network was up: every connect to the endpoint
	// succeeds - so connect-based health never notices, and each success reset
	// its streak - but no session survives. That is what a byte-count freeze on
	// the route looks like (the TSPU #490 pattern, stand run #7b: ten choices of
	// one address in six minutes, the data plane alive 4% of the time).
	Dead bool

	// Degraded says the client gave the session up as alive but useless: a
	// TCP flow inside it waited 30 s for an answer and two keepalives went
	// unanswered (tun's stall detector). It is booked like Dead whatever the
	// session's age - a session under a per-flow byte cap can live for hours
	// while nothing gets through it - and never as useful.
	Degraded bool
}

// SessionEnded books the end of a tunnel session.
//
// A session that was not useful costs its strategy confidence. A useful one
// restarts the fast-reconnect clock (it used to run from the moment the session
// connected, so any session longer than five minutes ended with the fast path
// expired) and clears the endpoint's dead-session streak. A dead session, and a
// storm, park the endpoint - see chargeSessionEndpoint.
//
// It feeds the storm detector exactly as RecordSessionEnd does and returns its
// verdict.
func (m *Manager) SessionEnded(end SessionEnd) (storming bool) {
	if end.Replaced && !end.Useful {
		m.stormDetector.SessionAbandoned(end.Strategy)
		return false
	}
	if !end.Useful && !end.UpgradeFailed {
		m.UpdateStrategyConfidence(end.Strategy, false)
	}
	storming = m.RecordSessionEnd(end.Strategy)
	sel := m.selector()

	if end.Useful && !storming && !end.Dead && !end.Degraded {
		m.mu.Lock()
		if m.lastSuccessfulStrategy != nil && m.lastSuccessfulStrategy.ID() == end.Strategy {
			m.lastSuccessfulTime = time.Now()
		}
		m.lastDeath = deathMark{server: -1}
		m.mu.Unlock()
		if sel != nil && end.HasEndpoint {
			sel.ReportSessionUseful(end.Endpoint)
		}
		return storming
	}

	switch {
	case end.Dead:
		m.chargeSessionEndpoint(sel, end, deathDead, "session went silent right after connecting")
	case end.Degraded:
		m.chargeSessionEndpoint(sel, end, deathDegraded, "session degraded: a flow stalled and keepalives went unanswered")
	case storming && !end.UpgradeFailed:
		// A strategy whose sessions keep dying on this endpoint is evidence
		// against the endpoint too: a freeze keyed to the address kills every
		// transport in turn, and the storm detector alone only ever walks the
		// strategy list on the same server, 2.5-3.5 minutes per strategy. One
		// ordinary failure here was reset by the next connect and never parked
		// anything.
		//
		// Not when the storm is completed by a failed upgrade: the storm
		// detector keys on the strategy, so short sessions from before the
		// switch to the fallback are still in its history, and the server the
		// fallback carries traffic on is not what failed.
		m.chargeSessionEndpoint(sel, end, deathStorm, "storm")
	}
	return storming
}

// chargeSessionEndpoint parks the endpoint a dead session or a storm happened
// on, growing the park with each one in a row (Selector.ReportDeadSession) -
// unless it is the route's death (routeDeath).
func (m *Manager) chargeSessionEndpoint(sel *endpoint.Selector, end SessionEnd, class deathClass, why string) {
	if sel == nil || !end.HasEndpoint {
		return
	}
	if end.LocalNetworkUp != nil && !end.LocalNetworkUp() {
		log.Info("Endpoint %s: %s, but the local network cannot be confirmed up - not charging it", end.Endpoint, why)
		return
	}
	if m.routeDeath(end.Endpoint, class, why, []string{end.Strategy}) {
		return
	}
	if sel.ReportDeadSession(end.Endpoint) {
		log.Warn("Endpoint %s charged for its session (%s); every address of the server has a verdict - parking the server", end.Endpoint, why)
	} else {
		log.Info("Endpoint %s charged for its session (%s)", end.Endpoint, why)
	}
	m.logEndpointHealth(sel, end.Endpoint)
}

// deathClass names the kind of verdict a server got, for routeDeath.
type deathClass string

const (
	deathSilent    deathClass = "silence"
	deathSwallowed deathClass = "swallowed handshakes"
	deathDead      deathClass = "dead session"
	deathDegraded  deathClass = "stalled session"
	deathStorm     deathClass = "storm"
)

// deathMark is the last verdict given to a server: which one, of what kind,
// on which transports, and when.
type deathMark struct {
	server int
	class  deathClass
	ids    []string
	at     time.Time
}

// routeDeathWindow bounds how far apart two deaths may be and still be "in a
// row". The chain between them - the other family of the first server, a
// reconnect, a session dying on the second - takes three or four minutes at
// most; a mark older than this is about a route that may have changed since,
// and must not decide a park on its own (P1-4 of the round-5 review, now that
// the mark survives an Android core restart).
const routeDeathWindow = 10 * time.Minute

// routeDeath books a verdict of class on cand's server and reports whether it
// is the route's rather than the server's. Then it parks the transports that
// died - ids - instead of the server, and the caller charges nothing.
//
// The same death on two different servers in a row, with nothing useful in
// between, says the route: a censor killing one transport on every exit, the
// way the stand's Polling throttle did. Parking every server it touches walked
// the client through the whole pool - listing it for an observer and burning
// every address - on the transport that cannot work anywhere, and a stall
// verdict never changed the strategy at all (P2-7 of the round-4 review). So
// the second server is not charged, the transports are set aside on the two
// servers where they died (routeSkip), and the next cycle tries another
// transport on the same server. The pool walk stops at two servers. Deaths on the two
// families of one server are one server's, and are charged as usual.
//
// The mark moves on every verdict: kept on the first server, it made every
// later death on the second look like "the same death on another server" and
// spared it forever. A server gets one pass after a switch and is charged on
// its second death in a row.
func (m *Manager) routeDeath(cand endpoint.Candidate, class deathClass, why string, ids []string) bool {
	// Wall clock: the mark crosses Android core restarts, and a phone asleep
	// between two deaths must count the sleep (P3-3 of the round-6 review).
	now := time.Now().Round(0)
	if len(ids) == 0 {
		// A verdict that names no transport - an address that never answered
		// a SYN - says nothing about the route, and must not become the
		// "previous death" the next server is compared with (P2-D of the
		// round-6 review: an IP-blocked server followed by a swallowing one
		// set three transports aside on both).
		return false
	}
	m.mu.Lock()
	prev := m.lastDeath
	m.lastDeath = deathMark{server: cand.EndpointIdx, class: class, ids: slices.Clone(ids), at: now}
	m.mu.Unlock()
	if prev.server < 0 || prev.server == cand.EndpointIdx || prev.class != class || now.Sub(prev.at) > routeDeathWindow {
		return false
	}
	// The same death means the same transports, except for a storm: the
	// storm detector parks a storming transport everywhere at once, so the
	// next server never runs it, and the storms there are of the next one.
	if class != deathStorm {
		ids = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return !slices.Contains(prev.ids, id) })
		if len(ids) == 0 {
			return false
		}
	}
	if m.IsForced() {
		log.Warn("Endpoint %s: %s, as on the previous server - the route, not the server; forced strategy, nothing else to try", cand, why)
		return true
	}
	until := now.Add(stormCooldown)
	m.mu.Lock()
	if m.routeParked == nil {
		m.routeParked = make(map[int]map[string]time.Time)
	}
	for _, server := range []int{prev.server, cand.EndpointIdx} {
		if m.routeParked[server] == nil {
			m.routeParked[server] = make(map[string]time.Time)
		}
		for _, id := range ids {
			m.routeParked[server][id] = until
		}
	}
	m.mu.Unlock()
	log.Warn("Endpoint %s: %s, as on the previous server - the route, not the server: setting %s aside on these two servers for %v and trying other transports here",
		cand, why, strings.Join(ids, ", "), stormCooldown)
	return true
}

// routeSkip returns the transports a route verdict set aside on addr's
// server (routeDeath), for the scan to try last there, after every other
// eligible transport, and for the upgrade path to leave alone. Scoped to the servers where the transport died:
// a third server is not assumed to share their fate, and pays one death of
// its own before the rule applies to it (P2-2 of the round-5 review; parked
// for every server, a false route verdict kept a healthy one on a lesser
// transport for five minutes). Empty in forced mode, which has nothing else
// to try. Takes m.mu: not to be called with it held.
func (m *Manager) routeSkip(addr string) map[string]bool {
	sel := m.selector()
	if sel == nil {
		return nil
	}
	cand, ok := sel.CandidateForAddr(addr)
	if !ok {
		return nil
	}
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.forced {
		return nil
	}
	var out map[string]bool
	for id, until := range m.routeParked[cand.EndpointIdx] {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[id] = true
		}
	}
	return out
}

// rescanPause draws the pause before a rescan after a route verdict. A var
// so tests can shorten it.
var rescanPause = func() time.Duration {
	return HumpDelay(300*time.Millisecond, 800*time.Millisecond, 2*time.Second)
}

// sleepCtx waits d, or less if ctx ends; false means ctx ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// maxEndpointAttempts caps how many endpoint candidates a single Connect may
// try. Two, and no more: handleDisconnect gives the whole reconnect 15 seconds,
// and each candidate costs a full strategy scan. A deeper walk would blow that
// budget and turn one dead family into a minutes-long outage.
const maxEndpointAttempts = 2

// Connect tries strategies in order until one succeeds
func (m *Manager) Connect(ctx context.Context, target string) (net.Conn, Strategy, error) {
	conn, s, _, _, err := m.ConnectSession(ctx, target)
	return conn, s, err
}

// ConnectSession is Connect that also names the endpoint candidate the
// connection rides, for a caller that books the session's end against it
// (SessionEnded). ok is false when there is none: no selector, or a stream on
// an existing mux carrier.
func (m *Manager) ConnectSession(ctx context.Context, target string) (net.Conn, Strategy, endpoint.Candidate, bool, error) {
	// Mux fast-path: if mux is enabled and a live session already exists, open a
	// new stream on it and return immediately - do NOT dial a fresh transport.
	// Without this, every call (e.g. every proxy CONNECT routed through
	// pool.DialTarget) unconditionally completes a full REALITY handshake below,
	// which wrapWithMux then discards in its reuse branch. That orphaned transport
	// is never used nor closed, so it hangs pre-auth on the server (goroutine +
	// peek-buffer + admission slot) until probeReadDeadline, and under a busy
	// client the accumulation outpaces reclamation -> server OOM.
	if stream, strat, ok := m.tryMuxFastPath(); ok {
		return stream, strat, endpoint.Candidate{}, false, nil
	}

	conn, strategy, cand, hasCand, err := m.dialEndpoints(ctx, target)
	if err != nil {
		m.recordConnectResult(false)
		return nil, nil, endpoint.Candidate{}, false, err
	}
	m.recordConnectResult(true)

	// Wrap with mux if enabled (BEFORE RTT masking in the chain)
	// Architecture: [Application] -> [RTT Camouflage] -> [Mux Layer] -> [Transport]
	m.muxMu.Lock()
	muxEnabled := m.muxEnabled
	muxConfig := m.muxConfig
	m.muxMu.Unlock()

	if muxEnabled {
		muxConn, muxErr := m.wrapWithMux(conn, muxConfig, strategy)
		if muxErr != nil {
			log.Warn("Mux wrap failed, using direct connection: %v", muxErr)
			// Fallback to direct connection without mux
			return conn, strategy, cand, hasCand, nil
		}
		log.Debug("Connection wrapped with mux layer")
		return muxConn, strategy, cand, hasCand, nil
	}

	return conn, strategy, cand, hasCand, nil
}

// dialEndpoints walks the endpoint candidates until one of them yields a
// connection.
//
// The loop only ever advances on errStrategyScanFailed - every transport on
// that address was tried and every one of them died. That signal is the useful
// one precisely because it arrives on the hot reconnect path, where the
// pre-flight gate is skipped. A pre-flight that fails outright means the whole
// network is down, not this endpoint, so it stops the loop without touching
// anyone's health: otherwise closing a laptop lid would park every candidate.
func (m *Manager) dialEndpoints(ctx context.Context, target string) (net.Conn, Strategy, endpoint.Candidate, bool, error) {
	sel := m.selector()
	if sel == nil {
		if _, err := m.preflightCandidate(ctx, nil, endpoint.Candidate{Addr: target}); err != nil {
			return nil, nil, endpoint.Candidate{}, false, err
		}
		conn, s, err := m.connectScan(ctx, m.withHoppedPort(target), nil, &scanState{addr: target})
		if err == nil {
			m.clearSwallowed(target)
		}
		return conn, s, endpoint.Candidate{}, false, err
	}

	// Family connectivity preflight BEFORE any strategy scan: drop the families
	// this host has no physical route to (an IPv6 endpoint with no IPv6 on the
	// line), so Reconsider and the failover walk below only ever land on a
	// candidate the host can actually reach.
	m.familyReachabilityPreflight(sel)

	cand, ok := sel.Reconsider(sel.Now())
	if !ok {
		return nil, nil, endpoint.Candidate{}, false, fmt.Errorf("no endpoint candidates configured")
	}
	// Without this line a log shows a client dialling the same address over and
	// over and cannot say whether the endpoint layer never condemned it or
	// condemned it and chose it anyway. Those are different bugs and we spent a
	// day telling them apart by hand.
	log.Info("Endpoint choice: %s (%s)", cand, m.endpointRoster(sel))

	budget := min(maxEndpointAttempts, len(sel.Candidates()))
	var lastErr error

	// stayHere repeats the scan on the same candidate once, after a route
	// verdict parked the transports that died there (routeDeath).
	stayHere, rescanned := false, false
	var rescanExclude []string // the transports the route verdict was about
	for attempt := 0; attempt < budget; attempt++ {
		if attempt > 0 && !stayHere {
			next, ok := sel.Next(sel.Now())
			if !ok {
				break
			}
			log.Warn("Endpoint %s failed a full strategy scan, switching to %s", cand, next)
			sel.Pin(next)
			cand = next
		}
		rescan := stayHere
		stayHere = false

		if rescan {
			// The same server again, right after the route verdict: no second
			// pre-flight (one more bare TCP connect and close), and a short
			// pause first, so the server does not see two volleys back to
			// back (P3-7 of the round-6 review).
			if !sleepCtx(ctx, rescanPause()) {
				break
			}
		} else {
			gated, err := m.preflightCandidate(ctx, sel, cand)
			if err != nil {
				// The gate found no network at all. That is not this endpoint's
				// fault and nobody has been charged for it - see the comment above.
				return nil, nil, endpoint.Candidate{}, false, err
			}
			cand = gated
		}

		// Family probe: one dial, at most once per candidate, and only when
		// there is somewhere to fall back to (see Selector.ProbeCurrent). It
		// runs AFTER the gate on purpose. The gate answers the same question
		// for free when it runs at all, and it marks the candidates it resolved
		// as probed, so this is a no-op then. On the hot reconnect path, where
		// the gate is skipped, this is the only thing that notices a dead
		// family - which is exactly what the old one-shot IPv6 check did.
		if !rescan {
			probed, kept := sel.ProbeCurrent(ctx)
			if !kept && probed.Addr != cand.Addr {
				// The family probe moved the pin. Before this line the move was
				// silent, and a log that announced one address went on to show
				// the client on another.
				log.Info("Endpoint %s did not answer the family probe, switching to %s", cand, probed)
			}
			cand = probed
		}

		// Name the secret for THIS candidate, on this dial's own context. The
		// pinned candidate can move underneath us - a concurrent Connect, the
		// pre-flight gate, a health report - so reading the pin again down in a
		// strategy would let a handshake authenticate to one server with another
		// server's key. Here the address and the key are decided together and
		// travel together.
		dialCtx := m.withDialCandidate(ctx, cand)

		start := time.Now()
		scan := &scanState{addr: cand.Addr}
		var swallowedOn, swallowedTransports []string
		var exclude []string
		if rescan {
			// Only the transports still standing: the ones this verdict was
			// about died here a moment ago. Not every route park on the
			// server - an older one may be on a transport that works again,
			// and leaving it out left nothing to dial (P2-2 of the round-7
			// review).
			exclude = rescanExclude
		}
		conn, strategy, err := m.connectScan(dialCtx, m.withHoppedPort(cand.Addr), exclude, scan)
		if err == nil {
			m.clearSwallowed(cand.Addr)
			sel.Report(cand, true, time.Since(start))
			return conn, strategy, cand, true, nil
		}
		lastErr = err

		if rescan && errors.Is(err, errStrategyScanFailed) && !errors.Is(err, errAddrSilent) &&
			!scan.answered && scan.timeouts > 0 && scan.unheard == 0 {
			// The rescan heard nothing from the transports left after the
			// route verdict, however few: with one or two left the scan
			// never reached the silence threshold, and the server was not
			// charged (P2-C of the round-6 review). It is the server's
			// second verdict - if each of them ran out its own timeout. An
			// attempt the cycle cut short is no verdict either way (P3-3
			// of the round-7 review).
			err = fmt.Errorf("%w: %w, the transports left heard nothing either: %w", errAddrSilent, errStrategyScanFailed, err)
			lastErr = err
		}

		if !errors.Is(err, errStrategyScanFailed) {
			// Context cancelled, or no strategy was even eligible. Neither
			// says anything about this endpoint on its own; a run of them in
			// which its handshakes heard nothing does (swallowCycle).
			verdict, covered, heard := m.swallowCycle(cand.Addr, scan)
			if !verdict {
				if !scan.answered && (scan.timeouts > 0 || scan.unheard > 0) {
					lastErr = fmt.Errorf("%w: %w", ErrCycleUnanswered, err)
				}
				// The run is the server's. Its other family gets the next
				// cycle, once: under a censor the two are often in different
				// states, and two cycles on one family before it reached the
				// other were how a swallowing server kept the client for five.
				if len(covered) > 0 {
					if sib, ok := m.swallowSibling(sel, cand, covered); ok {
						log.Info("Endpoint %s heard nothing this cycle - the next one tries the server's other address %s", cand, sib)
						sel.Pin(sib)
					}
				}
				break
			}
			err = fmt.Errorf("%w: %w, handshakes swallowed cycle after cycle: %w", errAddrSilent, errStrategyScanFailed, err)
			lastErr = err
			swallowedOn, swallowedTransports = covered, heard
		} else {
			m.endSwallowRun(cand.Addr)
		}
		if errors.Is(err, errAddrSilent) {
			class, died := deathSilent, scan.silent
			if swallowedOn != nil {
				class, died = deathSwallowed, swallowedTransports
			}
			if m.routeDeath(cand, class, "it answered nothing", died) {
				// Not the server's: the transports still standing get their
				// turn here, now, without counting as another candidate. If
				// they are silent too, the second verdict on this server is
				// its own and charges it: the route verdict costs a server
				// that is down for good one scan, not a cycle of its own.
				if rescanned || ctxErr(ctx) != nil || m.IsForced() {
					// Forced mode has nothing else to try: the rescan would
					// dial the same transport again (P3-1 of the round-6
					// review).
					break
				}
				rescanned, stayHere, rescanExclude = true, true, died
				attempt--
				continue
			}
			if sel.ReportSilent(cand, swallowedOn...) {
				log.Warn("Endpoint %s: every address of the server has a verdict - parking the server", cand)
			}
		} else {
			sel.Report(cand, false, 0)
		}
		m.logEndpointHealth(sel, cand)
		if ctxErr(ctx) != nil {
			// The verdict is in; the next candidate gets the next cycle. Its
			// pre-flight on a dead context would read as "no network" instead.
			break
		}
	}

	return nil, nil, endpoint.Candidate{}, false, lastErr
}

// endpointRoster renders the pool the way a reader of the log needs it: which
// candidates are parked and until when. "6 servers, selection=priority" says
// what was configured; this says what the client currently believes.
func (m *Manager) endpointRoster(sel *endpoint.Selector) string {
	now := sel.Now()
	var parked []string
	total := 0
	for _, st := range sel.Snapshot() {
		total++
		if st.CooldownUntil.IsZero() || !now.Before(st.CooldownUntil) {
			continue
		}
		parked = append(parked, fmt.Sprintf("%s for %s", st.Addr, st.CooldownUntil.Sub(now).Round(time.Second)))
	}
	if len(parked) == 0 {
		return fmt.Sprintf("%d candidates, none parked", total)
	}
	return fmt.Sprintf("%d candidates, parked: %s", total, strings.Join(parked, ", "))
}

// logEndpointHealth reports what a failed cycle did to a candidate, so a log
// can distinguish "not parked" from "parked and picked again".
func (m *Manager) logEndpointHealth(sel *endpoint.Selector, cand endpoint.Candidate) {
	now := sel.Now()
	for _, st := range sel.Snapshot() {
		if st.Addr != cand.Addr {
			continue
		}
		if !st.CooldownUntil.IsZero() && now.Before(st.CooldownUntil) {
			log.Info("Endpoint %s parked for %s after %d consecutive failure(s)",
				cand, st.CooldownUntil.Sub(now).Round(time.Second), st.ConsecutiveFailures)
			return
		}
		log.Info("Endpoint %s failed (%d consecutive), not parked yet", cand, st.ConsecutiveFailures)
		return
	}
}

// withHoppedPort rewrites the port when port hopping is active.
func (m *Manager) withHoppedPort(target string) string {
	if m.portHopper == nil {
		return target
	}
	return m.replacePort(target, m.portHopper.CurrentPort())
}

// preflightCandidate runs the pre-flight connectivity gate for cand and returns
// the candidate to dial - which may differ from the one passed in when the gate
// found the sibling address answering instead.
//
// The skip condition is unchanged: on the hot reconnect path the real connect
// below has its own timeout and would reach a briefly-reset server itself, so
// checking first only adds latency to recovery. The gate runs on the very first
// connect, or once several connects in a row have failed - the signal that the
// network is genuinely down rather than a one-off server RST.
func (m *Manager) preflightCandidate(ctx context.Context, sel *endpoint.Selector, cand endpoint.Candidate) (endpoint.Candidate, error) {
	m.mu.Lock()
	checker := m.connectivityChecker
	connectedBefore := m.lastSuccessfulStrategy != nil
	fails := m.consecutiveConnectFailures
	armed := m.preflightArmed
	if checker != nil && (!connectedBefore || fails >= preflightFailThreshold || armed) {
		// This run is the one the flag asked for; a second candidate in the
		// same cycle goes back to the ordinary rule.
		m.preflightArmed = false
	}
	m.mu.Unlock()

	if checker == nil {
		return cand, nil
	}
	if connectedBefore && fails < preflightFailThreshold && !armed {
		return cand, nil
	}

	if sel != nil {
		// The whole pool, not just this endpoint's other family: the gate
		// decides between dialling and waiting, so a narrow view makes a client
		// wait out its first server while the rest of the pool sits idle.
		checker.SetAddrs(cand.Addr, sel.GateAddrs(cand)...)
	}

	// TCP to the pool and nothing else: the gate's question is whether any of
	// these addresses answers. The UDP probe only feeds the QUIC gate, so it
	// runs only for a client that has a QUIC strategy to gate (see Check).
	var result ConnectivityResult
	if m.hasUDPStrategies() {
		result = checker.Check(ctx)
	} else {
		result = checker.CheckTCP(ctx)
	}
	if !result.TCP {
		// No TCP connectivity - wait in loop until it's restored
		log.Warn("No TCP connectivity to server, waiting for network...")
		result = checker.WaitForConnectivity(ctx, defaultProbeInterval)
		if !result.TCP {
			return cand, fmt.Errorf("%w: %w", ErrNoServerAnswered, result.Error)
		}
	}

	// Only a finished probe is a verdict. A cold start whose probe is still in
	// flight carries UDP=false as a placeholder, and reading it as "blocked"
	// left a forced -strategy quic_salamander client with no strategy at all.
	if result.UDPKnown {
		m.applyUDPGate(result.UDP)
	} else {
		m.udpGateDeferQUIC()
	}

	if sel == nil || result.Addr == "" {
		return cand, nil
	}
	if result.Addr == cand.Addr {
		// The pinned address answered. Record it as a probe, not as a connect:
		// a completed TCP handshake is not evidence that the transport works,
		// so this refreshes latency and deliberately leaves both the failure
		// streak and any cooldown alone (see Selector.ReportProbe).
		sel.ReportProbe(cand, true, result.Latency)
		return cand, nil
	}
	other, ok := sel.CandidateForAddr(result.Addr)
	if !ok {
		return cand, nil
	}

	// The gate probes parked candidates on purpose - its question is whether
	// this client has a network at all, and leaving a parked-but-live server
	// out would make it wait when it has somewhere to go. Acting on that answer
	// is a different question, and for a parked candidate the selector has
	// already answered it, on evidence the gate cannot produce: an address that
	// swallowed every transport still completes a TCP handshake. Switching here
	// sent the client straight back to the server a full scan had just
	// condemned, over and over.
	if sel.IsParked(other) {
		log.Debug("Pre-flight: %s answered but is parked - staying on %s", other, cand)
		return cand, nil
	}

	// The gate walked the pool and something other than the pinned address
	// answered - the other family of this server, or another server entirely.
	// That is a free verdict, the packets went out either way, so act on it
	// instead of dialling a silent address through every strategy in turn.
	log.Info("Pre-flight: %s silent, %s answered - switching endpoint", cand, other)
	sel.ReportProbe(cand, false, 0)
	sel.ReportProbe(other, true, result.Latency)
	sel.Pin(other)
	return other, nil
}

// scanState is what one connect cycle learns about the ADDRESS rather than
// about any single transport, carried across both passes ConnectExcluding
// makes over the strategy list.
//
// It has to outlive a pass. Every failure re-sorts the list by confidence, so
// the masked pass sees the same transports in a different order, and a per-pass
// counter would let that reordering manufacture a silence verdict for an
// address that had already answered.
type scanState struct {
	// answered records that some transport got a reply - a refusal, a reset, a
	// rejected handshake. One is enough: whatever is wrong from there on is a
	// property of a transport, which is what the scan exists to work around.
	answered bool
	// timeouts counts non-UDP strategies that died on the connect timeout.
	timeouts int
	// addr is the address the cycle's swallow record is kept under: the
	// candidate as the endpoint layer names it, since the dial target can
	// carry a hopped port. Empty means the dial target.
	addr string
	// connectedSilent lists the transports whose TCP connect came up and
	// whose handshake then heard nothing until its attempt ran out.
	connectedSilent []string
	// inconclusive lists the transports whose attempt heard nothing and was
	// still no verdict (attemptInconclusive), with a real chance to answer
	// (swallowEvidence).
	inconclusive []string
	// allowance is how long the last attempt had to hear an answer, from
	// its TCP connect when known (connectThroughRefusal).
	allowance time.Duration
	// unheard counts the attempts that heard nothing and were no verdict,
	// evidence or not: what makes a cycle "unanswered" (ErrCycleUnanswered).
	unheard int
	// silent lists the non-UDP transports whose TCP connect completed and
	// whose attempt was then silence (attemptSilent): what a silence verdict
	// says died. A SYN nobody answered is left out - every transport dials
	// the same host:port, so it says the address is unreachable (an IP
	// block, a dead host), nothing about the transports, and counting it
	// parked working transports for the route (P1-2 of the round-5 review).
	silent []string
}

// swallowEvidence reports whether an attempt of s that heard nothing for
// allowance is evidence that the address swallows handshakes. Not for a UDP
// transport: a datagram blackhole is the route's, not the server's. And not
// for an attempt that had less than a third of connectTimeout (10 s on the
// desktop) to answer: cut by what was left of the cycle - half of it taken
// by another transport - a healthy Polling handshake needing a couple of
// seconds looked swallowed, and a working server was parked.
//
// A strategy that does not report its TCP connect is held to half of a
// short cycle as a whole, under the floor: it never counts. A server that
// swallows every handshake swallows the reporting ones too (REALITY, Polling,
// Stego, Seqovl), and the first of them in a cycle runs to the cycle's end.
func (m *Manager) swallowEvidence(s Strategy, allowance time.Duration) bool {
	return !isUDPBasedStrategy(s) && allowance >= m.connectTimeout/3
}

// swallowRecord is what one server's last reconnect cycles left behind. The
// run is kept per server: a server that swallows handshakes on one family is
// checked on its other family next (N9 of the 1.11.9 acceptance), and the run
// counts the cycles on both. The skip lists stay per address: under a censor
// the two families are often in different states, and a transport swallowed
// on v6 may well work on v4 (P1-3 of the round-5 review).
type swallowRecord struct {
	// skip holds, per address, the transports whose connected handshake heard
	// nothing there; the next cycle on that address starts without them.
	skip map[string]map[string]bool
	last time.Time
	// cycles counts the cycles in a row that ended with no verdict while a
	// transport heard nothing there, and heardNothing names those
	// transports (see swallowCycle).
	cycles       int
	heardNothing map[string]bool
	// addrs are the server's addresses those cycles ran on.
	addrs map[string]bool
	// unanswered counts the cycles in a row that ended with no verdict and
	// no answer at all, evidence or not (see swallowUnansweredMax).
	unanswered int
}

// endRun ends the run of no-verdict cycles; the skip lists stay.
func (r *swallowRecord) endRun() {
	r.cycles, r.unanswered, r.heardNothing, r.addrs = 0, 0, make(map[string]bool), make(map[string]bool)
}

// swallowKey names the swallow record addr belongs to: its server when the
// selector knows the address, else the address itself. Takes m.mu (through
// selector): not to be called with it held.
func (m *Manager) swallowKey(addr string) string {
	if sel := m.selector(); sel != nil {
		if cand, ok := sel.CandidateForAddr(addr); ok {
			return fmt.Sprintf("server %d", cand.EndpointIdx)
		}
	}
	return addr
}

// swallowSibling returns the address of cand's server that the run has not
// covered yet - routable and not parked - for the next cycle to try. False when
// there is none: the run has seen every family of the server, or it has one.
func (m *Manager) swallowSibling(sel *endpoint.Selector, cand endpoint.Candidate, covered []string) (endpoint.Candidate, bool) {
	for _, addr := range sel.Siblings(cand) {
		sib, ok := sel.CandidateForAddr(addr)
		if !ok || slices.Contains(covered, addr) || !sel.Reachable(addr) || sel.IsParked(sib) {
			continue
		}
		return sib, true
	}
	return endpoint.Candidate{}, false
}

// swallowCyclesMax is how many no-verdict cycles in a row, with a handshake
// heard nothing in each, are an address's silence verdict on one transport.
// Two cycles are enough when they span two transports.
const swallowCyclesMax = 3

// swallowUnansweredMax is how many cycles in a row with no verdict and no
// answer from any transport are the server's silence verdict, whether or not
// a cycle had evidence (swallowEvidence). The backstop for transports that do
// not report their TCP connect and so never count as swallowed: a server that
// swallows every handshake of a forced Geneva, or of a set without a
// reporting transport, kept the client for good (P3-12 of the round-5
// review). Four cycles, one more than swallowCyclesMax, because these cycles
// prove less.
const swallowUnansweredMax = 4

// swallowWindow is how long a swallow record outlives its last cycle. The
// reconnect backoff reaches two minutes and a cycle takes 15-30 s more, so a
// shorter window would forget a run of cycles between two of them.
const swallowWindow = 3 * time.Minute

// swallowSkip returns the transports the next cycle on addr starts without:
// those whose connected handshake heard nothing in the recent cycles there.
// Empty in forced mode, which has nothing else to try, and when skipping them
// would leave no transport at all.
func (m *Manager) swallowSkip(addr string) map[string]bool {
	sincePark := m.serverSincePark(addr)
	key := m.swallowKey(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.swallowed[key]
	if r == nil || len(r.skip[addr]) == 0 || m.forced || swallowStale(r, sincePark) {
		return nil
	}
	skip := r.skip[addr]
	if !slices.ContainsFunc(m.strategies, func(s Strategy) bool { return s.Priority() > 0 && !skip[s.ID()] }) {
		return nil
	}
	return maps.Clone(skip)
}

// noteSwallowed books the transports whose connected handshake heard nothing
// this cycle against addr.
func (m *Manager) noteSwallowed(addr string, ids []string) {
	if len(ids) == 0 {
		return
	}
	sincePark := m.serverSincePark(addr)
	key := m.swallowKey(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.swallowRecordLocked(key, sincePark)
	if r.skip[addr] == nil {
		r.skip[addr] = make(map[string]bool)
	}
	for _, id := range ids {
		r.skip[addr][id] = true
	}
}

// swallowRecordLocked returns the swallow record under key, fresh if it had
// none or it is stale (swallowStale), and stamps it now. m.mu held;
// sincePark is serverSincePark for the address in hand, asked before taking it.
func (m *Manager) swallowRecordLocked(key string, sincePark time.Duration) *swallowRecord {
	r := m.swallowed[key]
	if r == nil || swallowStale(r, sincePark) {
		r = &swallowRecord{skip: make(map[string]map[string]bool), heardNothing: make(map[string]bool), addrs: make(map[string]bool)}
		if m.swallowed == nil {
			m.swallowed = make(map[string]*swallowRecord)
		}
		m.swallowed[key] = r
	}
	// Wall clock: the record crosses an Android core restart, and the
	// monotonic clock stops while the phone sleeps (P3-6 of the round-7
	// review).
	r.last = time.Now().Round(0)
	return r
}

// swallowStale reports a record whose last cycle, and the end of its
// server's last park, are both more than swallowWindow ago. A park can outlast
// the window (it doubles), and counting from the last cycle alone, a client
// coming back to the server after a park of more than three minutes had
// forgotten which transports the server swallows and lost its first cycle to
// them again (P2-3 of the round-5 review). sincePark is serverSincePark for
// the record's address.
func swallowStale(r *swallowRecord, sincePark time.Duration) bool {
	return time.Since(r.last) > swallowWindow && sincePark > swallowWindow
}

// neverParked is serverSincePark's answer for a server with no park on record.
const neverParked = time.Duration(math.MaxInt64)

// serverSincePark reports how long ago the last park of addr's server ended:
// negative while any of its addresses is parked, neverParked when none has a
// park on record. Takes m.mu (through selector): not to be called with it
// held.
func (m *Manager) serverSincePark(addr string) time.Duration {
	sel := m.selector()
	if sel == nil {
		return neverParked
	}
	cand, ok := sel.CandidateForAddr(addr)
	if !ok {
		return neverParked
	}
	var end time.Time
	for _, st := range sel.Snapshot() {
		if st.EndpointIdx == cand.EndpointIdx && st.CooldownUntil.After(end) {
			end = st.CooldownUntil
		}
	}
	if end.IsZero() {
		return neverParked
	}
	return sel.Now().Sub(end)
}

// swallowCycle books a cycle on addr that ended with no verdict and reports
// whether the run of such cycles is now the silence verdict, with the
// addresses of the server the run covered (addr among them) and, on a
// verdict, the transports that heard nothing.
//
// Since a connected handshake may use the rest of its cycle, a server that
// completes every TCP connect and then answers nothing ends each cycle on one
// swallowed transport, out of time, with nothing counted: the next cycle comes
// back to it with the next transport, and it is never charged. Two cycles in
// a row in which the address heard nothing on two different transports, or
// swallowCyclesMax cycles on any, are the verdict. One cycle never is - a
// single slow handshake, Polling's included, parks nothing - and a cycle in
// which any transport got an answer ends the run.
//
// The run is the server's: cycles on both its families count together.
func (m *Manager) swallowCycle(addr string, scan *scanState) (verdict bool, covered, heard []string) {
	sincePark := m.serverSincePark(addr)
	key := m.swallowKey(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	if scan.answered {
		if r := m.swallowed[key]; r != nil {
			r.endRun()
		}
		return false, nil, nil
	}
	if len(scan.inconclusive) == 0 && scan.unheard == 0 {
		return false, nil, nil
	}
	r := m.swallowRecordLocked(key, sincePark)
	r.addrs[addr] = true
	r.unanswered++
	if len(scan.inconclusive) > 0 {
		r.cycles++
		for _, id := range scan.inconclusive {
			r.heardNothing[id] = true
		}
	}
	covered = slices.Sorted(maps.Keys(r.addrs))
	if r.unanswered < swallowUnansweredMax && r.cycles < swallowCyclesMax && (r.cycles < 2 || len(r.heardNothing) < 2) {
		return false, covered, nil
	}
	if r.cycles < 2 || (r.cycles < swallowCyclesMax && len(r.heardNothing) < 2) {
		// The verdict of the unanswered cycles alone: no transport counted as
		// swallowed, so there is none to name.
		log.Warn("%s answered nothing over %d cycles in a row (%s) - its silence verdict",
			key, r.unanswered, strings.Join(covered, ", "))
	} else {
		log.Warn("%s heard nothing on %s over %d cycles in a row (%s) - its silence verdict",
			key, strings.Join(slices.Sorted(maps.Keys(r.heardNothing)), ", "), r.cycles, strings.Join(covered, ", "))
	}
	heard = slices.Sorted(maps.Keys(r.heardNothing))
	r.endRun()
	return true, covered, heard
}

// handshakeRun is a server's run of unanswered session handshakes.
type handshakeRun struct {
	count int
	addrs map[string]bool
	ids   map[string]bool
	last  time.Time
}

// handshakeRunVerdict is how many unanswered session handshakes in a row
// are the server's verdict: two, so the server's other family gets one try
// in between, as with a swallowed transport handshake.
const handshakeRunVerdict = 2

// HandshakeUnanswered books a session handshake the server never answered:
// s connected to cand, the tunnel's request went out, and nothing came
// back before the read deadline. Some transports connect without hearing
// from the server at all (Protocol Confusion), so their connect had been
// booked as a success: the fast path took the same transport to the same
// server every cycle, the server was never parked, and two swallowing
// servers kept the client from the healthy third for over seven minutes,
// the backoff growing to 2 minutes (R1 of the fix9 stand run).
//
// The transport is set aside like a swallowed one, on every address of the
// server, and loses the fast path; the server's other family gets the next
// try, with another transport; a second unanswered handshake on the server is
// its silence verdict, or the route's when the same transport died that way
// on the server before (routeDeath). Set aside on the one address only, the
// mute transport was tried again on the other family, and its second miss
// condemned a server another transport worked on (P2-3 of the round-8
// review). The other cure, a verdict only from two distinct transports, was
// not taken: a client with one transport would never reach one, and it costs
// the healthy transport a cycle.
// The error to wrap the handshake failure in is returned: ErrAddrSilent on
// a verdict, ErrCycleUnanswered otherwise - both cap the reconnect backoff
// at the silence cap.
func (m *Manager) HandshakeUnanswered(s Strategy, cand endpoint.Candidate, hasCand bool) error {
	if s == nil {
		return ErrCycleUnanswered
	}
	id := s.ID()
	m.mu.Lock()
	if m.lastSuccessfulStrategy != nil && m.lastSuccessfulStrategy.ID() == id {
		m.lastSuccessfulStrategy = nil
	}
	m.updateConfidence(id, false)
	m.sortStrategies()
	m.mu.Unlock()

	sel := m.selector()
	if sel == nil || !hasCand {
		return ErrCycleUnanswered
	}
	for _, addr := range append([]string{cand.Addr}, sel.Siblings(cand)...) {
		m.noteSwallowed(addr, []string{id})
	}
	key := m.swallowKey(cand.Addr)
	now := time.Now().Round(0)
	m.mu.Lock()
	if m.unansweredHS == nil {
		m.unansweredHS = make(map[string]*handshakeRun)
	}
	r := m.unansweredHS[key]
	if r == nil || now.Sub(r.last) > routeDeathWindow {
		r = &handshakeRun{addrs: make(map[string]bool), ids: make(map[string]bool)}
		m.unansweredHS[key] = r
	}
	r.count++
	r.addrs[cand.Addr] = true
	r.ids[id] = true
	r.last = now
	covered := slices.Sorted(maps.Keys(r.addrs))
	ids := slices.Sorted(maps.Keys(r.ids))
	verdict := r.count >= handshakeRunVerdict
	if verdict {
		delete(m.unansweredHS, key)
	}
	m.mu.Unlock()

	if !verdict {
		if sib, ok := m.swallowSibling(sel, cand, covered); ok {
			log.Info("Endpoint %s: the %s session handshake went unanswered - the next cycle tries the server's other address %s", cand, s.Name(), sib)
			sel.Pin(sib)
		} else {
			log.Info("Endpoint %s: the %s session handshake went unanswered", cand, s.Name())
		}
		return ErrCycleUnanswered
	}
	log.Warn("%s left %d session handshakes unanswered in a row (%s on %s) - its silence verdict",
		key, handshakeRunVerdict, strings.Join(ids, ", "), strings.Join(covered, ", "))
	if m.routeDeath(cand, deathSwallowed, "its session handshake went unanswered", ids) {
		return ErrCycleUnanswered
	}
	if sel.ReportSilent(cand, covered...) {
		log.Warn("Endpoint %s: every address of the server has a verdict - parking the server", cand)
	}
	m.logEndpointHealth(sel, cand)
	return ErrAddrSilent
}

// HandshakeAnswered ends cand's server's run of unanswered session
// handshakes: the server answered one.
func (m *Manager) HandshakeAnswered(cand endpoint.Candidate, hasCand bool) {
	if !hasCand {
		return
	}
	key := m.swallowKey(cand.Addr)
	m.mu.Lock()
	delete(m.unansweredHS, key)
	m.mu.Unlock()
}

// endSwallowRun ends addr's run of no-verdict cycles: a cycle reached a
// verdict. The skip list stays until a transport gets through.
func (m *Manager) endSwallowRun(addr string) {
	key := m.swallowKey(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.swallowed[key]; r != nil {
		r.endRun()
	}
}

// clearSwallowed forgets addr's swallow record: a transport got through.
//
// Only addr's part: the run ends - the server answered - and addr's skip
// list goes, but the other family's stays. Deleting the whole record cost a
// cycle on the next return to v6 when v4 had connected (P3-6 of the round-6
// review).
func (m *Manager) clearSwallowed(addr string) {
	key := m.swallowKey(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.swallowed[key]
	if r == nil {
		return
	}
	r.endRun()
	delete(r.skip, addr)
	if len(r.skip) == 0 {
		delete(m.swallowed, key)
	}
}

// ConnectExcluding tries strategies excluding specified ones (for fallback)
func (m *Manager) ConnectExcluding(ctx context.Context, target string, excludeIDs []string) (net.Conn, Strategy, error) {
	// One scan, not two. RTT masking is a post-success wrapper (WrapWithRTTMasking
	// on an already-connected conn); it never changes whether a strategy connects.
	// The old code scanned once WITHOUT masking and, on total failure, scanned the
	// whole list AGAIN with masking on - a full second round of connectTimeouts and
	// the same DPI fingerprint, unable by construction to reach any conn the first
	// round did not. Decide masking up front and make a single pass, so a
	// successful connection is wrapped when masking is on and a failed scan is not
	// paid for twice.
	return m.connectScan(ctx, target, excludeIDs, &scanState{})
}

// connectScan is ConnectExcluding on a scan state the caller reads afterwards.
func (m *Manager) connectScan(ctx context.Context, target string, excludeIDs []string, scan *scanState) (net.Conn, Strategy, error) {
	m.mu.RLock()
	rttEnabled := m.rttMaskingEnabled
	m.mu.RUnlock()
	return m.connectWithRTTScan(ctx, target, excludeIDs, rttEnabled, scan)
}

// connectWithRTT is the internal connect method with optional RTT masking. It
// scans on its own, for callers that make a single pass.
func (m *Manager) connectWithRTT(ctx context.Context, target string, excludeIDs []string, useRTTMasking bool) (net.Conn, Strategy, error) {
	return m.connectWithRTTScan(ctx, target, excludeIDs, useRTTMasking, &scanState{})
}

// connectWithRTTScan is connectWithRTT with the cycle-wide scan state supplied
// by the caller.
func (m *Manager) connectWithRTTScan(ctx context.Context, target string, excludeIDs []string, useRTTMasking bool, scan *scanState) (net.Conn, Strategy, error) {
	// Every path that reaches a strategy's Connect goes through here, so this is
	// where a dial that nobody labelled picks up the pinned endpoint's secret.
	// dialEndpoints labels its own, per candidate, and that label wins.
	ctx = m.ensureDialSecret(ctx)
	m.udpGateRefresh()

	m.mu.RLock()
	// Check if we have a recent successful strategy to try first (for fast reconnect)
	lastSuccessful := m.lastSuccessfulStrategy
	lastSuccessfulTime := m.lastSuccessfulTime
	androidMode := m.androidMode
	tcpFailuresThreshold := m.tcpFailuresBeforeQUIC
	excludeUDP := m.excludeUDPStrategies
	m.mu.RUnlock()

	// Exclusion set, built once: the fast-reconnect gate and the full scan below
	// both consult it.
	excludeMap := make(map[string]bool, len(excludeIDs))
	for _, id := range excludeIDs {
		excludeMap[id] = true
	}
	// A connected handshake may use the rest of its cycle, so a swallowed one
	// costs the cycle; the transports swallowed on this address in the recent
	// cycles keep it from costing the next ones too. All of them, not the last
	// one: with one slot two swallowed transports took turns, cycle after
	// cycle, and the one that worked was never reached.
	if scan.addr == "" {
		scan.addr = target
	}
	swallowSkip := m.swallowSkip(scan.addr)
	if len(swallowSkip) > 0 {
		log.Info("Strategies %s ran out a recent cycle on %s in their handshake - leaving them out this cycle unless nothing else is left",
			strings.Join(slices.Sorted(maps.Keys(swallowSkip)), ", "), scan.addr)
	}
	// The transports a route verdict set aside on this server are tried
	// last, after every other eligible one - not left out while anything else
	// is eligible: a transport refused on both servers could hold them off
	// for cycle after cycle, each one charging the servers (P2-E of the
	// round-6 review). The route park is weaker evidence than a swallow and
	// lasts longer.
	routeLast := m.routeSkip(scan.addr)
	if len(routeLast) > 0 {
		log.Info("Strategies %s died on this server and the one before it - trying them last here",
			strings.Join(slices.Sorted(maps.Keys(routeLast)), ", "))
	}
	defer func() { m.noteSwallowed(scan.addr, scan.connectedSilent); scan.connectedSilent = nil }()

	// Try last successful strategy first if it was recent (within 5 minutes), but
	// only if it clears the same gates the full scan applies to every other
	// candidate: not on the caller's exclusion list, not a UDP transport while UDP
	// is blocked, not storm-parked (auto mode), and admitted by its circuit
	// breaker. The fast path used to skip all of these and dial straight through,
	// so a strategy the caller had just excluded, one riding a dead UDP path, or
	// one whose circuit was open still cost a full connectTimeout on every
	// reconnect. Forced mode keeps its single strategy regardless of parking.
	fastEligible := lastSuccessful != nil &&
		time.Since(lastSuccessfulTime) < 5*time.Minute &&
		!excludeMap[lastSuccessful.ID()] &&
		!swallowSkip[lastSuccessful.ID()] && !routeLast[lastSuccessful.ID()] &&
		(!excludeUDP || !isUDPBasedStrategy(lastSuccessful)) &&
		(m.forced || !m.stormDetector.IsParked(lastSuccessful.ID())) &&
		m.circuitBreakers.CanTry(lastSuccessful.ID())

	fastSilent := false // the fast path heard nothing this cycle
	var fastErr error   // how the fast path failed this cycle, if it was dialled
	if fastEligible {
		// Loop guard: a strategy that connects but whose tunnel dies seconds later
		// can ride this fast path in a tight reconnect loop without ever being
		// parked. After too many fast reconnects in a short window, fall through
		// to the full scan (forced mode has no alternative, so never skips).
		m.mu.Lock()
		skipFast := !m.forced && m.shouldSkipFastReconnect(lastSuccessful.ID(), time.Now())
		m.mu.Unlock()

		switch {
		case skipFast:
			log.Warn("Fast reconnect via %s exceeded %d attempts within %v - forcing full strategy scan",
				lastSuccessful.Name(), fastReconnectLimit, fastReconnectWindow)
		case !m.circuitBreakers.BeginHalfOpenAttempt(lastSuccessful.ID()):
			// Half-open slots were taken between the CanTry check and here; let the
			// full scan decide, exactly as it would for any other strategy.
			log.Debug("Fast reconnect via %s skipped (circuit breaker half-open slots exhausted)", lastSuccessful.Name())
		default:
			log.Info("Trying last successful strategy first: %s", lastSuccessful.Name())

			// The fast path may not wait out the whole cycle for a TCP
			// connect: the reconnect gives a cycle 15 s and an attempt may
			// take 30, and half is left for the scan. A connect that is up
			// keeps the rest, because the handshake on it is the one that
			// worked last time, and a slow one (7-9 s through a lossy path
			// or a server dialling its cover) used to be cut at half and
			// land the tunnel on HTTP Polling.
			budget := m.attemptBudget(ctx)
			dialBudget := budget
			if budget < m.connectTimeout {
				dialBudget = budget / 2
			}
			conn, latency, refused, err := m.connectThroughRefusal(ctx, lastSuccessful, target, budget, dialBudget, scan)

			if err == nil {
				// Success - update stats (also records the breaker success)
				m.mu.Lock()
				m.lastSuccessfulTime = time.Now()
				m.consecutiveTCPTimeouts = 0 // Reset TCP timeout counter on success
				m.updateConfidenceWithLatency(lastSuccessful.ID(), true, latency)
				m.mu.Unlock()

				optimizeTCPConn(conn)
				if useRTTMasking {
					m.mu.RLock()
					rttProfile := m.rttProfile
					m.mu.RUnlock()
					conn = WrapWithRTTMasking(conn, rttProfile)
				}

				log.Info("Fast reconnect via %s (latency=%v)", lastSuccessful.Name(), latency)
				return conn, lastSuccessful, nil
			}

			if refused {
				// Not the strategy's failure: the port is closed to all of them.
				m.circuitBreakers.CancelHalfOpenAttempt(lastSuccessful.ID())
				return nil, nil, refusedScan(target, fmt.Errorf("%s: %w", lastSuccessful.Name(), err))
			}

			// The fast path is the first transport of this cycle, and what it
			// heard is evidence about the address like any other: a silent
			// server costs the fast path the most, and leaving it out of the
			// count is how a reconnect spent its whole budget here and then
			// called the address "answering".
			if !isUDPBasedStrategy(lastSuccessful) {
				switch m.classifyAttempt(err, latency, attemptLimit(lastSuccessful, budget, dialBudget)) {
				case attemptSilent:
					scan.timeouts++
					if !dialNeverConnected(err) {
						scan.silent = append(scan.silent, lastSuccessful.ID())
					}
					fastSilent = true
					// It had its turn this cycle; dialling it again in the
					// scan would only spend the rest of the budget the same way.
					excludeMap[lastSuccessful.ID()] = true
				case attemptInconclusive:
					scan.unheard++
					if m.swallowEvidence(lastSuccessful, scan.allowance) {
						scan.inconclusive = append(scan.inconclusive, lastSuccessful.ID())
					}
					excludeMap[lastSuccessful.ID()] = true
				case attemptNotDialled:
					// Still queued on this client when its dial limit came:
					// no verdict, and the queue is not shorter in the scan.
					excludeMap[lastSuccessful.ID()] = true
				default:
					scan.answered = true
				}
			}

			fastErr = fmt.Errorf("%s: %w", lastSuccessful.Name(), err)

			// Record the failure so a fast reconnect that keeps failing feeds the
			// breaker and confidence stats instead of looping invisibly past them.
			// Mirror the scan: one record per attempt, timeout counted as timeout.
			m.mu.Lock()
			m.updateConfidenceStats(lastSuccessful.ID(), false, 0)
			if isTimeoutError(err) {
				m.circuitBreakers.RecordTimeout(lastSuccessful.ID())
			} else {
				m.circuitBreakers.RecordFailure(lastSuccessful.ID())
			}
			m.mu.Unlock()
			log.Debug("Last successful strategy failed: %v, falling back to full strategy list", err)
		}
	}

	m.mu.RLock()
	// Filter out disabled strategies (priority <= 0) and excluded strategies
	var strategies []Strategy
	var quicStrategies []Strategy // Collect QUIC strategies separately for fast fallback
	skippedOthers := 0            // held back by a breaker, a storm park or the UDP gate
	var sittingOut []Strategy     // eligible, but swallowed in a recent cycle here
	var last []Strategy           // eligible, set aside here by a route verdict: tried last

	for _, s := range m.strategies {
		if s.Priority() <= 0 {
			log.Debug("Skipping disabled strategy: %s (priority=%d)", s.Name(), s.Priority())
			continue
		}
		if excludeMap[s.ID()] {
			log.Debug("Skipping excluded strategy: %s", s.Name())
			continue
		}
		// Check circuit breaker. This only assembles the candidate list, so use
		// the non-mutating CanTry - the half-open slot is occupied later, at the
		// actual dial, so listing a strategy never burns a recovery attempt.
		if !m.circuitBreakers.CanTry(s.ID()) {
			log.Debug("Skipping strategy %s (circuit breaker open)", s.Name())
			skippedOthers++
			continue
		}
		// Skip strategies parked by the storm detector (auto-mode only).
		// Forced mode keeps its single strategy regardless.
		if !m.forced && m.stormDetector.IsParked(s.ID()) {
			log.Debug("Skipping strategy %s (storm cooldown)", s.Name())
			skippedOthers++
			continue
		}
		// Skip UDP-based strategies (like QUIC) if UDP is not working
		if excludeUDP && isUDPBasedStrategy(s) {
			log.Debug("Skipping UDP strategy %s (UDP connectivity issue)", s.Name())
			skippedOthers++
			continue
		}

		if swallowSkip[s.ID()] {
			// Held back, not gone: the fast path alone being silent is not
			// "every transport" while this one sits out its turn. Checked
			// after the gates, so only an otherwise eligible transport sits
			// out - and before the route's set-aside: a transport swallowed
			// here sits out even if the route also set it aside (P3-5 of
			// the round-7 review).
			log.Debug("Skipping strategy %s (handshake swallowed in a recent cycle)", s.Name())
			skippedOthers++
			sittingOut = append(sittingOut, s)
			continue
		}

		if routeLast[s.ID()] {
			last = append(last, s)
			continue
		}

		// Separate QUIC strategies for fast fallback
		if isUDPBasedStrategy(s) {
			quicStrategies = append(quicStrategies, s)
		}
		strategies = append(strategies, s)
	}
	rttProfile := m.rttProfile
	m.mu.RUnlock()

	for _, s := range last {
		if isUDPBasedStrategy(s) {
			quicStrategies = append(quicStrategies, s)
		}
		strategies = append(strategies, s)
	}
	// strategies[lastFrom:] are the set-aside transports.
	lastFrom := len(strategies) - len(last)

	if len(strategies) == 0 && len(sittingOut) > 0 {
		// Every eligible transport is sitting out its turn: the skip list
		// was meant to let the others go first, and there are no others.
		// Skipping anyway emptied the cycle, gave no verdict and grew the
		// backoff, and the run of swallowed cycles never reached its
		// verdict either.
		log.Info("Only transports swallowed in a recent cycle are eligible - trying them again")
		strategies, skippedOthers = sittingOut, skippedOthers-len(sittingOut)
		for _, s := range sittingOut {
			if isUDPBasedStrategy(s) {
				quicStrategies = append(quicStrategies, s)
			}
		}
	}

	if len(strategies) == 0 {
		// If storm parking emptied the list, unpark everything and retry with
		// the full set: a storming strategy is still better than no tunnel.
		// This guarantees the failover loop converges instead of dead-ending.
		if !m.forced && m.stormDetector.AnyParked() {
			log.Warn("All strategies parked by storm cooldown - unparking to avoid total outage")
			m.stormDetector.Reset()
			return m.connectWithRTTScan(ctx, target, excludeIDs, useRTTMasking, scan)
		}
		if fastSilent && skippedOthers == 0 {
			// The fast path was the only transport there is, and it heard
			// nothing: that is every transport. Not when the others were only
			// held back by a breaker, a storm park or the UDP gate.
			return nil, nil, fmt.Errorf("%w: %w, only transport silent", errAddrSilent, errStrategyScanFailed)
		}
		if fastErr != nil {
			// The fast path was the only transport left and it was dialled:
			// its failure is the cycle's. "No available strategies" read as a
			// circuit-breaker problem and doubled the backoff to 2 minutes
			// (Geneva on the 2026-10-22 stand: back 63 s after the fault
			// ended).
			return nil, nil, fastErr
		}
		return nil, nil, fmt.Errorf("no available strategies (all excluded or circuit-broken)")
	}

	modeStr := ""
	if useRTTMasking {
		modeStr = " [RTT masking]"
	}
	log.Info("Connecting to %s (trying %d strategies)%s", target, len(strategies), modeStr)

	var lastErr error
	attemptCount := 0
	addrSilent := false
	toLast := false // skipping to the set-aside transports

	for i, s := range strategies {
		if ctxErr(ctx) != nil {
			// Out of time before this strategy was dialled. Dialling it anyway
			// fails at once and charges it for the caller's deadline.
			return nil, nil, scanOutOfTime(ctx, target, scan, lastErr)
		}
		if !scan.answered && scan.timeouts >= tcpFailuresThreshold && !isUDPBasedStrategy(s) && len(last) > 0 && i < lastFrom {
			// The verdict is in, but the transports the route set aside here
			// have not been dialled: they died elsewhere, and may be what
			// works here now. Abandoning the scan before them left them
			// never tried on a server where everything else timed out (P3-5
			// of the round-7 review).
			if !toLast {
				log.Info("Address %s answered nothing on %d transports - trying the ones set aside before giving up", target, scan.timeouts)
				toLast = true
			}
			continue
		}
		if !scan.answered && scan.timeouts >= tcpFailuresThreshold && !isUDPBasedStrategy(s) && len(last) == 0 {
			// Nothing has come back from this address on any transport. Walking
			// the rest of the list means one connect timeout per strategy for a
			// verdict already in hand, and the endpoint layer is waiting for
			// that verdict to move the client to another server.
			log.Info("Address %s answered nothing on %d transports - abandoning the scan%s",
				target, scan.timeouts, modeStr)
			addrSilent = true

			// QUIC rides UDP, which the TCP verdict says nothing about. Android
			// jumps to it here rather than losing it with the rest of the list.
			if androidMode {
				log.Info("Fast QUIC fallback: %d TCP timeouts, skipping remaining TCP strategies", scan.timeouts)
				for _, qs := range quicStrategies {
					if excludeMap[qs.ID()] || !m.circuitBreakers.CanTry(qs.ID()) {
						continue
					}
					// About to really dial this QUIC strategy: occupy a half-open
					// slot now, at the dial, not during list assembly.
					if !m.circuitBreakers.BeginHalfOpenAttempt(qs.ID()) {
						log.Debug("Skipping QUIC fallback %s (circuit breaker half-open slots exhausted)", qs.Name())
						continue
					}

					log.Debug("Trying QUIC fallback: %s", qs.Name())
					connectCtx, cancel := context.WithTimeout(ctx, m.connectTimeout)
					start := time.Now()
					conn, err := qs.Connect(connectCtx, target)
					latency := time.Since(start)
					cancel()

					if err == nil {
						m.mu.Lock()
						m.lastSuccessfulStrategy = qs
						m.lastSuccessfulTime = time.Now()
						m.consecutiveTCPTimeouts = 0
						m.updateConfidenceWithLatency(qs.ID(), true, latency)
						m.sortStrategies()
						m.lastConnectionLatency = latency
						m.lastConnectionAttempts = attemptCount
						m.lastConnectionStrategy = qs.Name()
						m.lastConnectionStrategyID = qs.ID()
						m.mu.Unlock()

						optimizeTCPConn(conn)
						if useRTTMasking {
							conn = WrapWithRTTMasking(conn, rttProfile)
						}

						log.Info("Connected via QUIC fallback %s (latency=%v)", qs.Name(), latency)
						return conn, qs, nil
					}
					lastErr = fmt.Errorf("%s: %w", qs.Name(), err)
				}
			}
			break
		}

		m.mu.RLock()
		confidence := m.results[s.ID()].Confidence
		m.mu.RUnlock()

		log.Debug("Trying strategy %d/%d: %s (confidence=%.2f)%s",
			i+1, len(strategies), s.Name(), confidence, modeStr)

		// About to really dial this strategy: occupy a half-open probe slot here,
		// at the dial, not during list assembly (which used CanTry). One slot per
		// logical strategy attempt, mirroring the single breaker record on
		// exhaustion below - retries do not each take a slot.
		if !m.circuitBreakers.BeginHalfOpenAttempt(s.ID()) {
			log.Debug("Skipping strategy %s (circuit breaker half-open slots exhausted)", s.Name())
			continue
		}

		// Tracks whether the strategy's final failing attempt was a timeout, so
		// the single circuit-breaker record on exhaustion reflects the right
		// outcome (timeouts are treated more aggressively by the breaker).
		strategyTimedOut := false
		for retry := 0; retry < m.maxRetries; retry++ {
			attemptCount++
			log.Debug("  Attempt %d/%d for %s", retry+1, m.maxRetries, s.Name())

			// Same rule as the fast path: while other transports remain, one
			// attempt may not wait the whole of a short cycle for its TCP
			// connect; once connected, its handshake keeps the rest.
			budget := m.attemptBudget(ctx)
			dialBudget := budget
			if budget < m.connectTimeout && i < len(strategies)-1 {
				dialBudget = budget / 2
			}
			conn, latency, refused, err := m.connectThroughRefusal(ctx, s, target, budget, dialBudget, scan)

			if err == nil {
				// Success - update confidence with latency and save for fast reconnect
				m.mu.Lock()
				m.lastSuccessfulStrategy = s
				m.lastSuccessfulTime = time.Now()
				m.consecutiveTCPTimeouts = 0 // Reset on success
				m.updateConfidenceWithLatency(s.ID(), true, latency)
				m.sortStrategies()
				m.mu.Unlock()

				// Optimize TCP connection for low latency
				optimizeTCPConn(conn)

				// Apply RTT masking if this pass uses it
				if useRTTMasking {
					conn = WrapWithRTTMasking(conn, rttProfile)
				}

				// Store connection info for Android UI
				m.mu.Lock()
				m.lastConnectionLatency = latency
				m.lastConnectionAttempts = attemptCount
				m.lastConnectionStrategy = s.Name()
				m.lastConnectionStrategyID = s.ID()
				m.mu.Unlock()

				log.Info("Connected via %s (latency=%v, attempts=%d, rtt_masking=%v)", s.Name(), latency, attemptCount, useRTTMasking)
				return conn, s, nil
			}

			lastErr = fmt.Errorf("%s: %w", s.Name(), err)

			if refused {
				m.circuitBreakers.CancelHalfOpenAttempt(s.ID())
				return nil, nil, refusedScan(target, lastErr)
			}

			// Distinguish between timeout and regular errors. The circuit
			// breaker is NOT recorded per retry here - it is recorded once when
			// the strategy is exhausted, so one logical failure counts once
			// regardless of maxRetries.
			timedOut := isTimeoutError(err)
			// Whether the address said anything is a question about the clock,
			// not about the wording of the error. On the device the same
			// ten-second wait came back as a timeout on one cycle and as
			// "use of closed network connection" on the next - the deadline
			// fired, something closed the socket, and the text stopped
			// containing the word the classifier looks for. A refusal or a
			// reset arrives in milliseconds; only silence costs the whole
			// budget.
			verdict := m.classifyAttempt(err, latency, attemptLimit(s, budget, dialBudget))

			if timedOut {
				log.Debug("  Failed: %s TIMEOUT (latency=%v)", s.Name(), latency)
			} else {
				log.Debug("  Failed: %v (latency=%v)", err, latency)
			}
			strategyTimedOut = timedOut

			switch verdict {
			case attemptSilent:
				if !isUDPBasedStrategy(s) {
					scan.timeouts++
					if !dialNeverConnected(err) {
						scan.silent = append(scan.silent, s.ID())
					}
					log.Debug("TCP silence count: %d/%d", scan.timeouts, tcpFailuresThreshold)
				}
				// Track TCP timeouts for Android fast fallback
				if androidMode && !isUDPBasedStrategy(s) {
					m.mu.Lock()
					m.consecutiveTCPTimeouts++
					// Re-sort strategies with updated penalty
					m.sortStrategies()
					m.mu.Unlock()
				}
			case attemptInconclusive:
				scan.unheard++
				if m.swallowEvidence(s, scan.allowance) {
					scan.inconclusive = append(scan.inconclusive, s.ID())
				}
			case attemptAnswered:
				// A refusal, a reset, a handshake that got an answer it did not
				// like: the address is talking. Whatever is wrong here is a
				// property of this transport, which is precisely the case the
				// full scan exists for, so the address is no longer a candidate
				// for the silence verdict this cycle.
				scan.answered = true
			}
			if verdict != attemptAnswered {
				// Silence once per transport per cycle, not once per attempt:
				// with the desktop's two attempts a single swallowed transport
				// made "two silent transports", and the retry spent the budget
				// the next transport needed.
				break
			}

			// Brief pause before retry
			select {
			case <-ctx.Done():
				return nil, nil, scanOutOfTime(ctx, target, scan, lastErr)
			case <-time.After(100 * time.Millisecond):
			}
		}

		// Strategy exhausted all retries - update confidence EMA and record
		// exactly one circuit-breaker failure for the whole strategy attempt.
		// The retry loop no longer writes to the breaker, so a single logical
		// strategy failure counts once (as timeout or failure) regardless of
		// maxRetries. Confidence EMA is still updated honestly on every attempt.
		m.mu.Lock()
		m.updateConfidenceStats(s.ID(), false, 0)
		if strategyTimedOut {
			m.circuitBreakers.RecordTimeout(s.ID())
		} else {
			m.circuitBreakers.RecordFailure(s.ID())
		}
		m.mu.Unlock()

		log.Debug("Strategy %s exhausted, moving to next", s.Name())
	}

	if !addrSilent && !scan.answered && scan.timeouts >= tcpFailuresThreshold {
		// The last transport walked was the one that completed the count:
		// the same verdict as abandoning the scan before the next one. It
		// read as an ordinary failure, under the threshold of two, so a
		// server whose remaining transports were all silent after a route
		// verdict was not charged (routeDeath).
		log.Info("Address %s answered nothing on %d transports%s", target, scan.timeouts, modeStr)
		addrSilent = true
	}
	if !addrSilent && ctxErr(ctx) != nil {
		// The last transport ran into the caller's deadline: the same ending
		// as running out of time between transports.
		return nil, nil, scanOutOfTime(ctx, target, scan, lastErr)
	}
	if addrSilent {
		// No emergency reprobe here: it exists to find a way back to an address
		// that went dark, and this scan's whole point is that the client should
		// stop asking this one and try another server.
		return nil, nil, fmt.Errorf("%w: %w, last error: %w", errAddrSilent, errStrategyScanFailed, lastErr)
	}

	log.Error("All %d strategies failed after %d attempts%s", len(strategies), attemptCount, modeStr)

	// Trigger emergency reprobe to recover from network outage. Hang it off the
	// manager lifecycle context, not context.Background(), so Close stops it
	// instead of leaving it to run out its own attempt budget after teardown.
	go m.TriggerEmergencyReprobe(m.lifeCtx)

	return nil, nil, fmt.Errorf("%w, last error: %w", errStrategyScanFailed, lastErr)
}

// GetStats returns current strategy statistics
func (m *Manager) GetStats() map[string]Result {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]Result)
	for id, r := range m.results {
		stats[id] = *r
	}
	return stats
}

// GetOrderedStrategies returns strategies in current priority order
func (m *Manager) GetOrderedStrategies() []Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Strategy, len(m.strategies))
	copy(result, m.strategies)
	return result
}

// ConnectionInfo holds last connection metadata for Android UI
type ConnectionInfo struct {
	StrategyID string
	Strategy   string
	Latency    time.Duration
	Attempts   int
}

// GetLastConnectionInfo returns info about the last successful connection
func (m *Manager) GetLastConnectionInfo() ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ConnectionInfo{
		StrategyID: m.lastConnectionStrategyID,
		Strategy:   m.lastConnectionStrategy,
		Latency:    m.lastConnectionLatency,
		Attempts:   m.lastConnectionAttempts,
	}
}

// StrategyConn wraps connection with strategy info
type StrategyConn struct {
	net.Conn
	strategy Strategy
}

// NetConn returns the wrapped connection.
func (sc *StrategyConn) NetConn() net.Conn { return sc.Conn }

// ServerKeepaliveCounter is implemented by a tunnel conn that splices
// keepalive frames of its own into what it delivers - HTTP Polling's feeder,
// which keeps the TUN reader's deadline fed while polls succeed.
// ServerKeepalives counts only the zero-length frames the server sent, which
// is what a keepalive echo has to be judged by.
type ServerKeepaliveCounter interface {
	// ServerKeepalives returns the count; tracked is false while the conn
	// can not tell the server's frames apart (before the TUN frame stream,
	// or after losing its framing), and the count then says nothing.
	ServerKeepalives() (n uint64, tracked bool)
}

// KeepaliveMaker is implemented by a strategy whose conns splice keepalive
// frames of their own into the downlink (HTTP Polling). A caller that judges
// echoes needs those conns' ServerKeepaliveCounter, and must not judge them
// without it.
type KeepaliveMaker interface {
	MakesUpKeepalives() bool
}

// ServerKeepaliveCounterOf finds a ServerKeepaliveCounter in conn or under
// its wrappers (anything with NetConn).
func ServerKeepaliveCounterOf(conn net.Conn) (ServerKeepaliveCounter, bool) {
	return findUnder[ServerKeepaliveCounter](conn)
}

// UplinkQueue is implemented by a tunnel conn whose Write only queues: HTTP
// Polling, where a write is on its way only when a poll takes it. See
// HTTPPollingConn.UplinkProgress.
type UplinkQueue interface {
	UplinkProgress() (accepted, sent uint64)
}

// UplinkQueueOf finds an UplinkQueue in conn or under its wrappers.
func UplinkQueueOf(conn net.Conn) (UplinkQueue, bool) {
	return findUnder[UplinkQueue](conn)
}

// findUnder looks for a T in conn and under its wrappers (anything with
// NetConn), a few levels deep.
func findUnder[T any](conn net.Conn) (T, bool) {
	for range 8 {
		if c, ok := conn.(T); ok {
			return c, true
		}
		w, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		conn = w.NetConn()
	}
	var zero T
	return zero, false
}

// Strategy returns the strategy used for this connection
func (sc *StrategyConn) Strategy() Strategy {
	return sc.strategy
}

// Ensure interface compliance
var _ io.ReadWriteCloser = (*StrategyConn)(nil)

// DefaultManagerConfig contains configuration for default manager
type DefaultManagerConfig struct {
	ServerAddr string       // Server address for server-based strategies
	Secret     []byte       // Shared secret for authentication
	RelayNodes []*RelayNode // Mesh relay nodes (optional)
	CoverHost  string       // Host to impersonate for HTTP/2 stego

	// IPv6 Transport Layer
	ServerAddrV6 string // IPv6 server address (e.g., "[2001:db8::100]:995")
	PreferIPv6   bool   // Prefer IPv6 transport if available (default: false)
	FallbackToV4 bool   // Fallback to IPv4 if IPv6 fails (default: true)

	// Endpoints, when non-empty, replaces the single ServerAddr/ServerAddrV6
	// pair above. The legacy fields stay: they are what ControlConfig,
	// tun.VPNConfig, the pool, JNI, macOS and the benchmarks read, and they
	// still describe the first endpoint.
	Endpoints []endpoint.Endpoint

	// EndpointTuning is the [selection] section: which endpoint wins among the
	// healthy ones and how quickly a failing one is parked. Its zero value
	// keeps the historical behaviour - configured order, and the family policy
	// derived from PreferIPv6/FallbackToV4 above.
	EndpointTuning endpoint.Tuning

	// RTT Masking configuration
	RTTMaskingEnabled bool        // Enable RTT masking on connections
	RTTProfile        *RTTProfile // RTT profile to use (nil = auto-select)

	// Mux configuration (99.5% success rate with VLESS+Reality+mux)
	MuxEnabled bool        // Enable connection multiplexing (default: true)
	MuxConfig  *mux.Config // Mux configuration (nil = use default)

	// QUIC configuration
	QUICEnabled bool // Enable QUIC strategy
	// QUICPort is what -quic-port carried. It is not a dial port: QUIC goes to
	// derivedQUICPort, and a different value only earns a warning (see
	// registerQUICStrategies).
	QUICPort              int
	QUICSalamanderEnabled bool // Enable QUIC with Salamander obfuscation

	// ICMP tunnel configuration (backup transport, requires CAP_NET_RAW)
	ICMPTunnelEnabled bool // Enable ICMP tunnel strategy (off by default)

	// Seqovl level-A packet overlap (Linux + CAP_NET_ADMIN, off by default)
	SeqovlPacketEnabled bool // Enable packet-level TCP sequence overlap on top of level-B decoy

	// REALITY configuration
	REALITYEnabled bool // Enable REALITY protocol (99.5% success rate)

	// REALITYServerPubKeyB64 is the server's static X25519 public key, base64.
	// Non-empty switches the REALITY client onto the B1 transport: a real TLS
	// 1.3 handshake with authentication in session_id.
	REALITYServerPubKeyB64 string

	// TLSFingerprint names the uTLS browser profile used for ClientHellos
	// (see internal/tls.FingerprintMap). Empty selects the default profile.
	// It is fixed for the process lifetime on purpose — rotating fingerprints
	// after a censor throttles a SNI escalates the penalty.
	TLSFingerprint string

	// REALITYRequireDataV2 refuses servers that do not confirm the v2 data
	// layer (per-connection X25519 keys + ChaCha20-Poly1305) instead of falling
	// back to v1. Off during the rollout, since clients are upgraded last.
	REALITYRequireDataV2 bool

	// WebSocket Padded configuration
	WebSocketPaddedEnabled bool // Enable WebSocket with Salamander padding

	// ECH (Encrypted Client Hello) configuration
	ECHEnabled    bool   // Enable ECH to hide SNI from DPI
	ECHConfigList []byte // ECHConfigList from server (base64 decoded)
	ECHPublicName string // Outer SNI visible to network (e.g. "cloudflare-ech.com")

	// QUIC SNI fragmentation for GFW bypass
	QUICSNIFragEnabled bool // Enable SNI fragmentation in QUIC CRYPTO frames

	// Post-Quantum crypto for REALITY
	PQEnabled         bool   // Enable post-quantum crypto (ML-KEM-768 + ML-DSA-65)
	PQServerKemPubB64 string // Server's Kyber768 public key in base64

	// Android-specific optimizations
	AndroidMode bool // Running on Android - use shorter timeouts, fewer retries, TCP-first

	// Port hopping for DPI evasion
	// High ports (47000+) are less analyzed by DPI, periodic port changes complicate blocking
	PortHopping *porthopping.Config

	// Shaper, when non-nil, is injected into Traffic-Morph strategies and
	// drives sizing/inter-arrival in MorphedConn. nil keeps the legacy
	// NoopShaper behaviour (wire-format unchanged).
	Shaper shaper.Shaper

	// BurstReshape configures the nudge/ack exchange. It has to match the
	// server: see internal/strategy/burst_reshape.go.
	BurstReshape BurstReshapeConfig

	// ShaperID is the 1-byte value advertised to the server in the MRPH
	// handshake so it can rebuild the matching framing. 0 (noop) keeps the
	// legacy wire format. Ignored when Shaper is nil.
	ShaperID byte
}

// NewDefaultManager creates a manager with all strategies pre-registered
func NewDefaultManager(cfg DefaultManagerConfig) *Manager {
	m := NewManager()

	// Set before registering: strategies copy this at construction.
	m.SetBurstReshape(cfg.BurstReshape)

	// Set before the selector exists: it is the fallback every endpoint without
	// a secret of its own resolves to, and CurrentSecret must never return nil
	// once a dial can start.
	m.setDefaultSecret(cfg.Secret)

	initManagerTransport(m, cfg)
	initManagerPortHopping(m, cfg)
	initManagerAndroidMode(m, cfg)
	initManagerMux(m, cfg)
	initManagerRTTMasking(m, cfg)
	registerAllStrategies(m, cfg)

	return m
}

// initManagerTransport builds the endpoint selector.
//
// With no explicit Endpoints list it synthesises the single dual-addressed
// server the legacy flags describe, so a unit started with nothing but -server
// keeps working and keeps dialling exactly the same address.
func initManagerTransport(m *Manager, cfg DefaultManagerConfig) {
	eps := cfg.Endpoints
	if len(eps) == 0 {
		if cfg.ServerAddr == "" && cfg.ServerAddrV6 == "" {
			return
		}
		eps = []endpoint.Endpoint{{Name: "server", V4: cfg.ServerAddr, V6: cfg.ServerAddrV6}}
	}
	// Synthesised or passed in, every endpoint goes through the same
	// normalisation as client.ResolveEndpoints, so a raw -server-v6 value
	// ("2001:db8::2") reaching this fallback still dials as [2001:db8::2]:port.
	normalized := make([]endpoint.Endpoint, 0, len(eps))
	for _, e := range eps {
		n, err := e.Normalized()
		if err != nil {
			log.Warn("Endpoint selector not configured: %s: %v", e.Label(len(normalized)), err)
			return
		}
		normalized = append(normalized, n)
	}
	eps = normalized

	legacy := endpoint.FamilyPolicyFromLegacy(cfg.PreferIPv6, cfg.FallbackToV4)
	sel, err := endpoint.NewTunedSelector(eps, cfg.EndpointTuning, legacy)
	if err != nil {
		log.Warn("Endpoint selector not configured: %v", err)
		return
	}
	m.endpoints = sel

	if len(eps) > 1 {
		log.Info("Endpoint pool: %d servers, selection=%s, family=%s",
			len(eps), cfg.EndpointTuning.Selection, cfg.EndpointTuning.FamilyOr(legacy))
	}
	if cfg.ServerAddrV6 != "" && cfg.PreferIPv6 {
		log.Info("IPv6 transport enabled (IPv6=%s, IPv4=%s, fallback=%v)",
			cfg.ServerAddrV6, cfg.ServerAddr, cfg.FallbackToV4)
	}
}

// SetEndpoints replaces the endpoint list and the family policy.
//
// Health is discarded only when the new list is genuinely different: selectors
// are process-scoped per configuration, so re-applying the same endpoints hands
// back the same instance rather than forgetting everything it measured. Use
// ResetHealth to discard verdicts deliberately - that is what a network change
// does.
func (m *Manager) SetEndpoints(eps []endpoint.Endpoint, policy endpoint.FamilyPolicy) error {
	return m.SetEndpointsTuned(eps, endpoint.Tuning{Family: &policy})
}

// SetEndpointsTuned is SetEndpoints with the whole [selection] section rather
// than the family policy alone, and with the same health semantics.
func (m *Manager) SetEndpointsTuned(eps []endpoint.Endpoint, tuning endpoint.Tuning) error {
	sel, err := endpoint.NewTunedSelector(eps, tuning, endpoint.PreferV6)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.endpoints = sel
	m.mu.Unlock()
	return nil
}

// selector returns the endpoint selector, or nil when the manager was built
// without one (NewManager, benchmarks, strategy unit tests).
func (m *Manager) selector() *endpoint.Selector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.endpoints
}

// initManagerPortHopping configures the port hopper if enabled.
func initManagerPortHopping(m *Manager, cfg DefaultManagerConfig) {
	if cfg.PortHopping == nil || !cfg.PortHopping.Enabled {
		return
	}
	hopper, err := porthopping.NewPortHopper(cfg.PortHopping)
	if err != nil {
		log.Warn("Port hopping disabled: %v", err)
		return
	}
	m.portHopper = hopper
	hopper.OnHop(func(oldPort, newPort int) {
		log.Info("Port hop: %d -> %d, triggering reconnect", oldPort, newPort)
		m.triggerReconnect()
	})
	log.Info("Port hopping enabled (range=%d-%d, interval=%v, strategy=%s)",
		cfg.PortHopping.PortRangeStart, cfg.PortHopping.PortRangeEnd,
		cfg.PortHopping.HopInterval, cfg.PortHopping.Strategy)
}

// initManagerAndroidMode applies Android-specific timeout and retry optimizations.
func initManagerAndroidMode(m *Manager, cfg DefaultManagerConfig) {
	if !cfg.AndroidMode {
		return
	}
	m.probeTimeout = 3 * time.Second
	m.connectTimeout = 10 * time.Second
	m.maxRetries = 1
	m.androidMode = true
	m.tcpFailuresBeforeQUIC = androidSilentScanAbort
	log.Info("Android mode: using optimized timeouts (probe=%v, connect=%v, retries=%d, TCP-first)",
		m.probeTimeout, m.connectTimeout, m.maxRetries)
}

// initManagerMux enables mux multiplexing if configured.
func initManagerMux(m *Manager, cfg DefaultManagerConfig) {
	if !cfg.MuxEnabled {
		return
	}
	muxConfig := cfg.MuxConfig
	if muxConfig == nil {
		if cfg.AndroidMode {
			muxConfig = mux.MobileConfig()
		} else {
			muxConfig = mux.DefaultConfig()
		}
	}
	m.EnableMux(muxConfig)
}

// initManagerRTTMasking enables RTT masking if configured.
func initManagerRTTMasking(m *Manager, cfg DefaultManagerConfig) {
	if !cfg.RTTMaskingEnabled {
		return
	}
	profile := cfg.RTTProfile
	if profile == nil {
		profile = MoscowToYandexProfile
	}
	m.EnableRTTMasking(profile)
}

// registerAllStrategies registers all transport strategies onto the manager.
func registerAllStrategies(m *Manager, cfg DefaultManagerConfig) {
	// A config that only fills Endpoints has a server just as much as one that
	// fills ServerAddr. Checking ServerAddr alone would register nothing at all
	// for a pure server-list client - every strategy gated out, and the failure
	// mode is "no strategies available" rather than anything that points at the
	// config.
	hasServer := cfg.ServerAddr != "" || cfg.ServerAddrV6 != "" || len(cfg.Endpoints) > 0
	hasSecret := len(cfg.Secret) > 0

	warnEndpointPinnedFlags(cfg)

	registerQUICStrategies(m, cfg, hasServer, hasSecret)
	registerTLSStrategies(m, cfg, hasServer, hasSecret)
	registerMorphStrategies(m, cfg, hasSecret)
	registerMeshAndAntiProbe(m, cfg, hasServer, hasSecret)
	registerConfusionAndExhaustion(m, cfg, hasServer, hasSecret)
	registerSSHCamouflage(m, cfg, hasServer, hasSecret)
	registerIMAPCamouflage(m, cfg, hasServer, hasSecret)
	registerGenevaStrategies(m, cfg, hasServer, hasSecret)
	registerSeqovlStrategy(m, cfg, hasServer, hasSecret)
	registerICMPStrategy(m, cfg, hasServer, hasSecret)
}

// derivedQUICPort is the UDP port both QUIC variants dial: the port of
// ServerAddr, then of the first endpoint, then 443. The server opens its QUIC
// listener on its -listen address unless told otherwise (-quic-listen), so the
// TCP port the client already dials is where QUIC is.
//
// The endpoint fallback matters for a client configured only through
// [[servers]], where ServerAddr is empty and the old derivation silently landed
// on 443 - a port the exit is not listening on.
func derivedQUICPort(cfg DefaultManagerConfig) int {
	addrs := []string{cfg.ServerAddr}
	if len(cfg.Endpoints) > 0 {
		addrs = append(addrs, cfg.Endpoints[0].V4, cfg.Endpoints[0].V6)
	}
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			return p
		}
	}
	return 443
}

// warnEndpointPinnedFlags reports the settings that a server list silently
// makes wrong, rather than letting them fail as an unexplained dead transport.
//
// The QUIC port is derived from the FIRST endpoint's port and then applied to whatever host the selector picks.
// With a list whose members listen on different ports that is simply the wrong
// port on every endpoint but one. Making it per-endpoint needs a per-endpoint
// port in the config, which the [[servers]] section does not carry today.
func warnEndpointPinnedFlags(cfg DefaultManagerConfig) {
	if len(cfg.Endpoints) < 2 {
		return
	}
	if !cfg.QUICEnabled {
		return
	}
	ports := make(map[string]bool, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		for _, addr := range []string{ep.V4, ep.V6} {
			if addr == "" {
				continue
			}
			if _, port, err := net.SplitHostPort(addr); err == nil {
				ports[port] = true
			}
		}
	}
	if len(ports) > 1 {
		log.Warn("QUIC port is derived from the first endpoint but the pool uses %d different ports; "+
			"QUIC will dial the wrong port on the others - keep the pool on one port to use QUIC", len(ports))
	}
}

// registerSeqovlStrategy registers the seqovl (TCP sequence overlap, level B
// app-framing) strategy. It rides the REALITY handshake with a secret-marked
// decoy prefix, so it needs both a server and a shared secret. Cross-platform,
// including Android.
func registerSeqovlStrategy(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	seqovl := NewSeqovlStrategy(m, cfg.Secret, cfg.SeqovlPacketEnabled)
	seqovl.SetFingerprint(cfg.TLSFingerprint)
	seqovl.SetRequireDataV2(cfg.REALITYRequireDataV2)
	m.Register(seqovl)
}

// registerICMPStrategy registers the ICMP tunnel backup strategy.
// Off by default: opening a raw ICMP socket needs CAP_NET_RAW, so it is only
// wired in when the client explicitly opts in via -icmp-tunnel.
func registerICMPStrategy(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !cfg.ICMPTunnelEnabled || !hasServer || !hasSecret {
		return
	}
	m.Register(NewICMPTunnelStrategy(cfg.ServerAddr, cfg.Secret))
}

// registerSSHCamouflage registers the SSH camouflage strategy.
func registerSSHCamouflage(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	m.Register(NewSSHCamouflageStrategy(m, cfg.Secret))
}

// registerIMAPCamouflage registers the IMAP camouflage strategy.
func registerIMAPCamouflage(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	m.Register(NewIMAPCamouflageStrategy(m, cfg.Secret))
}

// registerQUICStrategies registers QUIC and QUIC-Salamander strategies.
func registerQUICStrategies(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	// Both plain QUIC and QUIC Salamander are QUIC transports, so both must be
	// gated behind QUICEnabled. Registering Salamander unconditionally leaked it
	// into the benchmark/probe list even when -quic was not passed (issue #54).
	if !cfg.QUICEnabled {
		return
	}

	// The server's QUIC listener speaks exactly one dialect: Salamander by
	// default, unwrapped QUIC only under -quic-sni-reassembly, which exists for
	// -quic-sni-frag clients (QUICServer.wrapPacketConn). So the two client
	// variants are exclusive, and the switch between them is QUICSNIFragEnabled.
	// Plain QUIC used to be registered next to Salamander as well; against a
	// default server it could only time out, costing a full handshake timeout
	// per scan and failing every -strategy quic run.
	//
	// Both dial the server's port. -quic-port never reached a dial: plain QUIC
	// ignored it and Salamander derived its own port, while the startup line
	// printed the flag's 8443 default. It stays ignored rather than starting to
	// work now, because the Android app sends -quic-port on every start with
	// values nobody chose - its own 443 default, or the 8443 that "admin add"
	// wrote into connection strings - and honouring them would point QUIC at
	// ports no server listens on.
	port := derivedQUICPort(cfg)
	if cfg.QUICPort != 0 && cfg.QUICPort != port {
		// 443 and 8443 are the values the Android app and old connection
		// strings send on every start without anyone choosing them; a warning
		// in every log would be noise. Anything else was typed on purpose.
		logf := log.Warn
		if cfg.QUICPort == 443 || cfg.QUICPort == 8443 {
			logf = log.Debug
		}
		logf("-quic-port %d is ignored: QUIC dials the server's port %d, where its QUIC listener sits "+
			"unless the server runs with -quic-listen", cfg.QUICPort, port)
	}

	var s *QUICStrategy
	if cfg.QUICSNIFragEnabled {
		s = NewQUICStrategy(m, cfg.Secret, port)
		s.SetSNIFragmentation(true, nil)
	} else {
		s = NewQUICSalamanderStrategy(m, cfg.Secret, port)
	}
	log.Info("QUIC transport: %s on UDP port %d", s.Name(), port)
	m.Register(s)
}

// quicPlainForForce builds plain QUIC for an explicit -strategy quic when
// only Salamander is registered, or returns nil.
//
// Auto mode registers one dialect per client (see registerQUICStrategies),
// but a server started with -quic-sni-reassembly speaks unwrapped QUIC to any
// client, fragmenting or not, and main reached it with a plain -strategy quic.
// Asking for it by name is the one signal that the server is such a one, so
// that is when it comes back - with Salamander's port and secret, the same
// server. Without -quic neither exists and the plain "no strategy matching"
// answer is the right one.
func quicPlainForForce(idPrefix string, registered []Strategy) *QUICStrategy {
	if idPrefix != "quic" {
		return nil
	}
	var sal *QUICStrategy
	for _, s := range registered {
		if s.ID() == "quic" {
			return nil
		}
		if q, ok := s.(*QUICStrategy); ok && q.useSalamander {
			sal = q
		}
	}
	if sal == nil {
		return nil
	}
	return NewQUICStrategy(sal.manager, sal.secret, sal.port)
}

// registerTLSStrategies registers REALITY, WebSocket, HTTP Polling and HTTP/2 Stego.
func registerTLSStrategies(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}

	reality := NewREALITYStrategy(m, cfg.Secret)
	reality.SetFingerprint(cfg.TLSFingerprint)
	if cfg.REALITYServerPubKeyB64 != "" {
		key, err := customtls.DecodeKeyBase64(cfg.REALITYServerPubKeyB64)
		if err != nil {
			log.Warn("REALITY: B1 server key is not valid base64: %v; B1 stays off", err)
		} else {
			reality.SetB1(key)
		}
	}
	reality.SetRequireDataV2(cfg.REALITYRequireDataV2)
	if cfg.PQEnabled && cfg.PQServerKemPubB64 != "" {
		kemPub, err := base64.StdEncoding.DecodeString(cfg.PQServerKemPubB64)
		if err == nil && len(kemPub) > 0 {
			if err := reality.SetPostQuantum(kemPub); err != nil {
				log.Warn("REALITY: PQ init failed, using classical: %v", err)
			}
		}
	}
	m.Register(reality)

	m.Register(NewWebSocketPaddedStrategy(m, cfg.Secret))
	m.Register(NewHTTPPollingStrategy(m, cfg.Secret))

	stego := NewHTTP2StegoStrategy(m, cfg.Secret, cfg.CoverHost)
	if cfg.ECHEnabled && len(cfg.ECHConfigList) > 0 {
		stego.SetECH(cfg.ECHConfigList, cfg.ECHPublicName)
	}
	m.Register(stego)
}

// registerMorphStrategies registers Traffic Morphing strategies for multiple profiles.
func registerMorphStrategies(m *Manager, cfg DefaultManagerConfig, hasSecret bool) {
	if !hasSecret {
		return
	}
	for _, profile := range []*TrafficProfile{
		YandexVideoProfile,
		VKVideoProfile,
		BaiduVideoProfile,
		AparatVideoProfile,
	} {
		strat := NewTrafficMorphStrategy(m, profile, nil, cfg.Secret)
		if cfg.Shaper != nil {
			strat.SetShaperWithID(cfg.Shaper, cfg.ShaperID)
		}
		m.Register(strat)
	}
}

// registerMeshAndAntiProbe registers Mesh Relay and Anti-Probe strategies.
func registerMeshAndAntiProbe(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if hasServer && len(cfg.RelayNodes) > 0 {
		mesh := NewMeshRelayStrategy(cfg.ServerAddr)
		mesh.AddRelays(cfg.RelayNodes)
		m.Register(mesh)
	}
	if hasServer && hasSecret {
		antiprobe := NewAntiProbeStrategy(m, cfg.Secret)
		if cfg.ECHEnabled && len(cfg.ECHConfigList) > 0 {
			antiprobe.SetECH(cfg.ECHConfigList, cfg.ECHPublicName)
		}
		m.Register(antiprobe)
	}
}

// registerConfusionAndExhaustion registers Protocol Confusion and State Exhaustion.
//
// Both were registered unconditionally until 1.11.0, the only two of the
// sixteen that were. That was not a shortcut but a consequence: neither read a
// secret, so there was nothing to gate on. Now that the confusion wire is keyed
// end to end - the marker, the record layer, the server's answer - a client
// without a secret cannot complete either of them, and registering them would
// only add two dead entries to the strategy scan.
//
// State exhaustion is gated on the same pair despite RequiresServer() being
// false: its fallback path dials our server and wraps the connection in the
// confusion carrier, so it needs a server and a secret just as much.
func registerConfusionAndExhaustion(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	for _, confStrat := range AllConfusionTypes(m, cfg.Secret) {
		m.Register(confStrat)
	}
	m.Register(NewStateExhaustionStrategy(m, cfg.Secret))
}

// registerGenevaStrategies registers Geneva strategies for Russia, China, and Iran.
func registerGenevaStrategies(m *Manager, cfg DefaultManagerConfig, hasServer, hasSecret bool) {
	if !hasServer || !hasSecret {
		return
	}
	m.Register(NewGenevaStrategy(m, cfg.Secret, "russia"))
	m.Register(NewGenevaStrategy(m, cfg.Secret, "china"))
	m.Register(NewGenevaStrategy(m, cfg.Secret, "iran"))
}

// ConnectWithFallback is a convenience function for one-shot connection
func ConnectWithFallback(ctx context.Context, target string, cfg DefaultManagerConfig) (net.Conn, Strategy, error) {
	m := NewDefaultManager(cfg)
	return m.Connect(ctx, target)
}

// PrintStrategySummary prints current strategy order and stats
func (m *Manager) PrintStrategySummary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result string
	result += "=== Strategy Summary ===\n"
	result += fmt.Sprintf("Registered strategies: %d\n\n", len(m.strategies))

	for i, s := range m.strategies {
		r := m.results[s.ID()]
		status := "untested"
		if r.TestedAt.Unix() > 0 {
			if r.Success {
				status = "✓ working"
			} else {
				status = "✗ failed"
			}
		}

		// Get circuit breaker state
		cbStats := m.circuitBreakers.Get(s.ID()).Stats()
		cbState := cbStats.State.String()

		result += fmt.Sprintf("%d. [%s] %s\n", i+1, s.ID(), s.Name())
		result += fmt.Sprintf("   Priority: %d | Confidence: %.2f | Status: %s | Circuit: %s\n",
			s.Priority(), r.Confidence, status, cbState)
		result += fmt.Sprintf("   Success: %d | Failures: %d | ConsecFail: %d | AvgLatency: %v\n",
			r.SuccessCount, r.FailureCount, r.ConsecutiveFail, r.AvgLatency)
		result += fmt.Sprintf("   Requires Server: %v\n", s.RequiresServer())
		result += fmt.Sprintf("   %s\n\n", s.Description())
	}

	return result
}

// StartPeriodicReprobe starts background re-probing of strategies.
//
// It takes no target: each cycle asks for the pinned candidate, so a reprobe
// started before a family fallback still measures the path the tunnel actually
// uses afterwards.
func (m *Manager) StartPeriodicReprobe(ctx context.Context) {
	m.mu.Lock()
	if m.reprobeRunning {
		m.mu.Unlock()
		log.Debug("Periodic reprobe already running")
		return
	}
	m.reprobeRunning = true
	m.stopReprobe = make(chan struct{})
	m.mu.Unlock()

	log.Info("Starting periodic reprobe (interval=%v, target=%s)", m.reprobeInterval, m.GetServerAddr(ctx))

	go func() {
		timer := time.NewTimer(nextReprobeDelay(m.reprobeInterval))
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Periodic reprobe stopped (context cancelled)")
				return
			case <-m.stopReprobe:
				log.Info("Periodic reprobe stopped")
				return
			case <-timer.C:
				m.doPeriodicReprobe(ctx)
				timer.Reset(nextReprobeDelay(m.reprobeInterval))
			}
		}
	}()
}

// nextReprobeDelay is the pause before the next periodic reprobe.
//
// It was a strict time.Ticker: a burst of probe connects to the pinned server
// every 300.000 s from process start, the cleanest metronome the client put
// on the wire. Now each pause is RandomDelay(interval/2, interval, 2 x
// interval): the mean stays near the interval, the gaps vary, and nothing lands
// on a fixed value. No measured reference; not uniform jitter (verification
// rule 3).
func nextReprobeDelay(interval time.Duration) time.Duration {
	return RandomDelay(interval/2, interval, 2*interval)
}

// StopPeriodicReprobe stops background re-probing
func (m *Manager) StopPeriodicReprobe() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reprobeRunning {
		close(m.stopReprobe)
		m.reprobeRunning = false
	}
}

// HoldReprobe holds periodic reprobes off while held is true. The TUN client
// holds them while it has no tunnel and is reconnecting.
//
// A reprobe in an outage probed the pinned server that had just gone silent:
// about 16 connects, 30-40 SYNs with their retransmits, within ~20 s, from a
// client whose reconnect loop was already dialling that same pool - the burst
// a sweep against a blocked address looks like. It found nothing (0/21 on the
// stand), the upgrade it feeds needs a live tunnel, and the reconnect and the
// pool poll already say when a server answers again.
func (m *Manager) HoldReprobe(held bool) {
	m.reprobeHeld.Store(held)
}

// doPeriodicReprobe performs a single reprobe cycle
func (m *Manager) doPeriodicReprobe(ctx context.Context) {
	if m.reprobeHeld.Load() {
		log.Debug("Periodic reprobe skipped: no tunnel, the reconnect is dialling")
		return
	}
	target := m.GetServerAddr(ctx)
	if target == "" {
		log.Warn("No reprobe target set")
		return
	}

	log.Info("Running periodic reprobe...")

	// Create a timeout context for the reprobe
	reprobeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	results := m.ProbeAll(reprobeCtx, target)

	// Log summary
	available := 0
	for _, r := range results {
		if r.Success {
			available++
		}
	}
	log.Info("Periodic reprobe complete: %d/%d strategies available", available, len(results))

	m.offerUpgrade(results)
}

// SetStrategyUpgradeCallback registers fn to hear, some time after a periodic
// reprobe, which strategies the reprobe found reachable and the upgrade backoff
// lets through, best first (UpgradeRank). The TUN client uses it to move a live
// tunnel off a fallback strategy (see VPNClient.tryStrategyUpgrade). Nil turns
// upgrades off.
func (m *Manager) SetStrategyUpgradeCallback(fn func([]Strategy)) {
	m.mu.Lock()
	m.upgradeCallback = fn
	m.mu.Unlock()
}

// upgradeMaxSkip caps how many reprobes a strategy sits out after failed
// upgrades: six reprobes, half an hour at the default interval.
const upgradeMaxSkip = 6

// upgradeDelay is how long after a reprobe the upgrade offer goes out. A var
// so tests can make it immediate.
//
// The offer used to go out the moment the reprobe burst finished, so on the
// wire a burst of probe connects was followed at once by a new session to the
// same server, on the reprobe's 5-minute grid. RandomDelay with a 20 s floor,
// a 90 s mean and a 4 min ceiling: an upgrade is
// one event per degradation episode, and the memoryless shape is what
// independent user-driven events have. There is no measured reference for it;
// it is chosen to unhook the switch from the reprobe, not to imitate anything.
var upgradeDelay = func() time.Duration {
	return RandomDelay(20*time.Second, 90*time.Second, 4*time.Minute)
}

// RandomDelay draws a pause of floor plus an exponential with mean
// (mean - floor), redrawn - not clamped - while it exceeds ceiling.
//
// Clamping put a spike of exact values on the wire: about 5% of reprobe gaps
// came out at exactly 600.000 s and 4% of upgrade delays at exactly 240 s, a
// fixed value an observer can count. The redraw keeps the tail inside the
// ceiling without piling it up there. There is no measured reference
// distribution behind the shape; it is chosen to have no grid and no spike,
// and it is not uniform jitter (verification rule 3).
func RandomDelay(floor, mean, ceiling time.Duration) time.Duration {
	span := float64(mean - floor)
	if span <= 0 || ceiling <= floor {
		return floor
	}
	for range 64 {
		if d := floor + time.Duration(rand.ExpFloat64()*span); d < ceiling {
			return d
		}
	}
	return floor + time.Duration(rand.Float64()*float64(ceiling-floor))
}

// HumpDelay draws a pause of floor plus a gamma of shape 3 with mean
// (mean - floor), redrawn while it reaches ceiling.
//
// RandomDelay's exponential piles its draws at the floor: about 40% of them
// land in the lowest fifth of the range, and the floor becomes a hard edge in
// the gap distribution - a minimum an observer of many gaps reads off at once.
// A gamma of shape 3 has no density at the floor and its bulk in the middle,
// so the lower edge is soft. There is no measured reference distribution
// behind the shape either (verification rule 3); it is chosen to have no
// edge, no grid and no spike.
func HumpDelay(floor, mean, ceiling time.Duration) time.Duration {
	theta := float64(mean-floor) / 3
	if theta <= 0 || ceiling <= floor {
		return floor
	}
	for range 64 {
		g := rand.ExpFloat64() + rand.ExpFloat64() + rand.ExpFloat64()
		if d := floor + time.Duration(g*theta); d < ceiling {
			return d
		}
	}
	return floor + time.Duration(rand.Float64()*float64(ceiling-floor))
}

// UpgradeRank is the order an upgrade compares strategies in: the base
// priority plus the Android UDP penalty the scan applies (sortStrategies).
// Lower is better.
//
// Confidence is left out on purpose. A strategy that was blocked during the
// fault comes out of it with its confidence on the floor, and it rises by one
// probe's worth per reprobe - two or three reprobes before it would outrank a
// fallback that never failed, for no information the real upgrade dial does
// not provide better. What the rank must not ignore is what the scan would
// refuse: QUIC on Android ranks behind TCP until TCP has timed out, and a
// UDP strategy while UDP is excluded is not offered at all.
func (m *Manager) UpgradeRank(s Strategy) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rank := float64(s.Priority())
	if m.androidMode && isUDPBasedStrategy(s) {
		rank += max(10-5*float64(m.consecutiveTCPTimeouts), 0)
	}
	return rank
}

// ScanScore is the score the full scan orders strategies by (sortStrategies):
// priority minus weighted confidence, plus the Android UDP penalty. Lower is
// better.
func (m *Manager) ScanScore(s Strategy) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	score := float64(s.Priority())
	if r := m.results[s.ID()]; r != nil {
		score -= r.Confidence * confidenceWeight
	}
	if m.androidMode && isUDPBasedStrategy(s) {
		score += max(10-5*float64(m.consecutiveTCPTimeouts), 0)
	}
	return score
}

// UpgradeEligible reports whether a scan on addr would admit s right now: not
// a UDP strategy while UDP is excluded, not storm-parked, breaker closed, and
// not set aside on addr's server by a route verdict (routeSkip). The offer
// checks it when it is built; the dial comes up to minutes later and checks it
// again. Without the last check an upgrade moved the tunnel straight back
// onto the transport the route had just killed there, and its next death
// charged the server - the false charge the route rule exists to prevent
// (P2-B of the round-6 review).
func (m *Manager) UpgradeEligible(s Strategy, addr string) bool {
	if m.routeSkip(addr)[s.ID()] {
		return false
	}
	m.mu.RLock()
	excludeUDP := m.excludeUDPStrategies
	m.mu.RUnlock()
	id := s.ID()
	return (!excludeUDP || !isUDPBasedStrategy(s)) && !m.stormDetector.IsParked(id) && m.circuitBreakers.CanTry(id)
}

// offerUpgrade hands the upgrade callback, after upgradeDelay, the strategies
// this reprobe found reachable and that a scan would admit right now, best
// first.
//
// Nothing else ever moves a live tunnel off the strategy it connected with.
// The reprobe only refreshed confidence, so a client that fell back to HTTP
// Polling or Geneva during a fault stayed there for as long as the session
// held - fourteen minutes and two clean reprobes in the stand's run #9.
//
// A probe is a TCP connect and proves only the port; the callback's real dial,
// handshake and a useful session are what prove the strategy
// (UpgradeOutcome). A strategy whose upgrades keep failing (REALITY under a
// censor that resets its handshake) sits out 1, 2, 4 and then 6 reprobes after
// its second, third, fourth and later consecutive failure. The first failure
// costs nothing: a fault that has just been lifted is the common case.
func (m *Manager) offerUpgrade(results []Result) {
	m.muxMu.Lock()
	muxEnabled := m.muxEnabled
	m.muxMu.Unlock()

	// The reprobe ran against the pinned server, and the tunnel rides it.
	var routeSkip map[string]bool
	if sel := m.selector(); sel != nil {
		if cand, ok := sel.Current(); ok {
			routeSkip = m.routeSkip(cand.Addr)
		}
	}

	m.mu.Lock()
	cb := m.upgradeCallback
	if cb == nil || m.forced || muxEnabled {
		// With mux the tunnel rides a shared carrier that budget recycling
		// swaps; an upgrade from here would race it.
		m.mu.Unlock()
		return
	}
	excludeUDP := m.excludeUDPStrategies
	var cands []Strategy
	for _, r := range results {
		s := r.Strategy
		if s == nil {
			continue
		}
		id := s.ID()
		if n := m.upgradeSkip[id]; n > 0 {
			m.upgradeSkip[id] = n - 1 // one more reprobe sat out
			continue
		}
		if !r.Success || s.Priority() <= 0 {
			continue
		}
		if (excludeUDP && isUDPBasedStrategy(s)) || m.stormDetector.IsParked(id) || !m.circuitBreakers.CanTry(id) ||
			routeSkip[id] {
			continue
		}
		cands = append(cands, s)
	}
	m.mu.Unlock()

	if len(cands) == 0 {
		return
	}
	slices.SortStableFunc(cands, func(a, b Strategy) int { return cmp.Compare(m.UpgradeRank(a), m.UpgradeRank(b)) })
	delay := upgradeDelay()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("strategy upgrade panic: %v", r)
			}
		}()
		select {
		case <-time.After(delay):
		case <-m.lifeCtx.Done():
			return
		}
		cb(cands)
	}()
}

// recordUpgradeResultLocked books one upgrade of id. Caller holds m.mu.
func (m *Manager) recordUpgradeResultLocked(id string, ok bool) {
	if m.upgradeFails == nil {
		m.upgradeFails = make(map[string]int)
		m.upgradeSkip = make(map[string]int)
	}
	if ok {
		delete(m.upgradeFails, id)
		delete(m.upgradeSkip, id)
		return
	}
	m.upgradeFails[id]++
	if n := m.upgradeFails[id]; n >= 2 {
		m.upgradeSkip[id] = min(1<<(n-2), upgradeMaxSkip)
	}
}

// UpgradeFailures reports how many upgrades to id have failed in a row, for
// logs and tests.
func (m *Manager) UpgradeFailures(id string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.upgradeFails[id]
}

// UpgradeOutcome books how an upgrade to s ended after its dial: ok once the
// upgraded session has carried traffic for a meaningful time, not ok when the
// handshake failed, the session was rejected, or it died before proving
// itself. Only a confirmed upgrade makes s the fast-reconnect strategy; until
// then a reconnect goes back the way the tunnel came.
func (m *Manager) UpgradeOutcome(s Strategy, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordUpgradeResultLocked(s.ID(), ok)
	if !ok {
		m.updateConfidenceStats(s.ID(), false, 0)
		return
	}
	m.lastSuccessfulStrategy = s
	m.lastSuccessfulTime = time.Now()
	m.updateConfidenceWithLatency(s.ID(), true, 0)
	m.sortStrategies()
	m.lastConnectionStrategy = s.Name()
	m.lastConnectionStrategyID = s.ID()
}

// ConnectStrategy dials exactly s at cand - the endpoint the tunnel's session
// rides - with that endpoint's secret. It is the upgrade dial: the caller
// already has a working tunnel and wants this strategy specifically, so there
// is no fallback to anything else and no endpoint walk. A failed dial is booked
// as a failed upgrade; a successful one is not booked at all until
// UpgradeOutcome says how the session went.
func (m *Manager) ConnectStrategy(ctx context.Context, s Strategy, cand endpoint.Candidate) (net.Conn, error) {
	m.muxMu.Lock()
	muxEnabled := m.muxEnabled
	m.muxMu.Unlock()
	if muxEnabled {
		return nil, fmt.Errorf("strategy upgrade is not supported with mux")
	}

	dialCtx := m.withDialCandidate(ctx, cand)
	connectCtx, cancel := context.WithTimeout(dialCtx, m.connectTimeout)
	conn, err := s.Connect(connectCtx, m.withHoppedPort(cand.Addr))
	cancel()

	if err != nil {
		m.mu.Lock()
		m.recordUpgradeResultLocked(s.ID(), false)
		m.updateConfidenceStats(s.ID(), false, 0)
		if isTimeoutError(err) {
			m.circuitBreakers.RecordTimeout(s.ID())
		} else {
			m.circuitBreakers.RecordFailure(s.ID())
		}
		m.mu.Unlock()
		return nil, err
	}
	m.mu.RLock()
	useRTTMasking, rttProfile := m.rttMaskingEnabled, m.rttProfile
	m.mu.RUnlock()

	optimizeTCPConn(conn)
	if useRTTMasking {
		conn = WrapWithRTTMasking(conn, rttProfile)
	}
	return conn, nil
}

// CurrentCandidate returns the pinned endpoint candidate.
func (m *Manager) CurrentCandidate() (endpoint.Candidate, bool) {
	sel := m.selector()
	if sel == nil {
		return endpoint.Candidate{}, false
	}
	return sel.Current()
}

// SetReprobeInterval changes the reprobe interval
func (m *Manager) SetReprobeInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reprobeInterval = interval
}

// EnableRTTMasking enables RTT masking on all connections
func (m *Manager) EnableRTTMasking(profile *RTTProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rttMaskingEnabled = true
	m.rttProfile = profile
	if profile != nil {
		log.Info("RTT masking enabled (profile=%s, mean=%v)", profile.Name, profile.MeanDelay)
	} else {
		log.Info("RTT masking enabled (default profile)")
	}
}

// DisableRTTMasking disables RTT masking
func (m *Manager) DisableRTTMasking() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rttMaskingEnabled = false
	m.rttProfile = nil
	log.Info("RTT masking disabled")
}

// IsRTTMaskingEnabled returns RTT masking status
func (m *Manager) IsRTTMaskingEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rttMaskingEnabled
}

// EnableMux enables connection multiplexing for DPI evasion
// According to research data, VLESS+Reality+mux shows 99.5% success rate
func (m *Manager) EnableMux(config *mux.Config) {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	m.muxEnabled = true
	if config != nil {
		m.muxConfig = config
		log.Info("Mux enabled (keepalive=%v)", config.KeepAliveInterval)
	} else {
		m.muxConfig = mux.DefaultConfig()
		log.Info("Mux enabled (default config)")
	}
}

// DisableMux disables connection multiplexing
func (m *Manager) DisableMux() {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	m.muxEnabled = false

	// Close existing mux client if any
	if m.muxClient != nil {
		m.muxClient.Close()
		m.muxClient = nil
	}
	if m.muxConn != nil {
		m.muxConn.Close()
		m.muxConn = nil
	}

	log.Info("Mux disabled")
}

// IsMuxEnabled returns whether mux is enabled
func (m *Manager) IsMuxEnabled() bool {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()
	return m.muxEnabled
}

// tryMuxFastPath opens a stream on the existing mux session, if mux is enabled
// and the session is alive, without dialing a new transport. It returns the
// stream, the last successful strategy (for logging/metrics parity with the full
// path) and true on success. On a dead session it tears the session down and
// returns false so the caller falls through to a full dial. When mux is disabled
// or no session exists it returns false.
func (m *Manager) tryMuxFastPath() (net.Conn, Strategy, bool) {
	m.muxMu.Lock()
	if !m.muxEnabled || m.muxClient == nil || m.muxClient.IsClosed() {
		m.muxMu.Unlock()
		return nil, nil, false
	}

	// Trigger budget recycling if the carrier exceeded its byte limit; new
	// streams keep flowing on the current carrier until the swap completes.
	if m.muxClient.BudgetExceeded() && !m.recyclingInProgress {
		m.recyclingInProgress = true
		go m.performBudgetRecycling()
	}

	stream, err := m.muxClient.OpenStream()
	if err != nil {
		// Session is dead - tear it down and let the caller do a full dial.
		log.Debug("Mux fast-path: existing session failed, recreating: %v", err)
		m.muxClient.Close()
		m.muxClient = nil
		if m.muxConn != nil {
			m.muxConn.Close()
			m.muxConn = nil
		}
		m.muxMu.Unlock()
		return nil, nil, false
	}
	active := m.muxClient.NumStreams()
	// Report the strategy bound to this carrier, not m.lastSuccessfulStrategy:
	// storm parking clears the latter out from under a live session, and the
	// caller (pool.go) dereferences the returned strategy.
	strat := m.muxStrategy
	m.muxMu.Unlock()

	log.Debug("Mux fast-path: stream on existing session, no new dial (active=%d)", active)
	return stream, strat, true
}

// wrapWithMux wraps a connection with mux layer and opens a stream
// If an existing mux session is available and not closed, reuse it
func (m *Manager) wrapWithMux(conn net.Conn, config *mux.Config, strat Strategy) (net.Conn, error) {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	// Reuse existing mux session if available and not closed
	if m.muxClient != nil && !m.muxClient.IsClosed() {
		// Trigger budget recycling if carrier exceeded its byte limit.
		// New streams continue on current carrier until the swap completes.
		if m.muxClient.BudgetExceeded() && !m.recyclingInProgress {
			m.recyclingInProgress = true
			go m.performBudgetRecycling()
		}
		stream, err := m.muxClient.OpenStream()
		if err == nil {
			// The passed-in conn is a freshly dialed transport that this reuse
			// branch does not adopt (m.muxConn stays on the live carrier). Close
			// it, otherwise it is orphaned: never written to, it hangs pre-auth on
			// the server and piles up until OOM. Belt-and-suspenders behind the
			// Connect() fast-path, which normally avoids the dial entirely.
			if conn != nil && conn != m.muxConn {
				conn.Close()
			}
			log.Debug("Mux stream opened on existing session (active=%d)", m.muxClient.NumStreams())
			return stream, nil
		}
		// Session is dead, close it
		log.Debug("Existing mux session failed, recreating: %v", err)
		m.muxClient.Close()
		m.muxClient = nil
		if m.muxConn != nil {
			m.muxConn.Close()
			m.muxConn = nil
		}
	}

	// Create new mux client
	if config == nil {
		config = mux.DefaultConfig()
	}

	client, err := mux.NewClient(conn, config)
	if err != nil {
		return nil, fmt.Errorf("mux client creation failed: %w", err)
	}

	m.muxClient = client
	m.muxConn = conn
	m.muxStrategy = strat

	// Open first stream
	stream, err := client.OpenStream()
	if err != nil {
		client.Close()
		m.muxClient = nil
		m.muxConn = nil
		return nil, fmt.Errorf("mux stream open failed: %w", err)
	}

	log.Debug("Mux client created and stream opened")
	return stream, nil
}

// GetMuxMetrics returns current mux metrics (if mux is active)
func (m *Manager) GetMuxMetrics() *mux.MetricsSnapshot {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	if m.muxClient == nil {
		return nil
	}
	snapshot := m.muxClient.GetMetrics()
	return &snapshot
}

// CloseMuxSession closes the current mux session (forces reconnection on next Connect)
func (m *Manager) CloseMuxSession() {
	m.muxMu.Lock()
	defer m.muxMu.Unlock()

	if m.muxClient != nil {
		m.muxClient.Close()
		m.muxClient = nil
	}
	if m.muxConn != nil {
		m.muxConn.Close()
		m.muxConn = nil
	}
	m.muxStrategy = nil
	log.Debug("Mux session closed")
}

// GetCircuitBreakerStats returns circuit breaker statistics
func (m *Manager) GetCircuitBreakerStats() map[string]CircuitStats {
	return m.circuitBreakers.GetAllStats()
}

// tcpConnExtractor is an interface for connections that wrap TCP
type tcpConnExtractor interface {
	NetConn() net.Conn
}

// extractTCPConn recursively unwraps connection wrappers to find the underlying TCP connection
func extractTCPConn(conn net.Conn) *net.TCPConn {
	// Direct TCP connection
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc
	}

	// Connection with NetConn() method (TLS, MorphedConn, etc)
	if extractor, ok := conn.(tcpConnExtractor); ok {
		return extractTCPConn(extractor.NetConn())
	}

	return nil
}

// optimizeTCPConn sets TCP_NODELAY and buffer sizes on the underlying TCP connection
// This is critical for low-latency proxy operations
func optimizeTCPConn(conn net.Conn) {
	// Recursively unwrap to find the underlying TCP connection
	// Chain: MorphedConn -> TLS -> TCP
	tcpConn := extractTCPConn(conn)

	if tcpConn == nil {
		log.Debug("Cannot optimize connection: not a TCP connection (type=%T)", conn)
		return
	}

	// Disable Nagle's algorithm - critical for interactive traffic
	// Without this, small packets are delayed up to 40ms waiting for more data
	if err := tcpConn.SetNoDelay(true); err != nil {
		log.Debug("Failed to set TCP_NODELAY: %v", err)
	}

	// Increase socket buffers to cover the BDP on high-RTT links. 64KB was far
	// below the bandwidth-delay product at 150-300ms RTT and throttled the TCP
	// window. Applies to both client and relay sockets; relay sockets only
	// benefit from the larger buffer (the server side already uses 4MB).
	if err := tcpConn.SetReadBuffer(clientSocketBufferBytes); err != nil {
		log.Debug("Failed to set read buffer: %v", err)
	}
	if err := tcpConn.SetWriteBuffer(clientSocketBufferBytes); err != nil {
		log.Debug("Failed to set write buffer: %v", err)
	}

	log.Debug("TCP connection optimized: NoDelay=true, buffers=%dKB", clientSocketBufferBytes/1024)
}

// TriggerEmergencyReprobe starts aggressive re-probing when all strategies fail
// This helps recover from network outages by periodically retrying with short intervals
//
// Not while the reprobe is held (HoldReprobe): the TUN client holds it while it
// reconnects, and a reconnect is where every failed scan used to start one -
// ProbeAll against the pinned server every 30.000 s, next to a reconnect loop
// already dialling it, the burst HoldReprobe exists to keep off the wire. The
// reconnect is the recovery there. Where nothing holds it (no TUN) the pauses
// are drawn like the periodic reprobe's, not ticked.
func (m *Manager) TriggerEmergencyReprobe(ctx context.Context) {
	if m.reprobeHeld.Load() {
		log.Debug("Emergency reprobe skipped: no tunnel, the reconnect is dialling")
		return
	}
	// Read the pinned candidate BEFORE taking m.mu: GetServerAddr takes the
	// same lock to reach the selector.
	target := m.GetServerAddr(ctx)

	m.mu.Lock()

	// Check if already running
	if m.emergencyReprobeRunning {
		m.mu.Unlock()
		return
	}

	// Don't trigger too frequently (at most once per minute)
	if time.Since(m.lastEmergencyReprobe) < 1*time.Minute {
		m.mu.Unlock()
		log.Debug("Emergency reprobe throttled (last: %v ago)", time.Since(m.lastEmergencyReprobe))
		return
	}

	m.emergencyReprobeRunning = true
	m.lastEmergencyReprobe = time.Now()
	stopCh := make(chan struct{})
	m.emergencyReprobeStop = stopCh
	m.mu.Unlock()

	log.Warn("EMERGENCY REPROBE: All strategies failed, entering aggressive recovery mode")

	go func() {
		defer func() {
			m.mu.Lock()
			// Clear the running state only if this goroutine still owns the
			// current stop channel. A StopEmergencyReprobe / ResetForNetworkChange
			// (or a later Trigger) may have already replaced or nilled it, and
			// clobbering their state would resurrect a stopped reprobe.
			if m.emergencyReprobeStop == stopCh {
				m.emergencyReprobeRunning = false
				m.emergencyReprobeStop = nil
			}
			m.mu.Unlock()
			log.Info("Emergency reprobe stopped")
		}()

		timer := time.NewTimer(nextReprobeDelay(m.emergencyInterval))
		defer timer.Stop()

		maxAttempts := 10 // Try for 5 minutes max
		attempt := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-timer.C:
				timer.Reset(nextReprobeDelay(m.emergencyInterval))
				if m.reprobeHeld.Load() {
					// A reconnect started since: it is the recovery now.
					return
				}
				attempt++
				if attempt > maxAttempts {
					log.Warn("Emergency reprobe giving up after %d attempts", maxAttempts)
					return
				}

				log.Info("Emergency reprobe attempt %d/%d...", attempt, maxAttempts)

				// Give strategies a fresh chance without wiping accumulated
				// failure history: only circuits already Open are nudged into
				// half-open so the next dial gets a graduated-recovery test.
				// A blind Reset() here would erase the failure window exactly
				// when it matters most (and is unnecessary - ProbeAll below
				// probes every strategy regardless of circuit state).
				m.mu.Lock()
				nudged := 0
				for _, s := range m.strategies {
					if m.circuitBreakers.Get(s.ID()).AllowRecoveryProbe() {
						nudged++
					}
				}
				m.mu.Unlock()
				log.Debug("Emergency reprobe: nudged %d open circuit(s) into half-open", nudged)

				// Probe all strategies
				reprobeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				results := m.ProbeAll(reprobeCtx, target)
				cancel()

				// Check if any succeeded
				available := 0
				for _, r := range results {
					if r.Success {
						available++
					}
				}

				log.Info("Emergency reprobe result: %d/%d strategies available", available, len(results))

				// If at least one strategy works, we're recovered
				if available > 0 {
					log.Info("Network recovered! %d strategies now available", available)
					return
				}
			}
		}
	}()
}

// StopEmergencyReprobe stops the emergency reprobe process
func (m *Manager) StopEmergencyReprobe() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Key on the channel, not emergencyReprobeRunning: nil it out after closing
	// so a second Stop, or a ResetForNetworkChange right after, is a no-op rather
	// than a close-of-closed-channel panic. Mirrors StopPortHopChecker.
	if m.emergencyReprobeStop != nil {
		close(m.emergencyReprobeStop)
		m.emergencyReprobeStop = nil
		m.emergencyReprobeRunning = false
	}
}

// ResetForNetworkChange resets all circuit breakers and strategy confidences
// This is called when Android detects a network change (WiFi→LTE, cell handoff)
// After a network change, old connection state is meaningless - we need fresh start
func (m *Manager) ResetForNetworkChange() {
	// Endpoint health describes the OLD network: which family was up, which
	// server was reachable, which one is parked. None of that survives a
	// handover, and until now none of it was cleared either - the family
	// verdict outlived every network change on desktop.
	m.ResetHealth()

	m.mu.Lock()
	defer m.mu.Unlock()

	log.Info("Network change detected - resetting all circuit breakers and confidences")
	m.resetStrategyBlocksLocked()

	// Storm state is tied to the old network - clear it after a network change.
	m.stormDetector.Reset()
	m.lastDeath = deathMark{server: -1}
	m.swallowed = nil
	m.unansweredHS = nil
	m.routeParked = nil

	// So is the UDP verdict: it gated QUIC for the old network (or for no
	// network at all, when this runs because the link went down). Void it,
	// take a fresh one in the background, and until it lands treat QUIC as on
	// a cold start: forced keeps it, auto lets it sit out the scans.
	if m.connectivityChecker != nil {
		m.connectivityChecker.invalidateUDPVerdict()
		m.connectivityChecker.resetPathRTT()
		m.connectivityChecker.refreshUDPAsync()
	}
	if m.forced {
		m.excludeUDPStrategies = false
		m.udpGatePending = false
	} else {
		m.udpGateDeferQUICLocked()
	}

	// Stop any running emergency reprobe. Nil the channel after closing so a
	// StopEmergencyReprobe that already fired (or a second network change) does
	// not close it twice and panic.
	if m.emergencyReprobeStop != nil {
		close(m.emergencyReprobeStop)
		m.emergencyReprobeStop = nil
		m.emergencyReprobeRunning = false
	}

	// Re-sort strategies by priority (confidence is now neutral for all)
	m.sortStrategies()
}

// EndpointHealth returns the selector's per-candidate health, for a manager
// that takes over from this one (ImportEndpointHealth). Nil without a
// selector.
func (m *Manager) EndpointHealth() []endpoint.HealthRecord {
	if sel := m.selector(); sel != nil {
		return sel.ExportHealth()
	}
	return nil
}

// ImportEndpointHealth takes over what another manager over the same pool
// learned about its candidates: failures and parks.
func (m *Manager) ImportEndpointHealth(recs []endpoint.HealthRecord) {
	if sel := m.selector(); sel != nil {
		sel.ImportHealth(recs)
	}
}

// StormHistory returns the storm detector, for a manager that takes over
// from this one (AdoptStormHistory).
func (m *Manager) StormHistory() *StormDetector { return m.stormDetector }

// AdoptStormHistory makes d this manager's storm detector: the session
// history another manager collected goes on counting here.
func (m *Manager) AdoptStormHistory(d *StormDetector) {
	if d != nil {
		m.stormDetector = d
	}
}

// RouteMemory is what a manager knows about the route beyond endpoint health
// and storm history: the last server verdict (routeDeath), the runs of
// swallowed handshakes with their skip lists, and the transports a route
// verdict set aside per server. Opaque; see RouteHistory.
//
// Servers are named by address in it, not by their index in the pool: a pool
// reordered between two cores must not move a verdict onto another server
// (P3-2 of the round-6 review). Each server is named by its first address in
// candidate order.
type RouteMemory struct {
	death     deathMark
	deathAddr string
	swallowed map[string]*swallowRecord // key: server address, or the dial address without a selector
	parked    map[string]map[string]time.Time
	// handshakes are the runs of unanswered session handshakes, by server
	// address: on Android every unanswered handshake ends the core, and a run
	// that did not cross the restart never reached its verdict.
	handshakes map[string]*handshakeRun
}

// serverAddr names endpoint idx by its first candidate address; "" if none.
func serverAddr(sel *endpoint.Selector, idx int) string {
	for _, c := range sel.Candidates() {
		if c.EndpointIdx == idx {
			return c.Addr
		}
	}
	return ""
}

// RouteHistory returns a copy of the route verdict marker, the swallow runs
// and the route parks, for a manager that takes over from this one
// (AdoptRouteHistory). The Android app replaces the whole core on every dead
// connection; without these the next core's first verdict was a first
// verdict again, and the route rule never fired there (P1-4 of the round-5
// review).
func (m *Manager) RouteHistory() RouteMemory {
	sel := m.selector()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := RouteMemory{death: m.lastDeath, swallowed: make(map[string]*swallowRecord, len(m.swallowed)),
		parked: make(map[string]map[string]time.Time, len(m.routeParked))}
	if sel == nil {
		return out
	}
	if m.lastDeath.server >= 0 {
		out.deathAddr = serverAddr(sel, m.lastDeath.server)
	}
	for server, ids := range m.routeParked {
		if addr := serverAddr(sel, server); addr != "" {
			out.parked[addr] = maps.Clone(ids)
		}
	}
	for k, r := range m.unansweredHS {
		var idx int
		if _, err := fmt.Sscanf(k, "server %d", &idx); err != nil {
			continue
		}
		if addr := serverAddr(sel, idx); addr != "" {
			if out.handshakes == nil {
				out.handshakes = make(map[string]*handshakeRun)
			}
			out.handshakes[addr] = &handshakeRun{count: r.count, addrs: maps.Clone(r.addrs), ids: maps.Clone(r.ids), last: r.last}
		}
	}
	for k, r := range m.swallowed {
		c := &swallowRecord{
			skip:         make(map[string]map[string]bool, len(r.skip)),
			last:         r.last,
			cycles:       r.cycles,
			unanswered:   r.unanswered,
			heardNothing: maps.Clone(r.heardNothing),
			addrs:        maps.Clone(r.addrs),
		}
		for a, ids := range r.skip {
			c.skip[a] = maps.Clone(ids)
		}
		var idx int
		if _, err := fmt.Sscanf(k, "server %d", &idx); err == nil {
			k = serverAddr(sel, idx)
		}
		if k != "" {
			out.swallowed[k] = c
		}
	}
	return out
}

// AdoptRouteHistory takes over another manager's RouteHistory. Whatever
// names a server this manager's pool does not have is dropped. The zero
// RouteMemory changes nothing.
func (m *Manager) AdoptRouteHistory(rm RouteMemory) {
	if rm.swallowed == nil && rm.death.at.IsZero() && rm.handshakes == nil {
		return
	}
	sel := m.selector()
	if sel == nil {
		return
	}
	server := func(addr string) (int, bool) {
		c, ok := sel.CandidateForAddr(addr)
		return c.EndpointIdx, ok
	}
	death := deathMark{server: -1}
	if idx, ok := server(rm.deathAddr); ok {
		death = rm.death
		death.server = idx
	}
	parked := make(map[int]map[string]time.Time, len(rm.parked))
	for addr, ids := range rm.parked {
		if idx, ok := server(addr); ok {
			parked[idx] = ids
		}
	}
	swallowed := make(map[string]*swallowRecord, len(rm.swallowed))
	for addr, r := range rm.swallowed {
		if idx, ok := server(addr); ok {
			swallowed[fmt.Sprintf("server %d", idx)] = r
		}
	}
	handshakes := make(map[string]*handshakeRun, len(rm.handshakes))
	for addr, r := range rm.handshakes {
		if idx, ok := server(addr); ok {
			handshakes[fmt.Sprintf("server %d", idx)] = r
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastDeath = death
	m.swallowed = swallowed
	m.routeParked = parked
	m.unansweredHS = handshakes
}

// ResetStrategyBlocks closes every circuit breaker and puts every strategy's
// confidence back to neutral, and nothing else. It is for a reconnect whose
// strategies are all blocked on the same network - not a network change, so
// what the client learned about the endpoints (parks, swallowed handshakes,
// the route marker, the UDP verdict) stays. The reconnect loop used to call
// ResetForNetworkChange here, once per failed cycle, which wiped that every
// 15 s: a run of swallowed cycles never reached its verdict, and parks were
// lifted as soon as they were set.
func (m *Manager) ResetStrategyBlocks() {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Info("Resetting circuit breakers and confidences (endpoint health kept)")
	m.resetStrategyBlocksLocked()
	m.sortStrategies()
}

// resetStrategyBlocksLocked is ResetStrategyBlocks without the lock and the
// re-sort. m.mu held.
func (m *Manager) resetStrategyBlocksLocked() {
	for _, s := range m.strategies {
		m.circuitBreakers.Get(s.ID()).Reset()
		// Neutral confidence: don't punish strategies for failures that were
		// the network's.
		if result, exists := m.results[s.ID()]; exists {
			result.Confidence = 0.5
			result.ConsecutiveFail = 0
			result.LastFailure = time.Time{}
		}
	}
}

// ConnectForReconnect is optimized for network change scenarios
// It skips circuit breaker checks since we just reset them
// and uses shorter timeouts for faster reconnection
// For Android: first tries the last successful strategy multiple times before fallback
func (m *Manager) ConnectForReconnect(ctx context.Context, target string) (net.Conn, Strategy, error) {
	// A network change can flip which family works, so drop the cached verdict
	// and re-probe. Deliberately NO outer loop over candidates here: this path
	// already retries the last strategy five times and then walks the whole
	// list, and a second level of retries turns a WiFi/LTE handover into a
	// minute-long stall.
	if sel := m.selector(); sel != nil {
		sel.ResetHealth()
		if cand, _ := sel.ProbeCurrent(ctx); cand.Addr != "" {
			target = cand.Addr
			log.Debug("Reconnect: using effective server address: %s", target)
		}
	}
	// This path calls Connect on the strategies itself rather than going through
	// connectWithRTT, so it has to name the key for the address it just resolved.
	ctx = m.ensureDialSecret(ctx)

	m.mu.RLock()
	lastStrategy := m.lastSuccessfulStrategy
	strategies := make([]Strategy, 0, len(m.strategies))
	for _, s := range m.strategies {
		if s.Priority() > 0 {
			strategies = append(strategies, s)
		}
	}
	m.mu.RUnlock()

	if len(strategies) == 0 {
		return nil, nil, fmt.Errorf("no strategies available")
	}

	// Use shorter timeout for reconnect (5s per attempt)
	reconnectTimeout := 5 * time.Second
	var lastErr error

	// Phase 1: Try last successful strategy up to 5 times
	// This is optimized for Android network handoff where the network needs time to stabilize.
	// Skip Phase 1 in auto-mode if the strategy is parked for a storm: retrying it 5x is exactly
	// the relay-mode reconnect-storm we are trying to break. Forced mode has no alternative.
	if lastStrategy != nil && (m.IsForced() || !m.stormDetector.IsParked(lastStrategy.ID())) {
		log.Info("Reconnecting to %s: trying last successful strategy %s (up to 5 attempts)", target, lastStrategy.Name())

		for attempt := 1; attempt <= 5; attempt++ {
			// Wait a bit before each attempt for network to stabilize
			if attempt > 1 {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(300 * time.Millisecond):
				}
			}

			log.Debug("Reconnect: attempt %d/5 with %s", attempt, lastStrategy.Name())

			connectCtx, cancel := context.WithTimeout(ctx, reconnectTimeout)
			start := time.Now()

			conn, err := lastStrategy.Connect(connectCtx, target)
			latency := time.Since(start)
			cancel()

			if err == nil {
				// Success
				m.mu.Lock()
				m.updateConfidenceWithLatency(lastStrategy.ID(), true, latency)
				m.sortStrategies()
				m.mu.Unlock()

				optimizeTCPConn(conn)
				log.Info("Reconnected via %s (attempt %d, latency=%v)", lastStrategy.Name(), attempt, latency)
				return conn, lastStrategy, nil
			}

			lastErr = err
			log.Debug("Reconnect attempt %d with %s failed: %v", attempt, lastStrategy.Name(), err)
		}

		log.Info("Last successful strategy %s failed after 5 attempts, falling back to full scan", lastStrategy.Name())
	}

	// Phase 2: Try all strategies (excluding the one we just tried)
	log.Info("Reconnecting to %s (trying %d strategies with fast timeout)", target, len(strategies))

	for i, s := range strategies {
		// Skip the strategy we already tried 5 times
		if lastStrategy != nil && s.ID() == lastStrategy.ID() {
			continue
		}

		log.Debug("Reconnect: trying strategy %d/%d: %s", i+1, len(strategies), s.Name())

		connectCtx, cancel := context.WithTimeout(ctx, reconnectTimeout)
		start := time.Now()

		conn, err := s.Connect(connectCtx, target)
		latency := time.Since(start)
		cancel()

		if err == nil {
			// Success - update last successful strategy
			m.mu.Lock()
			m.lastSuccessfulStrategy = s
			m.updateConfidenceWithLatency(s.ID(), true, latency)
			m.sortStrategies()
			m.mu.Unlock()

			optimizeTCPConn(conn)
			log.Info("Reconnected via %s (latency=%v)", s.Name(), latency)
			return conn, s, nil
		}

		lastErr = fmt.Errorf("%s: %w", s.Name(), err)
		log.Debug("Reconnect strategy %s failed: %v", s.Name(), err)

		// Short pause between attempts
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	return nil, nil, fmt.Errorf("all strategies failed during reconnect, last error: %w", lastErr)
}

// HasAvailableStrategies checks if any strategy is currently available
func (m *Manager) HasAvailableStrategies() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.strategies {
		// Check circuit breaker. Availability probe only - use the non-mutating
		// CanTry so repeatedly asking "is anything available" never spends a
		// strategy's half-open recovery slots.
		if !m.circuitBreakers.CanTry(s.ID()) {
			continue
		}

		// Check if strategy has been tested and is working
		if result, exists := m.results[s.ID()]; exists {
			if result.Success || result.Confidence > 0.3 {
				return true
			}
		}
	}

	return false
}

// replacePort replaces the port in a host:port string with newPort
func (m *Manager) replacePort(target string, newPort int) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// Target may not have a port, just return as-is
		return target
	}
	return net.JoinHostPort(host, strconv.Itoa(newPort))
}

// triggerReconnect is called when port hopping changes the port
// Uses "make before break" approach: establish new connection first, then swap
func (m *Manager) triggerReconnect() {
	m.portHopperMu.Lock()
	defer m.portHopperMu.Unlock()

	// Get new target with updated port
	newPort := m.portHopper.CurrentPort()

	// Get current target (we need the host part)
	m.mu.Lock()
	currentStrategy := m.lastSuccessfulStrategy
	m.mu.Unlock()

	if currentStrategy == nil {
		// No active connection, just close and let next Connect() handle it
		m.CloseMuxSession()
		log.Debug("Port hop: no active strategy, will reconnect on next request")
		return
	}

	// Try to establish new connection in background
	go m.performMakeBeforeBreak(newPort)
}

// performMakeBeforeBreak establishes new connection before closing old one
func (m *Manager) performMakeBeforeBreak(newPort int) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Get target address for reconnect
	target := m.GetServerAddr(ctx)
	m.mu.Lock()
	lastStrategy := m.lastSuccessfulStrategy
	m.mu.Unlock()

	if target == "" || lastStrategy == nil {
		log.Debug("Port hop: no target/strategy available, forcing hard reconnect")
		m.CloseMuxSession()
		return
	}

	// Build new target with new port
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	newTarget := net.JoinHostPort(host, strconv.Itoa(newPort))

	log.Debug("Port hop: establishing new connection to %s (make before break)", newTarget)

	// Try to connect using the last successful strategy. Same endpoint, only a
	// different port, so the pinned endpoint's key is the right one.
	conn, err := lastStrategy.Connect(m.ensureDialSecret(ctx), newTarget)
	if err != nil {
		log.Warn("Port hop: new connection failed (%v), forcing hard reconnect", err)
		m.CloseMuxSession()
		return
	}

	// Create new mux client on the new connection
	m.muxMu.Lock()

	// Store old client/conn for cleanup
	oldClient := m.muxClient
	oldConn := m.muxConn

	// Create new mux client
	config := m.muxConfig
	if config == nil {
		config = mux.DefaultConfig()
	}

	newClient, err := mux.NewClient(conn, config)
	if err != nil {
		m.muxMu.Unlock()
		conn.Close()
		log.Warn("Port hop: mux client creation failed (%v), forcing hard reconnect", err)
		m.CloseMuxSession()
		return
	}

	// Test new connection by opening a stream
	stream, err := newClient.OpenStream()
	if err != nil {
		m.muxMu.Unlock()
		newClient.Close()
		conn.Close()
		log.Warn("Port hop: stream open failed (%v), forcing hard reconnect", err)
		m.CloseMuxSession()
		return
	}
	stream.Close() // Just testing, close it

	// Atomic swap: new connection is ready
	m.muxClient = newClient
	m.muxConn = conn
	m.muxStrategy = lastStrategy
	m.muxMu.Unlock()

	// Now close old connection (traffic already switched to new one)
	if oldClient != nil {
		oldClient.Close()
	}
	if oldConn != nil {
		oldConn.Close()
	}

	log.Info("Port hop: seamless switch to port %d completed", newPort)

	// Notify external callback (e.g., VPN client) about port hop
	m.portHopCallbackMu.Lock()
	callback := m.portHopCallback
	m.portHopCallbackMu.Unlock()
	if callback != nil {
		// Run callback in goroutine to avoid blocking
		go callback(0, newPort) // oldPort not tracked, just pass newPort
	}
}

// performBudgetRecycling replaces the current mux carrier once its byte budget
// is exhausted. Runs in a goroutine; clears recyclingInProgress when done.
//
// Make-before-break: new carrier is fully established before old one is touched.
// Old carrier drains gracefully (up to 10 s) so in-flight streams finish cleanly.
func (m *Manager) performBudgetRecycling() {
	defer func() {
		m.muxMu.Lock()
		m.recyclingInProgress = false
		m.muxMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := m.GetServerAddr(ctx)
	m.mu.Lock()
	lastStrategy := m.lastSuccessfulStrategy
	m.mu.Unlock()

	if target == "" || lastStrategy == nil {
		log.Debug("Budget recycling: no target/strategy, skipping")
		return
	}

	log.Debug("Budget recycling: pre-warming new carrier to %s", target)

	// The replacement carrier goes to the same endpoint the old one did, so it
	// authenticates with that endpoint's key.
	conn, err := lastStrategy.Connect(m.ensureDialSecret(ctx), target)
	if err != nil {
		log.Warn("Budget recycling: new connection failed (%v), keeping current carrier", err)
		return
	}

	m.muxMu.Lock()
	config := m.muxConfig
	if config == nil {
		config = mux.DefaultConfig()
	}
	newClient, err := mux.NewClient(conn, config)
	if err != nil {
		m.muxMu.Unlock()
		conn.Close()
		log.Warn("Budget recycling: mux client creation failed (%v)", err)
		return
	}
	// Verify new carrier with a probe stream
	probe, err := newClient.OpenStream()
	if err != nil {
		m.muxMu.Unlock()
		newClient.Close()
		conn.Close()
		log.Warn("Budget recycling: probe stream failed (%v)", err)
		return
	}
	probe.Close()

	// Atomic swap: from this point new streams go to newClient
	oldClient := m.muxClient
	oldConn := m.muxConn
	m.muxClient = newClient
	m.muxConn = conn
	m.muxStrategy = lastStrategy
	m.muxMu.Unlock()

	log.Info("Budget recycling: carrier swapped, draining old session")

	// Graceful drain: wait for in-flight streams to finish (10 s max)
	drainDeadline := time.Now().Add(10 * time.Second)
	for oldClient != nil && oldClient.NumStreams() > 0 && time.Now().Before(drainDeadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if oldClient != nil {
		oldClient.Close()
	}
	if oldConn != nil {
		oldConn.Close()
	}
	log.Debug("Budget recycling: old carrier closed")
}

// SetPortHopCallback sets a callback function that will be called when port hop occurs
// This allows external components (like VPN client) to react to port changes
func (m *Manager) SetPortHopCallback(callback func(oldPort, newPort int)) {
	m.portHopCallbackMu.Lock()
	defer m.portHopCallbackMu.Unlock()
	m.portHopCallback = callback
}

// StartPortHopChecker starts background goroutine that checks for port hops
func (m *Manager) StartPortHopChecker(ctx context.Context) {
	if m.portHopper == nil {
		return
	}

	m.portHopperMu.Lock()
	if m.portHopperStop != nil {
		m.portHopperMu.Unlock()
		return // Already running
	}
	m.portHopperStop = make(chan struct{})
	stopCh := m.portHopperStop
	m.portHopperMu.Unlock()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				if m.portHopper.ShouldHop() {
					m.portHopper.NextPort() // Triggers OnHop callback
				}
			}
		}
	}()

	log.Debug("Port hop checker started")
}

// StopPortHopChecker stops the port hop checker goroutine
func (m *Manager) StopPortHopChecker() {
	m.portHopperMu.Lock()
	defer m.portHopperMu.Unlock()

	if m.portHopperStop != nil {
		close(m.portHopperStop)
		m.portHopperStop = nil
		log.Debug("Port hop checker stopped")
	}
}

// GetPortHopperStats returns current port hopper statistics
func (m *Manager) GetPortHopperStats() *porthopping.Stats {
	if m.portHopper == nil {
		return nil
	}
	stats := m.portHopper.Stats()
	return &stats
}

// GetCurrentPort returns current port being used (for port hopping)
// Returns 0 if port hopping is disabled
func (m *Manager) GetCurrentPort() int {
	if m.portHopper == nil {
		return 0
	}
	return m.portHopper.CurrentPort()
}

// EnablePortHopping enables port hopping dynamically (e.g., from server capabilities)
// Returns true if port hopping was enabled, false if already enabled or error
func (m *Manager) EnablePortHopping(cfg *porthopping.Config) bool {
	m.portHopperMu.Lock()
	defer m.portHopperMu.Unlock()

	// Already enabled
	if m.portHopper != nil {
		log.Debug("Port hopping already enabled, ignoring auto-enable")
		return false
	}

	if cfg == nil || !cfg.Enabled {
		return false
	}

	hopper, err := porthopping.NewPortHopper(cfg)
	if err != nil {
		log.Warn("Failed to enable port hopping: %v", err)
		return false
	}

	m.portHopper = hopper
	// Set callback for port change - triggers reconnect
	hopper.OnHop(func(oldPort, newPort int) {
		log.Info("Port hop: %d -> %d, triggering reconnect", oldPort, newPort)
		m.triggerReconnect()
	})

	log.Info("Port hopping auto-enabled from server (range=%d-%d, interval=%v, strategy=%s)",
		cfg.PortRangeStart, cfg.PortRangeEnd, cfg.HopInterval, cfg.Strategy)

	return true
}

// IsPortHoppingEnabled returns true if port hopping is enabled
func (m *Manager) IsPortHoppingEnabled() bool {
	return m.portHopper != nil
}

// TLSSessionCache returns the shared client session cache used by stdlib-TLS
// strategies for resumption across reconnects. Safe for concurrent use; the
// returned value is fixed at construction and never replaced.
func (m *Manager) TLSSessionCache() tls.ClientSessionCache {
	return m.tlsSessionCache
}

// GetServerAddr returns the address of the currently pinned endpoint candidate.
//
// It is a pure read and never touches the network. It used to hold a mutex
// across a 3-second DialContext while roughly fifteen call sites - including
// every strategy in a scan - went through it. The probe now lives in one
// explicit step per connect cycle (see dialEndpoints); this returns whatever
// that step decided, so a whole scan sees one and the same address.
//
// A dial that was decided for a particular candidate carries its address on
// ctx (see withDialCandidate), and that address wins over the pin: the pin may
// have moved since the dial started, the dial's key has not.
func (m *Manager) GetServerAddr(ctx context.Context) string {
	if a, ok := dialAddr(ctx); ok {
		return a
	}
	sel := m.selector()
	if sel == nil {
		return ""
	}
	c, ok := sel.Current()
	if !ok {
		return ""
	}
	return c.Addr
}

// PoolAddrs returns the addresses of every candidate with a physical route,
// in preference order - what a "does anyone answer" poll walks.
//
// The route verdicts are refreshed first. They used to be refreshed only by a
// connect cycle's family preflight, and the pool wait does not run connect
// cycles: a family whose route came back mid-wait stayed excluded while the
// family that was left kept timing out. The refresh reads the routing table
// and sends nothing.
func (m *Manager) PoolAddrs() []string {
	sel := m.selector()
	if sel == nil {
		return nil
	}
	m.familyReachabilityPreflight(sel)
	var out []string
	for _, c := range sel.Candidates() {
		if sel.Reachable(c.Addr) {
			out = append(out, c.Addr)
		}
	}
	return out
}

// PinAnswering moves the pin to the candidate at addr after a TCP poll found it
// answering while the rest of the pool was silent, so the reconnect that
// follows starts there instead of walking the silent addresses first. It
// reports whether it did.
//
// A parked candidate is un-parked and pinned too. The gate refuses to switch to
// a parked address because a blackhole answers TCP; but this poll runs only
// when no address answered at all, and an answer after that is newer evidence
// than the park - and the only way out. Leaving it parked sent the reconnect
// walking the silent addresses again.
//
// Except a park for dead sessions: sessions there connect and then die, so a
// TCP answer is exactly what that server gives and no evidence at all. Lifting
// it undid the escalation - a server parked for one minute, then two, then
// four was unparked by the next poll 5-8 s later and the client died on it
// again about every 45 s. It stays parked until its cooldown runs out.
func (m *Manager) PinAnswering(addr string) bool {
	sel := m.selector()
	if sel == nil {
		return true
	}
	cand, ok := sel.CandidateForAddr(addr)
	if !ok {
		return true
	}
	if sel.ParkedForDeadSessions(cand) {
		log.Debug("Pool poll: %s answers but is parked for dead sessions - waiting out its park", cand)
		return false
	}
	sel.ReportProbe(cand, true, 0)
	if sel.IsParked(cand) {
		log.Info("Pool poll: %s answered after the pool went silent - lifting its park", cand)
		sel.Unpark(cand)
	}
	if cur, _ := sel.Current(); cur.Addr != cand.Addr {
		log.Info("Pool poll: %s answered first, pinning it", cand)
	}
	sel.Pin(cand)
	return true
}

// PinParkedAnswering pins the candidate at addr whatever its park says, and
// lifts the park, keeping its history: for a pool poll that has heard only
// this server, parked for dead sessions, for long enough (see the TUN
// client's waitForPool). The dead-session park doubles up to MaxCooldown, and
// a single-server pool would otherwise wait it out in full.
func (m *Manager) PinParkedAnswering(addr string) {
	sel := m.selector()
	if sel == nil {
		return
	}
	cand, ok := sel.CandidateForAddr(addr)
	if !ok {
		return
	}
	log.Info("Pool poll: %s answers and nothing else does - lifting its park for dead sessions", cand)
	sel.ReportProbe(cand, true, 0)
	sel.Unpark(cand)
	sel.Pin(cand)
}

// ProbeEndpointFamily runs the one-shot transport-family probe for the pinned
// candidate and returns the address that came out of it.
//
// This is the explicit step that replaced the dial GetServerAddr used to hide.
// Connect calls it once per cycle; it is exported so the wiring around the
// manager can drive it too.
func (m *Manager) ProbeEndpointFamily(ctx context.Context) string {
	sel := m.selector()
	if sel == nil {
		return ""
	}
	c, _ := sel.ProbeCurrent(ctx)
	return c.Addr
}

// EndpointStates returns the current endpoint candidates and their health, for
// logging and diagnostics.
func (m *Manager) EndpointStates() []endpoint.CandidateState {
	sel := m.selector()
	if sel == nil {
		return nil
	}
	return sel.Snapshot()
}

// ResetHealth discards every cached endpoint verdict and re-pins the most
// preferred candidate. Call it when the network underneath changed and old
// observations describe a network that no longer exists.
func (m *Manager) ResetHealth() {
	sel := m.selector()
	if sel == nil {
		return
	}
	sel.ResetHealth()
	log.Debug("Endpoint health reset, family will be re-probed on next connection")
}

// ResetIPv6Check forces a re-check of the transport family on the next connect.
//
// Deprecated: use ResetHealth. Kept because the Android control-socket path
// calls it by this name.
func (m *Manager) ResetIPv6Check() {
	m.ResetHealth()
}

// SetBurstReshape configures burst reshaping for strategies created afterwards.
// Call it before building strategies: the setting is copied at construction.
func (m *Manager) SetBurstReshape(cfg BurstReshapeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.burstReshape = cfg
}

// BurstReshape returns the configured reshaping settings.
func (m *Manager) BurstReshape() BurstReshapeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.burstReshape
}
