package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Donor mirroring for the B1 fallback.
//
// The upstream reference opens a connection to the donor for every incoming
// connection and mirrors the client's bytes into it as they arrive. That gives
// a prober a fallback indistinguishable from talking to the donor directly -
// and costs a stream of half-finished handshakes to sberbank.ru from our
// address, one per user connection, which is the exact problem B1 set out to
// remove.
//
// So the dial is conditional on what we know about the source. An address that
// authenticated recently is a user, and users never need a donor: nothing is
// dialled for them at all. An address we have not seen gets the full
// treatment. Traffic to donors then scales with probing rather than with usage.

// Donor dial counters, split by when the dial happened. The split is the point:
// it shows whether mirroring is costing us donor traffic proportional to
// probing, as intended, or proportional to users, which would mean the
// reputation set is not working.
var (
	realityDonorDialsEager atomic.Uint64
	realityDonorDialsLazy  atomic.Uint64
)

// sourceReputationTTL is how long a successful authentication vouches for an
// address. An hour is long enough that a user reconnecting through the day
// never triggers a dial, and short enough that an address changing hands is
// forgotten before it matters.
const sourceReputationTTL = time.Hour

// sourceReputation remembers addresses that recently authenticated.
//
// Keyed by IP without the port, because a client's port changes every
// connection and it is the host we are vouching for.
type sourceReputation struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration

	swept time.Time
}

func newSourceReputation(ttl time.Duration) *sourceReputation {
	return &sourceReputation{seen: map[string]time.Time{}, ttl: ttl, swept: time.Now()}
}

var reputation = newSourceReputation(sourceReputationTTL)

// remember records that an address authenticated.
func (r *sourceReputation) remember(addr net.Addr, now time.Time) {
	host := hostOf(addr)
	if host == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	r.seen[host] = now
}

// known reports whether an address authenticated inside the TTL.
func (r *sourceReputation) known(addr net.Addr, now time.Time) bool {
	host := hostOf(addr)
	if host == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.seen[host]
	return ok && now.Sub(at) < r.ttl
}

// sweepLocked drops expired entries. Cheap and rare: the set only grows on
// successful authentication, so its size tracks the number of real users.
func (r *sourceReputation) sweepLocked(now time.Time) {
	if now.Sub(r.swept) < r.ttl/4 {
		return
	}
	r.swept = now
	for host, at := range r.seen {
		if now.Sub(at) >= r.ttl {
			delete(r.seen, host)
		}
	}
}

func hostOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// shouldMirror decides whether this connection gets a donor connection opened
// for it before we know whether it needs one.
func shouldMirror(mode string, remote net.Addr, now time.Time) bool {
	switch mode {
	case MirrorAlways:
		return true
	case MirrorAdaptive:
		// A prober always arrives from an address that has never
		// authenticated, so it always gets the full treatment. A user's address
		// is vouched for by its last successful handshake and costs nothing.
		return !reputation.known(remote, now)
	default: // MirrorOff
		return false
	}
}

// mirrorConn wraps the client connection and copies everything read from it
// into a donor connection, preserving the boundaries the client wrote in.
//
// Preserving boundaries is why this exists rather than a buffer flushed at the
// end: a ClientHello split across three segments has to reach the donor as
// three writes, or the fallback is distinguishable from a direct connection by
// its framing alone.
//
// Unlike the reference (.ref/REALITY/tls.go:64-102) there is no
// Unlock/Gosched/Lock dance around the read. That dance exists to let a second
// goroutine win the race to stop mirroring before the next chunk is forwarded.
// Here the goroutine that reads is the goroutine that decides, so there is no
// race to arbitrate - the only concurrency is the dialer attaching the target,
// which the mutex covers on its own. Simpler, and it cannot deadlock.
type mirrorConn struct {
	net.Conn

	mu       sync.Mutex
	target   net.Conn
	stopped  bool
	recorded [][]byte // chunks read before the target was ready
}

func newMirrorConn(c net.Conn) *mirrorConn { return &mirrorConn{Conn: c} }

// Read forwards whatever it reads to the donor, in the same sized pieces.
func (m *mirrorConn) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	if n <= 0 {
		return n, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return n, err
	}
	if m.target == nil {
		// The donor is still being dialled. Keep the chunk, with its own
		// boundary, to replay in order once the connection is up.
		chunk := make([]byte, n)
		copy(chunk, b[:n])
		m.recorded = append(m.recorded, chunk)
		return n, err
	}
	_, _ = m.target.Write(b[:n])
	return n, err
}

// attach hands the mirror its donor connection and replays whatever was read
// while the dial was in flight.
func (m *mirrorConn) attach(target net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		// The gate finished first and the donor is not needed.
		_ = target.Close()
		return
	}
	m.target = target
	for _, chunk := range m.recorded {
		_, _ = m.target.Write(chunk)
	}
	m.recorded = nil
}

// stop ends mirroring and hands back the donor connection, if one was ever
// attached, for the caller to close. After this the wrapper is a plain conn.
func (m *mirrorConn) stop() net.Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	target := m.target
	m.target = nil
	m.recorded = nil
	return target
}

// donorHandoff is the result of an eager dial.
type donorHandoff struct {
	conn net.Conn
	dest string
	err  error
}

// dialDonorEagerly starts the donor connection concurrently and reports the
// outcome on the returned channel.
//
// A note on how eager this can be. The reference dials at accept because its
// destination is configured; ours comes from the ClientHello's SNI, and the
// destination policy - allowlisted name, else the cover domain, else nothing -
// is the anti-SSRF guarantee and does not change. So the earliest honest moment
// is the one where the name is known, which is the moment the gate starts. The
// dial then runs alongside the key agreement and the client's next writes
// instead of starting only after the verdict, which is what it was doing
// before.
func dialDonorEagerly(peekBuf []byte, srvCtx *serverContext) <-chan donorHandoff {
	out := make(chan donorHandoff, 1)

	dest := donorDestination(peekBuf, srvCtx.cfg.REALITYCoverDomain)
	if dest == "" {
		out <- donorHandoff{err: errNoDonor}
		return out
	}

	go func() {
		realityDonorDialsEager.Add(1)
		c, err := net.DialTimeout("tcp", net.JoinHostPort(dest, "443"), 10*time.Second)
		out <- donorHandoff{conn: c, dest: dest, err: err}
	}()
	return out
}

// errNoDonor means the destination policy allows no donor for this connection:
// the SNI is not on the allowlist and no cover domain is configured.
var errNoDonor = errors.New("reality: no donor for this connection")

// writeREALITYDonorMetrics renders the donor dial counters.
func writeREALITYDonorMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP reality_donor_dials_total Connections opened to donor sites, by when the dial happened\n")
	fmt.Fprintf(w, "# TYPE reality_donor_dials_total counter\n")
	fmt.Fprintf(w, "reality_donor_dials_total{when=\"eager\"} %d\n", realityDonorDialsEager.Load())
	fmt.Fprintf(w, "reality_donor_dials_total{when=\"lazy\"} %d\n", realityDonorDialsLazy.Load())
	fmt.Fprintf(w, "\n")
}

// mirrorLog keeps the mode visible at startup, since a deployment running
// "always" is spending real traffic on donors and that should not be a surprise.
func logMirrorMode(mode string) {
	switch mode {
	case MirrorAlways:
		log.Warn("REALITY: -reality-mirror=always dials a donor for every connection, including users; " +
			"intended for comparative measurement, not production")
	case MirrorAdaptive:
		log.Info("REALITY: donor mirroring is adaptive - only sources that have not authenticated recently")
	}
}
