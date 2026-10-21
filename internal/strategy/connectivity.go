package strategy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Probe pacing for the connectivity wait loop. After a server-side reset the
// real outage is usually sub-second, so we retry quickly first and back off
// exponentially rather than polling on a flat 5s ticker (which turned a <1s
// reset into a ~5s freeze). See WaitForConnectivity.
const (
	defaultProbeInterval = 250 * time.Millisecond  // first retry after a failed check
	maxProbeInterval     = 2500 * time.Millisecond // backoff ceiling
	probeBackoffFactor   = 2                       // interval multiplier per miss
)

// ConnectivityResult holds the result of a connectivity check
type ConnectivityResult struct {
	TCP  bool // TCP connect to server port succeeded
	UDP  bool // UDP connectivity check passed
	ICMP bool // ICMP ping succeeded (optional)

	// UDPKnown is true when UDP carries a verdict: a probe to this address
	// finished with silence (works) or an ICMP refusal (blocked), this round
	// or an earlier one, on a network whose TCP gate passed. It is false on a
	// cold start whose probe has not landed yet, after the TCP gate failed,
	// after a network change, and when the probe died on a local error such
	// as "network is unreachable" - none of which says anything about UDP to
	// the server. UDP is then a placeholder the QUIC gate must not act on.
	// Before this field every cold start read the placeholder as "UDP down"
	// and a forced -strategy quic_salamander client exited on the spot.
	UDPKnown bool

	// Addr is the address that actually answered the TCP gate, empty when none
	// did. The gate already tries several addresses and knows which one worked;
	// reporting it costs nothing and is what lets the endpoint selector learn
	// "the other family is up" without a single extra packet.
	Addr string

	Latency   time.Duration // RTT to server
	Error     error         // Last error encountered
	CheckedAt time.Time     // When the check was performed
}

// HasBasicConnectivity returns true if at least TCP works
func (r ConnectivityResult) HasBasicConnectivity() bool {
	return r.TCP
}

// ConnectivityChecker performs pre-flight connectivity checks before trying strategies
type ConnectivityChecker struct {
	timeout     time.Duration // timeout for the TCP gate (2-3 sec)
	auxTimeout  time.Duration // bounded timeout for the UDP/ICMP probes
	auxGrace    time.Duration // how long Check waits for UDP/ICMP after TCP lands
	androidMode bool          // skip ICMP check on Android (os/exec not allowed)

	// serverAddr and altAddrs move with the pinned endpoint, so both are
	// guarded: Connect rewrites them per cycle while a wait loop may be reading
	// them from another goroutine.
	mu         sync.RWMutex
	serverAddr string   // full addr host:port
	altAddrs   []string // same server on its other address families, optional
	lastResult ConnectivityResult

	// udpPort is where QUIC dials, 0 when no QUIC strategy is registered. The
	// UDP check probes the primary host on this port: its verdict gates QUIC,
	// and the server's TCP port answered for a different socket entirely.
	udpPort int

	// The cached UDP verdict (lastResult.UDP/UDPKnown) is only ever written by
	// storeUDPVerdict and invalidateUDPVerdict. udpVerdictAddr is the address
	// it is about: a verdict for another server or family is no verdict here.
	// udpVerdictStart orders verdicts by when their probe started, so a slow
	// probe from an older round cannot overwrite a newer one, nor revive a
	// verdict that invalidateUDPVerdict voided after the probe went out.
	udpVerdictAddr  string
	udpVerdictStart time.Time

	// udpDial opens the probe socket; nil means a plain net.Dialer. Tests use
	// it to stand in for a host whose network is down.
	udpDial func(ctx context.Context, network, addr string) (net.Conn, error)

	// tcpDial opens the TCP gate's connections; nil means a plain net.Dialer.
	// Tests use it for an address that times out instead of refusing.
	tcpDial func(ctx context.Context, network, addr string) (net.Conn, error)

	// icmpCheck stands in for checkICMP when set. Tests use it for a host
	// whose 443 and 80 swallow the ICMP check's dials.
	icmpCheck func(ctx context.Context, host string) error

	// rttHost and rttMin are the path RTT the auto-mode QUIC budget scales
	// with: the minimum TCP connect time to the host that answered the gate.
	rttHost string
	rttMin  time.Duration
}

// udpGateVerdict is what one UDP probe established. known is false when the
// probe ended without hearing about the path at all.
type udpGateVerdict struct {
	known bool
	ok    bool
}

// NewConnectivityChecker creates a new connectivity checker
func NewConnectivityChecker(serverAddr string, timeout time.Duration, androidMode bool) *ConnectivityChecker {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &ConnectivityChecker{
		serverAddr:  serverAddr,
		timeout:     timeout,
		auxTimeout:  700 * time.Millisecond,
		auxGrace:    300 * time.Millisecond,
		androidMode: androidMode,
	}
}

// setUDPProbePort points the UDP check at QUIC's port. See udpPort.
func (c *ConnectivityChecker) setUDPProbePort(port int) {
	c.mu.Lock()
	c.udpPort = port
	c.mu.Unlock()
	c.invalidateUDPVerdict()
}

// storeUDPVerdict caches a finished probe's verdict. Unknown results are not
// stored, and neither is a verdict whose probe started before the cached one
// or before the last invalidation.
func (c *ConnectivityChecker) storeUDPVerdict(addr string, start time.Time, v udpGateVerdict) {
	if !v.known {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if start.Before(c.udpVerdictStart) {
		return
	}
	c.lastResult.UDP, c.lastResult.UDPKnown = v.ok, true
	c.udpVerdictAddr, c.udpVerdictStart = addr, start
}

// cachedUDPVerdict returns the cached verdict if it is about addr.
func (c *ConnectivityChecker) cachedUDPVerdict(addr string) (ok, known bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.lastResult.UDPKnown || c.udpVerdictAddr != addr {
		return false, false
	}
	return c.lastResult.UDP, true
}

// invalidateUDPVerdict forgets the cached verdict: the network it was taken on
// is gone or was down, so it describes nothing the next connect will cross.
func (c *ConnectivityChecker) invalidateUDPVerdict() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastResult.UDP, c.lastResult.UDPKnown = false, false
	c.udpVerdictAddr, c.udpVerdictStart = "", time.Now()
}

// refreshUDPAsync probes UDP to the current primary in the background and
// caches the verdict. The hot paths that skip the full Check (recovery from
// WaitForConnectivity, a network change) use it so the QUIC gate is not left
// on an invalidated verdict until the next pre-flight.
func (c *ConnectivityChecker) refreshUDPAsync() {
	c.mu.RLock()
	primary := c.serverAddr
	c.mu.RUnlock()
	addr := c.udpProbeAddr(primary)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*c.auxTimeout)
		defer cancel()
		start := time.Now()
		v, err := c.checkUDP(ctx, addr)
		log.Debug("UDP re-probe of %s: known=%v ok=%v (%v)", addr, v.known, v.ok, err)
		c.storeUDPVerdict(addr, start, v)
	}()
}

// udpProbeAddr is the address the UDP check probes for primary.
func (c *ConnectivityChecker) udpProbeAddr(primary string) string {
	c.mu.RLock()
	port := c.udpPort
	c.mu.RUnlock()
	if port == 0 {
		return primary
	}
	host, _, err := net.SplitHostPort(primary)
	if err != nil {
		return primary
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// SetAltAddr registers the same server's address on the other family (the
// IPv6 one when -server carries IPv4, or the reverse). The TCP gate then
// accepts either: the question it answers is "can this client reach its
// server", and with a dual-addressed server that is true as long as one family
// works. Without it a client configured with both addresses sat in
// "waiting for network" against a blocked IPv4 while its IPv6 transport was
// perfectly reachable. Empty or duplicate values are ignored.
func (c *ConnectivityChecker) SetAltAddr(addr string) {
	c.mu.RLock()
	primary := c.serverAddr
	c.mu.RUnlock()
	c.SetAddrs(primary, addr)
}

// SetAddrs points the gate at primary, with alts as the same server's other
// address families. Empty and duplicate values are dropped; an empty primary is
// ignored, so a caller that only knows the alternates cannot blank out the
// address the gate dials.
func (c *ConnectivityChecker) SetAddrs(primary string, alts ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if primary != "" {
		c.serverAddr = primary
	}
	seen := map[string]bool{c.serverAddr: true}
	c.altAddrs = nil
	for _, a := range alts {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		c.altAddrs = append(c.altAddrs, a)
	}
}

// addrsToTry returns the addresses the TCP gate probes, preferred one first.
func (c *ConnectivityChecker) addrsToTry() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, 1+len(c.altAddrs))
	out = append(out, c.serverAddr)
	return append(out, c.altAddrs...)
}

// checkTCPAny reports the address that answered as soon as any configured one
// does, and returns the last error when none do.
func (c *ConnectivityChecker) checkTCPAny(ctx context.Context) (string, error) {
	addr, _, err := c.checkTCPAnyTimed(ctx)
	return addr, err
}

// checkTCPAnyTimed is checkTCPAny that also reports how long the connect to
// the answering address took. Only that one: the walk's total time also
// held the timeouts of the dead addresses before it - three seconds for a
// blocked IPv4 ahead of a live IPv6 - which is not anyone's RTT.
func (c *ConnectivityChecker) checkTCPAnyTimed(ctx context.Context) (string, time.Duration, error) {
	var lastErr error
	for _, addr := range c.addrsToTry() {
		start := time.Now()
		err := c.checkTCP(ctx, addr)
		if err == nil {
			rtt := time.Since(start)
			c.notePathRTT(addr, rtt)
			return addr, rtt, nil
		}
		lastErr = err
	}
	return "", 0, lastErr
}

// notePathRTT folds one TCP connect time into the per-host minimum. A single
// connect also counts SYN retransmits (a lost SYN adds a second or more on a
// lossy mobile link); the minimum over the samples so far is the path's RTT.
func (c *ConnectivityChecker) notePathRTT(addr string, rtt time.Duration) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if host != c.rttHost || c.rttMin == 0 || rtt < c.rttMin {
		if host != c.rttHost {
			c.rttHost = host
		}
		c.rttMin = rtt
	}
}

// pathRTT is the minimum TCP connect time measured to host, 0 when there is
// none for it.
func (c *ConnectivityChecker) pathRTT(host string) time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if host != c.rttHost {
		return 0
	}
	return c.rttMin
}

// resetPathRTT forgets the RTT, which belongs to the network just left.
func (c *ConnectivityChecker) resetPathRTT() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rttHost, c.rttMin = "", 0
}

// currentUDPVerdict is the cached verdict about the address the UDP check
// would probe now. LastResult carries the last verdict of any address, which
// after an endpoint switch is the previous server's.
func (c *ConnectivityChecker) currentUDPVerdict() (ok, known bool) {
	c.mu.RLock()
	primary := c.serverAddr
	c.mu.RUnlock()
	return c.cachedUDPVerdict(c.udpProbeAddr(primary))
}

// Check performs TCP, UDP and ICMP connectivity checks
func (c *ConnectivityChecker) Check(ctx context.Context) ConnectivityResult {
	result := ConnectivityResult{
		CheckedAt: time.Now(),
	}

	c.mu.RLock()
	primary := c.serverAddr
	c.mu.RUnlock()

	// Parse host from server address
	host, port, err := net.SplitHostPort(primary)
	if err != nil {
		result.Error = fmt.Errorf("invalid server address: %w", err)
		return result
	}

	// TCP is the only gate (HasBasicConnectivity == TCP), so it runs on the hot
	// reconnect path and decides the result. UDP/ICMP only gate QUIC selection,
	// so they run concurrently but must never delay the TCP verdict: we wait for
	// them just auxGrace, then fall back to the last known value and let them
	// finish updating the cache in the background.
	var tcpErr error
	var tcpAddr string
	var tcpLatency time.Duration
	tcpDone := make(chan struct{})
	go func() {
		tcpAddr, tcpLatency, tcpErr = c.checkTCPAnyTimed(ctx)
		close(tcpDone)
	}()

	// UDP and ICMP run apart: only UDP gates anything, and the ICMP check's
	// TCP dials (700ms each on a silent port) must not hold a refused UDP
	// verdict back past the grace.
	udpAddr := c.udpProbeAddr(primary)
	udpStart := time.Now()
	var udpV udpGateVerdict
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		udpV, _ = c.checkUDP(ctx, udpAddr)
	}()
	var icmpOK atomic.Bool
	icmpDone := make(chan struct{})
	go func() {
		defer close(icmpDone)
		// ICMP check (optional, may fail without root).
		// Skip on Android - os/exec causes SIGSYS due to seccomp.
		if !c.androidMode {
			c.mu.RLock()
			check := c.icmpCheck
			c.mu.RUnlock()
			if check == nil {
				check = c.checkICMP
			}
			icmpOK.Store(check(ctx, host) == nil)
		}
	}()

	<-tcpDone
	result.TCP = tcpErr == nil
	if result.TCP {
		result.Latency = tcpLatency
		result.Addr = tcpAddr
	}
	if tcpErr != nil {
		result.Error = tcpErr
	}

	switch {
	case !result.TCP:
		// The server is unreachable, so whatever the UDP probe meets is the
		// network being down or changing, not the path to the server. Its
		// verdict, and the cached one, would outlive the outage: a client
		// started with the link down came back with "UDP blocked" and a
		// forced QUIC client exited on "no available strategies".
		c.invalidateUDPVerdict()
	default:
		select {
		case <-udpDone:
			c.storeUDPVerdict(udpAddr, udpStart, udpV)
		case <-time.After(c.auxGrace):
			// Slow this round: let the probe refresh the cache once it lands.
			// storeUDPVerdict orders it against newer rounds by start time.
			go func() {
				<-udpDone
				c.storeUDPVerdict(udpAddr, udpStart, udpV)
			}()
		}
		// This round's verdict if it landed, else the last one for this
		// address, else unknown.
		result.UDP, result.UDPKnown = c.cachedUDPVerdict(udpAddr)
	}

	select {
	case <-icmpDone:
		result.ICMP = icmpOK.Load()
	default:
		c.mu.RLock()
		result.ICMP = c.lastResult.ICMP
		c.mu.RUnlock()
		go func() {
			<-icmpDone
			c.mu.Lock()
			c.lastResult.ICMP = icmpOK.Load()
			c.mu.Unlock()
		}()
	}

	// The address that ANSWERED, not the one the walk started from. The gate
	// tries the pool in order, so a line naming only the first address reads as
	// "this one is up" when the verdict may have come from a different server
	// entirely - which is what it did on the device.
	answered := result.Addr
	if answered == "" {
		answered = "none"
	}
	log.Debug("Connectivity check from %s - TCP:%v (answered=%s) UDP:%v (known=%v) ICMP:%v (latency=%v)",
		net.JoinHostPort(host, port), result.TCP, answered, result.UDP, result.UDPKnown, result.ICMP, result.Latency)

	c.cacheResult(result)
	return result
}

// CheckTCP runs the TCP leg of the gate alone, over every address it is set
// to, and caches the result like Check does. It sends nothing but the TCP
// handshakes: no UDP probe, and none of the extra :443/:80 dials Check's ICMP
// leg makes. Meant for loops that ask "does anyone in the pool answer yet" on a
// timer, where those extras would repeat with every round.
func (c *ConnectivityChecker) CheckTCP(ctx context.Context) ConnectivityResult {
	return c.checkTCPOnly(ctx)
}

// checkTCPOnly performs just the TCP gate, carrying forward the last known
// UDP/ICMP verdict. Used on the hot retry path (WaitForConnectivity) where the
// only thing that matters is whether the server's TCP port is back; pulling in
// UDP/ICMP probes there only adds latency to recovery.
func (c *ConnectivityChecker) checkTCPOnly(ctx context.Context) ConnectivityResult {
	result := ConnectivityResult{CheckedAt: time.Now()}

	addr, rtt, err := c.checkTCPAnyTimed(ctx)
	result.TCP = err == nil
	if err != nil {
		result.Error = err
	} else {
		result.Latency = rtt
		result.Addr = addr
	}

	// Carry forward last known UDP/ICMP (they gate QUIC and rarely flip) -
	// unless the TCP gate failed, which voids the UDP verdict (see Check).
	if !result.TCP {
		c.invalidateUDPVerdict()
	}
	c.mu.RLock()
	result.UDP = c.lastResult.UDP
	result.ICMP = c.lastResult.ICMP
	result.UDPKnown = c.lastResult.UDPKnown
	c.mu.RUnlock()
	c.cacheResult(result)

	return result
}

// cacheResult stores result as the last one, keeping the cached UDP verdict:
// that is owned by storeUDPVerdict and invalidateUDPVerdict, which order
// verdicts by probe start, and a round that only carried it must not undo a
// verdict that landed in the meantime.
func (c *ConnectivityChecker) cacheResult(result ConnectivityResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	udp, known := c.lastResult.UDP, c.lastResult.UDPKnown
	c.lastResult = result
	c.lastResult.UDP, c.lastResult.UDPKnown = udp, known
}

// checkTCP verifies that the server's TCP port is reachable.
// A plain TCP dial is enough — the server speaks a custom protocol, so a TLS
// handshake would always fail the connectivity check even when the port is up.
func (c *ConnectivityChecker) checkTCP(ctx context.Context, addr string) error {
	c.mu.RLock()
	dial := c.tcpDial
	c.mu.RUnlock()
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.timeout}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP connect failed: %w", err)
	}
	conn.Close()
	return nil
}

// checkUDP sends a datagram to addr and reads for a moment.
//
// Only two outcomes are a verdict about UDP to the server. Silence until the
// read deadline: the datagram left and nothing refused it (it may still have
// been dropped - the probe cannot tell). An ICMP port unreachable, which the
// connected socket reports as ECONNREFUSED: refused. A reply also counts as
// working. Everything else - "network is unreachable", "no route to host", a
// dial that fails before any packet leaves - is the local network talking,
// and comes back as unknown instead of the "UDP blocked" it used to be.
func (c *ConnectivityChecker) checkUDP(ctx context.Context, addr string) (udpGateVerdict, error) {
	c.mu.RLock()
	dial := c.udpDial
	c.mu.RUnlock()
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.auxTimeout}).DialContext
	}
	conn, err := dial(ctx, "udp", addr)
	if err != nil {
		return udpGateVerdict{}, fmt.Errorf("UDP dial failed: %w", err)
	}
	defer conn.Close()

	// Set short deadline for write/read
	deadline := time.Now().Add(c.auxTimeout)
	conn.SetDeadline(deadline)

	// Send a probe packet that won't trigger Salamander "ciphertext too short" errors
	// Salamander needs at least 8 bytes, so we send 16 random-looking bytes
	// This is NOT a valid QUIC packet, just checking if UDP can be sent/received
	probe := []byte{
		0xc0, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, // 8 bytes header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 bytes padding
	}
	if _, err = conn.Write(probe); err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return udpGateVerdict{known: true}, fmt.Errorf("UDP blocked: %w", err)
		}
		return udpGateVerdict{}, fmt.Errorf("UDP write failed: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	switch {
	case err == nil:
		return udpGateVerdict{known: true, ok: true}, nil
	case errors.Is(err, os.ErrDeadlineExceeded):
		return udpGateVerdict{known: true, ok: true}, nil
	case errors.Is(err, syscall.ECONNREFUSED):
		return udpGateVerdict{known: true}, fmt.Errorf("UDP blocked: %w", err)
	default:
		return udpGateVerdict{}, fmt.Errorf("UDP probe inconclusive: %w", err)
	}
}

func (c *ConnectivityChecker) checkICMP(ctx context.Context, host string) error {
	d := net.Dialer{Timeout: c.auxTimeout}
	var err error
	for _, port := range []string{"443", "80"} {
		// JoinHostPort, not host+":"+port: host is unbracketed here, and
		// "2001:db8::1:443" is not an address net.Dial accepts.
		var conn net.Conn
		if conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(host, port)); err == nil {
			conn.Close()
			return nil
		}
	}
	return fmt.Errorf("host unreachable: %w", err)
}

// WaitForConnectivity waits in a loop until TCP connectivity is available.
//
// interval is the FIRST retry delay; on each miss it backs off by
// probeBackoffFactor up to maxProbeInterval. A short server-side reset is
// usually back within a few hundred ms, so the early retries are fast (recovery
// drops from the old flat ~5s to <1s) while the ceiling keeps a truly-down
// network from being hammered. Only the TCP gate is probed here — UDP/ICMP just
// gate QUIC selection and are carried forward from the cache.
func (c *ConnectivityChecker) WaitForConnectivity(ctx context.Context, interval time.Duration) ConnectivityResult {
	if interval <= 0 {
		interval = defaultProbeInterval
	}

	// First check immediately.
	result := c.checkTCPOnly(ctx)
	if result.TCP {
		// Back before the wait began, but the Check that sent the caller here
		// failed its TCP leg and voided the verdict: re-probe as the loop below
		// does, or auto mode keeps QUIC deferred with nothing to lift it.
		if !result.UDPKnown {
			c.refreshUDPAsync()
		}
		return result
	}

	log.Warn("No connectivity to %s, waiting for network...", strings.Join(c.addrsToTry(), " or "))

	backoff := interval
	timer := time.NewTimer(backoff)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ConnectivityResult{
				Error:     ctx.Err(),
				CheckedAt: time.Now(),
			}
		case <-timer.C:
			result = c.checkTCPOnly(ctx)
			if result.TCP {
				log.Info("Connectivity restored to %s", result.Addr)
				// The outage voided the UDP verdict; take a fresh one in the
				// background rather than slow the recovery down with it.
				c.refreshUDPAsync()
				return result
			}
			backoff = nextProbeBackoff(backoff)
			timer.Reset(backoff)
			log.Debug("Still no connectivity to %s, retrying in %v...", c.ServerAddr(), backoff)
		}
	}
}

// nextProbeBackoff advances the WaitForConnectivity retry delay: multiply by
// probeBackoffFactor, clamped at maxProbeInterval. A caller-supplied interval
// already at or above the ceiling is left alone rather than pulled down to it.
func nextProbeBackoff(cur time.Duration) time.Duration {
	if cur >= maxProbeInterval {
		return cur
	}
	next := cur * probeBackoffFactor
	if next > maxProbeInterval {
		next = maxProbeInterval
	}
	return next
}

// LastResult returns the last cached connectivity result
func (c *ConnectivityChecker) LastResult() ConnectivityResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastResult
}

// ServerAddr returns the primary server address currently being checked.
func (c *ConnectivityChecker) ServerAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverAddr
}
